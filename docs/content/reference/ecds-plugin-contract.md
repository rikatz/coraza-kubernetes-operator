---
title: "ECDS Plugin Contract"
linkTitle: "ECDS Plugin Contract"
weight: 40
description: "How the Coraza Kubernetes Operator delivers rules to the upstream coraza-proxy-wasm plugin over ECDS."
---

The Coraza Kubernetes Operator (CKO) delivers rules to the **upstream
[`coraza-proxy-wasm`](https://github.com/corazawaf/coraza-proxy-wasm) plugin**, unmodified.
There is no operator-specific plugin fork and no extra payload fields: the runtime JSON is
the plugin's own configuration schema.

## Runtime configuration JSON

The ECDS resource carries this JSON in `PluginConfig.configuration`
(`google.protobuf.StringValue`):

```json
{
  "directives_map": {
    "default": ["SecRuleEngine On\nSecRule ARGS \"@attack\" \"id:1001,phase:2,deny,status:403\""]
  },
  "default_directives": "default",
  "failure_policy": "fail",
  "metric_labels": {
    "engine": "checkout",
    "namespace": "shop",
    "uid": "11111111-1111-4111-8111-111111111111"
  },
  "enable_filter_state_logs": true
}
```

| Field | Type | Rules |
| --- | --- | --- |
| `directives_map` | object(name -> list of strings) | One entry, key `default`. Its single element is the complete assembled SecLang text. The plugin joins the list with `\n`, so the text is delivered byte-exact. |
| `default_directives` | string | Always `default`; names the directives entry used for every authority. |
| `failure_policy` | string | `fail` or `allow`, from `Engine.spec.failurePolicy`. Also drives the native WASM `failure_policy`. |
| `metric_labels` | object(string -> string) | `engine`, `namespace`, and `uid` of the Engine, for the plugin's metrics. |
| `enable_filter_state_logs` | boolean | Mirrors `Engine.spec.observability.mode == Enabled`. Ignored by plugin releases older than the filter-state log feature. |

What the operator guarantees:

- No token, token path, polling interval, HTTP rule-server address, or per-pod identifier
  appears in the payload. Rules only change when a new ECDS snapshot is published.
- The plugin builds synchronously in `OnPluginStart`; a payload it rejects is NACKed and
  Envoy keeps the previous configuration.
- An empty RuleSet is refused unless `spec.emptyRulesPolicy: Allow`; in that case the
  operator renders `SecRuleEngine Off` as an intentional no-op WAF instead of an empty
  configuration.
- Fail-closed is the default end to end: `Engine.spec.failurePolicy: fail` maps to native
  `FAIL_CLOSED` plus block-on-error in the plugin.

## Rule data files are not supported yet

The plugin resolves data files (`@pmFromFile`, `Include`) only from the CoreRuleSet
compiled into the module, so the operator cannot ship `RuleData` content with this
payload. An Engine whose RuleSet has data files stays `Degraded` with
`RenderFailed: ... RuleData delivery is a follow-up` rather than publishing a
configuration the plugin could never build.

Use rules that need no external files, or the module's built-in aliases
(`@recommended-conf`, `@demo-conf`, `@ftw-conf`, `@crs-setup-conf`, `@owasp_crs`).

Release artifacts: raw `plugin.wasm`, `plugin.wasm.sha256` (lowercase hex),
`plugin.manifest.yaml` (`schema_version`, module name, file, sha256, git SHA, Coraza
version, proxy-wasm SDK version). CKO bundles exactly these bytes and manifest.

## Cold start

The bundled module is delivered inline, so a proxy that has never seen the configuration
still applies it on the first push.

A module from `spec.driver.wasm.url` is fetched by Envoy instead. A proxy without it in its
cache rejects that first push and never asks for the resource again on its own, so the
operator republishes the same content under a derived version and closes the stream (at most
three times per configuration); Envoy resubscribes and reapplies it. A proxy that keeps
rejecting stays fail-closed and the operator logs `ECDS retry budget exhausted`.

## ECDS resource shape

One `TypedExtensionConfig` per Engine, named
`coraza.waf.<namespace>.<engine-name>.<engine-uid>`:

```yaml
"@type": type.googleapis.com/envoy.config.core.v3.TypedExtensionConfig
name: coraza.waf.shop.checkout.11111111-1111-4111-8111-111111111111
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.wasm.v3.Wasm
  config:
    name: coraza.waf.shop.checkout.11111111-1111-4111-8111-111111111111
    root_id: coraza.waf.shop.checkout.11111111-1111-4111-8111-111111111111
    failure_policy: FAIL_CLOSED
    vm_config:
      vm_id: coraza-11111111-1111-4111-8111-111111111111
      runtime: envoy.wasm.runtime.v8
      # The bundled module travels inline: no fetch, no cold-start window.
      code:
        local:
          inline_bytes: <module bytes>
      # A module from spec.driver.wasm.url is fetched instead:
      # code:
      #   remote:
      #     http_uri: {uri: https://..., cluster: coraza_wasm, timeout: 10s}
      #     sha256: <64hex>
    configuration:
      "@type": type.googleapis.com/google.protobuf.StringValue
      value: "<runtime configuration JSON>"
```

The wire profile is streaming state-of-the-world `ExtensionConfigDiscoveryService`
scoped to one resource per stream. Delta and ADS are out of scope.

## Versions and hashes

- Resource identity includes the Engine UID, so a recreated Engine never reuses a
  deleted Engine's cached configuration.
- The ECDS `version_info` is the complete-resource content hash:
  `sha256:<64 lowercase hexadecimal characters>`.
- `ruleSetHash = sha256(canonical(rule text + sorted filename list + raw bytes))`.
- The Engine version hashes schema and rendering versions, Engine identity, the RuleSet
  UID and content hash, failure and empty-rules policies, observability, binary URL and
  WASM digest, and VM settings.
- No timestamp, Kubernetes `resourceVersion`, nonce, replica identity, token, or CA
  material enters a content hash. Rule text is byte-sensitive: whitespace and comment
  changes change the version.
- Versions are opaque, not monotonic. Reverting to identical effective content may
  reproduce an older version.
- A replica publishes only when it reconstructs the exact bytes whose version matches
  the Engine's accepted configuration.
