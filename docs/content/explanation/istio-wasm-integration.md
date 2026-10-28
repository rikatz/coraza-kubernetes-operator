---
title: "Istio WASM Integration"
linkTitle: "Istio WASM Integration"
weight: 30
description: "How the operator injects the Coraza WAF into Istio gateways with EnvoyFilter and ECDS."
---

The Coraza Kubernetes Operator integrates with Istio by patching the Gateway's Envoy
configuration directly (an `EnvoyFilter`) and streaming the WAF configuration to the proxy
over `ExtensionConfigDiscoveryService` (ECDS). No `WasmPlugin` resource is created.

## How the integration works

For each accepted Engine the operator:

1. Creates or updates an **EnvoyFilter** targeting the Gateway's pods (GEP-1762
   `gateway.networking.k8s.io/gateway-name` label) with two patches:
   - a `CLUSTER` patch adding `coraza_wasm`, the HTTPS cluster that serves the module, and
   - an `HTTP_FILTER` patch inserting the WASM filter before the router, subscribed to ECDS
     for the Engine's resource name.
2. Serves the filter configuration over **ECDS** on its own listener (port 18080, HTTP/2),
   authenticated with the Gateway's ServiceAccount token and a CA-pinned TLS channel.
3. Serves the module bytes over HTTPS at `/wasm/<sha256>.wasm` (or the URL from
   `spec.driver.wasm.url`); Envoy fetches them once, verifies the digest, and caches the
   module, so rule updates never carry the binary again.

Until the ECDS resource arrives, Envoy applies a **deny-all RBAC** default config, so a
Gateway whose Engine is not accepted never forwards traffic unfiltered.

## The plugin

The WASM module is an ECDS-aware build of
[coraza-proxy-wasm](https://github.com/corazawaf/coraza-proxy-wasm). It runs the
Coraza WAF engine inside Envoy and blocks or allows requests based on the rules it is given.

The operator's ECDS resource is the plugin's schema-versioned configuration: the assembled
SecLang text, the RuleData files, the failure policy, and the engine identity. The module
itself is referenced by URL and digest. See the [ECDS plugin
contract]({{< relref "/reference/ecds-plugin-contract" >}}) for the exact payload.

## Rule updates

Rules are pushed, not polled. When a RuleSet changes and the Engine re-accepts, the operator
publishes a new ECDS snapshot; Envoy reconfigures the filter in place and the Gateway pods do
not restart. There is no cache server, no polling interval, and no token in the rule payload.

If the plugin rejects a payload, Envoy NACKs the update and keeps the previous configuration.

Each applied change is visible on both sides without raising log levels:

```
# operator
ECDS configuration published  version=sha256:... ruleSources=4 ruleBytes=... dataFiles=0
# proxy acknowledgement seen by the operator
ECDS configuration accepted by proxy  resource=coraza.waf.<ns>.<engine>.<uid>  version=sha256:...
```

Envoy itself only logs failures by default. Set `wasm=debug` on the proxy admin port
(`curl -X POST localhost:15000/logging?wasm=debug`) to see the plugin instance being
recreated. The module is not downloaded again: Envoy keeps it in its digest-keyed code cache, so a rule
change is a kilobyte-sized message. The compiled module is not re-instantiated either — the
VM is keyed by `vm_id` plus the module bytes — and only the WAF is rebuilt from the new
configuration.

## Target selection

The Engine's `target` field identifies the Gateway by name. The operator derives the
workload label selector using the GEP-1762 convention — Gateway API implementations label
Gateway pods with:

```
gateway.networking.k8s.io/gateway-name: <gateway-name>
```

The `target.provider` field (default: `Istio`) identifies the infrastructure provider, which
determines which driver types are valid for the Engine. This field is immutable after
creation — to switch providers, create a new Engine resource.

## Custom modules

By default the operator serves the module bundled in its image. To use another build, set
both fields on the Engine (see [Deploying a WAF
Engine]({{< relref "/howto/deploying-waf-engine" >}})):

```yaml
spec:
  driver:
    type: wasm
    wasm:
      url: "https://files.example.com/coraza-proxy-wasm/v0.6.0/plugin.wasm"
      sha256: "<64 lowercase hex characters>"
```

The URL must be HTTPS, and Envoy refuses bytes that do not match the digest.
