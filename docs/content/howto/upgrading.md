---
title: "Upgrading the Operator"
linkTitle: "Upgrading"
weight: 50
description: "Upgrade the Coraza Kubernetes Operator to a new version."
---

## Upgrading with Helm

To upgrade to the latest version:

```bash
helm repo update
helm upgrade coraza-kubernetes-operator \
  coraza-kubernetes-operator/coraza-kubernetes-operator \
  --namespace coraza-system
```

To upgrade to a specific version:

```bash
helm upgrade coraza-kubernetes-operator \
  coraza-kubernetes-operator/coraza-kubernetes-operator \
  --namespace coraza-system \
  --version 0.3.0
```

Helm automatically applies any CRD changes included in the new chart version.

## Upgrading on OpenShift (OLM)

If you installed the operator through OperatorHub with automatic approval, OLM handles upgrades automatically when new versions are published to the catalog.

If you chose manual approval, pending upgrades appear in the OpenShift web console under **Operators > Installed Operators**. Approve the upgrade to proceed.

## Checking Release Notes

Before upgrading, review the release notes for any breaking changes or migration steps:

- [GitHub Releases](https://github.com/networking-incubator/coraza-kubernetes-operator/releases)

## Rendering Schema Upgrades

The operator renders each Engine's ECDS configuration into a versioned payload. When a release bumps the rendering schema, accepted configurations recorded by an older version are not published by the new build.

Affected Engines re-accept their configuration on the next reconcile and the new payload replaces the old one. While they wait, their older accepted records are ignored for operator readiness, so an upgrade does not block the operator from becoming Ready. An Engine that cannot re-accept (for example because its RuleSet is missing or no verified CA is configured) stays `Degraded` with `Ready=False`, and its Gateway fails closed until the problem is fixed.

The readiness deadline applies to any accepted record this build never reconstructs, not only records left behind by a rendering schema bump; after the deadline the record stops gating operator readiness and is reported once.

## Rule Validation Guard

This release rejects rule text that opens or creates host files while the operator compiles it: `SecDebugLog` (including `/dev/stdout`), `SecUploadDir`, and `SecUploadKeepFiles` with any value other than `Off`. A RuleSet that an older version accepted with one of these directives now fails validation and becomes `Degraded` with `InvalidRuleSet`, and the Engine drops that content from its accepted configuration instead of publishing it again; the Gateway keeps the last configuration the operator published until the directive is removed. RuleSets whose rules `Include` a file carrying such a directive are affected the same way.

`SecAuditLog` is now accepted only with `/dev/stdout` or `/dev/stderr`. Any other target made the plugin NACK the configuration (the WASM sandbox cannot open files), so the Engine reported `Ready` without a working WAF. `SecAuditLogType` is still accepted.

The same guard rejects `Include` targets the plugin cannot resolve: unknown `@` aliases, globs outside the exact `@owasp_crs/*.conf` form, and globs in a non-final `@owasp_crs/` segment. A RuleSet whose rules `Include` a RuleData file name containing `/` is rejected as well.

## RuleData Size Limits

This release lowers the default decoded RuleData limit per Engine from 12 MiB to 8 MiB (`--xds-max-decoded-data-bytes`). RuleData sets totalling 8–12 MiB that were accepted before now fail acceptance: the Engine reports `Degraded` with `InvalidRuleSet` and its content is not delivered. Reduce the RuleData files, or raise the flag within the plugin's compile-time cap — the operator also refuses at startup a decoded limit whose base64-encoded form plus the maximum data-file key overhead would not fit `--xds-max-message-bytes`.

## Rolling Back

To roll back a Helm upgrade to the previous version:

```bash
helm rollback coraza-kubernetes-operator -n coraza-system
```

To list available revision history:

```bash
helm history coraza-kubernetes-operator -n coraza-system
```
