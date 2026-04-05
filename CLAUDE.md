# Coraza Kubernetes Operator — Development Guide

## Controller patterns and conventions

### Environment: ISTIO_VERSION is always required

Unit tests download Istio CRDs at startup. Without `ISTIO_VERSION`, tests fail immediately. Always read the default from `Makefile` — never hardcode it:
```bash
grep '^ISTIO_VERSION' Makefile
```

### `go build` does NOT compile test files

`go build ./...` and `go vet ./...` silently ignore `_test.go` files. To verify test compilation, use `go test -c` or `go test -run ^$`.

### Build tags for test tiers

- Integration: `//go:build integration` — requires `-tags=integration`
- Conformance: `//go:build conformance` — requires `-tags=conformance`
- E2E: `//go:build e2e` — requires `-tags=e2e`

Running `go test ./test/integration/...` without the tag finds zero tests silently.

### Finalizer + GenerationChangedPredicate

The Engine controller uses `predicate.GenerationChangedPredicate{}` on its primary watch. Metadata-only changes (labels, annotations, finalizers) do NOT bump `.metadata.generation`, so the update event is filtered out.

When adding a finalizer and returning early, always use `RequeueAfter` (never `Requeue`, which is deprecated):
```go
return ctrl.Result{RequeueAfter: 100 * time.Millisecond}, nil
```

### Two-reconcile pattern in unit tests

Engine unit tests require two `Reconcile()` calls — first adds the finalizer (returns `RequeueAfter`), second does the actual work:
```go
result, err := reconciler.Reconcile(ctx, req)
require.NoError(t, err)
assert.NotZero(t, result.RequeueAfter)  // finalizer added

result, err = reconciler.Reconcile(ctx, req)
require.NoError(t, err)
assert.Zero(t, result.RequeueAfter)     // provisioning done
```

### EngineReconciler in tests must set operatorNamespace

The NetworkPolicy logic uses `operatorNamespace` to determine the target namespace. Missing it silently creates resources in the wrong namespace.

### DNS-1123 resource names

Kubernetes names must be <= 63 characters. When constructing names from user input (namespace + name), truncate and append a stable hash suffix. See `buildNetworkPolicyName()` for the reference implementation.

### Watch predicates for SSA-managed resources

When watching resources the controller creates via server-side apply, filter out update events to prevent reconcile loops:
```go
predicate.And(
    predicate.NewPredicateFuncs(labelFilter),
    predicate.Funcs{
        CreateFunc:  func(event.CreateEvent) bool { return true },
        DeleteFunc:  func(event.DeleteEvent) bool { return true },
        UpdateFunc:  func(event.UpdateEvent) bool { return false },
        GenericFunc: func(event.GenericEvent) bool { return false },
    },
)
```

### TLS: HTTP/2 is disabled

The operator disables HTTP/2 via `NextProtos: []string{"http/1.1"}` to mitigate CVE-2023-44487 (HTTP/2 Rapid Reset). Preserve this when modifying TLS config in `cmd/manager/main.go`.

### RBAC changes require manifest regeneration

When adding or modifying `+kubebuilder:rbac` markers, you must regenerate and sync:
```bash
make manifests generate helm.sync
```
For cluster tests, also redeploy: `make deploy`.

## Integration test framework

### Scenario pattern (mandatory)

All integration tests must use the framework `Scenario` pattern — never reimplement port-forwarding or cleanup logic directly:
```go
s := fw.NewScenario(t)
ns := s.GenerateNamespace("my-test")
s.Step("apply manifests")
s.ApplyManifest(ns, "path/to/manifest.yaml")
s.Step("verify behavior")
```

### Key helpers
- `s.OnCleanup(fn)` — LIFO cleanup, automatic via `t.Cleanup`
- `s.ProxyToGateway(ns, name)` — HTTP testing against a gateway
- `s.ProxyToPod(ns, selector, port)` — port-forward to arbitrary pods
- `framework.DefaultTimeout` / `framework.DefaultInterval` — never hardcode durations

### Skip validation annotations
- ConfigMaps: `coraza.io/validation: "false"` — skips per-ConfigMap rule validation
- RuleSets: `waf.k8s.coraza.io/skip-unsupported-rules-check: "true"` — prevents degrading on unsupported rules

---

