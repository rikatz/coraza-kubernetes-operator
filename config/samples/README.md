# Sample: Coraza WAF with Istio Gateway

Deploys a Coraza WAF Engine in front of a simple echo service using the
Kubernetes Gateway API and Istio.

## What's included

- `ruleset.yaml` — ConfigMaps with SecRule directives and a `RuleSet` CR that aggregates them
- `engine.yaml` — `Engine` CR referencing the RuleSet, configured for the Istio WASM driver
- `gateway.yaml` — Gateway API `Gateway` using the Istio gateway class
- `httproute.yaml` — `HTTPRoute` routing traffic through the gateway to the echo service
- `echo.yaml` — Simple echo Deployment + Service backend

## Prerequisites

- Kubernetes cluster with Istio and Gateway API CRDs installed
- coraza-kubernetes-operator running in the cluster

## Deploy

All samples must be deployed to the same namespace.

```bash
kubectl apply -f config/samples/
```

## Test

```bash
kubectl port-forward svc/coraza-gateway-istio 8080:80
```

```bash
curl http://localhost:8080/                                  # normal request
curl -I "http://localhost:8080/?q=evilmonkey"                # blocked (rule 3001, 403)
curl "http://localhost:8080/?q=select+*+from+users"          # logged (rule 1001)
curl "http://localhost:8080/?q=<script>alert(1)</script>"    # logged (rule 2001)
```

Check gateway logs for Coraza output:

```bash
kubectl logs deploy/coraza-gateway-istio
```

## Cleanup

```bash
kubectl delete -f config/samples/
```
