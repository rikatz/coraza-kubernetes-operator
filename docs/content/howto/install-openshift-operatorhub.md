---
title: "Install on OpenShift"
linkTitle: "Install (OpenShift)"
weight: 15
description: "Install the Coraza Kubernetes Operator on OpenShift via OperatorHub or Helm."
---

This guide covers installing the Coraza Kubernetes Operator on OpenShift Container Platform.

## Prerequisites

- OpenShift Container Platform **v4.20 or later**
- Cluster administrator privileges
- Gateway API enabled on your cluster (see [Enable Gateway API](#enable-gateway-api) below)
- [OpenShift Service Mesh](https://docs.redhat.com/en/documentation/red_hat_openshift_service_mesh/3.0/html-single/gateways/index) or Istio installed with Gateway API support

### Enable Gateway API

On OpenShift 4.20 and later, the Gateway API CRDs are included by default. You must create the `openshift-default` GatewayClass, which is the [officially supported GatewayClass](https://docs.redhat.com/en/documentation/openshift_container_platform/4.21/html/ingress_and_load_balancing/configuring-ingress-cluster-traffic#ingress-gateway-api) provided by the OpenShift Ingress Operator:

```bash
oc apply -f - <<EOF
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata:
  name: openshift-default
spec:
  controllerName: openshift.io/gateway-controller/v1
EOF
```

## Install from OperatorHub

OperatorHub is the preferred installation method on OpenShift.

{{% alert title="Note" color="info" %}}
The Coraza Kubernetes Operator is not yet published to OperatorHub. Track progress in [issue #201](https://github.com/networking-incubator/coraza-kubernetes-operator/issues/201). In the meantime, use the [Helm installation method](#install-with-helm) below.
{{% /alert %}}

### Web Console

1. Log in to the OpenShift web console as a cluster administrator.
2. Navigate to **Operators > OperatorHub**.
3. Search for **Coraza Kubernetes Operator**.
4. Select the operator tile and click **Install**.
5. Choose the update channel, installation mode, and approval strategy.
6. Click **Install** and wait for the operator to reach the **Succeeded** phase.

### CLI

Create a Subscription resource:

```yaml
apiVersion: operators.coreos.com/v1alpha1
kind: Subscription
metadata:
  name: coraza-kubernetes-operator
  namespace: openshift-operators
spec:
  channel: alpha
  name: coraza-kubernetes-operator
  source: community-operators
  sourceNamespace: openshift-marketplace
```

```bash
oc apply -f subscription.yaml
```

## Install with Helm

If the operator is not yet available in OperatorHub, you can install it with Helm.

### Prerequisites

- [Helm 3](https://helm.sh/docs/intro/install/) installed

### Install from the Helm Repository

Add the Helm repository hosted on GitHub Pages and install:

```bash
helm repo add coraza-kubernetes-operator \
  https://networking-incubator.github.io/coraza-kubernetes-operator/
helm repo update
```

```bash
helm upgrade --install coraza-kubernetes-operator \
  coraza-kubernetes-operator/coraza-kubernetes-operator \
  --namespace coraza-system \
  --create-namespace \
  --set openshift.enabled=true \
  --set istio.revision=openshift-gateway \
  --set metrics.serviceMonitor.enabled=true
```

{{% alert title="Namespace conflict on versions 0.4.0 and earlier" color="warning" %}}
Versions 0.4.0 and earlier have a bug where the first install fails with `namespaces "coraza-system" already exists`. If you hit this error, run the same command again. The first run creates the namespace and a failed release record; the second run succeeds because Helm treats it as an upgrade, which patches the existing namespace instead of trying to create it.
{{% /alert %}}

### Pin a Specific Version

Add `--version <chart-version>` to any of the install commands above. Replace `<chart-version>` with the desired version (e.g. `0.1.0`). Available versions are listed on the [releases page](https://github.com/networking-incubator/coraza-kubernetes-operator/releases).

### OpenShift Values

Setting `openshift.enabled` to `true` omits `runAsUser`, `fsGroup`, and `fsGroupChangePolicy` from the pod security context so that OpenShift can inject its own UID via Security Context Constraints (SCCs).

For more advanced configuration, use a values file:

```yaml
# openshift-values.yaml
openshift:
  enabled: true

istio:
  revision: openshift-gateway

metrics:
  serviceMonitor:
    enabled: true
```

```bash
helm upgrade --install coraza-kubernetes-operator \
  coraza-kubernetes-operator/coraza-kubernetes-operator \
  --namespace coraza-system \
  --create-namespace \
  -f openshift-values.yaml
```

An example values file is also available in the repository at `charts/coraza-kubernetes-operator/examples/openshift-values.yaml`.

For the complete list of configurable values, see the [Helm Chart Values reference]({{< relref "../reference/helm-values" >}}).

## Verify the Installation

Check that the operator pod is running:

```bash
oc get pods -n coraza-system
```

The operator pod should be in a `Running` state.

Check the operator logs:

```bash
oc logs -n coraza-system deploy/coraza-kubernetes-operator
```

## Uninstall

### OperatorHub

1. Navigate to **Operators > Installed Operators**.
2. Select the Coraza Kubernetes Operator.
3. Click **Uninstall Operator**.

### Helm

```bash
helm uninstall coraza-kubernetes-operator -n coraza-system
```

To also remove the CRDs:

```bash
oc delete crd engines.waf.k8s.coraza.io rulesets.waf.k8s.coraza.io
```

{{% alert title="Note" color="warning" %}}
Removing CRDs will delete all Engine and RuleSet resources in the cluster.
{{% /alert %}}
