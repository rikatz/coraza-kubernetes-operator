/*
Copyright Coraza Kubernetes Operator contributors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	wafv1alpha1 "github.com/networking-incubator/coraza-kubernetes-operator/api/v1alpha1"
)

// -----------------------------------------------------------------------------
// Engine Controller - NetworkPolicy RBAC
// -----------------------------------------------------------------------------

// +kubebuilder:rbac:groups=networking.k8s.io,namespace=system,resources=networkpolicies,verbs=get;list;watch;create;update;patch;delete

// -----------------------------------------------------------------------------
// Engine Controller - NetworkPolicy Constants
// -----------------------------------------------------------------------------

const (
	// NetworkPolicyNamePrefix is the prefix used for all created NetworkPolicy resources.
	NetworkPolicyNamePrefix = "coraza-cache-"

	// operatorPodLabelKey and operatorPodLabelValue identify the operator pods
	// targeted by the cache server NetworkPolicy. These match the labels set by
	// the Helm chart's selectorLabels template.
	operatorPodLabelKey   = "control-plane"
	operatorPodLabelValue = "coraza-controller-manager"
)

// -----------------------------------------------------------------------------
// Engine Controller - NetworkPolicy Naming
// -----------------------------------------------------------------------------

func networkPolicyName(engine *wafv1alpha1.Engine) string {
	return fmt.Sprintf("%s%s-%s", NetworkPolicyNamePrefix, engine.Namespace, engine.Name)
}

// networkPolicyNameFromReq derives the NetworkPolicy name from a reconcile
// request. Used for cleanup when the Engine has already been deleted.
func networkPolicyNameFromReq(req ctrl.Request) string {
	return fmt.Sprintf("%s%s-%s", NetworkPolicyNamePrefix, req.Namespace, req.Name)
}

// -----------------------------------------------------------------------------
// Engine Controller - NetworkPolicy Apply / Delete
// -----------------------------------------------------------------------------

// applyNetworkPolicy creates or updates a NetworkPolicy in the operator namespace
// that allows ingress from the Engine's gateway pods to the cache server port.
func (r *EngineReconciler) applyNetworkPolicy(ctx context.Context, log logr.Logger, req ctrl.Request, engine *wafv1alpha1.Engine) error {
	if r.operatorNamespace == "" {
		logDebug(log, req, "Engine", "Skipping NetworkPolicy: operator namespace not configured")
		return nil
	}

	if engine.Spec.Driver == nil || engine.Spec.Driver.Istio == nil ||
		engine.Spec.Driver.Istio.Wasm == nil || engine.Spec.Driver.Istio.Wasm.WorkloadSelector == nil ||
		len(engine.Spec.Driver.Istio.Wasm.WorkloadSelector.MatchLabels) == 0 {
		return fmt.Errorf("workload selector with at least one label is required for NetworkPolicy creation")
	}

	np := r.buildNetworkPolicy(engine)
	logDebug(log, req, "Engine", "Applying cache server NetworkPolicy", "networkPolicyName", np.Name)
	if err := r.Patch(ctx, np, client.Apply, client.FieldOwner(fieldManager), client.ForceOwnership); err != nil {
		logError(log, req, "Engine", err, "Failed to apply NetworkPolicy")
		return err
	}

	logInfo(log, req, "Engine", "NetworkPolicy applied", "networkPolicyName", np.Name, "networkPolicyNamespace", np.Namespace)
	return nil
}

// cleanupNetworkPolicy removes the NetworkPolicy associated with a deleted Engine.
// Called from Reconcile when the Engine is not found (already deleted).
func (r *EngineReconciler) cleanupNetworkPolicy(ctx context.Context, log logr.Logger, req ctrl.Request) {
	if r.operatorNamespace == "" {
		return
	}

	np := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      networkPolicyNameFromReq(req),
			Namespace: r.operatorNamespace,
		},
	}
	if err := r.Delete(ctx, np); err != nil {
		if client.IgnoreNotFound(err) != nil {
			logError(log, req, "Engine", err, "Failed to cleanup NetworkPolicy")
		}
		return
	}
	logInfo(log, req, "Engine", "NetworkPolicy cleaned up", "networkPolicyName", np.Name)
}

// -----------------------------------------------------------------------------
// Engine Controller - NetworkPolicy Builder
// -----------------------------------------------------------------------------

func (r *EngineReconciler) buildNetworkPolicy(engine *wafv1alpha1.Engine) *networkingv1.NetworkPolicy {
	protocol := corev1.ProtocolTCP
	port := intstr.FromInt32(int32(DefaultRuleSetCacheServerPort))

	matchLabels := map[string]string{}
	if engine.Spec.Driver != nil && engine.Spec.Driver.Istio != nil &&
		engine.Spec.Driver.Istio.Wasm != nil && engine.Spec.Driver.Istio.Wasm.WorkloadSelector != nil {
		for k, v := range engine.Spec.Driver.Istio.Wasm.WorkloadSelector.MatchLabels {
			matchLabels[k] = v
		}
	}

	return &networkingv1.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "networking.k8s.io/v1",
			Kind:       "NetworkPolicy",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      networkPolicyName(engine),
			Namespace: r.operatorNamespace,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by":       "coraza-kubernetes-operator",
				"waf.k8s.coraza.io/engine-name":      engine.Name,
				"waf.k8s.coraza.io/engine-namespace": engine.Namespace,
			},
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					operatorPodLabelKey: operatorPodLabelValue,
				},
			},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			Ingress: []networkingv1.NetworkPolicyIngressRule{
				{
					From: []networkingv1.NetworkPolicyPeer{
						{
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"kubernetes.io/metadata.name": engine.Namespace,
								},
							},
							PodSelector: &metav1.LabelSelector{
								MatchLabels: matchLabels,
							},
						},
					},
					Ports: []networkingv1.NetworkPolicyPort{
						{
							Protocol: &protocol,
							Port:     &port,
						},
					},
				},
			},
		},
	}
}

// -----------------------------------------------------------------------------
// Engine Controller - NetworkPolicy Watch Mapper
// -----------------------------------------------------------------------------

func (r *EngineReconciler) findEnginesForNetworkPolicy(_ context.Context, obj client.Object) []ctrl.Request {
	labels := obj.GetLabels()
	name := labels["waf.k8s.coraza.io/engine-name"]
	ns := labels["waf.k8s.coraza.io/engine-namespace"]
	if name == "" || ns == "" {
		return nil
	}
	return []ctrl.Request{{NamespacedName: types.NamespacedName{Name: name, Namespace: ns}}}
}
