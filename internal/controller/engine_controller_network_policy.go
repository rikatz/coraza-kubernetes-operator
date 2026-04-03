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
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

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
	// networkPolicyFinalizer is added to Engine resources to guarantee that the
	// cross-namespace NetworkPolicy is deleted before the Engine is removed.
	// Without this, a missed delete event would orphan the NetworkPolicy.
	networkPolicyFinalizer = "waf.k8s.coraza.io/network-policy-cleanup"

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

const (
	// dns1123MaxLen is the maximum length of a Kubernetes resource name.
	dns1123MaxLen = 63
	// hashSuffixLen is the length of the truncated SHA-256 hash suffix
	// (8 hex characters) plus the separating dash.
	hashSuffixLen = 9 // "-" + 8 hex chars
)

func networkPolicyName(engine *wafv1alpha1.Engine) string {
	return buildNetworkPolicyName(engine.Namespace, engine.Name)
}

// networkPolicyNameFromReq derives the NetworkPolicy name from a reconcile
// request. Used for cleanup when the Engine has already been deleted.
func networkPolicyNameFromReq(req ctrl.Request) string {
	return buildNetworkPolicyName(req.Namespace, req.Name)
}

// buildNetworkPolicyName constructs a DNS-1123 compliant name from the
// engine namespace and name. When the full name would exceed 63 characters
// it is truncated and a stable hash suffix is appended to preserve uniqueness.
func buildNetworkPolicyName(namespace, name string) string {
	full := fmt.Sprintf("%s%s-%s", NetworkPolicyNamePrefix, namespace, name)
	if len(full) <= dns1123MaxLen {
		return full
	}
	hash := sha256.Sum256([]byte(full))
	suffix := hex.EncodeToString(hash[:4]) // 8 hex chars
	truncated := full[:dns1123MaxLen-hashSuffixLen]
	return fmt.Sprintf("%s-%s", truncated, suffix)
}

// -----------------------------------------------------------------------------
// Engine Controller - NetworkPolicy Finalizer
// -----------------------------------------------------------------------------

// ensureNetworkPolicyFinalizer adds the finalizer to the Engine if it is not
// already present. Returns true if the Engine was patched.
func (r *EngineReconciler) ensureNetworkPolicyFinalizer(ctx context.Context, log logr.Logger, req ctrl.Request, engine *wafv1alpha1.Engine) (bool, error) {
	if controllerutil.ContainsFinalizer(engine, networkPolicyFinalizer) {
		return false, nil
	}

	patch := client.MergeFrom(engine.DeepCopy())
	controllerutil.AddFinalizer(engine, networkPolicyFinalizer)
	if err := r.Patch(ctx, engine, patch); err != nil {
		logError(log, req, "Engine", err, "Failed to add NetworkPolicy finalizer")
		return false, err
	}
	logDebug(log, req, "Engine", "Added NetworkPolicy finalizer")
	return true, nil
}

// handleNetworkPolicyDeletion cleans up the NetworkPolicy and removes the
// finalizer so the Engine can be garbage-collected. Returns true when the
// Engine is being deleted and the caller should stop reconciling.
func (r *EngineReconciler) handleNetworkPolicyDeletion(ctx context.Context, log logr.Logger, req ctrl.Request, engine *wafv1alpha1.Engine) (bool, error) {
	if engine.DeletionTimestamp.IsZero() {
		return false, nil
	}
	if !controllerutil.ContainsFinalizer(engine, networkPolicyFinalizer) {
		return true, nil
	}

	if err := r.cleanupNetworkPolicy(ctx, log, req); err != nil {
		return true, err
	}

	patch := client.MergeFrom(engine.DeepCopy())
	controllerutil.RemoveFinalizer(engine, networkPolicyFinalizer)
	if err := r.Patch(ctx, engine, patch); err != nil {
		logError(log, req, "Engine", err, "Failed to remove NetworkPolicy finalizer")
		return true, err
	}
	logDebug(log, req, "Engine", "Removed NetworkPolicy finalizer")
	return true, nil
}

// -----------------------------------------------------------------------------
// Engine Controller - NetworkPolicy Apply / Delete
// -----------------------------------------------------------------------------

// applyNetworkPolicy creates or updates a NetworkPolicy in the operator namespace
// that allows ingress from the Engine's gateway pods to the cache server port.
func (r *EngineReconciler) applyNetworkPolicy(ctx context.Context, log logr.Logger, req ctrl.Request, engine *wafv1alpha1.Engine) error {
	ws := workloadSelector(engine)
	if ws == nil || (len(ws.MatchLabels) == 0 && len(ws.MatchExpressions) == 0) {
		return fmt.Errorf("workload selector with at least one match criterion is required for NetworkPolicy creation")
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

// cleanupNetworkPolicy removes the NetworkPolicy associated with an Engine.
func (r *EngineReconciler) cleanupNetworkPolicy(ctx context.Context, log logr.Logger, req ctrl.Request) error {
	np := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      networkPolicyNameFromReq(req),
			Namespace: r.operatorNamespace,
		},
	}
	if err := r.Delete(ctx, np); err != nil {
		if client.IgnoreNotFound(err) != nil {
			logError(log, req, "Engine", err, "Failed to cleanup NetworkPolicy")
			return err
		}
	} else {
		logInfo(log, req, "Engine", "NetworkPolicy cleaned up", "networkPolicyName", np.Name)
	}
	return nil
}

// -----------------------------------------------------------------------------
// Engine Controller - NetworkPolicy Builder
// -----------------------------------------------------------------------------

// workloadSelector returns the Engine's workload selector, or nil if the
// driver chain is not fully configured.
func workloadSelector(engine *wafv1alpha1.Engine) *metav1.LabelSelector {
	if engine.Spec.Driver == nil || engine.Spec.Driver.Istio == nil ||
		engine.Spec.Driver.Istio.Wasm == nil {
		return nil
	}
	return engine.Spec.Driver.Istio.Wasm.WorkloadSelector
}

func (r *EngineReconciler) buildNetworkPolicy(engine *wafv1alpha1.Engine) *networkingv1.NetworkPolicy {
	protocol := corev1.ProtocolTCP
	port := intstr.FromInt32(int32(DefaultRuleSetCacheServerPort))

	// Deep-copy the full LabelSelector (MatchLabels + MatchExpressions)
	// so the NetworkPolicy peer matches the same pods as the WasmPlugin.
	podSelector := workloadSelector(engine).DeepCopy()

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
							PodSelector: podSelector,
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
// Engine Controller - NetworkPolicy Watch Predicate
// -----------------------------------------------------------------------------

// networkPolicyPredicate filters NetworkPolicy watch events to reconcile on:
//   - Create and Delete of operator-managed policies
//   - Update when the spec changes (generation increments), enabling drift detection
//
// Managedfields-only updates (from server-side-apply) don't increment generation,
// so they won't trigger reconciles, preventing reconcile loops.
func networkPolicyPredicate() predicate.Predicate {
	hasLabel := func(obj client.Object) bool {
		_, ok := obj.GetLabels()["waf.k8s.coraza.io/engine-name"]
		return ok
	}

	return predicate.And(
		predicate.NewPredicateFuncs(hasLabel),
		predicate.Or(
			predicate.Funcs{
				CreateFunc:  func(event.CreateEvent) bool { return true },
				DeleteFunc:  func(event.DeleteEvent) bool { return true },
				UpdateFunc:  func(event.UpdateEvent) bool { return false },
				GenericFunc: func(event.GenericEvent) bool { return false },
			},
			predicate.GenerationChangedPredicate{},
		),
	)
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
