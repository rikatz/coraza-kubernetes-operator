package controller

import (
	"k8s.io/apimachinery/pkg/util/validation"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	wafv1alpha1 "github.com/networking-incubator/coraza-kubernetes-operator/api/v1alpha1"
)

// -----------------------------------------------------------------------------
// Target Helpers
// -----------------------------------------------------------------------------

// hasGatewayTarget reports whether the Engine targets a Gateway resource.
func hasGatewayTarget(engine *wafv1alpha1.Engine) bool {
	if engine == nil {
		return false
	}
	return engine.Spec.Target.Type == wafv1alpha1.EngineTargetTypeGateway &&
		engine.Spec.Target.Name != ""
}

// targetLabelSelector returns the workload label selector derived from the
// Engine's target reference. For Gateway targets, the GEP-1762
// gateway.networking.k8s.io/gateway-name label is used.
//
// Returns nil if the name is empty or not a valid DNS-1035 label,
// preventing silent selector mismatches.
func targetLabelSelector(engine *wafv1alpha1.Engine) *metav1.LabelSelector {
	if engine == nil {
		return nil
	}
	switch engine.Spec.Target.Type {
	case wafv1alpha1.EngineTargetTypeGateway:
		name := engine.Spec.Target.Name
		if name == "" || len(validation.IsDNS1035Label(name)) > 0 {
			return nil
		}
		return &metav1.LabelSelector{
			MatchLabels: map[string]string{
				gatewayNameLabel: name,
			},
		}
	default:
		return nil
	}
}
