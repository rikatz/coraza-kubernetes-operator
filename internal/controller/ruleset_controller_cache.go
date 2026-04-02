package controller

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	ctrl "sigs.k8s.io/controller-runtime"

	wafv1alpha1 "github.com/networking-incubator/coraza-kubernetes-operator/api/v1alpha1"
)

// -----------------------------------------------------------------------------
// RuleSetReconciler - Cache Storage
// -----------------------------------------------------------------------------

// cacheRules stores the aggregated rules in the cache and patches the RuleSet
// status to Ready.
func (r *RuleSetReconciler) cacheRules(
	ctx context.Context,
	log logr.Logger,
	req ctrl.Request,
	ruleset *wafv1alpha1.RuleSet,
	aggregatedRules string,
	secretData map[string][]byte,
	unsupportedMsg string,
) (ctrl.Result, error) {
	cacheKey := fmt.Sprintf("%s/%s", ruleset.Namespace, ruleset.Name)
	// NOTE: The data stored in the cache (including any RuleData sourced from a Secret)
	// is served by the cache HTTP server for consumption by the WASM plugin and must
	// therefore not contain sensitive or credential material. Treat the cache server
	// endpoint as internal / trusted-only in deployments.
	r.Cache.Put(cacheKey, aggregatedRules, secretData)
	logInfo(log, req, "RuleSet", "Stored rules in cache", "cacheKey", cacheKey)

	statusMsg := buildCacheReadyMessage(ruleset.Namespace, ruleset.Name, unsupportedMsg)
	if err := patchReady(ctx, r.Status(), r.Recorder, log, req, "RuleSet", ruleset, &ruleset.Status.Conditions, ruleset.Generation, "RulesCached", statusMsg); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}
