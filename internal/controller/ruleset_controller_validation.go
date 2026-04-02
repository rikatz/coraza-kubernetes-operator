package controller

import (
	"context"
	"fmt"

	"github.com/corazawaf/coraza/v3"
	"github.com/go-logr/logr"
	ctrl "sigs.k8s.io/controller-runtime"

	wafv1alpha1 "github.com/networking-incubator/coraza-kubernetes-operator/api/v1alpha1"
	"github.com/networking-incubator/coraza-kubernetes-operator/internal/rulesets"
)

// -----------------------------------------------------------------------------
// RuleSet Validation
// -----------------------------------------------------------------------------

// validateConfigMapRules validates a single ConfigMap's rules via Coraza.
// Returns a validation error if the rules are invalid, or nil if valid or
// if the error is a missing-file error covered by the RuleData Secret.
func validateConfigMapRules(data, configMapName string, secretData map[string][]byte) error {
	conf := coraza.NewWAFConfig().WithDirectives(data)
	if _, err := coraza.NewWAF(conf); err != nil {
		if shouldSkipMissingFileError(err, secretData) {
			return nil
		}
		return fmt.Errorf("ConfigMap %s doesn't contain valid rules: %w", configMapName, sanitizeErrorMessage(err))
	}
	return nil
}

// validateAggregatedRules validates the aggregated rule set via Coraza.
// Sets Degraded status and emits Warning events on failure.
func (r *RuleSetReconciler) validateAggregatedRules(
	ctx context.Context,
	log logr.Logger,
	req ctrl.Request,
	ruleset *wafv1alpha1.RuleSet,
	conf coraza.WAFConfig,
	aggregatedErrors []error,
) error {
	if _, err := coraza.NewWAF(conf); err != nil {
		msg := fmt.Sprintf("Ruleset is invalid\n%v", sanitizeErrorMessage(err))
		for _, cmapErr := range aggregatedErrors {
			r.Recorder.Eventf(ruleset, nil, "Warning", "InvalidConfigMap", "Reconcile", truncateEventNote(cmapErr.Error()))
			msg = fmt.Sprintf("%s\n%v", msg, cmapErr)
		}
		if patchErr := patchDegraded(ctx, r.Status(), r.Recorder, log, req, "RuleSet", ruleset, &ruleset.Status.Conditions, ruleset.Generation, "InvalidRuleSet", msg); patchErr != nil {
			return patchErr
		}
		return sanitizeErrorMessage(err)
	}
	return nil
}

// rejectUnsupportedRules checks rules for IDs unsupported in WASM mode.
// Always emits a Warning event when unsupported rules are detected.
//
// When the AnnotationSkipUnsupportedRulesCheck annotation is "true", degradation
// is suppressed: returns (false, message, nil) so the caller can surface the
// detected rules in the Ready status without blocking reconciliation.
//
// Without the annotation, sets Degraded status and returns (true, "", nil).
func (r *RuleSetReconciler) rejectUnsupportedRules(
	ctx context.Context,
	log logr.Logger,
	req ctrl.Request,
	ruleset *wafv1alpha1.RuleSet,
	rules string,
) (bool, string, error) {
	unsupported := rulesets.CheckUnsupportedRules(rules)
	if len(unsupported) == 0 {
		return false, "", nil
	}

	msg := rulesets.FormatUnsupportedMessage(unsupported)
	logInfo(log, req, "RuleSet", "RuleSet contains unsupported rules", "count", len(unsupported))

	if ruleset.Annotations[wafv1alpha1.AnnotationSkipUnsupportedRulesCheck] == "true" {
		logDebug(log, req, "RuleSet", "Unsupported rules check overridden by annotation; not degrading")
		r.Recorder.Eventf(ruleset, nil, "Warning", "UnsupportedRules", "Reconcile", truncateEventNote(msg))
		return false, msg, nil
	}

	if patchErr := patchDegraded(ctx, r.Status(), r.Recorder, log, req, "RuleSet", ruleset, &ruleset.Status.Conditions, ruleset.Generation, "UnsupportedRules", msg); patchErr != nil {
		return true, "", patchErr
	}

	return true, "", nil
}
