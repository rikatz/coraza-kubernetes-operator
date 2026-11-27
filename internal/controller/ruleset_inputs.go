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
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/corazawaf/coraza/v3"
	"github.com/go-logr/logr"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	wafv1alpha1 "github.com/networking-incubator/coraza-kubernetes-operator/api/v1alpha1"
	"github.com/networking-incubator/coraza-kubernetes-operator/internal/rulesets"
	"github.com/networking-incubator/coraza-kubernetes-operator/internal/rulesets/assemble"
	"github.com/networking-incubator/coraza-kubernetes-operator/internal/rulesets/validation"
)

var errRuleSetInputsChanged = errors.New("RuleSet inputs changed while being read")

const ruleInputConsistencyRetry = 100 * time.Millisecond

func apiReaderOrClient(reader client.Reader, c client.Client) client.Reader {
	if reader != nil {
		return reader
	}
	// shortcut: nil APIReader uses Client for direct-client tests; SetupControllers wires Manager.GetAPIReader.
	return c
}

func (r *EngineReconciler) apiReader() client.Reader {
	return apiReaderOrClient(r.APIReader, r.Client)
}

type inputConditionState struct {
	Status             metav1.ConditionStatus `json:"status"`
	Reason             string                 `json:"reason"`
	ObservedGeneration int64                  `json:"observed_generation"`
}

type ruleSourceInputState struct {
	Name           string               `json:"name"`
	UID            types.UID            `json:"uid"`
	Generation     int64                `json:"generation"`
	SkipValidation string               `json:"skip_validation"`
	Ready          *inputConditionState `json:"ready,omitempty"`
	Degraded       *inputConditionState `json:"degraded,omitempty"`
}

// RuleData Ready is self-owned, informational status and does not gate content acceptance.
type ruleDataInputState struct {
	Name       string    `json:"name"`
	UID        types.UID `json:"uid"`
	Generation int64     `json:"generation"`
}

type ruleSetInputView struct {
	inputs  assemble.Inputs
	sources []ruleSourceInputState
	data    []ruleDataInputState
}

func (v ruleSetInputView) inputFingerprint() string {
	return assemble.Fingerprint(v.inputs)
}

// stateFingerprint tracks only metadata that changes RuleSet readiness or
// annotation semantics. It lets Engine and Publication cache hits avoid
// fetching payloads while still noticing status/annotation-only updates.
func (v ruleSetInputView) stateFingerprint() string {
	sources := v.sources
	if len(sources) == 0 {
		sources = nil
	}
	data := v.data
	if len(data) == 0 {
		data = nil
	}
	raw, err := json.Marshal(struct {
		Sources []ruleSourceInputState `json:"sources"`
		Data    []ruleDataInputState   `json:"data"`
	}{Sources: sources, Data: data})
	if err != nil {
		panic(fmt.Sprintf("controller: marshal RuleSet input state: %v", err))
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func (v ruleSetInputView) sameState(other ruleSetInputView) bool {
	return v.inputFingerprint() == other.inputFingerprint() &&
		v.stateFingerprint() == other.stateFingerprint()
}

func ruleSourceInputStateFor(source *wafv1alpha1.RuleSource) ruleSourceInputState {
	return ruleSourceInputState{
		Name:           source.Name,
		UID:            source.UID,
		Generation:     source.Generation,
		SkipValidation: source.Annotations[wafv1alpha1.AnnotationSkipValidation],
		Ready:          statusConditionState(source.Status.Conditions, conditionReady),
		Degraded:       statusConditionState(source.Status.Conditions, conditionDegraded),
	}
}

func ruleDataInputStateFor(data *wafv1alpha1.RuleData) ruleDataInputState {
	return ruleDataInputState{
		Name:       data.Name,
		UID:        data.UID,
		Generation: data.Generation,
	}
}

func statusConditionState(conditions []metav1.Condition, conditionType string) *inputConditionState {
	condition := apimeta.FindStatusCondition(conditions, conditionType)
	if condition == nil {
		return nil
	}
	return &inputConditionState{
		Status:             condition.Status,
		Reason:             condition.Reason,
		ObservedGeneration: condition.ObservedGeneration,
	}
}

func sameRuleSourceInputState(a, b *wafv1alpha1.RuleSource) bool {
	return ruleSourceInputStateFor(a).sameState(ruleSourceInputStateFor(b))
}

func (s ruleSourceInputState) sameState(other ruleSourceInputState) bool {
	return s.Name == other.Name &&
		s.UID == other.UID &&
		s.Generation == other.Generation &&
		s.SkipValidation == other.SkipValidation &&
		apiequality.Semantic.DeepEqual(s.Ready, other.Ready) &&
		apiequality.Semantic.DeepEqual(s.Degraded, other.Degraded)
}

func sameRuleDataInputState(a, b *wafv1alpha1.RuleData) bool {
	return ruleDataInputStateFor(a).sameState(ruleDataInputStateFor(b))
}

func (s ruleDataInputState) sameState(other ruleDataInputState) bool {
	return s.Name == other.Name &&
		s.UID == other.UID &&
		s.Generation == other.Generation
}

func loadConsistentRuleSourceFromCache(
	ctx context.Context,
	apiReader client.Reader,
	cached *wafv1alpha1.RuleSource,
) (wafv1alpha1.RuleSource, error) {
	name := cached.Name
	var live wafv1alpha1.RuleSource
	liveErr := apiReader.Get(ctx, types.NamespacedName{Namespace: cached.Namespace, Name: name}, &live)
	if liveErr != nil && !apierrors.IsNotFound(liveErr) {
		return wafv1alpha1.RuleSource{}, fmt.Errorf("get live RuleSource %s: %w", name, liveErr)
	}
	if liveErr != nil || !sameRuleSourceInputState(cached, &live) {
		return wafv1alpha1.RuleSource{}, fmt.Errorf("%w: RuleSource %s cache and API views differ", errRuleSetInputsChanged, name)
	}
	return live, nil
}

func loadConsistentRuleData(
	ctx context.Context,
	cacheReader, apiReader client.Reader,
	namespace, name string,
) (wafv1alpha1.RuleData, error) {
	var cached, live wafv1alpha1.RuleData
	cacheErr := cacheReader.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, &cached)
	if cacheErr != nil && !apierrors.IsNotFound(cacheErr) {
		return wafv1alpha1.RuleData{}, fmt.Errorf("get cached RuleData %s: %w", name, cacheErr)
	}
	liveErr := apiReader.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, &live)
	if liveErr != nil && !apierrors.IsNotFound(liveErr) {
		return wafv1alpha1.RuleData{}, fmt.Errorf("get live RuleData %s: %w", name, liveErr)
	}
	if apierrors.IsNotFound(cacheErr) && apierrors.IsNotFound(liveErr) {
		return wafv1alpha1.RuleData{}, fmt.Errorf("get RuleData %s: %w", name, liveErr)
	}
	if cacheErr != nil || liveErr != nil || !sameRuleDataInputState(&cached, &live) {
		return wafv1alpha1.RuleData{}, fmt.Errorf("%w: RuleData %s cache and API views differ", errRuleSetInputsChanged, name)
	}
	return live, nil
}

// loadRuleSetInputView resolves the ordered input identities and relevant
// metadata. includeContent is true only on paths that assemble or reconstruct
// accepted content; metadata-only callers must not retain informer payloads.
func loadRuleSetInputView(
	ctx context.Context,
	reader client.Reader,
	ruleset *wafv1alpha1.RuleSet,
	includeContent bool,
) (ruleSetInputView, error) {
	view := ruleSetInputView{
		inputs: assemble.Inputs{
			RuleSetUID:       ruleset.UID,
			RuleSetName:      ruleset.Name,
			Namespace:        ruleset.Namespace,
			EmptyRulesPolicy: assemble.EmptyRulesPolicy(ruleset.Spec.EmptyRulesPolicy),
		},
		sources: make([]ruleSourceInputState, 0, len(ruleset.Spec.Sources)),
		data:    make([]ruleDataInputState, 0, len(ruleset.Spec.Data)),
	}

	for _, ref := range ruleset.Spec.Sources {
		var source wafv1alpha1.RuleSource
		if err := reader.Get(ctx, types.NamespacedName{Namespace: ruleset.Namespace, Name: ref.Name}, &source); err != nil {
			return ruleSetInputView{}, fmt.Errorf("get RuleSource %s: %w", ref.Name, err)
		}
		input := assemble.SourceInput{
			Name:       source.Name,
			UID:        source.UID,
			Generation: source.Generation,
		}
		if includeContent {
			input.Rules = source.Spec.Rules
		}
		view.inputs.Sources = append(view.inputs.Sources, input)
		view.sources = append(view.sources, ruleSourceInputStateFor(&source))
	}

	for _, ref := range ruleset.Spec.Data {
		var data wafv1alpha1.RuleData
		if err := reader.Get(ctx, types.NamespacedName{Namespace: ruleset.Namespace, Name: ref.Name}, &data); err != nil {
			return ruleSetInputView{}, fmt.Errorf("get RuleData %s: %w", ref.Name, err)
		}
		input := assemble.DataInput{
			Name:       data.Name,
			UID:        data.UID,
			Generation: data.Generation,
		}
		if includeContent {
			input.Files = data.Spec.Files
		}
		view.inputs.Data = append(view.inputs.Data, input)
		view.data = append(view.data, ruleDataInputStateFor(&data))
	}

	return view, nil
}

// loadRuleSetInputs resolves a RuleSet's RuleSources and RuleData into
// assembler inputs, preserving spec order and UID/generation. It performs plain
// Gets and has no status or requeue semantics.
func loadRuleSetInputs(ctx context.Context, reader client.Reader, ruleset *wafv1alpha1.RuleSet) (assemble.Inputs, error) {
	view, err := loadRuleSetInputView(ctx, reader, ruleset, true)
	if err != nil {
		return assemble.Inputs{}, err
	}
	return view.inputs, nil
}

// engineInputsChanged reports whether the Engine, its RuleSet, or any resolved
// RuleSet input changed after they were read. A changed read must never be
// accepted as if it were one consistent configuration.
func (r *EngineReconciler) engineInputsChanged(ctx context.Context, engine *wafv1alpha1.Engine, ruleset *wafv1alpha1.RuleSet, inputs ruleSetInputView) (bool, error) {
	var currentEngine wafv1alpha1.Engine
	if err := r.Get(ctx, types.NamespacedName{Namespace: engine.Namespace, Name: engine.Name}, &currentEngine); err != nil {
		if apierrors.IsNotFound(err) {
			return true, nil
		}
		return false, err
	}
	if currentEngine.UID != engine.UID || currentEngine.Generation != engine.Generation {
		return true, nil
	}

	var currentRuleSet wafv1alpha1.RuleSet
	if err := r.Get(ctx, types.NamespacedName{Namespace: ruleset.Namespace, Name: ruleset.Name}, &currentRuleSet); err != nil {
		if apierrors.IsNotFound(err) {
			return true, nil
		}
		return false, err
	}
	if !sameRuleSetAcceptanceView(ruleset, &currentRuleSet) {
		return true, nil
	}

	currentInputs, err := loadRuleSetInputView(ctx, r.Client, &currentRuleSet, false)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return true, nil
		}
		return false, err
	}

	return !inputs.sameState(currentInputs), nil
}

// engineInputsChangedLive rechecks Engine and RuleSet acceptance through the
// direct API reader after a render-cache miss. Input content was already
// identity-checked against the live read; the cache-only recheck catches updates
// observed while rendering without fetching input payloads a second time.
func (r *EngineReconciler) engineInputsChangedLive(
	ctx context.Context,
	engine *wafv1alpha1.Engine,
	ruleset *wafv1alpha1.RuleSet,
	inputs ruleSetInputView,
) (bool, error) {
	changed, err := r.engineInputsChanged(ctx, engine, ruleset, inputs)
	if err != nil || changed {
		return changed, err
	}

	reader := r.apiReader()
	var currentEngine wafv1alpha1.Engine
	if err := reader.Get(ctx, types.NamespacedName{Namespace: engine.Namespace, Name: engine.Name}, &currentEngine); err != nil {
		if apierrors.IsNotFound(err) {
			return true, nil
		}
		return false, err
	}
	if currentEngine.UID != engine.UID || currentEngine.Generation != engine.Generation {
		return true, nil
	}

	var currentRuleSet wafv1alpha1.RuleSet
	if err := reader.Get(ctx, types.NamespacedName{Namespace: ruleset.Namespace, Name: ruleset.Name}, &currentRuleSet); err != nil {
		if apierrors.IsNotFound(err) {
			return true, nil
		}
		return false, err
	}
	if !sameRuleSetAcceptanceView(ruleset, &currentRuleSet) {
		return true, nil
	}

	return false, nil
}

func sameRuleSetAcceptanceView(a, b *wafv1alpha1.RuleSet) bool {
	return a.UID == b.UID &&
		a.Generation == b.Generation &&
		a.Annotations[wafv1alpha1.AnnotationSkipUnsupportedRulesCheck] == b.Annotations[wafv1alpha1.AnnotationSkipUnsupportedRulesCheck] &&
		apiequality.Semantic.DeepEqual(a.Status.AcceptedContent, b.Status.AcceptedContent) &&
		apiequality.Semantic.DeepEqual(
			apimeta.FindStatusCondition(a.Status.Conditions, conditionDegraded),
			apimeta.FindStatusCondition(b.Status.Conditions, conditionDegraded),
		)
}

func (r *RuleSetReconciler) ruleSetInputsChanged(
	ctx context.Context,
	ruleset *wafv1alpha1.RuleSet,
	inputs ruleSetInputView,
) (bool, error) {
	var cachedRuleSet, liveRuleSet wafv1alpha1.RuleSet
	if err := r.Get(ctx, types.NamespacedName{Namespace: ruleset.Namespace, Name: ruleset.Name}, &cachedRuleSet); err != nil {
		if apierrors.IsNotFound(err) {
			return true, nil
		}
		return false, err
	}
	if err := apiReaderOrClient(r.APIReader, r.Client).Get(
		ctx,
		types.NamespacedName{Namespace: ruleset.Namespace, Name: ruleset.Name},
		&liveRuleSet,
	); err != nil {
		if apierrors.IsNotFound(err) {
			return true, nil
		}
		return false, err
	}
	if !sameRuleSetAcceptanceView(ruleset, &cachedRuleSet) || !sameRuleSetAcceptanceView(ruleset, &liveRuleSet) {
		return true, nil
	}

	cachedInputs, err := loadRuleSetInputView(ctx, r.Client, &cachedRuleSet, false)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return true, nil
		}
		return false, err
	}
	return !inputs.sameState(cachedInputs), nil
}

// -----------------------------------------------------------------------------
// RuleSet Validation
// -----------------------------------------------------------------------------

const (
	ruleSetDegradedReasonInvalidRuleSet = "InvalidRuleSet"
	// ruleSetDegradedReasonRejectedContent marks content this build's delivery
	// contract refuses: host-file directives, unsupported includes, or limits
	// the plugin would NACK. Unlike an ordinary invalid edit, an accepted
	// configuration of this content must not keep serving.
	ruleSetDegradedReasonRejectedContent = "RejectedContent"
	// ruleSetDegradedReasonContentTooLarge marks rule text and RuleData that
	// together exceed the plugin's configuration limit. Like an ordinary
	// invalid edit, it keeps the content accepted before.
	ruleSetDegradedReasonContentTooLarge = "ContentTooLarge"
	ruleSetReadyReasonRulesAccepted      = "RulesAccepted"
)

// errRuleSetRulesInvalid indicates aggregate validation failed and the RuleSet
// status was patched to Degraded. Reconcile should stop without error.
var errRuleSetRulesInvalid = errors.New("aggregated rules failed validation")

// validateAggregatedRules checks the aggregated rule set against what
// envoy-coraza reads differently from Coraza and, for content not accepted
// yet, against the cluster rule policy, then compiles it with Coraza. The
// caller has already run the directive and Include guard
// (validation.ValidateIncludes), which must also cover accepted content.
// Sets Degraded status and emits Warning events on failure.
// The returned duration covers validation only (not status patches).
func (r *RuleSetReconciler) validateAggregatedRules(
	ctx context.Context,
	log logr.Logger,
	req ctrl.Request,
	ruleset *wafv1alpha1.RuleSet,
	rejectedContentHash string,
	content assemble.Content,
) (time.Duration, error) {
	start := time.Now()
	if err := validation.CheckGatewayParity(content.Rules, content.DataFiles); err != nil {
		return time.Since(start), r.markParityInvalid(ctx, log, req, ruleset, err)
	}
	// The cluster rule policy applies to content the RuleSet has not accepted
	// yet, so a tightened policy takes effect on the next content change.
	if accepted := ruleset.Status.AcceptedContent; accepted == nil || accepted.ContentHash != rejectedContentHash {
		if err := validation.CheckRulePolicy(content.Rules, content.DataFiles, r.RulePolicy); err != nil {
			return time.Since(start), r.markRulesInvalid(ctx, log, req, ruleset, ruleSetDegradedReasonInvalidRuleSet, rejectedContentHash, err)
		}
	}
	if err := r.compile(req.NamespacedName, rejectedContentHash, content); err != nil {
		return time.Since(start), r.markRulesInvalid(ctx, log, req, ruleset, ruleSetDegradedReasonInvalidRuleSet, rejectedContentHash, err)
	}
	return time.Since(start), nil
}

// compile compiles content with Coraza, once per content: the result only
// depends on the content, and compiling costs time and memory that grow with
// it.
func (r *RuleSetReconciler) compile(key types.NamespacedName, contentHash string, content assemble.Content) error {
	results := r.contentResults(key, contentHash)
	if !results.compiled {
		results.compiled = true
		if waf, err := coraza.NewWAF(validation.BuildWAFConfig(content.Rules, content.DataFiles)); err != nil {
			results.compileErr = truncateMessage(validation.SanitizeErrorMessage(err).Error(), maxResultMessageBytes)
		} else {
			validation.CloseWAF(waf)
		}
		r.storeContentResults(key, results)
	}
	if results.compileErr != "" {
		return errors.New(results.compileErr)
	}
	return nil
}

// markRulesInvalid patches Degraded (unless the condition is already current)
// and returns errRuleSetRulesInvalid so the caller stops reconciling.
func (r *RuleSetReconciler) markRulesInvalid(
	ctx context.Context,
	log logr.Logger,
	req ctrl.Request,
	ruleset *wafv1alpha1.RuleSet,
	reason string,
	rejectedContentHash string,
	cause error,
) error {
	// Only drop an accepted record for the exact content this build rejects:
	// legacy accepted content that now fails validation. A different record is
	// the last accepted RuleSet content and is kept for status/audit. The Engine
	// separately clears its own accepted configuration when it observes
	// RejectedContent for the current generation.
	clearAccepted := func() {
		if accepted := ruleset.Status.AcceptedContent; accepted != nil && accepted.ContentHash == rejectedContentHash {
			ruleset.Status.AcceptedContent = nil
		}
	}
	if err := r.markDegraded(ctx, log, req, ruleset, reason, invalidRuleSetMessage(cause), clearAccepted); err != nil {
		return err
	}
	return errRuleSetRulesInvalid
}

// markParityInvalid patches Degraded with InvalidRuleSet for content that
// fails the gateway-parity checks and keeps status.acceptedContent, so content
// a RuleSet accepted earlier keeps its record and the Engine its configuration.
func (r *RuleSetReconciler) markParityInvalid(
	ctx context.Context,
	log logr.Logger,
	req ctrl.Request,
	ruleset *wafv1alpha1.RuleSet,
	cause error,
) error {
	if err := r.markDegraded(ctx, log, req, ruleset, ruleSetDegradedReasonInvalidRuleSet, invalidRuleSetMessage(cause)); err != nil {
		return err
	}
	return errRuleSetRulesInvalid
}

// markDegraded patches Degraded unless the same reason and message are already
// current. It keeps status.acceptedContent unless mutate drops it in the patch.
func (r *RuleSetReconciler) markDegraded(ctx context.Context, log logr.Logger, req ctrl.Request, ruleset *wafv1alpha1.RuleSet, reason, msg string, mutate ...func()) error {
	msg = truncateMessage(msg, maxConditionMessageBytes)
	if isConditionCurrent(ruleset.Status.Conditions, conditionDegraded, reason, ruleset.Generation) &&
		degradedConditionMessage(ruleset, reason) == msg {
		return nil
	}
	return patchDegraded(ctx, r.Status(), r.Recorder, log, req, "RuleSet", ruleset, &ruleset.Status.Conditions, ruleset.Generation, reason, msg, mutate...)
}

// invalidRuleSetMessage is the Degraded message of a RuleSet whose content
// failed validation with cause.
func invalidRuleSetMessage(cause error) string {
	return fmt.Sprintf("Ruleset is invalid\n%v", validation.SanitizeErrorMessage(cause))
}

// degradedConditionMessage returns the current Degraded message for reason, so
// a new distinct error is not hidden by the generation-only idempotency guard.
func degradedConditionMessage(ruleset *wafv1alpha1.RuleSet, reason string) string {
	condition := apimeta.FindStatusCondition(ruleset.Status.Conditions, conditionDegraded)
	if condition == nil || condition.Reason != reason {
		return ""
	}
	return condition.Message
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

// -----------------------------------------------------------------------------
// RuleSetReconciler - Reference Validation
// -----------------------------------------------------------------------------

// findDuplicateReferences checks for duplicate RuleSource names in spec.sources
// and duplicate RuleData names in spec.data. Returns a descriptive message if
// any duplicates are found, or empty string if all references are unique.
func findDuplicateReferences(ruleset *wafv1alpha1.RuleSet) string {
	var msgs []string

	if dups := findDuplicateNames(ruleset.Spec.Sources, func(s wafv1alpha1.SourceReference) string { return s.Name }); len(dups) > 0 {
		msgs = append(msgs, fmt.Sprintf("spec.sources contains duplicate RuleSource name(s): %s", strings.Join(dups, ", ")))
	}

	if dups := findDuplicateNames(ruleset.Spec.Data, func(d wafv1alpha1.DataReference) string { return d.Name }); len(dups) > 0 {
		msgs = append(msgs, fmt.Sprintf("spec.data contains duplicate RuleData name(s): %s", strings.Join(dups, ", ")))
	}

	return strings.Join(msgs, "; ")
}

// findDuplicateNames returns the names that appear more than once in items.
func findDuplicateNames[T any](items []T, name func(T) string) []string {
	seen := make(map[string]int, len(items))
	for _, item := range items {
		seen[name(item)]++
	}

	var dups []string
	for n, count := range seen {
		if count > 1 {
			dups = append(dups, n)
		}
	}
	sort.Strings(dups)
	return dups
}

// -----------------------------------------------------------------------------
// RuleSetReconciler - Data Loading
// -----------------------------------------------------------------------------

// loadData fetches all RuleData objects referenced by the RuleSet and returns
// them in spec order. merge/validation is performed by assemble.Assemble.
func (r *RuleSetReconciler) loadData(
	ctx context.Context,
	log logr.Logger,
	req ctrl.Request,
	ruleset *wafv1alpha1.RuleSet,
) ([]assemble.DataInput, []ruleDataInputState, bool, error) {
	if len(ruleset.Spec.Data) == 0 {
		return nil, nil, false, nil
	}

	logInfo(log, req, "RuleSet", "Loading data", "dataCount", len(ruleset.Spec.Data))

	dataInputs := make([]assemble.DataInput, 0, len(ruleset.Spec.Data))
	dataStates := make([]ruleDataInputState, 0, len(ruleset.Spec.Data))
	for _, ref := range ruleset.Spec.Data {
		rd, err := loadConsistentRuleData(ctx, r.Client, apiReaderOrClient(r.APIReader, r.Client), ruleset.Namespace, ref.Name)
		if err != nil {
			if errors.Is(err, errRuleSetInputsChanged) {
				return nil, nil, false, err
			}
			if apierrors.IsNotFound(err) {
				logInfo(log, req, "RuleSet", "Referenced RuleData not found; waiting for it to appear", "ruleDataName", ref.Name)
				r.Metrics.ForgetRuleData(ruleset.Namespace, ref.Name)
				msg := fmt.Sprintf("Referenced RuleData %s does not exist", ref.Name)
				if patchErr := patchDegraded(ctx, r.Status(), r.Recorder, log, req, "RuleSet", ruleset, &ruleset.Status.Conditions, ruleset.Generation, "RuleDataNotFound", msg); patchErr != nil {
					return nil, nil, true, patchErr
				}
				return nil, nil, true, nil
			}
			logError(log, req, "RuleSet", err, "Failed to get RuleData", "ruleDataName", ref.Name)
			msg := fmt.Sprintf("Failed to access RuleData %s: %v", ref.Name, err)
			if patchErr := patchDegraded(ctx, r.Status(), r.Recorder, log, req, "RuleSet", ruleset, &ruleset.Status.Conditions, ruleset.Generation, "RuleDataAccessError", msg); patchErr != nil {
				return nil, nil, true, patchErr
			}
			return nil, nil, true, err
		}

		if !isConditionCurrent(rd.Status.Conditions, conditionReady, "Loaded", rd.Generation) {
			rdReq := ctrl.Request{NamespacedName: types.NamespacedName{Name: rd.Name, Namespace: rd.Namespace}}
			if patchErr := patchReady(ctx, r.Status(), r.Recorder, log, rdReq, "RuleData", &rd, &rd.Status.Conditions, rd.Generation, "Loaded", "Data loaded successfully"); patchErr != nil {
				return nil, nil, true, patchErr
			}
		}
		r.Metrics.RecordRuleData(&rd)

		dataInputs = append(dataInputs, assemble.DataInput{
			Name:       rd.Name,
			UID:        rd.UID,
			Generation: rd.Generation,
			Files:      rd.Spec.Files,
		})
		dataStates = append(dataStates, ruleDataInputStateFor(&rd))
	}

	return dataInputs, dataStates, false, nil
}

// -----------------------------------------------------------------------------
// RuleSetReconciler - Source Loading
// -----------------------------------------------------------------------------

func (r *RuleSetReconciler) ruleSourceLoadFailure(
	ctx context.Context,
	log logr.Logger,
	req ctrl.Request,
	ruleset *wafv1alpha1.RuleSet,
	name string,
	err error,
) (bool, error) {
	if errors.Is(err, errRuleSetInputsChanged) {
		return false, err
	}
	if apierrors.IsNotFound(err) {
		logInfo(log, req, "RuleSet", "Referenced RuleSource not found; waiting for it to appear", "ruleSourceName", name)
		msg := fmt.Sprintf("Referenced RuleSource %s does not exist", name)
		return true, patchDegraded(ctx, r.Status(), r.Recorder, log, req, "RuleSet", ruleset, &ruleset.Status.Conditions, ruleset.Generation, "RuleSourceNotFound", msg)
	}

	logError(log, req, "RuleSet", err, "Failed to get RuleSource", "ruleSourceName", name)
	msg := fmt.Sprintf("Failed to access RuleSource %s: %v", name, err)
	if patchErr := patchDegraded(ctx, r.Status(), r.Recorder, log, req, "RuleSet", ruleset, &ruleset.Status.Conditions, ruleset.Generation, "RuleSourceAccessError", msg); patchErr != nil {
		return true, patchErr
	}
	return true, err
}

func (r *RuleSetReconciler) referencedRuleSourceInvalid(
	ctx context.Context,
	log logr.Logger,
	req ctrl.Request,
	ruleset *wafv1alpha1.RuleSet,
	name string,
) error {
	msg := fmt.Sprintf("Referenced RuleSource %s has invalid rules (see RuleSource status for details)", name)
	return patchDegraded(ctx, r.Status(), r.Recorder, log, req, "RuleSet", ruleset, &ruleset.Status.Conditions, ruleset.Generation, "ReferencedRuleSourceInvalid", msg)
}

func (r *RuleSetReconciler) getCachedRuleSource(
	ctx context.Context,
	ruleset *wafv1alpha1.RuleSet,
	name string,
) (wafv1alpha1.RuleSource, error) {
	var source wafv1alpha1.RuleSource
	key := types.NamespacedName{Namespace: ruleset.Namespace, Name: name}
	if err := r.Get(ctx, key, &source); err == nil {
		return source, nil
	} else if !apierrors.IsNotFound(err) {
		return wafv1alpha1.RuleSource{}, err
	}

	var live wafv1alpha1.RuleSource
	if err := apiReaderOrClient(r.APIReader, r.Client).Get(ctx, key, &live); err != nil {
		return wafv1alpha1.RuleSource{}, err
	}
	return wafv1alpha1.RuleSource{}, errRuleSetInputsChanged
}

func (r *RuleSetReconciler) checkCachedRuleSourceStatuses(
	ctx context.Context,
	log logr.Logger,
	req ctrl.Request,
	ruleset *wafv1alpha1.RuleSet,
) ([]wafv1alpha1.RuleSource, []string, bool, error) {
	cachedSources := make([]wafv1alpha1.RuleSource, 0, len(ruleset.Spec.Sources))
	var pendingSources []string

	for _, ref := range ruleset.Spec.Sources {
		source, err := r.getCachedRuleSource(ctx, ruleset, ref.Name)
		if err != nil {
			done, loadErr := r.ruleSourceLoadFailure(ctx, log, req, ruleset, ref.Name, err)
			return nil, nil, done, loadErr
		}

		if ruleSourceInvalidForGeneration(source.Status.Conditions, source.Generation) {
			if err := r.referencedRuleSourceInvalid(ctx, log, req, ruleset, source.Name); err != nil {
				return nil, nil, true, err
			}
			return nil, nil, true, nil
		}

		skipFragmentValidation := source.Annotations[wafv1alpha1.AnnotationSkipValidation] == "false"
		if !ruleSourceValidatedForGeneration(source.Status.Conditions, source.Generation, skipFragmentValidation) {
			pendingSources = append(pendingSources, ref.Name)
		}
		cachedSources = append(cachedSources, source)
	}
	return cachedSources, pendingSources, false, nil
}

// loadSources fetches all RuleSource objects referenced by the RuleSet and
// returns them in spec order. Per-source Coraza validation and RuleSource
// status are owned by RuleSourceReconciler; this function gates on RuleSource
// status and returns a requeue interval while sources are not ready.
func (r *RuleSetReconciler) loadSources(
	ctx context.Context,
	log logr.Logger,
	req ctrl.Request,
	ruleset *wafv1alpha1.RuleSet,
) (sources []assemble.SourceInput, states []ruleSourceInputState, done bool, requeueAfter time.Duration, err error) {
	logInfo(log, req, "RuleSet", "Loading sources", "sourceCount", len(ruleset.Spec.Sources))

	cachedSources, pendingSources, done, err := r.checkCachedRuleSourceStatuses(ctx, log, req, ruleset)
	if done || err != nil {
		return nil, nil, done, 0, err
	}
	if len(pendingSources) > 0 {
		msg := fmt.Sprintf("Waiting for RuleSource validation: %s", strings.Join(pendingSources, ", "))
		if patchErr := r.patchRuleSetAwaitingRuleSources(ctx, log, req, ruleset, msg); patchErr != nil {
			return nil, nil, true, 0, patchErr
		}
		return nil, nil, true, ruleSourceValidationRequeue, nil
	}

	sources = make([]assemble.SourceInput, 0, len(cachedSources))
	states = make([]ruleSourceInputState, 0, len(cachedSources))
	apiReader := apiReaderOrClient(r.APIReader, r.Client)
	for _, cached := range cachedSources {
		rs, err := loadConsistentRuleSourceFromCache(ctx, apiReader, &cached)
		if err != nil {
			done, loadErr := r.ruleSourceLoadFailure(ctx, log, req, ruleset, cached.Name, err)
			return nil, nil, done, 0, loadErr
		}

		// The live read must preserve the preflight's gating decision; the
		// consistency helper compares status and annotation state as well as identity.
		if ruleSourceInvalidForGeneration(rs.Status.Conditions, rs.Generation) {
			if err := r.referencedRuleSourceInvalid(ctx, log, req, ruleset, rs.Name); err != nil {
				return nil, nil, true, 0, err
			}
			return nil, nil, true, 0, nil
		}

		sources = append(sources, assemble.SourceInput{
			Name:       rs.Name,
			UID:        rs.UID,
			Generation: rs.Generation,
			Rules:      rs.Spec.Rules,
		})
		states = append(states, ruleSourceInputStateFor(&rs))
	}

	return sources, states, false, 0, nil
}
