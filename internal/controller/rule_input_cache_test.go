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
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"

	wafv1alpha1 "github.com/networking-incubator/coraza-kubernetes-operator/api/v1alpha1"
	"github.com/networking-incubator/coraza-kubernetes-operator/internal/ecds/render"
	"github.com/networking-incubator/coraza-kubernetes-operator/internal/rulesets/assemble"
	"github.com/networking-incubator/coraza-kubernetes-operator/test/utils"
)

func TestRuleInputWatchPredicatesObserveStatusAndValidationAnnotation(t *testing.T) {
	oldSource := &wafv1alpha1.RuleSource{ObjectMeta: metav1.ObjectMeta{
		Namespace:  testNamespace,
		Name:       "watch-source",
		Generation: 4,
		Annotations: map[string]string{
			wafv1alpha1.AnnotationSkipValidation: "false",
		},
	}}
	newSource := oldSource.DeepCopy()
	newSource.Status.Conditions = []metav1.Condition{{
		Type:               conditionReady,
		Status:             metav1.ConditionTrue,
		ObservedGeneration: oldSource.Generation,
		Reason:             ruleSourceReadyReasonValidationSkipped,
	}}
	require.True(t, ruleSourceWatchPredicate().Update(event.UpdateEvent{
		ObjectOld: oldSource,
		ObjectNew: newSource,
	}), "a status-only RuleSource change must enqueue its RuleSets")

	annotatedSource := oldSource.DeepCopy()
	annotatedSource.Annotations = nil
	require.True(t, ruleSourceWatchPredicate().Update(event.UpdateEvent{
		ObjectOld: oldSource,
		ObjectNew: annotatedSource,
	}), "the validation annotation changes RuleSource readiness without generation")

	unrelatedSource := oldSource.DeepCopy()
	unrelatedSource.Annotations["example.com/note"] = "changed"
	require.False(t, ruleSourceWatchPredicate().Update(event.UpdateEvent{
		ObjectOld: oldSource,
		ObjectNew: unrelatedSource,
	}), "unrelated metadata does not trigger RuleSet validation")

	oldData := &wafv1alpha1.RuleData{ObjectMeta: metav1.ObjectMeta{
		Namespace:  testNamespace,
		Name:       "watch-data",
		Generation: 2,
	}}
	newData := oldData.DeepCopy()
	newData.Status.Conditions = []metav1.Condition{{
		Type:               conditionReady,
		Status:             metav1.ConditionTrue,
		ObservedGeneration: oldData.Generation,
		Reason:             "Loaded",
	}}
	require.True(t, ruleDataWatchPredicate().Update(event.UpdateEvent{
		ObjectOld: oldData,
		ObjectNew: newData,
	}), "a status-only RuleData change must refresh referencing RuleSets")
}

func TestRuleSetPendingRuleSourceSkipsFullInputReads(t *testing.T) {
	ctx := context.Background()
	namespace := setupTestNamespace(t, ctx)
	source := utils.NewTestRuleSource("pending-source", namespace, testAcceptRuleText)
	data := utils.NewTestRuleData("pending-data", namespace, map[string]string{"rules.data": "blocked.example\n"})
	require.NoError(t, k8sClient.Create(ctx, source))
	require.NoError(t, k8sClient.Create(ctx, data))
	t.Cleanup(func() {
		_ = k8sClient.Delete(ctx, source)
		_ = k8sClient.Delete(ctx, data)
	})
	ruleSet := utils.NewTestRuleSet(utils.RuleSetOptions{
		Name:      "pending-source-inputs",
		Namespace: namespace,
		Sources:   []wafv1alpha1.SourceReference{{Name: source.Name}},
		Data:      []wafv1alpha1.DataReference{{Name: data.Name}},
	})
	require.NoError(t, k8sClient.Create(ctx, ruleSet))
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, ruleSet) })

	cached := &ruleSetInputTestClient{
		Client:              k8sClient,
		stripRuleSourceSpec: true,
		stripRuleDataSpec:   true,
	}
	apiCounts := &apiReaderOperationCounts{}
	reconciler := &RuleSetReconciler{
		Client:    cached,
		APIReader: &countedAPIReader{Reader: k8sClient, counts: apiCounts},
		Scheme:    scheme,
		Recorder:  utils.NewTestRecorder(),
	}

	result, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(ruleSet)})
	require.NoError(t, err)
	require.Equal(t, ruleSourceValidationRequeue, result.RequeueAfter)
	sourceGets, dataGets := apiCounts.inputGets()
	require.Zero(t, sourceGets, "pending validation must be gated before live RuleSource reads")
	require.Zero(t, dataGets, "pending validation must be gated before live RuleData reads")
	require.Equal(t, 1, cached.sourceGets, "the preflight needs only informer RuleSource metadata")
	require.Zero(t, cached.dataGets, "RuleData must not be read while a RuleSource is pending")
}

func TestRuleSourceReconcilerReadsFullRulesFromAPIReader(t *testing.T) {
	ctx := context.Background()
	namespace := setupTestNamespace(t, ctx)
	rules := `SecRule REMOTE_ADDR "@rbl sbl.spamhaus.org" "id:1,phase:1,deny"`
	source := utils.NewTestRuleSource("pruned-source", namespace, rules)
	require.NoError(t, k8sClient.Create(ctx, source))
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, source) })

	cached := &ruleSetInputTestClient{Client: k8sClient, stripRuleSourceSpec: true}
	reconciler := &RuleSourceReconciler{
		Client:    cached,
		APIReader: k8sClient,
		Recorder:  utils.NewTestRecorder(),
	}
	_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(source)})
	require.NoError(t, err)
	require.Equal(t, 2, cached.sourceGets, "the cache view is checked again before a status patch")

	var current wafv1alpha1.RuleSource
	require.NoError(t, k8sClient.Get(ctx, client.ObjectKeyFromObject(source), &current))
	require.Equal(t, rules, current.Spec.Rules, "status patching must not erase the API-stored rules")
	degraded := apimeta.FindStatusCondition(current.Status.Conditions, conditionDegraded)
	require.NotNil(t, degraded)
	require.Contains(t, degraded.Message, "@rbl", "pruning must not bypass the unsupported-operator guard")
}

func TestRuleSetReconcilerLoadsFullInputsAndPatchesRuleDataFromAPIReader(t *testing.T) {
	ctx := context.Background()
	namespace := setupTestNamespace(t, ctx)
	source := utils.NewTestRuleSource("pruned-rulesource", namespace, testAcceptRuleText+"\n"+testAcceptDataRuleText)
	data := utils.NewTestRuleData("pruned-ruledata", namespace, map[string]string{"some.data": "evildata\n"})
	require.NoError(t, k8sClient.Create(ctx, source))
	require.NoError(t, k8sClient.Create(ctx, data))
	t.Cleanup(func() {
		_ = k8sClient.Delete(ctx, source)
		_ = k8sClient.Delete(ctx, data)
	})
	_, err := (&RuleSourceReconciler{Client: k8sClient, APIReader: k8sClient, Recorder: utils.NewTestRecorder()}).
		Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(source)})
	require.NoError(t, err)

	ruleSet := utils.NewTestRuleSet(utils.RuleSetOptions{
		Name:      "pruned-inputs",
		Namespace: namespace,
		Sources:   []wafv1alpha1.SourceReference{{Name: source.Name}},
		Data:      []wafv1alpha1.DataReference{{Name: data.Name}},
	})
	require.NoError(t, k8sClient.Create(ctx, ruleSet))
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, ruleSet) })

	cached := &ruleSetInputTestClient{
		Client:              k8sClient,
		stripRuleSourceSpec: true,
		stripRuleDataSpec:   true,
	}
	reconciler := &RuleSetReconciler{
		Client:    cached,
		APIReader: k8sClient,
		Scheme:    scheme,
		Recorder:  utils.NewTestRecorder(),
	}
	_, err = reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(ruleSet)})
	require.NoError(t, err)
	require.GreaterOrEqual(t, cached.sourceGets, 2)
	require.GreaterOrEqual(t, cached.dataGets, 2)

	var currentRuleSet wafv1alpha1.RuleSet
	require.NoError(t, k8sClient.Get(ctx, client.ObjectKeyFromObject(ruleSet), &currentRuleSet))
	require.NotNil(t, currentRuleSet.Status.AcceptedContent)
	inputs, err := loadRuleSetInputs(ctx, k8sClient, &currentRuleSet)
	require.NoError(t, err)
	content, err := assemble.Assemble(inputs)
	require.NoError(t, err)
	hash, err := render.RuleSetContentHash(content)
	require.NoError(t, err)
	require.Equal(t, hash, currentRuleSet.Status.AcceptedContent.ContentHash)

	var currentData wafv1alpha1.RuleData
	require.NoError(t, k8sClient.Get(ctx, client.ObjectKeyFromObject(data), &currentData))
	require.Equal(t, "evildata\n", currentData.Spec.Files["some.data"])
	require.True(t, isConditionCurrent(currentData.Status.Conditions, conditionReady, "Loaded", currentData.Generation))
}

func TestRuleSetReconcilerRetriesWhenCachedRuleSourceMetadataDiffers(t *testing.T) {
	for _, changed := range []string{"annotation", "status"} {
		t.Run(changed, func(t *testing.T) {
			ctx := context.Background()
			namespace := setupTestNamespace(t, ctx)
			source := utils.NewTestRuleSource("skewed-source-"+changed, namespace, testAcceptRuleText)
			source.Annotations = map[string]string{wafv1alpha1.AnnotationSkipValidation: "false"}
			require.NoError(t, k8sClient.Create(ctx, source))
			t.Cleanup(func() { _ = k8sClient.Delete(ctx, source) })
			_, err := (&RuleSourceReconciler{Client: k8sClient, APIReader: k8sClient, Recorder: utils.NewTestRecorder()}).
				Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(source)})
			require.NoError(t, err)

			var stale wafv1alpha1.RuleSource
			require.NoError(t, k8sClient.Get(ctx, client.ObjectKeyFromObject(source), &stale))
			cacheSnapshot := stale.DeepCopy()
			switch changed {
			case "annotation":
				stale.Annotations = nil
				require.NoError(t, k8sClient.Update(ctx, &stale))
			case "status":
				ready := apimeta.FindStatusCondition(stale.Status.Conditions, conditionReady)
				require.NotNil(t, ready)
				ready.Reason = "StatusOnlyUpdate"
				require.NoError(t, k8sClient.Status().Update(ctx, &stale))
			}

			ruleSet := utils.NewTestRuleSet(utils.RuleSetOptions{
				Name:      "skewed-input-" + changed,
				Namespace: namespace,
				Sources:   []wafv1alpha1.SourceReference{{Name: source.Name}},
			})
			require.NoError(t, k8sClient.Create(ctx, ruleSet))
			t.Cleanup(func() { _ = k8sClient.Delete(ctx, ruleSet) })

			cacheClient := &staleRuleSourceCacheClient{
				Client:      k8sClient,
				sourceKey:   client.ObjectKeyFromObject(source),
				staleSource: cacheSnapshot,
			}
			reconciler := &RuleSetReconciler{
				Client:    cacheClient,
				APIReader: k8sClient,
				Scheme:    scheme,
				Recorder:  utils.NewTestRecorder(),
			}
			result, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(ruleSet)})
			require.NoError(t, err)
			require.Equal(t, ruleInputConsistencyRetry, result.RequeueAfter)
			require.Equal(t, 1, cacheClient.sourceGets)

			var currentRuleSet wafv1alpha1.RuleSet
			require.NoError(t, k8sClient.Get(ctx, client.ObjectKeyFromObject(ruleSet), &currentRuleSet))
			require.Nil(t, currentRuleSet.Status.AcceptedContent, "inconsistent views must never be accepted")
		})
	}
}

func TestRuleSetReconcilerDoesNotRequeueForRuleDataReadyStatusSkew(t *testing.T) {
	ctx := context.Background()
	namespace := setupTestNamespace(t, ctx)
	source := utils.NewTestRuleSource("skewed-data-source", namespace, testAcceptRuleText)
	require.NoError(t, k8sClient.Create(ctx, source))
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, source) })
	_, err := (&RuleSourceReconciler{Client: k8sClient, APIReader: k8sClient, Recorder: utils.NewTestRecorder()}).
		Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(source)})
	require.NoError(t, err)

	data := utils.NewTestRuleData("skewed-data", namespace, map[string]string{"data.txt": "value\n"})
	require.NoError(t, k8sClient.Create(ctx, data))
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, data) })
	data.Status.Conditions = []metav1.Condition{{
		Type:               conditionReady,
		Status:             metav1.ConditionTrue,
		ObservedGeneration: data.Generation,
		Reason:             "Loaded",
		LastTransitionTime: metav1.Now(),
	}}
	require.NoError(t, k8sClient.Status().Update(ctx, data))
	var staleData wafv1alpha1.RuleData
	require.NoError(t, k8sClient.Get(ctx, client.ObjectKeyFromObject(data), &staleData))
	cacheSnapshot := staleData.DeepCopy()
	ready := apimeta.FindStatusCondition(staleData.Status.Conditions, conditionReady)
	require.NotNil(t, ready)
	ready.Reason = "StatusOnlyUpdate"
	require.NoError(t, k8sClient.Status().Update(ctx, &staleData))

	ruleSet := utils.NewTestRuleSet(utils.RuleSetOptions{
		Name:      "skewed-data-input",
		Namespace: namespace,
		Sources:   []wafv1alpha1.SourceReference{{Name: source.Name}},
		Data:      []wafv1alpha1.DataReference{{Name: data.Name}},
	})
	require.NoError(t, k8sClient.Create(ctx, ruleSet))
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, ruleSet) })

	cacheClient := &staleRuleDataCacheClient{
		Client:    k8sClient,
		dataKey:   client.ObjectKeyFromObject(data),
		staleData: cacheSnapshot,
	}
	reconciler := &RuleSetReconciler{
		Client:    cacheClient,
		APIReader: k8sClient,
		Scheme:    scheme,
		Recorder:  utils.NewTestRecorder(),
	}
	result, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(ruleSet)})
	require.NoError(t, err)
	require.Zero(t, result.RequeueAfter, "RuleData Ready is written by the RuleSet controller and does not gate accepted content")
	require.GreaterOrEqual(t, cacheClient.dataGets, 2)

	var currentRuleSet wafv1alpha1.RuleSet
	require.NoError(t, k8sClient.Get(ctx, client.ObjectKeyFromObject(ruleSet), &currentRuleSet))
	require.NotNil(t, currentRuleSet.Status.AcceptedContent, "a non-gating RuleData Ready change must not block content acceptance")
	var currentData wafv1alpha1.RuleData
	require.NoError(t, k8sClient.Get(ctx, client.ObjectKeyFromObject(data), &currentData))
	require.True(t, isConditionCurrent(currentData.Status.Conditions, conditionReady, "Loaded", currentData.Generation))
}

func TestRuleSetReadyPatchDoesNotSelfRequeueAgainstAsyncInformer(t *testing.T) {
	ctx := context.Background()
	namespace := setupTestNamespace(t, ctx)
	source := utils.NewTestRuleSource("async-source", namespace, testAcceptRuleText)
	require.NoError(t, k8sClient.Create(ctx, source))
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, source) })
	_, err := (&RuleSourceReconciler{Client: k8sClient, APIReader: k8sClient, Recorder: utils.NewTestRecorder()}).
		Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(source)})
	require.NoError(t, err)

	data := utils.NewTestRuleData("async-data", namespace, map[string]string{"rules.data": "blocked.example\n"})
	require.NoError(t, k8sClient.Create(ctx, data))
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, data) })
	ruleSet := utils.NewTestRuleSet(utils.RuleSetOptions{
		Name:      "async-data-ready",
		Namespace: namespace,
		Sources:   []wafv1alpha1.SourceReference{{Name: source.Name}},
		Data:      []wafv1alpha1.DataReference{{Name: data.Name}},
	})
	require.NoError(t, k8sClient.Create(ctx, ruleSet))
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, ruleSet) })

	cacheReader := k8sClient.(*indexedTestClient).reader
	waitForCachedObject(t, cacheReader, client.ObjectKeyFromObject(source), &wafv1alpha1.RuleSource{},
		func(obj client.Object) bool {
			current := obj.(*wafv1alpha1.RuleSource)
			return ruleSourceValidatedForGeneration(current.Status.Conditions, current.Generation, false)
		})
	waitForCachedObject(t, cacheReader, client.ObjectKeyFromObject(data), &wafv1alpha1.RuleData{})
	waitForCachedObject(t, cacheReader, client.ObjectKeyFromObject(ruleSet), &wafv1alpha1.RuleSet{})

	var staleData wafv1alpha1.RuleData
	require.NoError(t, cacheReader.Get(ctx, client.ObjectKeyFromObject(data), &staleData))
	reconciler := &RuleSetReconciler{
		Client: &cachedGetTestClient{
			Client:       k8sClient,
			reader:       cacheReader,
			staleDataKey: client.ObjectKeyFromObject(data),
			staleData:    staleData.DeepCopy(),
		},
		APIReader: k8sClient,
		Scheme:    scheme,
		Recorder:  utils.NewTestRecorder(),
	}
	request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(ruleSet)}
	result, err := reconciler.Reconcile(ctx, request)
	require.NoError(t, err)
	require.Zero(t, result.RequeueAfter, "patching RuleData Ready must not look like an input edit")

	// Wait for RuleSet acceptance in the informer, while the client wrapper
	// deliberately keeps serving the pre-patch RuleData Ready condition.
	waitForCachedObject(t, cacheReader, client.ObjectKeyFromObject(ruleSet), &wafv1alpha1.RuleSet{},
		func(obj client.Object) bool {
			return obj.(*wafv1alpha1.RuleSet).Status.AcceptedContent != nil
		})
	result, err = reconciler.Reconcile(ctx, request)
	require.NoError(t, err)
	require.Zero(t, result.RequeueAfter, "a stale informer Ready condition is non-gating on the accepted path")
	var currentRuleSet wafv1alpha1.RuleSet
	require.NoError(t, k8sClient.Get(ctx, client.ObjectKeyFromObject(ruleSet), &currentRuleSet))
	require.NotNil(t, currentRuleSet.Status.AcceptedContent)

	waitForCachedObject(t, cacheReader, client.ObjectKeyFromObject(data), &wafv1alpha1.RuleData{},
		func(obj client.Object) bool {
			current := obj.(*wafv1alpha1.RuleData)
			return isConditionCurrent(current.Status.Conditions, conditionReady, "Loaded", current.Generation)
		})
	require.True(t, ruleDataWatchPredicate().Update(event.UpdateEvent{
		ObjectOld: &wafv1alpha1.RuleData{ObjectMeta: metav1.ObjectMeta{Generation: data.Generation}},
		ObjectNew: &wafv1alpha1.RuleData{
			ObjectMeta: metav1.ObjectMeta{Generation: data.Generation},
			Status: wafv1alpha1.RuleDataStatus{Conditions: []metav1.Condition{{
				Type: conditionReady, Status: metav1.ConditionFalse, ObservedGeneration: data.Generation, Reason: "ExternalChange",
			}}},
		},
	}), "external RuleData status changes must still enqueue RuleSets")
}

func TestRuleSetReconcilerDoesNotBypassInvalidSourceStatusWithPrunedRules(t *testing.T) {
	ctx := context.Background()
	namespace := setupTestNamespace(t, ctx)
	source := utils.NewTestRuleSource("invalid-pruned-source", namespace,
		`SecRule REMOTE_ADDR "@rbl sbl.spamhaus.org" "id:1,phase:1,deny"`)
	require.NoError(t, k8sClient.Create(ctx, source))
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, source) })
	_, err := (&RuleSourceReconciler{Client: k8sClient, APIReader: k8sClient, Recorder: utils.NewTestRecorder()}).
		Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(source)})
	require.NoError(t, err)

	ruleSet := utils.NewTestRuleSet(utils.RuleSetOptions{
		Name:      "invalid-pruned-ruleset",
		Namespace: namespace,
		Sources:   []wafv1alpha1.SourceReference{{Name: source.Name}},
	})
	require.NoError(t, k8sClient.Create(ctx, ruleSet))
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, ruleSet) })

	reconciler := &RuleSetReconciler{
		Client: &ruleSetInputTestClient{
			Client:              k8sClient,
			stripRuleSourceSpec: true,
		},
		APIReader: k8sClient,
		Scheme:    scheme,
		Recorder:  utils.NewTestRecorder(),
	}
	_, err = reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(ruleSet)})
	require.NoError(t, err)
	var currentRuleSet wafv1alpha1.RuleSet
	require.NoError(t, k8sClient.Get(ctx, client.ObjectKeyFromObject(ruleSet), &currentRuleSet))
	require.Nil(t, currentRuleSet.Status.AcceptedContent)
	require.True(t, isConditionCurrent(currentRuleSet.Status.Conditions, conditionDegraded, "ReferencedRuleSourceInvalid", currentRuleSet.Generation))
}

func TestPublicationReconcilerRetainsSnapshotOnCachedLiveInputMismatch(t *testing.T) {
	fixture := newEngineNoopFixture(t, false)
	request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(fixture.engine)}
	publication := newPublicationReconciler(t)
	publication.inputCache = newRuleSetInputCache()
	_, err := publication.Reconcile(fixture.ctx, request)
	require.NoError(t, err)
	before, found := publication.Store.Get(request.NamespacedName.String())
	require.True(t, found)

	var staleSource wafv1alpha1.RuleSource
	require.NoError(t, k8sClient.Get(fixture.ctx, client.ObjectKeyFromObject(fixture.source), &staleSource))
	var updated wafv1alpha1.RuleSource
	require.NoError(t, k8sClient.Get(fixture.ctx, client.ObjectKeyFromObject(fixture.source), &updated))
	originalRules := updated.Spec.Rules
	updated.Spec.Rules += "\nSecRule ARGS \"@contains temporary\" \"id:3,phase:2,deny\""
	require.NoError(t, k8sClient.Update(fixture.ctx, &updated))
	require.NoError(t, k8sClient.Get(fixture.ctx, client.ObjectKeyFromObject(&updated), &updated))
	updated.Spec.Rules = originalRules
	require.NoError(t, k8sClient.Update(fixture.ctx, &updated))
	require.Greater(t, updated.Generation, staleSource.Generation)

	publication.clearState(request.NamespacedName)
	apiCounts := &apiReaderOperationCounts{}
	publication.APIReader = &countedAPIReader{Reader: k8sClient, counts: apiCounts}
	skewed := &skewedRuleSourceClient{
		Client:      k8sClient,
		sourceKey:   client.ObjectKeyFromObject(&staleSource),
		staleSource: staleSource.DeepCopy(),
	}
	publication.Client = skewed
	result, err := publication.Reconcile(fixture.ctx, request)
	require.NoError(t, err)
	require.Equal(t, ruleInputConsistencyRetry, result.RequeueAfter)
	require.Equal(t, 2, skewed.sourceGets, "a cache hit still performs the final informer-state race check")
	apiSourceGets, apiDataGets := apiCounts.inputGets()
	require.Zero(t, apiSourceGets, "a cache hit does not reread payloads before the final informer-state check")
	require.Zero(t, apiDataGets)

	after, found := publication.Store.Get(request.NamespacedName.String())
	require.True(t, found)
	require.Equal(t, before.Version, after.Version, "an inconsistent live read must not replace the accepted snapshot")
	state := publication.states[request.NamespacedName]
	require.NotNil(t, state)
	require.False(t, state.mismatchSince.IsZero())
}

func TestPublicationReconcilerDirectInputReadErrorsRemainTransient(t *testing.T) {
	fixture := newEngineNoopFixture(t, false)
	request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(fixture.engine)}
	publication := newPublicationReconciler(t)
	publication.inputCache = newRuleSetInputCache()
	publication.APIReader = &failingRuleInputReader{
		Reader:  k8sClient,
		dataErr: errors.New("injected direct RuleData failure"),
	}

	_, err := publication.Reconcile(fixture.ctx, request)
	require.ErrorContains(t, err, "injected direct RuleData failure")
	_, found := publication.Store.Get(request.NamespacedName.String())
	require.False(t, found, "a failed full-content read must not create a snapshot")
	require.Empty(t, publication.states, "a failed cold read must not create coalescing state")
}

func TestPublicationReconcilerSharesVerifiedInputsAcrossEngines(t *testing.T) {
	fixture := newEngineNoopFixture(t, false)
	publication := newPublicationReconciler(t)
	apiCounts := &apiReaderOperationCounts{}
	publication.APIReader = &countedAPIReader{Reader: k8sClient, counts: apiCounts}
	publication.inputCache = newRuleSetInputCache()

	firstRequest := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(fixture.engine)}
	_, err := publication.Reconcile(fixture.ctx, firstRequest)
	require.NoError(t, err)
	sourceGets, dataGets := apiCounts.inputGets()
	require.EqualValues(t, 1, sourceGets)
	require.EqualValues(t, 1, dataGets)

	inputs, err := loadRuleSetInputs(fixture.ctx, k8sClient, fixture.ruleSet)
	require.NoError(t, err)
	content, err := assemble.Assemble(inputs)
	require.NoError(t, err)
	secondEngine := createPublicationEngine(
		t,
		fixture.ctx,
		fixture.engine.Namespace,
		"noop-engine-shared",
		fixture.ruleSet.Name,
		fixture.gateway.Name,
	)
	accepted := acceptedConfigurationFor(t, secondEngine, fixture.ruleSet, content, nil)
	writeAcceptedConfiguration(t, fixture.ctx, secondEngine, accepted)

	secondRequest := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(secondEngine)}
	_, err = publication.Reconcile(fixture.ctx, secondRequest)
	require.NoError(t, err)
	sourceGets, dataGets = apiCounts.inputGets()
	require.EqualValues(t, 1, sourceGets, "the second Engine must reuse its replica's verified RuleSet inputs")
	require.EqualValues(t, 1, dataGets)
	snapshot, found := publication.Store.Get(secondRequest.NamespacedName.String())
	require.True(t, found)
	require.Equal(t, secondEngine.UID, snapshot.EngineUID)
	require.Equal(t, accepted.Version, snapshot.Version)
}

func TestSharedRuleSetInputCacheDoesNotStoreAcrossInformerLag(t *testing.T) {
	ctx := context.Background()
	namespace := setupTestNamespace(t, ctx)
	source := utils.NewTestRuleSource("lagging-source", namespace, testAcceptRuleText)
	require.NoError(t, k8sClient.Create(ctx, source))
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, source) })
	_, err := (&RuleSourceReconciler{Client: k8sClient, APIReader: k8sClient, Recorder: utils.NewTestRecorder()}).
		Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(source)})
	require.NoError(t, err)
	var staleSource wafv1alpha1.RuleSource
	require.NoError(t, k8sClient.Get(ctx, client.ObjectKeyFromObject(source), &staleSource))

	var updated wafv1alpha1.RuleSource
	require.NoError(t, k8sClient.Get(ctx, client.ObjectKeyFromObject(source), &updated))
	updated.Spec.Rules += "\nSecRule ARGS \"@contains concurrent-update\" \"id:99,phase:2,deny\""
	require.NoError(t, k8sClient.Update(ctx, &updated))

	ruleSet := utils.NewTestRuleSet(utils.RuleSetOptions{
		Name:      "cache-lag",
		Namespace: namespace,
		Sources:   []wafv1alpha1.SourceReference{{Name: source.Name}},
	})
	require.NoError(t, k8sClient.Create(ctx, ruleSet))
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, ruleSet) })
	var storedRuleSet wafv1alpha1.RuleSet
	require.NoError(t, k8sClient.Get(ctx, client.ObjectKeyFromObject(ruleSet), &storedRuleSet))

	staleCache := &staleRuleSourceCacheClient{
		Client:      k8sClient,
		sourceKey:   client.ObjectKeyFromObject(source),
		staleSource: staleSource.DeepCopy(),
	}
	cachedView, err := loadRuleSetInputView(ctx, staleCache, &storedRuleSet, false)
	require.NoError(t, err)
	cache := newRuleSetInputCache()
	_, cacheHit, err := loadConsistentRuleSetInputView(
		ctx,
		k8sClient,
		&storedRuleSet,
		cachedView,
		cacheTestAcceptedHash,
		cache,
	)
	require.ErrorIs(t, err, errRuleSetInputsChanged)
	require.False(t, cacheHit)
	entries, retainedBytes, _ := cache.stats()
	require.Zero(t, entries, "mismatched cached/live identities must never seed reusable payload")
	require.Zero(t, retainedBytes)
}

func TestPublicationReconcilerRequeuesOnRuleSetAcceptanceSkew(t *testing.T) {
	fixture := newEngineNoopFixture(t, false)
	request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(fixture.engine)}
	publication := newPublicationReconciler(t)
	publication.inputCache = newRuleSetInputCache()
	_, err := publication.Reconcile(fixture.ctx, request)
	require.NoError(t, err)
	before, found := publication.Store.Get(request.NamespacedName.String())
	require.True(t, found)

	var staleRuleSet wafv1alpha1.RuleSet
	require.NoError(t, k8sClient.Get(fixture.ctx, client.ObjectKeyFromObject(fixture.ruleSet), &staleRuleSet))
	var liveRuleSet wafv1alpha1.RuleSet
	require.NoError(t, k8sClient.Get(fixture.ctx, client.ObjectKeyFromObject(fixture.ruleSet), &liveRuleSet))
	require.NotNil(t, liveRuleSet.Status.AcceptedContent)
	liveRuleSet.Status.AcceptedContent.ObservedGeneration = liveRuleSet.Generation + 1
	require.NoError(t, k8sClient.Status().Update(fixture.ctx, &liveRuleSet))

	publication.clearState(request.NamespacedName)
	apiCounts := &apiReaderOperationCounts{}
	publication.APIReader = &countedAPIReader{Reader: k8sClient, counts: apiCounts}
	publication.Client = &staleRuleSetCacheClient{
		Client:       k8sClient,
		ruleSetKey:   client.ObjectKeyFromObject(fixture.ruleSet),
		staleRuleSet: staleRuleSet,
	}
	result, err := publication.Reconcile(fixture.ctx, request)
	require.NoError(t, err)
	require.Equal(t, ruleInputConsistencyRetry, result.RequeueAfter)
	apiSourceGets, apiDataGets := apiCounts.inputGets()
	require.Zero(t, apiSourceGets, "RuleSet acceptance skew is detected before full input reads")
	require.Zero(t, apiDataGets)

	after, found := publication.Store.Get(request.NamespacedName.String())
	require.True(t, found)
	require.Equal(t, before.Version, after.Version, "a stale RuleSet status must keep the accepted snapshot")
}

func TestEngineReconcilerRejectsOlderLiveInputView(t *testing.T) {
	fixture := newEngineNoopFixture(t, false)
	fixture.reconciler.inputCache = newRuleSetInputCache()
	request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(fixture.engine)}
	var before wafv1alpha1.Engine
	require.NoError(t, k8sClient.Get(fixture.ctx, request.NamespacedName, &before))
	filterBefore := requireEnvoyFilterExists(t, fixture.ctx, fixture.engine.Name, fixture.engine.Namespace)

	var stale wafv1alpha1.RuleSource
	require.NoError(t, k8sClient.Get(fixture.ctx, client.ObjectKeyFromObject(fixture.source), &stale))
	var current wafv1alpha1.RuleSource
	require.NoError(t, k8sClient.Get(fixture.ctx, client.ObjectKeyFromObject(fixture.source), &current))
	current.Spec.Rules += "\nSecRule ARGS \"@contains newer-cache\" \"id:7,phase:2,deny\""
	require.NoError(t, k8sClient.Update(fixture.ctx, &current))

	fixture.reconciler.APIReader = &staleRuleSourceAPIReader{
		Reader:      k8sClient,
		sourceKey:   client.ObjectKeyFromObject(&stale),
		staleSource: stale,
	}
	result, err := fixture.reconciler.Reconcile(fixture.ctx, request)
	require.NoError(t, err)
	require.Equal(t, ruleInputConsistencyRetry, result.RequeueAfter)

	var after wafv1alpha1.Engine
	require.NoError(t, k8sClient.Get(fixture.ctx, request.NamespacedName, &after))
	require.Equal(t, before.Status.AcceptedConfiguration, after.Status.AcceptedConfiguration)
	filterAfter := requireEnvoyFilterExists(t, fixture.ctx, fixture.engine.Name, fixture.engine.Namespace)
	require.Equal(t,
		filterBefore.GetAnnotations()["waf.k8s.coraza.io/configuration-version"],
		filterAfter.GetAnnotations()["waf.k8s.coraza.io/configuration-version"],
	)
}

func TestEngineReconcilerRechecksRuleSetAcceptanceAfterLiveContentRead(t *testing.T) {
	fixture := newEngineNoopFixture(t, false)
	fixture.reconciler.inputCache = newRuleSetInputCache()
	request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(fixture.engine)}
	var before wafv1alpha1.Engine
	require.NoError(t, k8sClient.Get(fixture.ctx, request.NamespacedName, &before))

	var staleRuleSet wafv1alpha1.RuleSet
	require.NoError(t, k8sClient.Get(fixture.ctx, client.ObjectKeyFromObject(fixture.ruleSet), &staleRuleSet))
	ruleSetKey := client.ObjectKeyFromObject(fixture.ruleSet)
	fixture.reconciler.Client = &staleRuleSetCacheClient{
		Client:       k8sClient,
		ruleSetKey:   ruleSetKey,
		staleRuleSet: staleRuleSet,
	}
	reader := &degradeRuleSetAfterSourceReadAPIReader{
		Client:     k8sClient,
		sourceKey:  client.ObjectKeyFromObject(fixture.source),
		ruleSetKey: ruleSetKey,
	}
	fixture.reconciler.APIReader = reader
	fixture.reconciler.renderCache.delete(request.NamespacedName)

	result, err := fixture.reconciler.Reconcile(fixture.ctx, request)
	require.NoError(t, err)
	require.Equal(t, ruleInputConsistencyRetry, result.RequeueAfter)
	require.True(t, reader.mutated, "the RuleSet status must change after the initial live input read")
	var after wafv1alpha1.Engine
	require.NoError(t, k8sClient.Get(fixture.ctx, request.NamespacedName, &after))
	require.Equal(t, before.Status.AcceptedConfiguration, after.Status.AcceptedConfiguration,
		"changed live RuleSet acceptance must not be accepted by a stale cache view")
}

func TestEngineReconcilerRechecksCachedIdentityAfterLiveContentRead(t *testing.T) {
	fixture := newEngineNoopFixture(t, false)
	fixture.reconciler.inputCache = newRuleSetInputCache()
	request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(fixture.engine)}
	var before wafv1alpha1.Engine
	require.NoError(t, k8sClient.Get(fixture.ctx, request.NamespacedName, &before))

	reader := &mutateRuleSourceAfterGetReader{
		Client:    k8sClient,
		sourceKey: client.ObjectKeyFromObject(fixture.source),
		newRules: fixture.source.Spec.Rules +
			"\nSecRule ARGS \"@contains changed-during-read\" \"id:8,phase:2,deny\"",
	}
	fixture.reconciler.renderCache.delete(request.NamespacedName)
	fixture.reconciler.APIReader = reader
	result, err := fixture.reconciler.Reconcile(fixture.ctx, request)
	require.NoError(t, err)
	require.Equal(t, ruleInputConsistencyRetry, result.RequeueAfter)
	require.True(t, reader.mutated)

	var after wafv1alpha1.Engine
	require.NoError(t, k8sClient.Get(fixture.ctx, request.NamespacedName, &after))
	require.Equal(t, before.Status.AcceptedConfiguration, after.Status.AcceptedConfiguration,
		"a source update during live content reads must not replace the accepted configuration")
}

type staleRuleSourceCacheClient struct {
	client.Client
	sourceKey   types.NamespacedName
	staleSource *wafv1alpha1.RuleSource
	sourceGets  int
}

type cachedGetTestClient struct {
	client.Client
	reader       client.Reader
	staleDataKey types.NamespacedName
	staleData    *wafv1alpha1.RuleData
}

func (c *cachedGetTestClient) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if c.staleData != nil && key == c.staleDataKey {
		*obj.(*wafv1alpha1.RuleData) = *c.staleData.DeepCopy()
		return nil
	}
	return c.reader.Get(ctx, key, obj, opts...)
}

type staleRuleDataCacheClient struct {
	client.Client
	dataKey   types.NamespacedName
	staleData *wafv1alpha1.RuleData
	dataGets  int
}

type staleRuleSetCacheClient struct {
	client.Client
	ruleSetKey   types.NamespacedName
	staleRuleSet wafv1alpha1.RuleSet
}

func (c *staleRuleSetCacheClient) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if key == c.ruleSetKey {
		*obj.(*wafv1alpha1.RuleSet) = *c.staleRuleSet.DeepCopy()
		return nil
	}
	return c.Client.Get(ctx, key, obj, opts...)
}

func (c *staleRuleDataCacheClient) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if key == c.dataKey {
		c.dataGets++
		if c.dataGets == 1 {
			*obj.(*wafv1alpha1.RuleData) = *c.staleData.DeepCopy()
			return nil
		}
	}
	return c.Client.Get(ctx, key, obj, opts...)
}

type staleRuleSourceAPIReader struct {
	client.Reader
	sourceKey   types.NamespacedName
	staleSource wafv1alpha1.RuleSource
}

func (r *staleRuleSourceAPIReader) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if key == r.sourceKey {
		*obj.(*wafv1alpha1.RuleSource) = *r.staleSource.DeepCopy()
		return nil
	}
	return r.Reader.Get(ctx, key, obj, opts...)
}

type mutateRuleSourceAfterGetReader struct {
	client.Client
	sourceKey types.NamespacedName
	newRules  string
	mutated   bool
}

type degradeRuleSetAfterSourceReadAPIReader struct {
	client.Client
	sourceKey  types.NamespacedName
	ruleSetKey types.NamespacedName
	mutated    bool
}

func (r *degradeRuleSetAfterSourceReadAPIReader) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if err := r.Client.Get(ctx, key, obj, opts...); err != nil {
		return err
	}
	if key != r.sourceKey || r.mutated {
		return nil
	}
	var ruleSet wafv1alpha1.RuleSet
	if err := r.Client.Get(ctx, r.ruleSetKey, &ruleSet); err != nil {
		return err
	}
	apimeta.SetStatusCondition(&ruleSet.Status.Conditions, metav1.Condition{
		Type:               conditionDegraded,
		Status:             metav1.ConditionTrue,
		ObservedGeneration: ruleSet.Generation,
		Reason:             ruleSetDegradedReasonInvalidRuleSet,
		Message:            "changed during live input read",
		LastTransitionTime: metav1.Now(),
	})
	if err := r.Client.Status().Update(ctx, &ruleSet); err != nil {
		return err
	}
	r.mutated = true
	return nil
}

func (r *mutateRuleSourceAfterGetReader) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if err := r.Client.Get(ctx, key, obj, opts...); err != nil {
		return err
	}
	if key != r.sourceKey || r.mutated {
		return nil
	}
	var source wafv1alpha1.RuleSource
	if err := r.Client.Get(ctx, key, &source); err != nil {
		return err
	}
	source.Spec.Rules = r.newRules
	if err := r.Client.Update(ctx, &source); err != nil {
		return err
	}
	r.mutated = true
	return nil
}

type failingRuleInputReader struct {
	client.Reader
	sourceErr error
	dataErr   error
}

func (r *failingRuleInputReader) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	switch obj.(type) {
	case *wafv1alpha1.RuleSource:
		if r.sourceErr != nil {
			return r.sourceErr
		}
	case *wafv1alpha1.RuleData:
		if r.dataErr != nil {
			return r.dataErr
		}
	}
	return r.Reader.Get(ctx, key, obj, opts...)
}

func (c *staleRuleSourceCacheClient) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if key == c.sourceKey {
		c.sourceGets++
		if c.sourceGets == 1 {
			*obj.(*wafv1alpha1.RuleSource) = *c.staleSource.DeepCopy()
			return nil
		}
	}
	return c.Client.Get(ctx, key, obj, opts...)
}
