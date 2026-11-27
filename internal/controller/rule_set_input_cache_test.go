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
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	wafv1alpha1 "github.com/networking-incubator/coraza-kubernetes-operator/api/v1alpha1"
	"github.com/networking-incubator/coraza-kubernetes-operator/internal/rulesets/assemble"
)

const cacheTestAcceptedHash = "sha256:accepted-content"

func TestRuleSetInputCacheReusesOnlyAnIsolatedCopy(t *testing.T) {
	ctx := context.Background()
	cache := newRuleSetInputCache()
	ruleset, fullView := ruleSetInputCacheFixture("shared")
	metadataView := ruleSetInputMetadataView(fullView)
	loads := 0
	load := func(context.Context) (ruleSetInputView, bool, error) {
		loads++
		return fullView, true, nil
	}

	first, cacheHit, err := cache.getOrLoad(ctx, ruleset, metadataView, cacheTestAcceptedHash, load)
	require.NoError(t, err)
	require.False(t, cacheHit)
	require.Equal(t, 1, loads)
	require.Equal(t, "SecRule REQUEST_URI \"@contains shared\"", first.inputs.Sources[0].Rules)

	second, cacheHit, err := cache.getOrLoad(ctx, ruleset, metadataView, cacheTestAcceptedHash, load)
	require.NoError(t, err)
	require.True(t, cacheHit)
	require.Equal(t, 1, loads)
	second.inputs.Data[0].Files["blocked.data"] = "mutated by one Engine"
	second.inputs.Sources[0].Rules = "mutated by one Engine"

	third, cacheHit, err := cache.getOrLoad(ctx, ruleset, metadataView, cacheTestAcceptedHash, load)
	require.NoError(t, err)
	require.True(t, cacheHit)
	require.Equal(t, "SecRule REQUEST_URI \"@contains shared\"", third.inputs.Sources[0].Rules)
	require.Equal(t, "blocked.example\n", third.inputs.Data[0].Files["blocked.data"])
	require.Equal(t, 1, loads)
}

func TestRuleSetInputCacheMissesAfterAcceptanceOrInputStateChanges(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*wafv1alpha1.RuleSet, *ruleSetInputView, *string)
	}{
		{
			name: "RuleSet UID on delete and recreate",
			mutate: func(ruleset *wafv1alpha1.RuleSet, view *ruleSetInputView, _ *string) {
				ruleset.UID = "replacement-ruleset"
				view.inputs.RuleSetUID = ruleset.UID
			},
		},
		{
			name: "RuleSet generation",
			mutate: func(ruleset *wafv1alpha1.RuleSet, _ *ruleSetInputView, _ *string) {
				ruleset.Generation++
			},
		},
		{
			name: "accepted content hash",
			mutate: func(ruleset *wafv1alpha1.RuleSet, _ *ruleSetInputView, expected *string) {
				*expected = "sha256:new-content"
				ruleset.Status.AcceptedContent.ContentHash = *expected
			},
		},
		{
			name: "skip unsupported annotation",
			mutate: func(ruleset *wafv1alpha1.RuleSet, _ *ruleSetInputView, _ *string) {
				ruleset.Annotations[wafv1alpha1.AnnotationSkipUnsupportedRulesCheck] = "true"
			},
		},
		{
			name: "RuleSet degraded condition",
			mutate: func(ruleset *wafv1alpha1.RuleSet, _ *ruleSetInputView, _ *string) {
				ruleset.Status.Conditions = []metav1.Condition{{
					Type:               conditionDegraded,
					Status:             metav1.ConditionTrue,
					ObservedGeneration: ruleset.Generation,
					Reason:             "InvalidRuleSet",
				}}
			},
		},
		{
			name: "RuleSource UID on recreate",
			mutate: func(_ *wafv1alpha1.RuleSet, view *ruleSetInputView, _ *string) {
				view.inputs.Sources[0].UID = "replacement-source"
				view.sources[0].UID = "replacement-source"
			},
		},
		{
			name: "RuleSource generation",
			mutate: func(_ *wafv1alpha1.RuleSet, view *ruleSetInputView, _ *string) {
				view.inputs.Sources[0].Generation++
				view.sources[0].Generation++
			},
		},
		{
			name: "RuleSource validation annotation",
			mutate: func(_ *wafv1alpha1.RuleSet, view *ruleSetInputView, _ *string) {
				view.sources[0].SkipValidation = "false"
			},
		},
		{
			name: "RuleSource Ready condition",
			mutate: func(_ *wafv1alpha1.RuleSet, view *ruleSetInputView, _ *string) {
				view.sources[0].Ready = &inputConditionState{
					Status:             metav1.ConditionFalse,
					Reason:             "ValidationSkipped",
					ObservedGeneration: view.sources[0].Generation,
				}
			},
		},
		{
			name: "RuleSource Degraded condition",
			mutate: func(_ *wafv1alpha1.RuleSet, view *ruleSetInputView, _ *string) {
				view.sources[0].Degraded = &inputConditionState{
					Status:             metav1.ConditionTrue,
					Reason:             "InvalidRules",
					ObservedGeneration: view.sources[0].Generation,
				}
			},
		},
		{
			name: "RuleData UID on recreate",
			mutate: func(_ *wafv1alpha1.RuleSet, view *ruleSetInputView, _ *string) {
				view.inputs.Data[0].UID = "replacement-data"
				view.data[0].UID = "replacement-data"
			},
		},
		{
			name: "RuleData generation",
			mutate: func(_ *wafv1alpha1.RuleSet, view *ruleSetInputView, _ *string) {
				view.inputs.Data[0].Generation++
				view.data[0].Generation++
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			cache := newRuleSetInputCache()
			ruleset, firstView := ruleSetInputCacheFixture("versioned")
			expectedHash := cacheTestAcceptedHash
			_, cacheHit, err := cache.getOrLoad(
				ctx,
				ruleset,
				ruleSetInputMetadataView(firstView),
				expectedHash,
				func(context.Context) (ruleSetInputView, bool, error) {
					return firstView, true, nil
				},
			)
			require.NoError(t, err)
			require.False(t, cacheHit)

			ruleset = ruleset.DeepCopy()
			currentView := cloneRuleSetInputView(firstView)
			test.mutate(ruleset, &currentView, &expectedHash)
			loads := 0
			_, cacheHit, err = cache.getOrLoad(
				ctx,
				ruleset,
				ruleSetInputMetadataView(currentView),
				expectedHash,
				func(context.Context) (ruleSetInputView, bool, error) {
					loads++
					return currentView, true, nil
				},
			)
			require.NoError(t, err)
			require.False(t, cacheHit, "a changed acceptance or input identity must not reuse the old payload")
			require.Equal(t, 1, loads)
		})
	}
}

func TestRuleSetInputCacheBoundsEntriesBytesAndEvictsLeastRecentlyUsed(t *testing.T) {
	ctx := context.Background()
	cache := newRuleSetInputCache()
	rulesets := make([]*wafv1alpha1.RuleSet, maxRuleSetInputCacheEntries+1)
	views := make([]ruleSetInputView, len(rulesets))
	var cacheHit bool
	var err error
	for i := 0; i < maxRuleSetInputCacheEntries; i++ {
		rulesets[i], views[i] = ruleSetInputCacheFixture(fmt.Sprintf("rules-%02d", i))
		_, cacheHit, err = cache.getOrLoad(
			ctx,
			rulesets[i],
			ruleSetInputMetadataView(views[i]),
			cacheTestAcceptedHash,
			func(context.Context) (ruleSetInputView, bool, error) {
				return views[i], true, nil
			},
		)
		require.NoError(t, err)
		require.False(t, cacheHit)
	}

	_, cacheHit, err = cache.getOrLoad(
		ctx,
		rulesets[0],
		ruleSetInputMetadataView(views[0]),
		cacheTestAcceptedHash,
		func(context.Context) (ruleSetInputView, bool, error) {
			t.Fatal("the first entry should still be cached")
			return ruleSetInputView{}, false, nil
		},
	)
	require.NoError(t, err)
	require.True(t, cacheHit)

	rulesets[maxRuleSetInputCacheEntries], views[maxRuleSetInputCacheEntries] =
		ruleSetInputCacheFixture(fmt.Sprintf("rules-%02d", maxRuleSetInputCacheEntries))
	_, cacheHit, err = cache.getOrLoad(
		ctx,
		rulesets[maxRuleSetInputCacheEntries],
		ruleSetInputMetadataView(views[maxRuleSetInputCacheEntries]),
		cacheTestAcceptedHash,
		func(context.Context) (ruleSetInputView, bool, error) {
			return views[maxRuleSetInputCacheEntries], true, nil
		},
	)
	require.NoError(t, err)
	require.False(t, cacheHit)

	entries, retainedBytes, evictions := cache.stats()
	require.Equal(t, maxRuleSetInputCacheEntries, entries)
	require.LessOrEqual(t, retainedBytes, int64(maxRuleSetInputCacheBytes))
	require.EqualValues(t, 1, evictions)

	_, cacheHit, err = cache.getOrLoad(
		ctx,
		rulesets[0],
		ruleSetInputMetadataView(views[0]),
		cacheTestAcceptedHash,
		func(context.Context) (ruleSetInputView, bool, error) {
			t.Fatal("the most recently used entry should remain")
			return ruleSetInputView{}, false, nil
		},
	)
	require.NoError(t, err)
	require.True(t, cacheHit)

	_, cacheHit, err = cache.getOrLoad(
		ctx,
		rulesets[1],
		ruleSetInputMetadataView(views[1]),
		cacheTestAcceptedHash,
		func(context.Context) (ruleSetInputView, bool, error) {
			return views[1], true, nil
		},
	)
	require.NoError(t, err)
	require.False(t, cacheHit, "the least recently used entry should have been evicted")

	largeCache := newRuleSetInputCache()
	largeRuleSet, largeView := ruleSetInputCacheFixture("too-large")
	largeView.inputs.Sources[0].Rules = strings.Repeat("x", maxRuleSetInputCacheBytes)
	_, cacheHit, err = largeCache.getOrLoad(
		ctx,
		largeRuleSet,
		ruleSetInputMetadataView(largeView),
		cacheTestAcceptedHash,
		func(context.Context) (ruleSetInputView, bool, error) {
			return largeView, true, nil
		},
	)
	require.NoError(t, err)
	require.False(t, cacheHit)
	entries, retainedBytes, _ = largeCache.stats()
	require.Zero(t, entries)
	require.Zero(t, retainedBytes)
}

func TestRuleSetInputCacheCoalescesAndHonorsCancellation(t *testing.T) {
	ctx := context.Background()
	cache := newRuleSetInputCache()
	ruleset, fullView := ruleSetInputCacheFixture("concurrent")
	metadataView := ruleSetInputMetadataView(fullView)
	started := make(chan struct{})
	release := make(chan struct{})
	var loadCalls atomic.Int32
	load := func(ctx context.Context) (ruleSetInputView, bool, error) {
		if loadCalls.Add(1) == 1 {
			close(started)
		}
		select {
		case <-ctx.Done():
			return ruleSetInputView{}, false, ctx.Err()
		case <-release:
			return fullView, true, nil
		}
	}

	type result struct {
		view ruleSetInputView
		hit  bool
		err  error
	}
	results := make(chan result, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			view, hit, err := cache.getOrLoad(ctx, ruleset, metadataView, cacheTestAcceptedHash, load)
			results <- result{view: view, hit: hit, err: err}
		}()
	}
	<-started
	close(release)
	wg.Wait()
	close(results)
	for result := range results {
		require.NoError(t, result.err)
		require.Equal(t, "SecRule REQUEST_URI \"@contains concurrent\"", result.view.inputs.Sources[0].Rules)
	}
	require.EqualValues(t, 1, loadCalls.Load())

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err := cache.getOrLoad(canceled, ruleset, metadataView, cacheTestAcceptedHash, load)
	require.ErrorIs(t, err, context.Canceled)
	require.EqualValues(t, 1, loadCalls.Load(), "a canceled caller must not start a load")
}

func TestRuleSetInputCacheInvalidationWinsAgainstAnActiveLoad(t *testing.T) {
	ctx := context.Background()
	cache := newRuleSetInputCache()
	ruleset, fullView := ruleSetInputCacheFixture("invalidate-during-load")
	metadataView := ruleSetInputMetadataView(fullView)
	started := make(chan struct{})
	release := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		_, _, err := cache.getOrLoad(ctx, ruleset, metadataView, cacheTestAcceptedHash,
			func(context.Context) (ruleSetInputView, bool, error) {
				close(started)
				<-release
				return fullView, true, nil
			})
		result <- err
	}()

	<-started
	cache.invalidate(types.NamespacedName{Namespace: ruleset.Namespace, Name: ruleset.Name})
	close(release)
	require.NoError(t, <-result)
	entries, retainedBytes, _ := cache.stats()
	require.Zero(t, entries, "an invalidated in-flight read must not repopulate the cache")
	require.Zero(t, retainedBytes)
}

func TestRuleSetInputCacheIgnoresNonGatingRuleDataReady(t *testing.T) {
	oldData := &wafv1alpha1.RuleData{ObjectMeta: metav1.ObjectMeta{
		Namespace: "cache-test", Name: "data", UID: "data-uid", Generation: 5,
	}}
	newData := oldData.DeepCopy()
	oldData.Status.Conditions = []metav1.Condition{{
		Type: conditionReady, Status: metav1.ConditionTrue, ObservedGeneration: oldData.Generation, Reason: "Loaded",
	}}
	newData.Status.Conditions = []metav1.Condition{{
		Type: conditionReady, Status: metav1.ConditionFalse, ObservedGeneration: newData.Generation, Reason: "ExternalStatusChange",
	}}
	require.True(t, sameRuleDataInputState(oldData, newData))
}

func ruleSetInputCacheFixture(name string) (*wafv1alpha1.RuleSet, ruleSetInputView) {
	ruleset := &wafv1alpha1.RuleSet{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:  "cache-test",
			Name:       name,
			UID:        types.UID("ruleset-" + name),
			Generation: 3,
			Annotations: map[string]string{
				wafv1alpha1.AnnotationSkipUnsupportedRulesCheck: "false",
			},
		},
		Spec: wafv1alpha1.RuleSetSpec{
			Sources: []wafv1alpha1.SourceReference{{Name: "source"}},
			Data:    []wafv1alpha1.DataReference{{Name: "data"}},
		},
		Status: wafv1alpha1.RuleSetStatus{
			AcceptedContent: &wafv1alpha1.RuleSetAcceptedContent{
				ObservedGeneration: 3,
				ContentHash:        cacheTestAcceptedHash,
			},
		},
	}
	sourceState := ruleSourceInputState{
		Name:           "source",
		UID:            "source-uid",
		Generation:     4,
		SkipValidation: "true",
		Ready: &inputConditionState{
			Status:             metav1.ConditionTrue,
			Reason:             ruleSourceReadyReasonValidated,
			ObservedGeneration: 4,
		},
	}
	dataState := ruleDataInputState{
		Name:       "data",
		UID:        "data-uid",
		Generation: 5,
	}
	view := ruleSetInputView{
		inputs: assemble.Inputs{
			RuleSetUID:       ruleset.UID,
			RuleSetName:      ruleset.Name,
			Namespace:        ruleset.Namespace,
			EmptyRulesPolicy: assemble.EmptyRulesPolicyReject,
			Sources: []assemble.SourceInput{{
				Name:       sourceState.Name,
				UID:        sourceState.UID,
				Generation: sourceState.Generation,
				Rules:      `SecRule REQUEST_URI "@contains ` + name + `"`,
			}},
			Data: []assemble.DataInput{{
				Name:       dataState.Name,
				UID:        dataState.UID,
				Generation: dataState.Generation,
				Files:      map[string]string{"blocked.data": "blocked.example\n"},
			}},
		},
		sources: []ruleSourceInputState{sourceState},
		data:    []ruleDataInputState{dataState},
	}
	return ruleset, view
}

func ruleSetInputMetadataView(full ruleSetInputView) ruleSetInputView {
	view := cloneRuleSetInputView(full)
	for i := range view.inputs.Sources {
		view.inputs.Sources[i].Rules = ""
	}
	for i := range view.inputs.Data {
		view.inputs.Data[i].Files = nil
	}
	return view
}

func cloneRuleSetInputView(view ruleSetInputView) ruleSetInputView {
	clone := view
	clone.inputs = cloneRuleSetInputs(view.inputs)
	clone.sources = append([]ruleSourceInputState(nil), view.sources...)
	clone.data = append([]ruleDataInputState(nil), view.data...)
	for i := range clone.sources {
		if view.sources[i].Ready != nil {
			ready := *view.sources[i].Ready
			clone.sources[i].Ready = &ready
		}
		if view.sources[i].Degraded != nil {
			degraded := *view.sources[i].Degraded
			clone.sources[i].Degraded = &degraded
		}
	}
	return clone
}
