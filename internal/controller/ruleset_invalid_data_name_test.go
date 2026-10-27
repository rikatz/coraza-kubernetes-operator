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
	"testing"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	wafv1alpha1 "github.com/networking-incubator/coraza-kubernetes-operator/api/v1alpha1"
	"github.com/networking-incubator/coraza-kubernetes-operator/test/utils"
)

// TestReservedDataFileNameBlocksAcceptance covers RuleData objects created
// before the CEL rule rejected ".", which CEL cannot guard on read.
func TestReservedDataFileNameBlocksAcceptance(t *testing.T) {
	ctx := context.Background()

	data := utils.NewTestRuleData("legacy-data", testNamespace, map[string]string{".": "evildata\n"})
	source := utils.NewTestRuleSource("legacy-source", testNamespace, `SecRule ARGS "@pmFromFile ." "id:1,phase:1,pass,nolog"`)
	apimeta.SetStatusCondition(&source.Status.Conditions, metav1.Condition{
		Type:               conditionReady,
		Status:             metav1.ConditionTrue,
		ObservedGeneration: source.Generation,
		Reason:             ruleSourceReadyReasonValidated,
		LastTransitionTime: metav1.Now(),
	})
	ruleset := utils.NewTestRuleSet(utils.RuleSetOptions{
		Name:      "legacy-ruleset",
		Namespace: testNamespace,
		Sources:   []wafv1alpha1.SourceReference{{Name: source.Name}},
		Data:      []wafv1alpha1.DataReference{{Name: data.Name}},
	})

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&wafv1alpha1.RuleSet{}, &wafv1alpha1.RuleData{}, &wafv1alpha1.Engine{}).
		WithObjects(ruleset, source, data).
		Build()

	metrics, err := NewCorazaMetrics(prometheus.NewRegistry())
	require.NoError(t, err)
	ruleSetReconciler := &RuleSetReconciler{
		Client:   c,
		Scheme:   scheme,
		Recorder: utils.NewTestRecorder(),
		Metrics:  metrics,
	}

	rulesetReq := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(ruleset)}
	_, err = ruleSetReconciler.Reconcile(ctx, rulesetReq)
	require.NoError(t, err)

	var updatedRuleSet wafv1alpha1.RuleSet
	require.NoError(t, c.Get(ctx, rulesetReq.NamespacedName, &updatedRuleSet))
	require.Nil(t, updatedRuleSet.Status.AcceptedContent, "invalid data file names must not be accepted")
	degraded := apimeta.FindStatusCondition(updatedRuleSet.Status.Conditions, conditionDegraded)
	require.NotNil(t, degraded)
	assert.Equal(t, metav1.ConditionTrue, degraded.Status)
	assert.Equal(t, ruleSetDegradedReasonInvalidRuleSet, degraded.Reason)
	assert.Contains(t, degraded.Message, `"."`)
	assert.Contains(t, degraded.Message, "RuleData legacy-data")

	engine := utils.NewTestEngine(utils.EngineOptions{
		Name:        "legacy-engine",
		Namespace:   testNamespace,
		GatewayName: "legacy-gw",
		RuleSetName: ruleset.Name,
		WasmURL:     utils.DefaultTestWasmURL,
		WasmSHA256:  utils.DefaultTestWasmSHA256,
	})
	require.NoError(t, c.Create(ctx, engine))

	engineReconciler := &EngineReconciler{
		Client:       c,
		Scheme:       scheme,
		Recorder:     utils.NewTestRecorder(),
		assetBaseURL: testAssetBaseURL,
		xdsConfig:    testXDSConfig(),
	}
	engineReq := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(engine)}
	_, err = engineReconciler.provisionWasmDriver(ctx, logr.Discard(), engineReq, engine)
	require.NoError(t, err)

	var updatedEngine wafv1alpha1.Engine
	require.NoError(t, c.Get(ctx, engineReq.NamespacedName, &updatedEngine))
	assert.Nil(t, updatedEngine.Status.AcceptedConfiguration, "the Engine must not accept a degraded RuleSet")
	progressing := apimeta.FindStatusCondition(updatedEngine.Status.Conditions, conditionProgressing)
	require.NotNil(t, progressing)
	assert.Equal(t, reasonAwaitingRuleSetAcceptance, progressing.Reason)
}

// TestHostWritingDirectiveInIncludedRuleDataBlocksAcceptance covers an Include
// of a RuleData file whose content is parsed as rule text: the aggregate
// validation must reject a host-writing directive hidden there.
func TestHostWritingDirectiveInIncludedRuleDataBlocksAcceptance(t *testing.T) {
	ctx := context.Background()

	const marker = "included-data-marker-83cf"
	data := utils.NewTestRuleData("debug-data", testNamespace, map[string]string{
		"bad.data": "SecDebugLog /dev/shm/" + marker + ".log\n",
	})
	source := utils.NewTestRuleSource("debug-source", testNamespace, "Include bad.data")
	apimeta.SetStatusCondition(&source.Status.Conditions, metav1.Condition{
		Type:               conditionReady,
		Status:             metav1.ConditionTrue,
		ObservedGeneration: source.Generation,
		Reason:             ruleSourceReadyReasonValidated,
		LastTransitionTime: metav1.Now(),
	})
	ruleset := utils.NewTestRuleSet(utils.RuleSetOptions{
		Name:      "debug-ruleset",
		Namespace: testNamespace,
		Sources:   []wafv1alpha1.SourceReference{{Name: source.Name}},
		Data:      []wafv1alpha1.DataReference{{Name: data.Name}},
	})

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&wafv1alpha1.RuleSet{}, &wafv1alpha1.RuleData{}, &wafv1alpha1.Engine{}).
		WithObjects(ruleset, source, data).
		Build()

	metrics, err := NewCorazaMetrics(prometheus.NewRegistry())
	require.NoError(t, err)
	ruleSetReconciler := &RuleSetReconciler{
		Client:   c,
		Scheme:   scheme,
		Recorder: utils.NewTestRecorder(),
		Metrics:  metrics,
	}

	req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(ruleset)}
	_, err = ruleSetReconciler.Reconcile(ctx, req)
	require.NoError(t, err)

	var updated wafv1alpha1.RuleSet
	require.NoError(t, c.Get(ctx, req.NamespacedName, &updated))
	require.Nil(t, updated.Status.AcceptedContent, "rules that write host files must not be accepted")
	degraded := apimeta.FindStatusCondition(updated.Status.Conditions, conditionDegraded)
	require.NotNil(t, degraded)
	assert.Equal(t, ruleSetDegradedReasonInvalidRuleSet, degraded.Reason)
	assert.Contains(t, degraded.Message, "SecDebugLog")
	assert.NotContains(t, degraded.Message, marker)
}
