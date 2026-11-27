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
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	wafv1alpha1 "github.com/networking-incubator/coraza-kubernetes-operator/api/v1alpha1"
	"github.com/networking-incubator/coraza-kubernetes-operator/internal/ecds/render"
	"github.com/networking-incubator/coraza-kubernetes-operator/internal/rulesets/assemble"
	"github.com/networking-incubator/coraza-kubernetes-operator/internal/xds"
	"github.com/networking-incubator/coraza-kubernetes-operator/test/utils"
)

// BenchmarkPublicationReconcileNoopEnvtest uses the same synthetic RuleSet as
// BenchmarkEngineReconcileNoopEnvtest and measures the replica-local publisher's
// steady-state path after its snapshot has been built. The Gateway has no Pods,
// so authorization includes its Gateway read and empty Pod list but no
// ServiceAccount reads; this isolates RuleSet reconstruction.
func BenchmarkPublicationReconcileNoopEnvtest(b *testing.B) {
	benchmarkPublicationReconcileEnvtest(b, false, false, "")
}

// BenchmarkPublicationReconcileColdEnvtest measures a local reconstruction
// miss with the Kubernetes client cache still warm. It clears the publisher's
// coalescing state and snapshot between iterations while the timer is stopped,
// so ns/op excludes fixture and reset cost and is not a process-startup measure.
func BenchmarkPublicationReconcileColdEnvtest(b *testing.B) {
	benchmarkPublicationReconcileEnvtest(b, true, false, "")
}

// BenchmarkPublicationReconcileMetadataOnlyEnvtest measures the coalescing
// path after a RuleSource annotation update. An untimed spec-stripped preflight
// verifies the publisher records no mismatch and retains its accepted snapshot;
// the timed loop checks for one cached full-object Get per input. Metadata
// writes and cache waits are untimed, but wall-time may still include residual
// GC, apiserver, or informer activity; this is not a perfectly isolated
// comparison.
func BenchmarkPublicationReconcileMetadataOnlyEnvtest(b *testing.B) {
	benchmarkPublicationReconcileEnvtest(b, false, true, "")
}

// BenchmarkPublicationReconcileInputGenerationChangeEnvtest measures a warm
// snapshot after a RuleSource or RuleData spec update. The input update and
// cache propagation are excluded; each timed reconcile takes the full mismatch
// path while retaining the accepted snapshot.
func BenchmarkPublicationReconcileInputGenerationChangeEnvtest(b *testing.B) {
	for _, kind := range []string{"RuleSource", "RuleData"} {
		b.Run(kind, func(b *testing.B) {
			benchmarkPublicationReconcileEnvtest(b, false, false, kind)
		})
	}
}

func benchmarkPublicationReconcileEnvtest(b *testing.B, cold, updateMetadata bool, inputGenerationChange string) {
	ctx := context.Background()
	namespace := "bench-pub-" + strings.ReplaceAll(uuid.NewString(), "-", "")[:18]
	gatewayName := "bench-gateway"
	engineName := "bench-engine"
	ruleSetName := "bench-rules"
	cacheReader := k8sClient.(*indexedTestClient).reader

	createBenchmarkNamespace(b, ctx, namespace)
	gateway := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: gatewayName, Namespace: namespace},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "istio",
			Listeners: []gatewayv1.Listener{{
				Name:     "http",
				Port:     gatewayv1.PortNumber(80),
				Protocol: gatewayv1.HTTPProtocolType,
			}},
		},
	}
	require.NoError(b, k8sClient.Create(ctx, gateway))

	sources := make([]wafv1alpha1.SourceReference, 30)
	for i := range sources {
		name := fmt.Sprintf("source-%02d", i)
		sources[i] = wafv1alpha1.SourceReference{Name: name}
		require.NoError(b, k8sClient.Create(ctx, utils.NewTestRuleSource(name, namespace, benchmarkRuleSource(i))))
	}
	var dataRules strings.Builder
	for i := range 7800 {
		fmt.Fprintf(&dataRules, "blocked-%05d.example\n", i)
	}
	dataValue := dataRules.String()
	data := utils.NewTestRuleData("bench-data", namespace, map[string]string{"blocked.data": dataValue})
	require.NoError(b, k8sClient.Create(ctx, data))

	ruleSet := utils.NewTestRuleSet(utils.RuleSetOptions{
		Name:      ruleSetName,
		Namespace: namespace,
		Sources:   sources,
		Data:      []wafv1alpha1.DataReference{{Name: data.Name}},
	})
	require.NoError(b, k8sClient.Create(ctx, ruleSet))
	var storedRuleSet wafv1alpha1.RuleSet
	require.NoError(b, k8sClient.Get(ctx, client.ObjectKeyFromObject(ruleSet), &storedRuleSet))
	inputs, err := loadRuleSetInputs(ctx, k8sClient, &storedRuleSet)
	require.NoError(b, err)
	content, err := assemble.Assemble(inputs)
	require.NoError(b, err)
	contentHash, err := render.RuleSetContentHash(content)
	require.NoError(b, err)
	patch := client.MergeFrom(storedRuleSet.DeepCopy())
	storedRuleSet.Status.AcceptedContent = &wafv1alpha1.RuleSetAcceptedContent{
		ObservedGeneration: storedRuleSet.Generation,
		ContentHash:        contentHash,
	}
	apimeta.SetStatusCondition(&storedRuleSet.Status.Conditions, metav1.Condition{
		Type:               conditionReady,
		Status:             metav1.ConditionTrue,
		ObservedGeneration: storedRuleSet.Generation,
		Reason:             ruleSetReadyReasonRulesAccepted,
		LastTransitionTime: metav1.Now(),
	})
	require.NoError(b, k8sClient.Status().Patch(ctx, &storedRuleSet, patch))

	engine := utils.NewTestEngine(utils.EngineOptions{
		Name:        engineName,
		Namespace:   namespace,
		RuleSetName: ruleSetName,
		GatewayName: gatewayName,
		WasmURL:     utils.DefaultTestWasmURL,
		WasmSHA256:  utils.DefaultTestWasmSHA256,
	})
	require.NoError(b, k8sClient.Create(ctx, engine))

	engineReconciler := &EngineReconciler{
		Client:            k8sClient,
		Scheme:            scheme,
		Recorder:          utils.NewTestRecorder(),
		xdsConfig:         testXDSConfig(),
		assetBaseURL:      testAssetBaseURL,
		operatorNamespace: testNamespace,
	}
	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: engine.Name, Namespace: engine.Namespace}}
	result, err := engineReconciler.Reconcile(ctx, req)
	require.NoError(b, err)
	require.NotZero(b, result.RequeueAfter, "the first reconcile adds the finalizer")
	waitForEngineFinalizer(b, cacheReader, engine)
	result, err = engineReconciler.Reconcile(ctx, req)
	require.NoError(b, err)
	require.Zero(b, result.RequeueAfter)
	waitForEngineInputsCache(b, cacheReader, engine, &storedRuleSet, sources, data, contentHash)
	waitForEngineReady(b, cacheReader, engine)

	counts := &engineClientOperationCounts{}
	measuredClient := &engineBenchmarkClient{Client: k8sClient, cache: cacheReader, counts: counts}
	apiCounts := &apiReaderOperationCounts{}
	apiReader := &countedAPIReader{Reader: k8sClient, counts: apiCounts}
	registry := prometheus.NewRegistry()
	metrics, err := xds.NewMetrics(registry)
	require.NoError(b, err)
	readiness := xds.NewPublicationReadiness()
	readiness.Initialize(nil)
	publisher := &PublicationReconciler{
		Client:    measuredClient,
		APIReader: apiReader,
		Scheme:    scheme,
		Store:     xds.NewSnapshotStore(),
		Authz:     xds.NewAuthzIndex(measuredClient, apiReader, 5*time.Minute, nil),
		Readiness: readiness,
		Metrics:   metrics,
		Limits:    xds.DefaultLimits(),
	}
	result, err = publisher.Reconcile(ctx, req)
	require.NoError(b, err)
	require.Zero(b, result.RequeueAfter)
	if inputGenerationChange != "" {
		updateBenchmarkInputSpec(b, ctx, cacheReader, namespace, inputGenerationChange)
	}
	if updateMetadata {
		snapshotBefore, found := publisher.Store.Get(req.NamespacedName.String())
		require.True(b, found)
		state := publisher.states[req.NamespacedName]
		require.NotNil(b, state)
		require.True(b, state.mismatchSince.IsZero())

		updateBenchmarkSourceMetadata(b, ctx, cacheReader, namespace, "preflight")
		publisher.Client = &ruleSetInputTestClient{
			Client:              measuredClient,
			stripRuleSourceSpec: true,
			stripRuleDataSpec:   true,
		}
		result, err = publisher.Reconcile(ctx, req)
		require.NoError(b, err)
		require.Zero(b, result.RequeueAfter)
		state = publisher.states[req.NamespacedName]
		require.NotNil(b, state)
		require.True(b, state.mismatchSince.IsZero(), "metadata-only inputs must not create a publication mismatch")
		snapshotAfter, found := publisher.Store.Get(req.NamespacedName.String())
		require.True(b, found)
		require.Equal(b, snapshotBefore, snapshotAfter, "metadata-only publication must retain its snapshot")
		publisher.Client = measuredClient
	}
	counts.reset()
	apiCounts.reset()

	b.ReportAllocs()
	b.ResetTimer()
	if cold {
		b.StopTimer()
		for range b.N {
			publisher.clearState(req.NamespacedName)
			publisher.Store.DeleteEngine(namespace, engineName)
			apiSourceGetsBefore, apiDataGetsBefore := apiCounts.inputGets()
			b.StartTimer()
			result, err = publisher.Reconcile(ctx, req)
			b.StopTimer()
			if err != nil {
				b.Fatalf("cold publication reconcile: %v", err)
			}
			if result.RequeueAfter != 0 {
				b.Fatalf("cold publication reconcile requeued after %s", result.RequeueAfter)
			}
			apiSourceGetsAfter, apiDataGetsAfter := apiCounts.inputGets()
			if got := apiSourceGetsAfter - apiSourceGetsBefore; got != int64(len(sources)) {
				b.Fatalf("cold publication performed %d direct RuleSource Gets; want %d", got, len(sources))
			}
			if got := apiDataGetsAfter - apiDataGetsBefore; got != int64(len(ruleSet.Spec.Data)) {
				b.Fatalf("cold publication performed %d direct RuleData Gets; want %d", got, len(ruleSet.Spec.Data))
			}
		}
	} else {
		for i := range b.N {
			sourceGetsBefore := counts.ruleSourceGets
			dataGetsBefore := counts.ruleDataGets
			apiSourceGetsBefore, apiDataGetsBefore := apiCounts.inputGets()
			if updateMetadata {
				b.StopTimer()
				updateBenchmarkSourceMetadata(b, ctx, cacheReader, namespace, fmt.Sprint(i))
				b.StartTimer()
			}
			result, err = publisher.Reconcile(ctx, req)
			if updateMetadata {
				b.StopTimer()
			}
			if err != nil {
				b.Fatalf("no-op publication reconcile: %v", err)
			}
			if result.RequeueAfter != 0 {
				b.Fatalf("no-op publication reconcile requeued after %s", result.RequeueAfter)
			}
			if updateMetadata {
				wantSourceGets := int64(len(sources))
				wantDataGets := int64(len(ruleSet.Spec.Data))
				if got := counts.ruleSourceGets - sourceGetsBefore; got != wantSourceGets {
					b.Fatalf("metadata-only publication performed %d RuleSource Gets; want %d (one input read per object)", got, wantSourceGets)
				}
				if got := counts.ruleDataGets - dataGetsBefore; got != wantDataGets {
					b.Fatalf("metadata-only publication performed %d RuleData Gets; want %d (one input read per object)", got, wantDataGets)
				}
				apiSourceGetsAfter, apiDataGetsAfter := apiCounts.inputGets()
				if got := apiSourceGetsAfter - apiSourceGetsBefore; got != 0 {
					b.Fatalf("metadata-only publication performed %d direct RuleSource Gets; want 0", got)
				}
				if got := apiDataGetsAfter - apiDataGetsBefore; got != 0 {
					b.Fatalf("metadata-only publication performed %d direct RuleData Gets; want 0", got)
				}
			}
			if inputGenerationChange != "" {
				wantSourceGets := int64(len(sources))
				wantDataGets := int64(len(ruleSet.Spec.Data))
				if got := counts.ruleSourceGets - sourceGetsBefore; got != wantSourceGets {
					b.Fatalf("input-generation publication performed %d RuleSource Gets; want %d (one full-input read)", got, wantSourceGets)
				}
				if got := counts.ruleDataGets - dataGetsBefore; got != wantDataGets {
					b.Fatalf("input-generation publication performed %d RuleData Gets; want %d (one full-input read)", got, wantDataGets)
				}
				apiSourceGetsAfter, apiDataGetsAfter := apiCounts.inputGets()
				if got := apiSourceGetsAfter - apiSourceGetsBefore; got != int64(len(sources)) {
					b.Fatalf("input-generation publication performed %d direct RuleSource Gets; want %d", got, len(sources))
				}
				if got := apiDataGetsAfter - apiDataGetsBefore; got != int64(len(ruleSet.Spec.Data)) {
					b.Fatalf("input-generation publication performed %d direct RuleData Gets; want %d", got, len(ruleSet.Spec.Data))
				}
			}
		}
		b.StopTimer()
	}

	counts.report(b, b.N)
	apiCounts.report(b, b.N)
	b.ReportMetric(float64(len(content.Rules)), "rule_bytes")
	b.ReportMetric(float64(len(dataValue)), "data_bytes")
}

// BenchmarkPublicationColdRestartSharedRuleSetEnvtest measures per-replica cold
// reconstruction for 18 Engines sharing one large RuleSet. Each publisher starts
// with an empty local snapshot/state and its own default-QPS API client, matching
// three process replicas restarting together.
func BenchmarkPublicationColdRestartSharedRuleSetEnvtest(b *testing.B) {
	const engineCount = 18
	const replicaCount = 3

	ctx := context.Background()
	namespace := "bench-restart-" + strings.ReplaceAll(uuid.NewString(), "-", "")[:16]
	gatewayName := "bench-gateway"
	cacheReader := k8sClient.(*indexedTestClient).reader
	createBenchmarkNamespace(b, ctx, namespace)
	gateway := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: gatewayName, Namespace: namespace},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "istio",
			Listeners: []gatewayv1.Listener{{
				Name: "http", Port: gatewayv1.PortNumber(80), Protocol: gatewayv1.HTTPProtocolType,
			}},
		},
	}
	require.NoError(b, k8sClient.Create(ctx, gateway))

	sources := make([]wafv1alpha1.SourceReference, 30)
	for i := range sources {
		name := fmt.Sprintf("source-%02d", i)
		sources[i] = wafv1alpha1.SourceReference{Name: name}
		require.NoError(b, k8sClient.Create(ctx, utils.NewTestRuleSource(name, namespace, benchmarkRuleSource(i))))
	}
	var dataRules strings.Builder
	for i := range 7800 {
		fmt.Fprintf(&dataRules, "blocked-%05d.example\n", i)
	}
	data := utils.NewTestRuleData("bench-data", namespace, map[string]string{"blocked.data": dataRules.String()})
	require.NoError(b, k8sClient.Create(ctx, data))
	ruleSet := utils.NewTestRuleSet(utils.RuleSetOptions{
		Name:      "bench-rules",
		Namespace: namespace,
		Sources:   sources,
		Data:      []wafv1alpha1.DataReference{{Name: data.Name}},
	})
	require.NoError(b, k8sClient.Create(ctx, ruleSet))
	var storedRuleSet wafv1alpha1.RuleSet
	require.NoError(b, k8sClient.Get(ctx, client.ObjectKeyFromObject(ruleSet), &storedRuleSet))
	inputs, err := loadRuleSetInputs(ctx, k8sClient, &storedRuleSet)
	require.NoError(b, err)
	content, err := assemble.Assemble(inputs)
	require.NoError(b, err)
	contentHash, err := render.RuleSetContentHash(content)
	require.NoError(b, err)

	engines := make([]*wafv1alpha1.Engine, engineCount)
	accepted := make([]*wafv1alpha1.EngineAcceptedConfiguration, engineCount)
	for i := range engines {
		engines[i] = createPublicationEngine(
			b,
			ctx,
			namespace,
			fmt.Sprintf("bench-engine-%02d", i),
			ruleSet.Name,
			gatewayName,
		)
		accepted[i] = acceptedConfigurationFor(b, engines[i], &storedRuleSet, content, nil)
		writeAcceptedConfiguration(b, ctx, engines[i], accepted[i])
		waitForCachedObject(b, cacheReader, client.ObjectKeyFromObject(engines[i]), &wafv1alpha1.Engine{}, func(obj client.Object) bool {
			current := obj.(*wafv1alpha1.Engine)
			return current.Status != nil && current.Status.AcceptedConfiguration != nil
		})
	}
	for _, source := range sources {
		waitForCachedObject(b, cacheReader, client.ObjectKey{Namespace: namespace, Name: source.Name}, &wafv1alpha1.RuleSource{})
	}
	waitForCachedObject(b, cacheReader, client.ObjectKeyFromObject(data), &wafv1alpha1.RuleData{})
	waitForCachedObject(b, cacheReader, client.ObjectKeyFromObject(ruleSet), &wafv1alpha1.RuleSet{})

	publishers := make([]*PublicationReconciler, replicaCount)
	apiCounts := make([]*apiReaderOperationCounts, replicaCount)
	for replica := range publishers {
		operations := &engineClientOperationCounts{}
		apiCounts[replica] = &apiReaderOperationCounts{}
		measuredClient := &engineBenchmarkClient{Client: k8sClient, cache: cacheReader, counts: operations}
		apiConfig := rest.CopyConfig(cfg)
		apiConfig.QPS = rest.DefaultQPS
		apiConfig.Burst = rest.DefaultBurst
		directClient, err := client.New(apiConfig, client.Options{Scheme: scheme})
		require.NoError(b, err)
		apiReader := &countedAPIReader{Reader: directClient, counts: apiCounts[replica]}
		registry := prometheus.NewRegistry()
		metrics, err := xds.NewMetrics(registry)
		require.NoError(b, err)
		readiness := xds.NewPublicationReadiness()
		readiness.Initialize(engines)
		publishers[replica] = &PublicationReconciler{
			Client:     measuredClient,
			APIReader:  apiReader,
			Scheme:     scheme,
			Store:      xds.NewSnapshotStore(),
			Authz:      xds.NewAuthzIndex(measuredClient, apiReader, 5*time.Minute, nil),
			Readiness:  readiness,
			Metrics:    metrics,
			Limits:     xds.DefaultLimits(),
			inputCache: newRuleSetInputCache(),
		}
	}

	b.ReportAllocs()
	b.ResetTimer()
	var coldElapsed time.Duration
	replicaElapsed := make([]time.Duration, replicaCount)
	for range b.N {
		b.StopTimer()
		for _, publisher := range publishers {
			publisher.inputCache.clear()
			for _, engine := range engines {
				publisher.clearState(client.ObjectKeyFromObject(engine))
				publisher.Store.DeleteEngine(namespace, engine.Name)
			}
		}
		b.StartTimer()
		coldStart := time.Now()
		errs := make(chan error, replicaCount)
		var wg sync.WaitGroup
		for replica, publisher := range publishers {
			wg.Add(1)
			go func(replica int, publisher *PublicationReconciler) {
				defer wg.Done()
				sourceGetsBefore, dataGetsBefore := apiCounts[replica].inputGets()
				replicaStart := time.Now()
				for i, engine := range engines {
					req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(engine)}
					result, err := publisher.Reconcile(ctx, req)
					if err != nil {
						errs <- fmt.Errorf("replica %d reconcile %s: %w", replica, req.NamespacedName, err)
						return
					}
					if result.RequeueAfter != 0 {
						errs <- fmt.Errorf("replica %d reconcile %s requeued after %s", replica, req.NamespacedName, result.RequeueAfter)
						return
					}
					snapshot, ok := publisher.Store.Get(req.NamespacedName.String())
					if !ok {
						errs <- fmt.Errorf("replica %d has no snapshot for %s", replica, req.NamespacedName)
						return
					}
					if snapshot.EngineUID != engine.UID || snapshot.Version != accepted[i].Version || snapshot.RuleSetHash != contentHash {
						errs <- fmt.Errorf("replica %d snapshot mismatch for %s", replica, req.NamespacedName)
						return
					}
				}
				if err := publisher.Readiness.Check(); err != nil {
					errs <- fmt.Errorf("replica %d readiness: %w", replica, err)
					return
				}
				replicaElapsed[replica] += time.Since(replicaStart)
				sourceGetsAfter, dataGetsAfter := apiCounts[replica].inputGets()
				if got := sourceGetsAfter - sourceGetsBefore; got != int64(len(sources)) {
					errs <- fmt.Errorf("replica %d performed %d RuleSource Gets; want %d", replica, got, len(sources))
					return
				}
				if got := dataGetsAfter - dataGetsBefore; got != int64(len(ruleSet.Spec.Data)) {
					errs <- fmt.Errorf("replica %d performed %d RuleData Gets; want %d", replica, got, len(ruleSet.Spec.Data))
					return
				}
			}(replica, publisher)
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			require.NoError(b, err)
		}
		coldElapsed += time.Since(coldStart)
		b.StopTimer()
	}

	var totalSourceGets, totalDataGets int64
	var totalInputGetTime time.Duration
	var totalCacheEntries int
	var totalCacheBytes int64
	var totalCacheEvictions uint64
	for _, counts := range apiCounts {
		counts.mu.Lock()
		totalSourceGets += counts.ruleSourceGets
		totalDataGets += counts.ruleDataGets
		totalInputGetTime += counts.ruleSourceGetTime + counts.ruleDataGetTime
		counts.mu.Unlock()
	}
	for _, publisher := range publishers {
		entries, retainedBytes, evictions := publisher.inputCache.stats()
		totalCacheEntries += entries
		totalCacheBytes += retainedBytes
		totalCacheEvictions += evictions
	}
	b.ReportMetric(float64(totalSourceGets)/float64(b.N), "api_rule_source_gets/cold")
	b.ReportMetric(float64(totalDataGets)/float64(b.N), "api_rule_data_gets/cold")
	b.ReportMetric(float64(totalSourceGets+totalDataGets)/float64(b.N), "api_input_gets/cold")
	b.ReportMetric(float64(totalSourceGets)/float64(replicaCount*b.N), "api_rule_source_gets/replica")
	b.ReportMetric(float64(totalDataGets)/float64(replicaCount*b.N), "api_rule_data_gets/replica")
	b.ReportMetric(float64(totalSourceGets+totalDataGets)/float64(replicaCount*b.N), "api_input_gets/replica")
	b.ReportMetric(float64(totalInputGetTime.Nanoseconds())/float64(b.N), "api_input_get_ns/cold")
	b.ReportMetric(float64(coldElapsed.Nanoseconds())/float64(b.N), "cold_elapsed_ns")
	for replica, elapsed := range replicaElapsed {
		b.ReportMetric(float64(elapsed.Nanoseconds())/float64(b.N), fmt.Sprintf("replica_%d_elapsed_ns", replica))
	}
	if totalSourceGets+totalDataGets > 0 {
		b.ReportMetric(
			float64(totalInputGetTime.Nanoseconds())/float64(totalSourceGets+totalDataGets),
			"api_input_get_ns/get",
		)
	}
	b.ReportMetric(float64(engineCount), "engines")
	b.ReportMetric(float64(replicaCount), "replicas")
	b.ReportMetric(float64(len(sources)), "shared_rule_sources")
	b.ReportMetric(float64(len(data.Spec.Files)), "shared_rule_data_objects")
	b.ReportMetric(float64(totalCacheEntries)/float64(replicaCount), "input_cache_entries/replica")
	b.ReportMetric(float64(totalCacheBytes)/float64(replicaCount), "input_cache_bytes/replica")
	b.ReportMetric(float64(totalCacheEvictions), "input_cache_evictions/cold")
	b.ReportMetric(float64(rest.DefaultQPS), "default_client_qps")
	b.ReportMetric(float64(rest.DefaultBurst), "default_client_burst")
}
