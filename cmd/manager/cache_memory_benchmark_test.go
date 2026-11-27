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

package main

import (
	"context"
	"fmt"
	goruntime "runtime"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	ctrlcache "sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	wafv1alpha1 "github.com/networking-incubator/coraza-kubernetes-operator/api/v1alpha1"
)

// BenchmarkRuleInputInformerRetainedHeap measures live Go heap retained by
// actual typed informers for a RuleSet with referenced and unreferenced inputs.
// Run with -benchtime=1x: setup is deliberately outside the timed interval and
// each sub-benchmark reports one post-GC retained-heap snapshot.
func BenchmarkRuleInputInformerRetainedHeap(b *testing.B) {
	b.StopTimer()
	testScheme := k8sruntime.NewScheme()
	if err := corev1.AddToScheme(testScheme); err != nil {
		b.Fatal(err)
	}
	if err := networkingv1.AddToScheme(testScheme); err != nil {
		b.Fatal(err)
	}
	if err := wafv1alpha1.AddToScheme(testScheme); err != nil {
		b.Fatal(err)
	}

	env := &envtest.Environment{
		CRDInstallOptions: envtest.CRDInstallOptions{
			Paths:           []string{"../../config/crd/bases"},
			CleanUpAfterUse: true,
		},
		Scheme:               testScheme,
		DownloadBinaryAssets: true,
	}
	cfg, err := env.Start()
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() {
		if err := env.Stop(); err != nil {
			b.Errorf("stop envtest: %v", err)
		}
	})

	apiClient, err := client.New(cfg, client.Options{Scheme: testScheme})
	if err != nil {
		b.Fatal(err)
	}
	namespace := "cache-memory"
	if err := apiClient.Create(context.Background(), &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: namespace},
	}); err != nil {
		b.Fatal(err)
	}

	referencedBytes, unreferencedBytes, sourceRefs := createRuleInputMemoryFixture(b, apiClient, namespace)
	goruntime.GC()
	b.Run("baseline", func(b *testing.B) {
		heap := measureRuleInputCacheHeap(b, cfg, testScheme, apiClient, baselineRuleInputCacheOptions(), false)
		b.ReportMetric(float64(heap), "retained_heap_bytes")
		b.ReportMetric(float64(referencedBytes), "referenced_input_bytes")
		b.ReportMetric(float64(unreferencedBytes), "unreferenced_input_bytes")
		b.ReportMetric(float64(len(sourceRefs)), "referenced_sources")
	})
	b.Run("configured", func(b *testing.B) {
		heap := measureRuleInputCacheHeap(b, cfg, testScheme, apiClient, buildCacheOptions(namespace), true)
		b.ReportMetric(float64(heap), "retained_heap_bytes")
		b.ReportMetric(float64(referencedBytes), "referenced_input_bytes")
		b.ReportMetric(float64(unreferencedBytes), "unreferenced_input_bytes")
		b.ReportMetric(float64(len(sourceRefs)), "referenced_sources")
	})
}

// baselineRuleInputCacheOptions reproduces the RuleSource and RuleData
// transforms before their spec payloads were pruned.
func baselineRuleInputCacheOptions() ctrlcache.Options {
	return ctrlcache.Options{
		DefaultTransform: ctrlcache.TransformStripManagedFields(),
		ByObject: map[client.Object]ctrlcache.ByObject{
			&wafv1alpha1.RuleSource{}: {Transform: stripLastApplied},
			&wafv1alpha1.RuleData{}:   {Transform: stripLastApplied},
		},
	}
}

func createRuleInputMemoryFixture(
	b *testing.B,
	apiClient client.Client,
	namespace string,
) (referencedBytes, unreferencedBytes int, sourceRefs []wafv1alpha1.SourceReference) {
	b.Helper()
	sourceRefs = make([]wafv1alpha1.SourceReference, 20)
	for i := range 30 {
		name := fmt.Sprintf("source-%02d", i)
		rules := strings.Repeat("x", 24<<10)
		if i < len(sourceRefs) {
			sourceRefs[i] = wafv1alpha1.SourceReference{Name: name}
			referencedBytes += len(rules)
		} else {
			unreferencedBytes += len(rules)
		}
		source := &wafv1alpha1.RuleSource{
			ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
			Spec:       wafv1alpha1.RuleSourceSpec{Rules: rules},
		}
		if i == 0 {
			source.Annotations = map[string]string{wafv1alpha1.AnnotationSkipValidation: "false"}
		}
		if err := apiClient.Create(context.Background(), source); err != nil {
			b.Fatal(err)
		}
		if i == 0 {
			source.Status.Conditions = []metav1.Condition{{
				Type:               "Ready",
				Status:             metav1.ConditionTrue,
				ObservedGeneration: source.Generation,
				Reason:             "Validated",
				LastTransitionTime: metav1.Now(),
			}}
			if err := apiClient.Status().Update(context.Background(), source); err != nil {
				b.Fatal(err)
			}
		}
	}

	referencedData := strings.Repeat("blocked.example\n", 10_000)
	unreferencedData := strings.Repeat("unused.example\n", 10_000)
	for _, data := range []struct {
		name       string
		value      string
		referenced bool
	}{
		{name: "referenced-data", value: referencedData, referenced: true},
		{name: "unreferenced-data", value: unreferencedData},
	} {
		rd := &wafv1alpha1.RuleData{
			ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: data.name},
			Spec:       wafv1alpha1.RuleDataSpec{Files: map[string]string{"rules.data": data.value}},
		}
		if err := apiClient.Create(context.Background(), rd); err != nil {
			b.Fatal(err)
		}
		if data.referenced {
			rd.Status.Conditions = []metav1.Condition{{
				Type:               "Ready",
				Status:             metav1.ConditionTrue,
				ObservedGeneration: rd.Generation,
				Reason:             "Loaded",
				LastTransitionTime: metav1.Now(),
			}}
			if err := apiClient.Status().Update(context.Background(), rd); err != nil {
				b.Fatal(err)
			}
		}
		if data.referenced {
			referencedBytes += len(data.value)
		} else {
			unreferencedBytes += len(data.value)
		}
	}

	if err := apiClient.Create(context.Background(), &wafv1alpha1.RuleSet{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: "referencing-rules"},
		Spec: wafv1alpha1.RuleSetSpec{
			Sources: sourceRefs,
			Data:    []wafv1alpha1.DataReference{{Name: "referenced-data"}},
		},
	}); err != nil {
		b.Fatal(err)
	}
	return referencedBytes, unreferencedBytes, sourceRefs
}

func measureRuleInputCacheHeap(
	b *testing.B,
	cfg *rest.Config,
	testScheme *k8sruntime.Scheme,
	apiClient client.Client,
	opts ctrlcache.Options,
	pruned bool,
) uint64 {
	b.Helper()
	opts.Scheme = testScheme
	goruntime.GC()
	var before goruntime.MemStats
	goruntime.ReadMemStats(&before)

	c, err := ctrlcache.New(cfg, opts)
	if err != nil {
		b.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- c.Start(ctx)
	}()
	for _, object := range []client.Object{
		&wafv1alpha1.RuleSource{},
		&wafv1alpha1.RuleData{},
		&wafv1alpha1.RuleSet{},
	} {
		if _, err := c.GetInformer(ctx, object); err != nil {
			cancel()
			b.Fatal(err)
		}
	}
	syncCtx, syncCancel := context.WithTimeout(ctx, 30*time.Second)
	defer syncCancel()
	if !c.WaitForCacheSync(syncCtx) {
		cancel()
		b.Fatal("typed informers did not sync")
	}

	var sources wafv1alpha1.RuleSourceList
	if err := c.List(ctx, &sources, client.InNamespace("cache-memory")); err != nil {
		cancel()
		b.Fatal(err)
	}
	var data wafv1alpha1.RuleDataList
	if err := c.List(ctx, &data, client.InNamespace("cache-memory")); err != nil {
		cancel()
		b.Fatal(err)
	}
	assertRuleInputCacheObjects(b, sources, data, pruned)
	sources = wafv1alpha1.RuleSourceList{}
	data = wafv1alpha1.RuleDataList{}

	goruntime.GC()
	var after goruntime.MemStats
	goruntime.ReadMemStats(&after)
	retained := after.HeapAlloc - before.HeapAlloc

	cancel()
	if err := <-done; err != nil {
		b.Fatalf("stop typed cache: %v", err)
	}
	assertRuleInputAPIObjects(b, apiClient)
	return retained
}

func assertRuleInputCacheObjects(
	b testing.TB,
	sources wafv1alpha1.RuleSourceList,
	data wafv1alpha1.RuleDataList,
	pruned bool,
) {
	b.Helper()
	if len(sources.Items) != 30 || len(data.Items) != 2 {
		b.Fatalf("cache has %d RuleSources and %d RuleData; want 30 and 2", len(sources.Items), len(data.Items))
	}
	for i := range sources.Items {
		if (sources.Items[i].Spec.Rules == "") != pruned {
			b.Fatalf("RuleSource %s payload-pruned=%t, want %t", sources.Items[i].Name, sources.Items[i].Spec.Rules == "", pruned)
		}
	}
	for i := range data.Items {
		if (len(data.Items[i].Spec.Files) == 0) != pruned {
			b.Fatalf("RuleData %s payload-pruned=%t, want %t", data.Items[i].Name, len(data.Items[i].Spec.Files) == 0, pruned)
		}
	}
	firstSource := findRuleSource(b, sources.Items, "source-00")
	if firstSource.UID == "" || firstSource.Generation == 0 ||
		firstSource.Annotations[wafv1alpha1.AnnotationSkipValidation] != "false" ||
		len(firstSource.Status.Conditions) != 1 || len(firstSource.ManagedFields) != 0 {
		b.Fatalf("cache RuleSource identity/status/annotation/managedFields: uid=%q generation=%d annotations=%v conditions=%v managedFields=%v",
			firstSource.UID, firstSource.Generation, firstSource.Annotations, firstSource.Status.Conditions, firstSource.ManagedFields)
	}
	firstData := findRuleData(b, data.Items, "referenced-data")
	if firstData.UID == "" || firstData.Generation == 0 ||
		len(firstData.Status.Conditions) != 1 || len(firstData.ManagedFields) != 0 {
		b.Fatal("cache did not retain RuleData identity/status or strip managed fields")
	}
}

func findRuleSource(b testing.TB, sources []wafv1alpha1.RuleSource, name string) *wafv1alpha1.RuleSource {
	b.Helper()
	for i := range sources {
		if sources[i].Name == name {
			return &sources[i]
		}
	}
	b.Fatalf("cache is missing RuleSource %s", name)
	return nil
}

func findRuleData(b testing.TB, data []wafv1alpha1.RuleData, name string) *wafv1alpha1.RuleData {
	b.Helper()
	for i := range data {
		if data[i].Name == name {
			return &data[i]
		}
	}
	b.Fatalf("cache is missing RuleData %s", name)
	return nil
}

func assertRuleInputAPIObjects(b testing.TB, apiClient client.Client) {
	b.Helper()
	var liveSource wafv1alpha1.RuleSource
	if err := apiClient.Get(context.Background(), client.ObjectKey{Namespace: "cache-memory", Name: "source-00"}, &liveSource); err != nil {
		b.Fatal(err)
	}
	if liveSource.Spec.Rules == "" {
		b.Fatal("cache transform changed the API-stored RuleSource")
	}
	var liveData wafv1alpha1.RuleData
	if err := apiClient.Get(context.Background(), client.ObjectKey{Namespace: "cache-memory", Name: "referenced-data"}, &liveData); err != nil {
		b.Fatal(err)
	}
	if len(liveData.Spec.Files) == 0 {
		b.Fatal("cache transform changed the API-stored RuleData")
	}
}
