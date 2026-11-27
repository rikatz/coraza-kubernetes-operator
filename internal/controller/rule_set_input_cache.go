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
	"sync"

	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	wafv1alpha1 "github.com/networking-incubator/coraza-kubernetes-operator/api/v1alpha1"
	"github.com/networking-incubator/coraza-kubernetes-operator/internal/rulesets/assemble"
)

const (
	maxRuleSetInputCacheEntries = 16
	maxRuleSetInputCacheBytes   = 16 << 20
	maxRuleSetInputCacheFlights = 16
)

type ruleSetInputCacheKey struct {
	ruleSetUID                 types.UID
	ruleSetGeneration          int64
	acceptedContentHash        string
	acceptanceStateFingerprint string
	inputFingerprint           string
	inputStateFingerprint      string
}

type ruleSetInputCacheEntry struct {
	key      ruleSetInputCacheKey
	inputs   assemble.Inputs
	weight   int64
	lastUsed uint64
}

type ruleSetInputCacheFlight struct {
	key         ruleSetInputCacheKey
	done        chan struct{}
	err         error
	invalidated bool
}

// ruleSetInputCache retains a small process-local working set of verified full
// inputs. Hits are valid only for the same accepted hash and informer-visible
// RuleSet/input identities, validation annotation, and gating conditions. A
// miss reads full objects from the API reader and compares their metadata with
// the informer view before storing them. Consumers still assemble and compare
// the content hash before accepting or publishing anything. Hits use the latest
// informer-visible state, not a linearizable API read; while an input watch is
// lagging, only the previously accepted hash can still be reused.
type ruleSetInputCache struct {
	mu        sync.Mutex
	entries   map[types.NamespacedName]ruleSetInputCacheEntry
	flights   map[types.NamespacedName]*ruleSetInputCacheFlight
	bytes     int64
	useClock  uint64
	evictions uint64
}

func newRuleSetInputCache() *ruleSetInputCache {
	return &ruleSetInputCache{}
}

// getOrLoad shares a single active load per RuleSet. The flight registry has a
// fixed cap and stores no input payload; waiters use the bounded cache after a
// successful load. Waiting observes the caller's context.
func (c *ruleSetInputCache) getOrLoad(
	ctx context.Context,
	ruleset *wafv1alpha1.RuleSet,
	cachedView ruleSetInputView,
	acceptedContentHash string,
	load func(context.Context) (ruleSetInputView, bool, error),
) (ruleSetInputView, bool, error) {
	if err := ctx.Err(); err != nil {
		return ruleSetInputView{}, false, err
	}
	if c == nil {
		view, _, err := load(ctx)
		return view, false, err
	}

	name := types.NamespacedName{Namespace: ruleset.Namespace, Name: ruleset.Name}
	key := ruleSetInputCacheKey{
		ruleSetUID:                 ruleset.UID,
		ruleSetGeneration:          ruleset.Generation,
		acceptedContentHash:        acceptedContentHash,
		acceptanceStateFingerprint: ruleSetAcceptanceFingerprint(ruleset),
		inputFingerprint:           cachedView.inputFingerprint(),
		inputStateFingerprint:      cachedView.stateFingerprint(),
	}

	for {
		c.mu.Lock()
		if entry, ok := c.entries[name]; ok {
			if entry.key != key {
				c.removeLocked(name)
				if flight := c.flights[name]; flight != nil && flight.key != key {
					flight.invalidated = true
				}
			} else {
				c.useClock++
				entry.lastUsed = c.useClock
				c.entries[name] = entry
				inputs := entry.inputs
				c.mu.Unlock()
				view := cachedView
				view.inputs = cloneRuleSetInputs(inputs)
				return view, true, nil
			}
		}

		if flight, ok := c.flights[name]; ok {
			sameKey := flight.key == key
			if !sameKey {
				flight.invalidated = true
			}
			done := flight.done
			c.mu.Unlock()
			select {
			case <-ctx.Done():
				return ruleSetInputView{}, false, ctx.Err()
			case <-done:
			}
			if err := ctx.Err(); err != nil {
				return ruleSetInputView{}, false, err
			}
			if sameKey && flight.err != nil {
				return ruleSetInputView{}, false, flight.err
			}
			continue
		}

		if len(c.flights) >= maxRuleSetInputCacheFlights {
			c.mu.Unlock()
			view, _, err := load(ctx)
			return view, false, err
		}

		flight := &ruleSetInputCacheFlight{key: key, done: make(chan struct{})}
		if c.flights == nil {
			c.flights = make(map[types.NamespacedName]*ruleSetInputCacheFlight)
		}
		c.flights[name] = flight
		c.mu.Unlock()

		view, cacheable, err := load(ctx)
		if err == nil && cacheable {
			c.store(name, key, flight, view.inputs)
		}

		c.mu.Lock()
		flight.err = err
		delete(c.flights, name)
		close(flight.done)
		c.mu.Unlock()
		return view, false, err
	}
}

// loadConsistentRuleSetInputView reads payloads only on a cache miss. The
// cached/live metadata check includes RuleSource UID/generation, validation
// annotation and Ready/Degraded state; RuleData UID/generation is checked too.
func loadConsistentRuleSetInputView(
	ctx context.Context,
	apiReader client.Reader,
	ruleset *wafv1alpha1.RuleSet,
	cachedView ruleSetInputView,
	acceptedContentHash string,
	cache *ruleSetInputCache,
) (ruleSetInputView, bool, error) {
	load := func(ctx context.Context) (ruleSetInputView, bool, error) {
		liveView, err := loadRuleSetInputView(ctx, apiReader, ruleset, true)
		if err != nil {
			return ruleSetInputView{}, false, err
		}
		if !cachedView.sameState(liveView) {
			return ruleSetInputView{}, false, errRuleSetInputsChanged
		}
		return liveView, true, nil
	}
	return cache.getOrLoad(ctx, ruleset, cachedView, acceptedContentHash, load)
}

func (c *ruleSetInputCache) store(
	name types.NamespacedName,
	key ruleSetInputCacheKey,
	flight *ruleSetInputCacheFlight,
	inputs assemble.Inputs,
) {
	weight := ruleSetInputCacheWeight(inputs)
	if weight > maxRuleSetInputCacheBytes {
		return
	}
	inputs = cloneRuleSetInputs(inputs)

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.flights[name] != flight || flight.invalidated {
		return
	}
	if entry, ok := c.entries[name]; ok {
		if entry.key != key {
			return
		}
		c.removeLocked(name)
	}
	for len(c.entries) >= maxRuleSetInputCacheEntries || c.bytes+weight > maxRuleSetInputCacheBytes {
		oldest, ok := c.oldestLocked()
		if !ok {
			return
		}
		c.removeLocked(oldest)
		c.evictions++
	}
	c.useClock++
	if c.entries == nil {
		c.entries = make(map[types.NamespacedName]ruleSetInputCacheEntry)
	}
	c.entries[name] = ruleSetInputCacheEntry{
		key:      key,
		inputs:   inputs,
		weight:   weight,
		lastUsed: c.useClock,
	}
	c.bytes += weight
}

func (c *ruleSetInputCache) invalidate(name types.NamespacedName) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.removeLocked(name)
	if flight := c.flights[name]; flight != nil {
		flight.invalidated = true
	}
}

func (c *ruleSetInputCache) clear() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = nil
	c.bytes = 0
	c.evictions = 0
	for _, flight := range c.flights {
		flight.invalidated = true
	}
}

func (c *ruleSetInputCache) stats() (entries int, retainedBytes int64, evictions uint64) {
	if c == nil {
		return 0, 0, 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries), c.bytes, c.evictions
}

func (c *ruleSetInputCache) removeLocked(name types.NamespacedName) {
	entry, ok := c.entries[name]
	if !ok {
		return
	}
	delete(c.entries, name)
	c.bytes -= entry.weight
}

func (c *ruleSetInputCache) oldestLocked() (types.NamespacedName, bool) {
	var oldest types.NamespacedName
	var lastUsed uint64
	found := false
	for name, entry := range c.entries {
		if !found || entry.lastUsed < lastUsed {
			oldest = name
			lastUsed = entry.lastUsed
			found = true
		}
	}
	return oldest, found
}

func ruleSetAcceptanceFingerprint(ruleset *wafv1alpha1.RuleSet) string {
	degraded := apimeta.FindStatusCondition(ruleset.Status.Conditions, conditionDegraded)
	if degraded != nil {
		degraded = degraded.DeepCopy()
	}
	raw, err := json.Marshal(struct {
		UID                       types.UID                           `json:"uid"`
		Generation                int64                               `json:"generation"`
		SkipUnsupportedRulesCheck string                              `json:"skip_unsupported_rules_check"`
		AcceptedContent           *wafv1alpha1.RuleSetAcceptedContent `json:"accepted_content,omitempty"`
		Degraded                  *metav1.Condition                   `json:"degraded,omitempty"`
	}{
		UID:                       ruleset.UID,
		Generation:                ruleset.Generation,
		SkipUnsupportedRulesCheck: ruleset.Annotations[wafv1alpha1.AnnotationSkipUnsupportedRulesCheck],
		AcceptedContent:           ruleset.Status.AcceptedContent,
		Degraded:                  degraded,
	})
	if err != nil {
		panic("controller: marshal RuleSet input-cache state: " + err.Error())
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func ruleSetInputCacheWeight(inputs assemble.Inputs) int64 {
	const (
		baseOverhead   = 256
		sourceOverhead = 128
		dataOverhead   = 128
		fileOverhead   = 64
	)
	weight := int64(baseOverhead + len(inputs.RuleSetUID) + len(inputs.RuleSetName) + len(inputs.Namespace) + len(inputs.EmptyRulesPolicy))
	for _, source := range inputs.Sources {
		weight += int64(sourceOverhead + len(source.Name) + len(source.UID) + len(source.Rules))
	}
	for _, data := range inputs.Data {
		weight += int64(dataOverhead + len(data.Name) + len(data.UID))
		for name, content := range data.Files {
			weight += int64(fileOverhead + len(name) + len(content))
		}
	}
	return weight
}

func cloneRuleSetInputs(inputs assemble.Inputs) assemble.Inputs {
	clone := inputs
	clone.Sources = append([]assemble.SourceInput(nil), inputs.Sources...)
	clone.Data = make([]assemble.DataInput, len(inputs.Data))
	for i, data := range inputs.Data {
		clone.Data[i] = data
		if data.Files == nil {
			continue
		}
		clone.Data[i].Files = make(map[string]string, len(data.Files))
		for name, content := range data.Files {
			clone.Data[i].Files[name] = content
		}
	}
	return clone
}
