/*
Copyright 2026 Shane Utt.

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

package xds

import (
	"crypto/sha256"
	"fmt"
	"sort"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	cachev3 "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	"github.com/envoyproxy/go-control-plane/pkg/cache/types"
	"github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/networking-incubator/coraza-kubernetes-operator/internal/rulesets/cache"
	xdsv1 "github.com/networking-incubator/coraza-kubernetes-operator/pkg/xds/v1"
)

const (
	// TypeURL is the xDS type URL for Coraza RuleSet resources (wrapped in ExtensionConfig)
	TypeURL = resource.ExtensionConfigType
	// RuleSetTypeURL is the inner type URL for the actual RuleSet proto
	RuleSetTypeURL = "type.googleapis.com/coraza.xds.v1.RuleSet"
)

// GenerateSnapshot creates an xDS snapshot from all entries in the cache
func GenerateSnapshot(rulesetCache *cache.RuleSetCache) (*cachev3.Snapshot, error) {
	// Get all cache keys (instance names)
	keys := rulesetCache.ListKeys()

	// Sort keys for deterministic snapshot generation
	sort.Strings(keys)

	// Build list of RuleSet resources
	resources := make([]types.Resource, 0, len(keys))
	versionComponents := make([]string, 0, len(keys))

	for _, key := range keys {
		entry, ok := rulesetCache.Get(key)
		if !ok {
			continue
		}

		// Create RuleSet proto message
		ruleSet := &xdsv1.RuleSet{
			Rules:     []byte(entry.Rules),
			Version:   entry.UUID,
			Name:      key,
			Timestamp: entry.Timestamp.Format("2006-01-02T15:04:05.999999999Z07:00"), // RFC3339Nano
		}

		// Marshal to Any
		anyResource, err := anypb.New(ruleSet)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal RuleSet to Any: %w", err)
		}

		// Set the type URL explicitly
		anyResource.TypeUrl = RuleSetTypeURL

		// Wrap in TypedExtensionConfig for xDS compatibility
		typedConfig := &corev3.TypedExtensionConfig{
			Name:        key,
			TypedConfig: anyResource,
		}

		resources = append(resources, typedConfig)
		versionComponents = append(versionComponents, entry.UUID)
	}

	// Generate aggregate version from all UUIDs
	version := generateVersion(versionComponents)

	// Create snapshot with Extension Config resources (ecds)
	// This is the standard way to distribute custom configuration via xDS
	snapshot, err := cachev3.NewSnapshot(
		version,
		map[resource.Type][]types.Resource{
			resource.ExtensionConfigType: resources,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create snapshot: %w", err)
	}

	return snapshot, nil
}

// generateVersion creates a deterministic version string from UUIDs
func generateVersion(uuids []string) string {
	if len(uuids) == 0 {
		return "empty"
	}

	// Create a hash of all UUIDs concatenated
	h := sha256.New()
	for _, uuid := range uuids {
		h.Write([]byte(uuid))
	}
	return fmt.Sprintf("%x", h.Sum(nil))[:16]
}
