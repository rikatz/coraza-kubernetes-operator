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
	"context"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/networking-incubator/coraza-kubernetes-operator/internal/rulesets/cache"
)

func TestGenerateSnapshot(t *testing.T) {
	tests := []struct {
		name          string
		setupCache    func(*cache.RuleSetCache)
		expectEntries int
	}{
		{
			name: "empty cache",
			setupCache: func(c *cache.RuleSetCache) {
				// No entries
			},
			expectEntries: 0,
		},
		{
			name: "single entry",
			setupCache: func(c *cache.RuleSetCache) {
				c.Put("default/test-ruleset", "SecRule ARGS \"@rx .*\" \"id:1,deny\"")
			},
			expectEntries: 1,
		},
		{
			name: "multiple entries",
			setupCache: func(c *cache.RuleSetCache) {
				c.Put("default/ruleset-1", "SecRule ARGS \"@rx .*\" \"id:1,deny\"")
				c.Put("default/ruleset-2", "SecRule ARGS \"@rx .*\" \"id:2,deny\"")
				c.Put("kube-system/ruleset-3", "SecRule ARGS \"@rx .*\" \"id:3,deny\"")
			},
			expectEntries: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rulesetCache := cache.NewRuleSetCache()
			tt.setupCache(rulesetCache)

			snapshot, err := GenerateSnapshot(rulesetCache)
			require.NoError(t, err)
			require.NotNil(t, snapshot)

			// Verify snapshot version is set
			version := snapshot.GetVersion(TypeURL)
			assert.NotEmpty(t, version)

			// Verify resource count
			resources := snapshot.GetResources(TypeURL)
			assert.Len(t, resources, tt.expectEntries)

			// For non-empty snapshots, verify version changes with updates
			if tt.expectEntries > 0 {
				// Update cache and regenerate
				rulesetCache.Put("default/new-entry", "SecRule ARGS \"@rx .*\" \"id:99,deny\"")
				newSnapshot, err := GenerateSnapshot(rulesetCache)
				require.NoError(t, err)

				// Version should be different
				newVersion := newSnapshot.GetVersion(TypeURL)
				assert.NotEqual(t, version, newVersion, "snapshot version should change when cache is updated")
			}
		})
	}
}

func TestObserverNotification(t *testing.T) {
	rulesetCache := cache.NewRuleSetCache()

	// Create xDS server (which registers as observer)
	logger := logr.Discard()
	server := NewServer(rulesetCache, 18001, logger)

	// Get initial snapshot version
	initialSnapshot, err := GenerateSnapshot(rulesetCache)
	require.NoError(t, err)
	initialVersion := initialSnapshot.GetVersion(TypeURL)

	// Update cache (should trigger observer notification)
	rulesetCache.Put("default/test-ruleset", "SecRule ARGS \"@rx .*\" \"id:1,deny\"")

	// Give observer a moment to process
	time.Sleep(50 * time.Millisecond)

	// Generate new snapshot and verify version changed
	newSnapshot, err := GenerateSnapshot(rulesetCache)
	require.NoError(t, err)
	newVersion := newSnapshot.GetVersion(TypeURL)

	assert.NotEqual(t, initialVersion, newVersion, "snapshot version should change after cache update")

	// Verify snapshot cache was updated
	snapshot, err := server.snapshotCache.GetSnapshot(DefaultNodeID)
	require.NoError(t, err)
	assert.Equal(t, newVersion, snapshot.GetVersion(TypeURL))
}

func TestServerLifecycle(t *testing.T) {
	rulesetCache := cache.NewRuleSetCache()
	logger := logr.Discard()

	// Use a high port to avoid conflicts
	port := 19000
	server := NewServer(rulesetCache, port, logger)

	// Start server in background
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errChan := make(chan error, 1)
	go func() {
		errChan <- server.Start(ctx)
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Cancel context to trigger graceful shutdown
	cancel()

	// Wait for shutdown with timeout
	select {
	case err := <-errChan:
		assert.NoError(t, err, "server should shut down gracefully")
	case <-time.After(15 * time.Second):
		t.Fatal("server shutdown timed out")
	}
}

func TestSnapshotUpdate(t *testing.T) {
	rulesetCache := cache.NewRuleSetCache()
	logger := logr.Discard()

	server := NewServer(rulesetCache, 18002, logger)

	// Initial state should have empty snapshot
	snapshot, err := server.snapshotCache.GetSnapshot(DefaultNodeID)
	require.NoError(t, err)
	initialVersion := snapshot.GetVersion(TypeURL)
	assert.NotEmpty(t, initialVersion)

	// Add entry to cache
	rulesetCache.Put("default/ruleset-1", "SecRule ARGS \"@rx .*\" \"id:1,deny\"")
	time.Sleep(50 * time.Millisecond)

	// Snapshot should be updated
	snapshot, err = server.snapshotCache.GetSnapshot(DefaultNodeID)
	require.NoError(t, err)
	version1 := snapshot.GetVersion(TypeURL)
	assert.NotEqual(t, initialVersion, version1)

	// Add another entry
	rulesetCache.Put("default/ruleset-2", "SecRule ARGS \"@rx .*\" \"id:2,deny\"")
	time.Sleep(50 * time.Millisecond)

	// Snapshot should be updated again
	snapshot, err = server.snapshotCache.GetSnapshot(DefaultNodeID)
	require.NoError(t, err)
	version2 := snapshot.GetVersion(TypeURL)
	assert.NotEqual(t, version1, version2)

	// Verify resources count
	resources := snapshot.GetResources(TypeURL)
	assert.Len(t, resources, 2)
}

func TestNeedLeaderElection(t *testing.T) {
	rulesetCache := cache.NewRuleSetCache()
	logger := logr.Discard()
	server := NewServer(rulesetCache, 18003, logger)

	// xDS server should NOT require leader election
	assert.False(t, server.NeedLeaderElection(), "xDS server should run on all replicas")
}

func TestGenerateVersion(t *testing.T) {
	tests := []struct {
		name     string
		uuids    []string
		expected string
	}{
		{
			name:     "empty list",
			uuids:    []string{},
			expected: "empty",
		},
		{
			name:     "single uuid",
			uuids:    []string{"abc123"},
			expected: generateVersion([]string{"abc123"}),
		},
		{
			name:  "deterministic",
			uuids: []string{"uuid1", "uuid2", "uuid3"},
			// Should produce same result every time
			expected: generateVersion([]string{"uuid1", "uuid2", "uuid3"}),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := generateVersion(tt.uuids)
			assert.Equal(t, tt.expected, result)

			// Verify deterministic behavior (run twice)
			if len(tt.uuids) > 0 {
				result2 := generateVersion(tt.uuids)
				assert.Equal(t, result, result2, "generateVersion should be deterministic")
			}
		})
	}

	// Verify different inputs produce different versions
	v1 := generateVersion([]string{"uuid1", "uuid2"})
	v2 := generateVersion([]string{"uuid1", "uuid3"})
	assert.NotEqual(t, v1, v2, "different UUIDs should produce different versions")
}
