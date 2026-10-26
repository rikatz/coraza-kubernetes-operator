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

package xds

import (
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSnapshotStoreLifecycle(t *testing.T) {
	store := NewSnapshotStore()

	require.NoError(t, store.Replace(&Snapshot{
		Namespace:  "ns",
		EngineName: "engine",
		Version:    "v1",
		Resource:   &corev3.TypedExtensionConfig{Name: "resource"},
	}))

	snapshot, ok := store.Get("ns/engine")
	require.True(t, ok)
	assert.Equal(t, "v1", snapshot.Version)

	store.DeleteEngine("ns", "engine")
	_, ok = store.Get("ns/engine")
	assert.False(t, ok)
}

func TestSnapshotStoreBumpKeepsAcceptedVersion(t *testing.T) {
	store := NewSnapshotStore()
	require.NoError(t, store.Replace(&Snapshot{
		ResourceName: "coraza.waf.ns.engine.uid",
		Namespace:    "ns",
		EngineName:   "engine",
		Version:      "sha256:v1",
		Resource:     &corev3.TypedExtensionConfig{Name: "coraza.waf.ns.engine.uid"},
	}))

	require.NoError(t, store.BumpRejected("coraza.waf.ns.engine.uid", 1))

	cached, err := store.cache.GetSnapshot("ns/engine")
	require.NoError(t, err)
	assert.Equal(t, "sha256:v1.retry1", cached.GetVersion(resource.ExtensionConfigType))

	snapshot, ok := store.Get("ns/engine")
	require.True(t, ok)
	assert.Equal(t, "sha256:v1", snapshot.Version, "the accepted version must not change")
	assert.Error(t, store.BumpRejected("missing", 1))
}

func TestSnapshotStoreRejectsEmptySnapshot(t *testing.T) {
	store := NewSnapshotStore()
	assert.Error(t, store.Replace(nil))
	assert.Error(t, store.Replace(&Snapshot{Version: "v1"}))
}
