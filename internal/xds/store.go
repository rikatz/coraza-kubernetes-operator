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
	"context"
	"errors"
	"fmt"
	"sync"

	cachetypes "github.com/envoyproxy/go-control-plane/pkg/cache/types"
	cachev3 "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	"github.com/envoyproxy/go-control-plane/pkg/resource/v3"
)

// SnapshotStore publishes one ECDS snapshot per Engine into go-control-plane's
// SnapshotCache. The cache key is "<namespace>/<engine>", which the stream
// callbacks write into node.id after authorization.
type SnapshotStore struct {
	cache cachev3.SnapshotCache

	mu   sync.RWMutex
	meta map[string]Snapshot
}

// NewSnapshotStore returns an empty snapshot store.
func NewSnapshotStore() *SnapshotStore {
	return &SnapshotStore{
		cache: cachev3.NewSnapshotCache(false, cachev3.IDHash{}, nil),
		meta:  make(map[string]Snapshot),
	}
}

// Replace publishes an Engine snapshot. The cache key is the Engine key, not
// the ECDS resource name, so it survives a UID change and can be deleted by
// namespace/name.
func (s *SnapshotStore) Replace(snapshot *Snapshot) error {
	if snapshot == nil || snapshot.Resource == nil {
		return errors.New("snapshot and resource are required")
	}
	compiled, err := cachev3.NewSnapshot(snapshot.Version, map[resource.Type][]cachetypes.Resource{
		resource.ExtensionConfigType: {snapshot.Resource},
	})
	if err != nil {
		return fmt.Errorf("build snapshot: %w", err)
	}
	key := engineSnapshotKey(snapshot.Namespace, snapshot.EngineName)
	if err := s.cache.SetSnapshot(context.Background(), key, compiled); err != nil {
		return err
	}
	s.mu.Lock()
	s.meta[key] = *snapshot
	s.mu.Unlock()
	return nil
}

// DeleteEngine removes an Engine's snapshot and any open watches.
func (s *SnapshotStore) DeleteEngine(namespace, engineName string) {
	key := engineSnapshotKey(namespace, engineName)
	s.cache.ClearSnapshot(key)
	s.mu.Lock()
	delete(s.meta, key)
	s.mu.Unlock()
}

// Get returns the published version for an Engine key ("namespace/name").
func (s *SnapshotStore) Get(engineKey string) (*Snapshot, bool) {
	s.mu.RLock()
	meta, ok := s.meta[engineKey]
	s.mu.RUnlock()
	if !ok {
		return nil, false
	}
	if _, err := s.cache.GetSnapshot(engineKey); err != nil {
		return nil, false
	}
	out := meta
	return &out, true
}

func engineSnapshotKey(namespace, engineName string) string {
	return namespace + "/" + engineName
}
