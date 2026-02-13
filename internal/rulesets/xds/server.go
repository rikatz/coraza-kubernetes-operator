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
	"fmt"
	"net"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	cachev3 "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	serverv3 "github.com/envoyproxy/go-control-plane/pkg/server/v3"
	"github.com/go-logr/logr"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"

	"github.com/networking-incubator/coraza-kubernetes-operator/internal/rulesets/cache"
)

const (
	// DefaultNodeID is the wildcard node ID for broadcast mode
	DefaultNodeID = "coraza-wasm-filter"
)

// Server implements an xDS server with ADS support
type Server struct {
	cache         *cache.RuleSetCache
	snapshotCache cachev3.SnapshotCache
	grpcServer    *grpc.Server
	xdsServer     serverv3.Server
	logger        logr.Logger
	port          int
	nodeID        string
}

// NewServer creates a new xDS server instance
func NewServer(rulesetCache *cache.RuleSetCache, port int, logger logr.Logger) *Server {
	logger = logger.WithName("xds-server")

	// Create snapshot cache with hash-based node ID
	snapshotCache := cachev3.NewSnapshotCache(true, cachev3.IDHash{}, &xdsLogger{logger: logger})

	// Create xDS server with callbacks
	callbacks := &serverCallbacks{logger: logger}
	xdsServer := serverv3.NewServer(context.Background(), snapshotCache, callbacks)

	s := &Server{
		cache:         rulesetCache,
		snapshotCache: snapshotCache,
		xdsServer:     xdsServer,
		logger:        logger,
		port:          port,
		nodeID:        DefaultNodeID,
	}

	// Generate and set initial snapshot
	if err := s.updateSnapshot(); err != nil {
		logger.Error(err, "Failed to generate initial snapshot")
	}

	// Register as observer for cache updates
	rulesetCache.RegisterObserver(s)

	return s
}

// OnCacheUpdate implements cache.Observer interface
func (s *Server) OnCacheUpdate(key string, entry *cache.RuleSetEntry) {
	s.logger.V(1).Info("Cache updated, regenerating snapshot", "key", key, "version", entry.UUID)
	if err := s.updateSnapshot(); err != nil {
		s.logger.Error(err, "Failed to update snapshot after cache update", "key", key)
	}
}

// updateSnapshot regenerates the snapshot from current cache state
func (s *Server) updateSnapshot() error {
	snapshot, err := GenerateSnapshot(s.cache)
	if err != nil {
		return fmt.Errorf("failed to generate snapshot: %w", err)
	}

	version := snapshot.GetVersion(TypeURL)
	s.logger.Info("Generating xDS snapshot", "version", version, "nodeID", s.nodeID)

	// Set snapshot for the wildcard node ID (broadcast mode)
	if err := s.snapshotCache.SetSnapshot(context.Background(), s.nodeID, snapshot); err != nil {
		return fmt.Errorf("failed to set snapshot: %w", err)
	}

	s.logger.Info("Snapshot updated", "nodeID", s.nodeID, "version", version)
	return nil
}

// Start implements manager.Runnable interface
func (s *Server) Start(ctx context.Context) error {
	// Create gRPC server with keepalive settings
	grpcOptions := []grpc.ServerOption{
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             15 * time.Second,
			PermitWithoutStream: true,
		}),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:    30 * time.Second,
			Timeout: 5 * time.Second,
		}),
	}

	s.grpcServer = grpc.NewServer(grpcOptions...)

	// Register ADS service
	discoveryv3.RegisterAggregatedDiscoveryServiceServer(s.grpcServer, s.xdsServer)

	// Start listening
	addr := fmt.Sprintf(":%d", s.port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	s.logger.Info("Starting xDS server", "address", addr, "nodeID", s.nodeID)

	// Start serving in a goroutine
	errChan := make(chan error, 1)
	go func() {
		if err := s.grpcServer.Serve(listener); err != nil {
			errChan <- err
		}
	}()

	// Wait for context cancellation or server error
	select {
	case <-ctx.Done():
		s.logger.Info("Shutting down xDS server")
		s.shutdown()
		return nil
	case err := <-errChan:
		return fmt.Errorf("gRPC server error: %w", err)
	}
}

// shutdown gracefully stops the gRPC server
func (s *Server) shutdown() {
	if s.grpcServer != nil {
		// Try graceful stop with timeout
		done := make(chan struct{})
		go func() {
			s.grpcServer.GracefulStop()
			close(done)
		}()

		// Wait up to 10 seconds for graceful shutdown
		select {
		case <-done:
			s.logger.Info("xDS server shutdown complete")
		case <-time.After(10 * time.Second):
			s.logger.Info("xDS server graceful shutdown timeout, forcing stop")
			s.grpcServer.Stop()
		}
	}
}

// NeedLeaderElection implements manager.LeaderElectionRunnable interface
func (s *Server) NeedLeaderElection() bool {
	// xDS server should run on all replicas, not just the leader
	return false
}

// serverCallbacks implements go-control-plane server callbacks
type serverCallbacks struct {
	logger logr.Logger
}

func (cb *serverCallbacks) OnStreamOpen(ctx context.Context, streamID int64, typeURL string) error {
	cb.logger.V(1).Info("Stream opened", "streamID", streamID, "typeURL", typeURL)
	return nil
}

func (cb *serverCallbacks) OnStreamClosed(streamID int64, node *corev3.Node) {
	cb.logger.V(1).Info("Stream closed", "streamID", streamID, "nodeID", node.GetId())
}

func (cb *serverCallbacks) OnDeltaStreamOpen(ctx context.Context, streamID int64, typeURL string) error {
	cb.logger.V(1).Info("Delta stream opened", "streamID", streamID, "typeURL", typeURL)
	return nil
}

func (cb *serverCallbacks) OnDeltaStreamClosed(streamID int64, node *corev3.Node) {
	cb.logger.V(1).Info("Delta stream closed", "streamID", streamID, "nodeID", node.GetId())
}

func (cb *serverCallbacks) OnStreamRequest(streamID int64, req *discoveryv3.DiscoveryRequest) error {
	cb.logger.V(1).Info("Stream request",
		"streamID", streamID,
		"nodeID", req.GetNode().GetId(),
		"typeURL", req.GetTypeUrl(),
		"versionInfo", req.GetVersionInfo(),
	)
	return nil
}

func (cb *serverCallbacks) OnStreamResponse(ctx context.Context, streamID int64, req *discoveryv3.DiscoveryRequest, resp *discoveryv3.DiscoveryResponse) {
	cb.logger.V(1).Info("Stream response",
		"streamID", streamID,
		"typeURL", req.GetTypeUrl(),
		"versionInfo", resp.GetVersionInfo(),
	)
}

func (cb *serverCallbacks) OnStreamDeltaRequest(streamID int64, req *discoveryv3.DeltaDiscoveryRequest) error {
	cb.logger.V(1).Info("Delta stream request",
		"streamID", streamID,
		"typeURL", req.GetTypeUrl(),
	)
	return nil
}

func (cb *serverCallbacks) OnStreamDeltaResponse(streamID int64, req *discoveryv3.DeltaDiscoveryRequest, resp *discoveryv3.DeltaDiscoveryResponse) {
	cb.logger.V(1).Info("Delta stream response",
		"streamID", streamID,
		"typeURL", req.GetTypeUrl(),
	)
}

func (cb *serverCallbacks) OnFetchRequest(ctx context.Context, req *discoveryv3.DiscoveryRequest) error {
	cb.logger.V(1).Info("Fetch request", "typeURL", req.GetTypeUrl())
	return nil
}

func (cb *serverCallbacks) OnFetchResponse(req *discoveryv3.DiscoveryRequest, resp *discoveryv3.DiscoveryResponse) {
	cb.logger.V(1).Info("Fetch response", "typeURL", req.GetTypeUrl())
}

// xdsLogger adapts logr.Logger to go-control-plane's logger interface
type xdsLogger struct {
	logger logr.Logger
}

func (l *xdsLogger) Debugf(format string, args ...interface{}) {
	l.logger.V(1).Info(fmt.Sprintf(format, args...))
}

func (l *xdsLogger) Infof(format string, args ...interface{}) {
	l.logger.Info(fmt.Sprintf(format, args...))
}

func (l *xdsLogger) Warnf(format string, args ...interface{}) {
	l.logger.Info(fmt.Sprintf("WARNING: "+format, args...))
}

func (l *xdsLogger) Errorf(format string, args ...interface{}) {
	l.logger.Error(fmt.Errorf(format, args...), "xDS error")
}
