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
	"strings"
	"sync"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	extensionconfigservice "github.com/envoyproxy/go-control-plane/envoy/service/extension/v3"
	xdsserver "github.com/envoyproxy/go-control-plane/pkg/server/v3"
	"github.com/go-logr/logr"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	authorizationHeader        = "authorization"
	invalidSubscriptionMessage = "invalid subscription"
)

// lifecycleKey carries the stream's cancel function from the interceptor into
// the go-control-plane callbacks, which have no other way to close a stream.
type lifecycleKey struct{}

type serverStream struct {
	ctx          context.Context
	identity     Identity
	session      *StreamSession
	resourceName string
	engineKey    string
}

// Server serves ECDS with go-control-plane's SnapshotCache and stream handler.
// Authentication, authorization, revalidation, and stream lifecycle remain
// CKO-owned.
type Server struct {
	Store   *SnapshotStore
	Auth    *Authenticator
	Authz   *AuthzIndex
	Streams *StreamRegistry
	Limits  Limits
	Metrics *Metrics
	Log     logr.Logger

	srv xdsserver.Server

	streams sync.Map // int64 -> *serverStream
}

// NewServer wires the go-control-plane server around the snapshot cache.
func NewServer(store *SnapshotStore, auth *Authenticator, authz *AuthzIndex, streams *StreamRegistry, limits Limits, metrics *Metrics, logger logr.Logger) *Server {
	s := &Server{
		Store:   store,
		Auth:    auth,
		Authz:   authz,
		Streams: streams,
		Limits:  limits,
		Metrics: metrics,
		Log:     logger,
	}
	s.srv = xdsserver.NewServer(context.Background(), store.cache, xdsserver.CallbackFuncs{
		StreamOpenFunc:    s.onStreamOpen,
		StreamRequestFunc: s.onStreamRequest,
		StreamClosedFunc:  s.onStreamClosed,
	})
	return s
}

// Register registers the ECDS service on the gRPC server.
func (s *Server) Register(registrar grpc.ServiceRegistrar) {
	extensionconfigservice.RegisterExtensionConfigDiscoveryServiceServer(registrar, s.srv)
}

// StreamInterceptor supplies the cancelable stream context the revalidation
// registry needs. go-control-plane has no public close-stream API.
func (s *Server) StreamInterceptor() grpc.StreamServerInterceptor {
	return func(srv any, stream grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		ctx, cancel := context.WithCancelCause(stream.Context())

		wrapped := &streamWithContext{
			ServerStream: stream,
			ctx:          context.WithValue(ctx, lifecycleKey{}, cancel),
		}
		err := handler(srv, wrapped)
		if ctx.Err() != nil {
			switch context.Cause(ctx) {
			case ErrRevoked:
				return status.Error(codes.PermissionDenied, "resource is not authorized")
			case ErrRevalidateFailed:
				return status.Error(codes.Unauthenticated, "authentication failed")
			case ErrLifetimeExpired, ErrServerShutdown:
				return status.Error(codes.Unavailable, "stream must be re-established")
			}
		}
		if err == nil {
			return nil
		}
		// Preserve explicit auth/authz/subscription errors. Only map errors that
		// come from the lifecycle cancellation below.
		if st, ok := status.FromError(err); ok && st.Code() != codes.Canceled && st.Code() != codes.Unknown {
			return err
		}
		if ctx.Err() != nil {
			switch context.Cause(ctx) {
			case ErrRevoked:
				return status.Error(codes.PermissionDenied, "resource is not authorized")
			case ErrRevalidateFailed:
				return status.Error(codes.Unauthenticated, "authentication failed")
			case ErrLifetimeExpired, ErrServerShutdown:
				return status.Error(codes.Unavailable, "stream must be re-established")
			}
		}
		return err
	}
}

type streamWithContext struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *streamWithContext) Context() context.Context { return s.ctx }

// RecvMsg and SendMsg observe the lifecycle context. go-control-plane's stream
// handler blocks in Recv, so cancellation must unblock it here;
// the read goroutine ends when the server closes the stream.
func (s *streamWithContext) RecvMsg(m any) error {
	done := make(chan error, 1)
	go func() { done <- s.ServerStream.RecvMsg(m) }()
	select {
	case err := <-done:
		return err
	case <-s.ctx.Done():
		return status.Error(codes.Canceled, "stream closed")
	}
}

func (s *streamWithContext) SendMsg(m any) error {
	if s.ctx.Err() != nil {
		return status.Error(codes.Canceled, "stream closed")
	}
	return s.ServerStream.SendMsg(m)
}

func (s *Server) onStreamOpen(ctx context.Context, streamID int64, _ string) error {
	// Authentication runs on the first request, after the stream is fully
	// established, so an auth failure is delivered as a gRPC status rather
	// than an early stream reset.
	s.streams.Store(streamID, &serverStream{ctx: ctx})
	return nil
}

func (s *Server) onStreamRequest(streamID int64, req *discoveryv3.DiscoveryRequest) error {
	raw, ok := s.streams.Load(streamID)
	if !ok {
		return status.Error(codes.Unauthenticated, "authentication failed")
	}
	entry := raw.(*serverStream)

	if entry.session == nil {
		token, err := bearerToken(entry.ctx)
		if err != nil {
			s.Metrics.AuthFailure("error")
			return status.Error(codes.Unauthenticated, "authentication failed")
		}
		identity, err := s.Auth.Authenticate(entry.ctx, token)
		if err != nil {
			s.Metrics.AuthFailure("error")
			return status.Error(codes.Unauthenticated, "authentication failed")
		}
		cancel, _ := entry.ctx.Value(lifecycleKey{}).(context.CancelCauseFunc)
		session, err := s.Streams.RegisterWithCancel(entry.ctx, cancel, "", *identity, token)
		if err != nil {
			return status.Error(codes.ResourceExhausted, "stream limit exceeded")
		}
		s.Metrics.AuthFailure("authenticated")
		entry.identity = *identity
		entry.session = session
	}

	// The client controls node.id. Keep the cache key pinned to the
	// authorized Engine on every request, including ACKs/NACKs.
	if entry.engineKey != "" && req.Node != nil {
		req.Node.Id = entry.engineKey
	}

	if req.GetErrorDetail() != nil {
		s.Metrics.Nack("rejected")
		return nil
	}

	names := req.GetResourceNames()
	if len(names) == 0 {
		if req.GetResponseNonce() != "" {
			s.Metrics.Ack()
			return nil
		}
		return status.Error(codes.InvalidArgument, invalidSubscriptionMessage)
	}
	if len(names) != 1 {
		return status.Error(codes.InvalidArgument, invalidSubscriptionMessage)
	}

	name := names[0]
	if name == "" || !strings.HasPrefix(name, resourceNamePrefix) || strings.ContainsAny(name, "*?") {
		return status.Error(codes.InvalidArgument, invalidSubscriptionMessage)
	}
	if name != entry.resourceName {
		if !s.Authz.Authorize(name, entry.identity) {
			s.Metrics.AuthFailure("unauthorized")
			return status.Error(codes.PermissionDenied, "resource is not authorized")
		}
		engineKey, ok := s.Authz.EngineKey(name)
		if !ok {
			s.Metrics.AuthFailure("unauthorized")
			return status.Error(codes.PermissionDenied, "resource is not authorized")
		}
		// The cache is keyed by node.id, which the client controls. Rewrite it
		// to the authorized Engine key before CreateWatch runs.
		if req.Node == nil {
			req.Node = &corev3.Node{}
		}
		req.Node.Id = engineKey
		entry.resourceName = name
		entry.engineKey = engineKey
		s.Streams.SetResource(entry.session.ID, name)
		return nil
	}

	if req.GetResponseNonce() != "" {
		s.Metrics.Ack()
	}
	return nil
}

func (s *Server) onStreamClosed(streamID int64, _ *corev3.Node) {
	raw, ok := s.streams.LoadAndDelete(streamID)
	if !ok {
		return
	}
	entry := raw.(*serverStream)
	if entry.session != nil {
		s.Streams.Unregister(entry.session.ID)
	}
}

// bearerToken extracts exactly one "Bearer <token>" authorization header.
func bearerToken(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", errors.New("missing gRPC metadata")
	}
	values := md.Get(authorizationHeader)
	if len(values) != 1 {
		return "", errors.New("missing or duplicate authorization header")
	}
	scheme, token, ok := strings.Cut(values[0], " ")
	if !ok || !strings.EqualFold(scheme, "bearer") || strings.TrimSpace(token) == "" {
		return "", errors.New("malformed authorization header")
	}
	return strings.TrimSpace(token), nil
}
