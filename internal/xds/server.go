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
	"sync/atomic"
	"time"

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
	// retryVersionSuffix marks a republished configuration.
	retryVersionSuffix = ".retry"

	// nackRetryLimit caps how many times one rejected configuration is retried.
	nackRetryLimit = 10
	// nackRetryWindow bounds the retries by time as well, so a slow module fetch
	// gets more attempts than a fast one without allowing an endless loop.
	nackRetryWindow = 20 * time.Second
)

// nackState tracks retries for one ECDS resource's current version.
type nackState struct {
	version  string
	attempts int
	first    time.Time
}

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
	Auth    *Authenticator
	Authz   *AuthzIndex
	Streams *StreamRegistry
	Limits  Limits
	Metrics *Metrics
	Store   *SnapshotStore
	Logger  logr.Logger

	// RetryDelay gives a rejected configuration's remote module fetch time to
	// finish before the proxy is asked to reapply it.
	RetryDelay time.Duration

	srv xdsserver.Server

	streams     sync.Map // int64 -> *serverStream
	nacks       sync.Map // resource name -> nackState
	openStreams atomic.Int64
}

// NewServer wires the go-control-plane server around the snapshot cache.
func NewServer(store *SnapshotStore, auth *Authenticator, authz *AuthzIndex, streams *StreamRegistry, limits Limits, metrics *Metrics) *Server {
	s := &Server{
		Auth:       auth,
		Authz:      authz,
		Streams:    streams,
		Limits:     limits.WithDefaults(),
		Metrics:    metrics,
		Store:      store,
		Logger:     logr.Discard(),
		RetryDelay: 2 * time.Second,
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

// lifecycleStatus maps a stream close cause to the bounded gRPC status
// returned to the client, or nil when the cause is not lifecycle-owned.
func lifecycleStatus(cause error) error {
	switch cause {
	case ErrRevoked:
		return status.Error(codes.PermissionDenied, "resource is not authorized")
	case ErrRevalidateFailed:
		return status.Error(codes.Unauthenticated, "authentication failed")
	case ErrLifetimeExpired, ErrServerShutdown, ErrResubscribe:
		return status.Error(codes.Unavailable, "stream must be re-established")
	}
	return nil
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
		if err != nil || ctx.Err() != nil {
			s.Logger.V(1).Info("ECDS stream ended", "err", err, "cause", context.Cause(ctx))
		}
		if ctx.Err() != nil {
			if mapped := lifecycleStatus(context.Cause(ctx)); mapped != nil {
				return mapped
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
			if mapped := lifecycleStatus(context.Cause(ctx)); mapped != nil {
				return mapped
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
	// The cap must hold at open time: a client can hold streams open without
	// ever sending a request, which RegisterWithCancel would never see.
	if s.openStreams.Add(1) > int64(s.Limits.MaxStreams) {
		s.openStreams.Add(-1)
		s.Metrics.StreamLimitRejected()
		return status.Error(codes.ResourceExhausted, "stream limit exceeded")
	}
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
			s.Metrics.StreamLimitRejected()
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
		// A proxy that rejects a configuration because the remote module is not
		// cached yet only re-applies it on a new subscription, so end the
		// stream with a retryable status. Envoy can send the NACK as the first
		// message of a reconnected stream, before any subscription was recorded.
		s.resubscribeRejected(entry, rejectedResourceName(entry, req), req.GetVersionInfo())
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
		// Record the subscription before authorizing so a concurrent
		// RevokeResource can find and cancel this session during setup. A
		// failed authorization ends the stream, so the entry is never reused.
		entry.resourceName = name
		s.Streams.SetResource(entry.session.ID, name)
		// Authorization is retryable: the mapping is rebuilt on Engine and pod
		// events, and Envoy treats PermissionDenied as terminal for a
		// subscription, which would leave the filter fail-closed for good.
		if !s.Authz.Authorize(name, entry.identity) {
			s.Metrics.AuthFailure("unauthorized")
			s.Logger.Info("ECDS subscription not authorized yet", "resource", name, "identity", entry.identity.Key(), "uid", entry.identity.UID)
			return status.Error(codes.Unavailable, "authorization is not ready")
		}
		engineKey, ok := s.Authz.EngineKey(name)
		if !ok {
			s.Metrics.AuthFailure("unauthorized")
			return status.Error(codes.Unavailable, "authorization is not ready")
		}
		// The cache is keyed by node.id, which the client controls. Rewrite it
		// to the authorized Engine key before CreateWatch runs.
		if req.Node == nil {
			req.Node = &corev3.Node{}
		}
		req.Node.Id = engineKey
		entry.engineKey = engineKey
		return nil
	}

	if req.GetResponseNonce() != "" {
		s.Metrics.Ack()
		s.nacks.Delete(entry.resourceName)
		s.Logger.Info("ECDS configuration accepted by proxy", "resource", entry.resourceName, "version", req.GetVersionInfo())
	}
	return nil
}

// resubscribeRejected reports whether the rejected configuration should end the
// stream so the proxy resubscribes. A cold proxy rejects the first push because
// the remote module is not cached yet, and Envoy never asks for that resource
// again on its own; the reconnect gives it the configuration once the fetch has
// completed.
// rejectedResourceName returns the resource a NACK refers to. Envoy may send it
// before the stream recorded its subscription.
func rejectedResourceName(entry *serverStream, req *discoveryv3.DiscoveryRequest) string {
	if entry.resourceName != "" {
		return entry.resourceName
	}
	if names := req.GetResourceNames(); len(names) == 1 {
		if name := names[0]; strings.HasPrefix(name, resourceNamePrefix) && !strings.ContainsAny(name, "*?") {
			return name
		}
	}
	return ""
}

func (s *Server) resubscribeRejected(entry *serverStream, resourceName, rejectedVersion string) {
	if resourceName == "" || s.Store == nil {
		return
	}
	// Retries of the same content carry a derived version; count them against
	// the version the Engine accepted.
	base := rejectedVersion
	if i := strings.Index(base, retryVersionSuffix); i > 0 {
		base = base[:i]
	}
	state := nackState{version: base, first: time.Now()}
	if prev, ok := s.nacks.Load(resourceName); ok {
		if current, ok := prev.(nackState); ok && current.version == base {
			state = current
		}
	}
	state.attempts++
	s.nacks.Store(resourceName, state)
	if state.attempts > nackRetryLimit || time.Since(state.first) > nackRetryWindow {
		s.Logger.Info("ECDS retry budget exhausted",
			"resource", resourceName, "version", rejectedVersion, "attempts", state.attempts)
		return
	}
	s.Logger.Info("resubscribing proxy after rejected configuration",
		"resource", resourceName, "version", rejectedVersion, "attempt", state.attempts)

	// Envoy never re-applies a version it rejected, and the remote module fetch
	// it started needs to finish first: publish a derived version and close the
	// stream so the proxy resubscribes and applies it from the code cache.
	attempt := state.attempts
	var sessionID uint64
	if entry.session != nil {
		sessionID = entry.session.ID
	}
	time.AfterFunc(s.RetryDelay, func() {
		if err := s.Store.BumpRejected(resourceName, attempt); err != nil {
			s.Logger.Error(err, "republish rejected configuration", "resource", resourceName)
			return
		}
		if sessionID != 0 {
			s.Streams.ResetStream(sessionID)
		}
	})
}

func (s *Server) onStreamClosed(streamID int64, _ *corev3.Node) {
	raw, ok := s.streams.LoadAndDelete(streamID)
	if !ok {
		// Rejected opens also trigger the closed callback; their slot was
		// already rolled back.
		return
	}
	s.openStreams.Add(-1)
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
