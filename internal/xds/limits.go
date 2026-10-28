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

// Package xds implements the operator-side ECDS serving plane: an immutable
// snapshot store, the state-of-the-world ExtensionConfigDiscoveryService,
// bearer-token authentication, per-Engine authorization, stream revalidation,
// TLS/ALPN dispatch, the digest-addressed WASM asset handler, readiness, and
// bounded metrics.
package xds

import (
	"flag"
	"fmt"
	"time"
)

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

const (
	// DefaultMaxMessageBytes bounds a single gRPC message (16 MiB).
	DefaultMaxMessageBytes = 16 << 20
	// DefaultMaxDecodedDataBytes bounds the decoded RuleData carried by one
	// Engine (8 MiB). RuleData is base64-encoded in the payload (4/3
	// expansion), so 8 MiB becomes ~10.7 MiB, and 4096 maximum-length
	// (253 byte) names add ~1 MiB of JSON keys and escaping: ~4.3 MiB of the
	// 16 MiB message remains for rule text and the ECDS envelope. The plugin
	// itself accepts up to 12 MiB of decoded RuleData and 16 MiB of payload.
	DefaultMaxDecodedDataBytes = 8 << 20
	// DefaultMaxDataFiles bounds the number of RuleData files per Engine.
	DefaultMaxDataFiles = 4096
	// DefaultMaxStreams bounds concurrent ECDS streams per replica.
	DefaultMaxStreams = 512
	// DefaultMaxStreamsPerIdentity bounds concurrent ECDS streams per
	// authenticated ServiceAccount.
	DefaultMaxStreamsPerIdentity = 8
	// DefaultMaxPendingWatches is the number of pending snapshot watches per
	// stream. Updates coalesce to the latest snapshot.
	DefaultMaxPendingWatches = 1
	// DefaultMaxQueuedUpdates is the number of queued snapshot updates per
	// stream. The latest snapshot always wins.
	DefaultMaxQueuedUpdates = 1
	// DefaultStreamMaxLifetime forces a reconnect so rotated tokens are
	// re-read.
	DefaultStreamMaxLifetime = 10 * time.Minute
	// DefaultTokenReviewRevalidate is the open-stream revalidation interval.
	DefaultTokenReviewRevalidate = 2 * time.Minute
	// DefaultAuthorizationMaxStaleness bounds how old an authorization mapping
	// may be before affected streams are closed and new subscriptions are
	// rejected.
	DefaultAuthorizationMaxStaleness = 5 * time.Minute
	// DefaultTokenReviewTimeout bounds one TokenReview call.
	DefaultTokenReviewTimeout = 5 * time.Second
	// DefaultTokenReviewRetries is the number of retries after the first
	// failed TokenReview call.
	DefaultTokenReviewRetries = 2
)

const (
	// MessageEnvelopeBytes reserves the DiscoveryResponse wrapper the xDS server
	// adds around a rendered resource (version_info, nonce, type_url, the
	// control-plane identifier and the Any framing). grpc.MaxSendMsgSize applies
	// to the whole message, so a resource that only fits without the wrapper is
	// Ready but undeliverable.
	MessageEnvelopeBytes = 1 << 10
	// DataFileNameBytes is the CKO API cap on a RuleData file name (and so the
	// plugin's cap on a data-file key).
	DataFileNameBytes = 253
	// dataFileKeyOverheadBytes bounds the JSON punctuation around one data-file
	// key (`"name":"content",`). Names are limited to [-._a-zA-Z0-9], so they
	// never need JSON escaping.
	dataFileKeyOverheadBytes = 8
)

// The plugin NACKs a configuration above its compile-time caps, so an operator
// configured past them would leave a Ready Engine without a published WAF.
const (
	pluginMaxMessageBytes     = 16 << 20
	pluginMaxDecodedDataBytes = 12 << 20
	pluginMaxDataFiles        = 4096
)

// Limits is the serving-plane resource envelope. Flag defaults live in
// DefaultLimits; the constant-only fields are not flags.
type Limits struct {
	MaxMessageBytes           int
	MaxDecodedDataBytes       int
	MaxDataFiles              int
	MaxStreams                int
	MaxStreamsPerIdentity     int
	MaxPendingWatches         int
	MaxQueuedUpdates          int
	StreamMaxLifetime         time.Duration
	TokenReviewRevalidate     time.Duration
	AuthorizationMaxStaleness time.Duration
	TokenReviewTimeout        time.Duration
	TokenReviewRetries        int
}

// DefaultLimits returns the plan defaults.
func DefaultLimits() Limits {
	return Limits{
		MaxMessageBytes:           DefaultMaxMessageBytes,
		MaxDecodedDataBytes:       DefaultMaxDecodedDataBytes,
		MaxDataFiles:              DefaultMaxDataFiles,
		MaxStreams:                DefaultMaxStreams,
		MaxStreamsPerIdentity:     DefaultMaxStreamsPerIdentity,
		MaxPendingWatches:         DefaultMaxPendingWatches,
		MaxQueuedUpdates:          DefaultMaxQueuedUpdates,
		StreamMaxLifetime:         DefaultStreamMaxLifetime,
		TokenReviewRevalidate:     DefaultTokenReviewRevalidate,
		AuthorizationMaxStaleness: DefaultAuthorizationMaxStaleness,
		TokenReviewTimeout:        DefaultTokenReviewTimeout,
		TokenReviewRetries:        DefaultTokenReviewRetries,
	}
}

// WithDefaults fills zero fields from DefaultLimits, so a partially set Limits
// still yields the full serving-plane envelope. Zero (or negative) means "use
// the default". Callers that accept Limits from flags or tests must apply it
// before using any field.
func (l Limits) WithDefaults() Limits {
	defaults := DefaultLimits()
	if l.MaxMessageBytes <= 0 {
		l.MaxMessageBytes = defaults.MaxMessageBytes
	}
	if l.MaxDecodedDataBytes <= 0 {
		l.MaxDecodedDataBytes = defaults.MaxDecodedDataBytes
	}
	if l.MaxDataFiles <= 0 {
		l.MaxDataFiles = defaults.MaxDataFiles
	}
	if l.MaxStreams <= 0 {
		l.MaxStreams = defaults.MaxStreams
	}
	if l.MaxStreamsPerIdentity <= 0 {
		l.MaxStreamsPerIdentity = defaults.MaxStreamsPerIdentity
	}
	if l.MaxPendingWatches <= 0 {
		l.MaxPendingWatches = defaults.MaxPendingWatches
	}
	if l.MaxQueuedUpdates <= 0 {
		l.MaxQueuedUpdates = defaults.MaxQueuedUpdates
	}
	if l.StreamMaxLifetime <= 0 {
		l.StreamMaxLifetime = defaults.StreamMaxLifetime
	}
	if l.TokenReviewRevalidate <= 0 {
		l.TokenReviewRevalidate = defaults.TokenReviewRevalidate
	}
	if l.AuthorizationMaxStaleness <= 0 {
		l.AuthorizationMaxStaleness = defaults.AuthorizationMaxStaleness
	}
	if l.TokenReviewTimeout <= 0 {
		l.TokenReviewTimeout = defaults.TokenReviewTimeout
	}
	if l.TokenReviewRetries < 0 {
		l.TokenReviewRetries = 0
	}
	return l
}

// Validate rejects limits the plugin cannot honour. Zero values pass and are
// filled by WithDefaults.
func (l Limits) Validate() error {
	l = l.WithDefaults()
	if l.MaxMessageBytes > pluginMaxMessageBytes {
		return fmt.Errorf("xds-max-message-bytes %d exceeds the plugin payload cap of %d bytes", l.MaxMessageBytes, pluginMaxMessageBytes)
	}
	if l.MaxDecodedDataBytes > pluginMaxDecodedDataBytes {
		return fmt.Errorf("xds-max-decoded-data-bytes %d exceeds the plugin decoded RuleData cap of %d bytes", l.MaxDecodedDataBytes, pluginMaxDecodedDataBytes)
	}
	if l.MaxDataFiles > pluginMaxDataFiles {
		return fmt.Errorf("xds-max-data-files %d exceeds the plugin data file cap of %d files", l.MaxDataFiles, pluginMaxDataFiles)
	}
	// Worst case: every RuleData byte is base64-expanded and every data file
	// name is at its maximum length. Base64 length is 4*ceil(size/3) per file,
	// so only counting the decoded total as one blob under-estimates the
	// padding; the bound allows 8 bytes of decoded input per data file, which
	// covers any per-file remainder. If that cannot fit one message, a
	// perfectly valid Engine would be accepted but never deliverable.
	base64Bytes := (l.MaxDecodedDataBytes*4 + 8*l.MaxDataFiles) / 3
	keyOverhead := l.MaxDataFiles * (DataFileNameBytes + dataFileKeyOverheadBytes)
	if required := base64Bytes + keyOverhead + MessageEnvelopeBytes; required > l.MaxMessageBytes {
		return fmt.Errorf("xds-max-decoded-data-bytes %d and xds-max-data-files %d need up to %d bytes once base64-encoded and keyed, which exceeds xds-max-message-bytes %d", l.MaxDecodedDataBytes, l.MaxDataFiles, required, l.MaxMessageBytes)
	}
	return nil
}

// AddFlags registers the serving-plane flags on fs.
func (l *Limits) AddFlags(fs *flag.FlagSet) {
	fs.IntVar(&l.MaxMessageBytes, "xds-max-message-bytes", DefaultMaxMessageBytes,
		"Maximum gRPC message size in bytes for the ECDS server (the plugin accepts at most 16 MiB of payload)")
	fs.IntVar(&l.MaxDecodedDataBytes, "xds-max-decoded-data-bytes", DefaultMaxDecodedDataBytes,
		"Maximum decoded RuleData bytes carried by one Engine (the plugin accepts at most 12 MiB)")
	fs.IntVar(&l.MaxDataFiles, "xds-max-data-files", DefaultMaxDataFiles,
		"Maximum number of RuleData files carried by one Engine (the plugin accepts at most 4096)")
	fs.IntVar(&l.MaxStreams, "xds-max-streams", DefaultMaxStreams,
		"Maximum concurrent ECDS streams per replica")
	fs.IntVar(&l.MaxStreamsPerIdentity, "xds-max-streams-per-identity", DefaultMaxStreamsPerIdentity,
		"Maximum concurrent ECDS streams per authenticated ServiceAccount")
	fs.DurationVar(&l.StreamMaxLifetime, "xds-stream-max-lifetime", DefaultStreamMaxLifetime,
		"Maximum ECDS stream lifetime before a forced reconnect (with jitter)")
	fs.DurationVar(&l.TokenReviewRevalidate, "xds-token-review-revalidate", DefaultTokenReviewRevalidate,
		"Interval between open-stream TokenReview and authorization revalidation")
	fs.DurationVar(&l.AuthorizationMaxStaleness, "xds-authorization-max-staleness", DefaultAuthorizationMaxStaleness,
		"Maximum age of an authorization mapping before affected streams are closed")
}
