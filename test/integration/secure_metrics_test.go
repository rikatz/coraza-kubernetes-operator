//go:build integration

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

package integration

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/networking-incubator/coraza-kubernetes-operator/test/framework"
)

const (
	operatorNamespace = "coraza-system"
	operatorSelector  = "control-plane=coraza-controller-manager"
	metricsPort       = 8443
)

// TestSecureMetrics verifies that the operator's metrics endpoint is served
// over HTTPS with TLS 1.3, requires authentication, and returns Prometheus
// metrics when properly authenticated.
func TestSecureMetrics(t *testing.T) {
	t.Parallel()
	s := fw.NewScenario(t)

	// -------------------------------------------------------------------------
	// Port-forward to the operator pod metrics port
	// -------------------------------------------------------------------------

	s.Step("port-forward to operator metrics")
	proxy := s.ProxyToPod(operatorNamespace, operatorSelector, metricsPort)
	metricsURL := fmt.Sprintf("https://localhost:%s/metrics", proxy.LocalPort())

	// Wait for the TLS endpoint to accept connections through the port-forward.
	tlsClient := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec // test against self-signed cert
			},
		},
	}
	require.Eventually(t, func() bool {
		resp, err := tlsClient.Get(metricsURL)
		if err != nil {
			return false
		}
		defer func() {
			_, _ = io.ReadAll(resp.Body)
			_ = resp.Body.Close()
		}()
		return true
	}, framework.DefaultTimeout, framework.DefaultInterval,
		"metrics endpoint not reachable via port-forward at %s", metricsURL,
	)

	// -------------------------------------------------------------------------
	// Verify TLS 1.3 is enforced
	// -------------------------------------------------------------------------

	s.Step("verify TLS 1.3 enforcement")
	t.Run("enforces TLS 1.3", func(t *testing.T) {
		tls12Client := &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true, //nolint:gosec // test against self-signed cert
					MaxVersion:         tls.VersionTLS12,
				},
			},
		}

		_, err := tls12Client.Get(metricsURL)
		require.Error(t, err, "TLS 1.2 connection should be rejected")
		t.Logf("TLS 1.2 correctly rejected: %v", err)
	})

	// -------------------------------------------------------------------------
	// Verify unauthenticated requests are rejected
	// -------------------------------------------------------------------------

	s.Step("verify unauthenticated requests rejected")
	t.Run("rejects unauthenticated requests", func(t *testing.T) {
		require.EventuallyWithT(t, func(collect *assert.CollectT) {
			resp, err := tlsClient.Get(metricsURL)
			if !assert.NoError(collect, err) {
				return
			}
			defer func() { _ = resp.Body.Close() }()
			assert.True(collect, resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden,
				"expected 401 or 403 for unauthenticated request, got %d", resp.StatusCode)
		}, framework.DefaultTimeout, framework.DefaultInterval)
	})

	// -------------------------------------------------------------------------
	// Verify authenticated requests succeed and return metrics
	// -------------------------------------------------------------------------

	s.Step("verify authenticated metrics access")
	t.Run("returns metrics with authentication", func(t *testing.T) {
		cmd := fw.Kubectl(operatorNamespace, "create", "token",
			"coraza-kubernetes-operator", "--duration=10m")
		tokenBytes, err := cmd.Output()
		require.NoError(t, err, "create service account token")
		token := strings.TrimSpace(string(tokenBytes))
		require.NotEmpty(t, token, "token should not be empty")

		require.EventuallyWithT(t, func(collect *assert.CollectT) {
			req, err := http.NewRequest(http.MethodGet, metricsURL, nil)
			if !assert.NoError(collect, err) {
				return
			}
			req.Header.Set("Authorization", "Bearer "+token)

			resp, err := tlsClient.Do(req)
			if !assert.NoError(collect, err) {
				return
			}
			defer func() { _ = resp.Body.Close() }()

			body, _ := io.ReadAll(resp.Body)

			assert.Equal(collect, http.StatusOK, resp.StatusCode,
				"expected 200 for authenticated metrics request, got %d: %s", resp.StatusCode, string(body))

			bodyStr := string(body)
			assert.Contains(collect, bodyStr, "# HELP",
				"metrics response should contain Prometheus HELP lines")
			assert.Contains(collect, bodyStr, "# TYPE",
				"metrics response should contain Prometheus TYPE lines")
		}, framework.DefaultTimeout, framework.DefaultInterval)
	})

	// -------------------------------------------------------------------------
	// Verify TLS connection uses TLS 1.3
	// -------------------------------------------------------------------------

	s.Step("verify TLS 1.3 negotiated")
	t.Run("connection uses TLS 1.3", func(t *testing.T) {
		conn, err := tls.Dial("tcp", fmt.Sprintf("localhost:%s", proxy.LocalPort()), &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // test against self-signed cert
		})
		require.NoError(t, err, "TLS dial should succeed")
		defer func() { _ = conn.Close() }()

		state := conn.ConnectionState()
		assert.Equal(t, uint16(tls.VersionTLS13), state.Version,
			"expected TLS 1.3, got 0x%04x", state.Version)
		t.Logf("TLS version: %s", tls.VersionName(state.Version))
	})
}
