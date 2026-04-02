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
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/transport/spdy"

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
	ctx := context.Background()

	// -------------------------------------------------------------------------
	// Step 1: Port-forward to the operator pod metrics port
	// -------------------------------------------------------------------------

	localPort := framework.AllocatePort()

	pods, err := fw.KubeClient.CoreV1().Pods(operatorNamespace).List(ctx, metav1.ListOptions{
		LabelSelector: operatorSelector,
	})
	require.NoError(t, err, "list operator pods")
	require.NotEmpty(t, pods.Items, "no operator pods found with selector %s", operatorSelector)

	podName := pods.Items[0].Name
	t.Logf("Port-forwarding to operator pod %s/%s port %d -> localhost:%s",
		operatorNamespace, podName, metricsPort, localPort)

	pfCtx, pfCancel := context.WithCancel(ctx)
	t.Cleanup(pfCancel)

	pfReady := make(chan struct{})
	pfErr := make(chan error, 1)
	go func() {
		transport, upgrader, err := spdy.RoundTripperFor(fw.RestConfig)
		if err != nil {
			pfErr <- fmt.Errorf("create SPDY transport: %w", err)
			return
		}

		pfURL := fw.KubeClient.CoreV1().RESTClient().Post().
			Resource("pods").
			Namespace(operatorNamespace).
			Name(podName).
			SubResource("portforward").
			URL()

		dialer := spdy.NewDialer(upgrader, &http.Client{Transport: transport}, "POST", pfURL)

		stopCh := make(chan struct{})
		go func() {
			<-pfCtx.Done()
			close(stopCh)
		}()

		pf, err := portforward.New(dialer,
			[]string{fmt.Sprintf("%s:%d", localPort, metricsPort)},
			stopCh, pfReady, io.Discard, io.Discard,
		)
		if err != nil {
			pfErr <- fmt.Errorf("create port-forwarder: %w", err)
			return
		}

		pfErr <- pf.ForwardPorts()
	}()

	select {
	case <-pfReady:
		t.Log("port-forward ready")
	case err := <-pfErr:
		t.Fatalf("port-forward failed to start: %v", err)
	case <-time.After(30 * time.Second):
		t.Fatal("timeout waiting for port-forward to become ready")
	}

	metricsURL := fmt.Sprintf("https://localhost:%s/metrics", localPort)

	// Use a TLS client that skips certificate verification (the operator
	// uses a self-signed cert by default in test environments).
	tlsClient := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec // test against self-signed cert
			},
		},
	}

	// -------------------------------------------------------------------------
	// Step 2: Verify TLS 1.3 is enforced
	// -------------------------------------------------------------------------

	t.Run("enforces TLS 1.3", func(t *testing.T) {
		// Try connecting with TLS 1.2 max — should fail
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
	// Step 3: Verify unauthenticated requests are rejected
	// -------------------------------------------------------------------------

	t.Run("rejects unauthenticated requests", func(t *testing.T) {
		require.EventuallyWithT(t, func(collect *assert.CollectT) {
			resp, err := tlsClient.Get(metricsURL)
			if !assert.NoError(collect, err) {
				return
			}
			defer func() { _ = resp.Body.Close() }()
			// controller-runtime returns 401 or 403 for unauthenticated requests
			assert.True(collect, resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden,
				"expected 401 or 403 for unauthenticated request, got %d", resp.StatusCode)
		}, 30*time.Second, 2*time.Second)
	})

	// -------------------------------------------------------------------------
	// Step 4: Verify authenticated requests succeed and return metrics
	// -------------------------------------------------------------------------

	t.Run("returns metrics with authentication", func(t *testing.T) {
		// Create a short-lived token for the operator's ServiceAccount which
		// already has the necessary RBAC to access its own metrics endpoint.
		cmd := fw.Kubectl(operatorNamespace, "create", "token",
			"coraza-kubernetes-operator", "--duration=300s")
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

			// Verify we get actual Prometheus metrics
			bodyStr := string(body)
			assert.Contains(collect, bodyStr, "# HELP",
				"metrics response should contain Prometheus HELP lines")
			assert.Contains(collect, bodyStr, "# TYPE",
				"metrics response should contain Prometheus TYPE lines")
		}, 30*time.Second, 2*time.Second)
	})

	// -------------------------------------------------------------------------
	// Step 5: Verify TLS connection uses TLS 1.3
	// -------------------------------------------------------------------------

	t.Run("connection uses TLS 1.3", func(t *testing.T) {
		conn, err := tls.Dial("tcp", fmt.Sprintf("localhost:%s", localPort), &tls.Config{
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
