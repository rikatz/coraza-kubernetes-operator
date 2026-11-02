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
	"bytes"
	"context"
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

const (
	testServingCertNamespace = "coraza-system"
	testServingCertSecret    = "coraza-kubernetes-operator-serving-cert"
	testServingCertDNS       = "coraza-kubernetes-operator.coraza-system.svc"
)

func testServingCertOptions(t *testing.T, client *k8sfake.Clientset, dir string) ServingCertOptions {
	t.Helper()
	return ServingCertOptions{
		Client:      client,
		Namespace:   testServingCertNamespace,
		SecretName:  testServingCertSecret,
		CertDir:     dir,
		CertName:    "tls.crt",
		KeyName:     "tls.key",
		CAPath:      filepath.Join(dir, "ca.crt"),
		DNSNames:    []string{testServingCertDNS},
		IPAddresses: []net.IP{net.ParseIP("10.0.0.10")},
		Logger:      logr.Discard(),
	}
}

func mustServingCert(t *testing.T) *ServingCert {
	t.Helper()
	cert, err := EnsureServingCert(context.Background(), testServingCertOptions(t, k8sfake.NewSimpleClientset(), t.TempDir()))
	if err != nil {
		t.Fatalf("EnsureServingCert() error = %v", err)
	}
	if cert == nil {
		t.Fatal("EnsureServingCert() returned no certificate")
	}
	return cert
}

func TestEnsureServingCertGeneratesAndPersists(t *testing.T) {
	client := k8sfake.NewSimpleClientset()
	cert, err := EnsureServingCert(context.Background(), testServingCertOptions(t, client, t.TempDir()))
	if err != nil {
		t.Fatalf("EnsureServingCert() error = %v", err)
	}
	if cert == nil || len(cert.Certificate.Certificate) == 0 {
		t.Fatal("EnsureServingCert() returned no certificate")
	}

	leaf, err := x509.ParseCertificate(cert.Certificate.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(cert.CAPEM) {
		t.Fatal("generated CA is not a valid PEM bundle")
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: testServingCertDNS}); err != nil {
		t.Fatalf("generated certificate does not verify against its CA: %v", err)
	}
	if len(leaf.IPAddresses) != 1 || !leaf.IPAddresses[0].Equal(net.ParseIP("10.0.0.10")) {
		t.Fatalf("IP SANs = %v, want 10.0.0.10", leaf.IPAddresses)
	}

	secret, err := client.CoreV1().Secrets(testServingCertNamespace).Get(context.Background(), testServingCertSecret, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get generated Secret: %v", err)
	}
	if !bytes.Equal(secret.Data[servingCertCAKey], cert.CAPEM) {
		t.Fatal("Secret CA does not match the served CA")
	}
	if !bytes.Equal(secret.Data[servingCertCertKey], cert.certPEM) {
		t.Fatal("Secret certificate does not match the served certificate")
	}
	if !bytes.Equal(secret.Data[servingCertKeyKey], cert.keyPEM) {
		t.Fatal("Secret key does not match the served key")
	}
}

func TestEnsureServingCertReusesStoredCertificate(t *testing.T) {
	client := k8sfake.NewSimpleClientset()
	opts := testServingCertOptions(t, client, t.TempDir())

	first, err := EnsureServingCert(context.Background(), opts)
	if err != nil {
		t.Fatalf("first EnsureServingCert() error = %v", err)
	}
	firstLeaf, err := x509.ParseCertificate(first.Certificate.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}

	before := len(client.Actions())
	second, err := EnsureServingCert(context.Background(), opts)
	if err != nil {
		t.Fatalf("second EnsureServingCert() error = %v", err)
	}
	secondLeaf, err := x509.ParseCertificate(second.Certificate.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if firstLeaf.SerialNumber.Cmp(secondLeaf.SerialNumber) != 0 {
		t.Fatal("a valid stored certificate was replaced")
	}
	for _, action := range client.Actions()[before:] {
		if action.GetVerb() != "get" {
			t.Fatalf("a reused certificate produced a %s call", action.GetVerb())
		}
	}
}

func TestEnsureServingCertUsesMountedFiles(t *testing.T) {
	sourceDir := t.TempDir()
	source := testServingCertOptions(t, k8sfake.NewSimpleClientset(), sourceDir)
	generated, err := EnsureServingCert(context.Background(), source)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "tls.crt"), generated.certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tls.key"), generated.keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ca.crt"), generated.CAPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	client := k8sfake.NewSimpleClientset()
	mounted, err := EnsureServingCert(context.Background(), testServingCertOptions(t, client, dir))
	if err != nil {
		t.Fatalf("EnsureServingCert() error = %v", err)
	}
	if mounted != nil {
		t.Fatal("a mounted certificate must leave the listener watching the files")
	}
	if actions := client.Actions(); len(actions) != 0 {
		t.Fatalf("mounted files caused %d Kubernetes calls", len(actions))
	}
}

func TestEnsureServingCertRegeneratesInvalidSecret(t *testing.T) {
	client := k8sfake.NewSimpleClientset(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: testServingCertSecret, Namespace: testServingCertNamespace},
		Data: map[string][]byte{
			servingCertCAKey:   []byte("not a CA"),
			servingCertCertKey: []byte("not a certificate"),
			servingCertKeyKey:  []byte("not a key"),
		},
	})
	cert, err := EnsureServingCert(context.Background(), testServingCertOptions(t, client, t.TempDir()))
	if err != nil {
		t.Fatalf("EnsureServingCert() error = %v", err)
	}
	if cert == nil {
		t.Fatal("EnsureServingCert() returned no certificate")
	}
	secret, err := client.CoreV1().Secrets(testServingCertNamespace).Get(context.Background(), testServingCertSecret, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(secret.Data[servingCertCAKey], cert.CAPEM) {
		t.Fatal("invalid Secret was not replaced")
	}
}

func TestEnsureServingCertReportsSecretErrors(t *testing.T) {
	client := k8sfake.NewSimpleClientset()
	client.PrependReactor("get", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "secrets"}, testServingCertSecret, nil)
	})
	_, err := EnsureServingCert(context.Background(), testServingCertOptions(t, client, t.TempDir()))
	if err == nil {
		t.Fatal("EnsureServingCert() error = nil, want the RBAC failure")
	}
}

func TestEnsureServingCertRequiresSecretConfiguration(t *testing.T) {
	_, err := EnsureServingCert(context.Background(), ServingCertOptions{
		CertDir:  t.TempDir(),
		CertName: "tls.crt",
		KeyName:  "tls.key",
		CAPath:   filepath.Join(t.TempDir(), "ca.crt"),
	})
	if err == nil {
		t.Fatal("EnsureServingCert() error = nil, want a configuration error")
	}
}

func TestCertWatcherServesStaticCertificate(t *testing.T) {
	servingCert := mustServingCert(t)
	dir := t.TempDir()
	watcher := newCertWatcher(dir, "tls.crt", "tls.key", servingCert, logr.Discard())

	got, err := watcher.GetCertificate(nil)
	if err != nil {
		t.Fatalf("GetCertificate() error = %v", err)
	}
	if got == nil || !bytes.Equal(got.Certificate[0], servingCert.Certificate.Certificate[0]) {
		t.Fatal("GetCertificate() did not return the static certificate")
	}
	if err := watcher.Ready(); err != nil {
		t.Fatalf("Ready() error = %v", err)
	}
	if err := watcher.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
}

func TestNewDependenciesUsesStaticServingCert(t *testing.T) {
	servingCert := mustServingCert(t)
	deps, err := NewDependencies(Config{
		KubeClient:  k8sfake.NewSimpleClientset(),
		ServingCert: servingCert,
		Registry:    prometheus.NewRegistry(),
	})
	if err != nil {
		t.Fatalf("NewDependencies() error = %v", err)
	}
	if !bytes.Equal(deps.CA.PEM(), servingCert.CAPEM) {
		t.Fatal("the CA source does not expose the static serving CA")
	}
	if deps.Listener == nil {
		t.Fatal("listener is nil")
	}
}
