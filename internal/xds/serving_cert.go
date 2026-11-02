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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	servingCertCAKey      = "ca.crt"
	servingCertCertKey    = "tls.crt"
	servingCertKeyKey     = "tls.key"
	servingCertValidity   = 365 * 24 * time.Hour
	servingCertRenewAfter = 30 * 24 * time.Hour

	servingCertManagedByLabel = "app.kubernetes.io/managed-by"
)

// +kubebuilder:rbac:groups="",namespace=system,resources=secrets,verbs=get;create;update

// ServingCert is a serving certificate and the CA bundle Gateways use to
// verify it. The operator provides it itself when no Secret is mounted (OLM
// and static-manifest installs).
type ServingCert struct {
	Certificate tls.Certificate
	CAPEM       []byte

	certPEM []byte
	keyPEM  []byte
}

// ServingCertOptions configures EnsureServingCert.
type ServingCertOptions struct {
	// Client writes the generated Secret. Required unless usable files exist.
	Client kubernetes.Interface
	// Namespace and SecretName locate the generated Secret.
	Namespace  string
	SecretName string
	// CertDir, CertName, KeyName and CAPath are the mounted-file locations.
	CertDir  string
	CertName string
	KeyName  string
	CAPath   string
	// DNSNames and IPAddresses are the serving certificate SANs.
	DNSNames    []string
	IPAddresses []net.IP
	Logger      logr.Logger
}

// EnsureServingCert returns a certificate in one of three ways:
//
//  1. the mounted files at CertDir/CAPath: nil is returned and the listener
//     keeps watching those files, exactly as before;
//  2. the operator-managed Secret, loaded without touching the files;
//  3. a newly generated CA and leaf, stored in the Secret so every replica and
//     restart serves the same identity.
//
// It returns an error only when no certificate is available and none can be
// generated.
func EnsureServingCert(ctx context.Context, opts ServingCertOptions) (*ServingCert, error) {
	opts.CertDir = defaultString(opts.CertDir, defaultCertDir)
	opts.CertName = defaultString(opts.CertName, defaultCertName)
	opts.KeyName = defaultString(opts.KeyName, defaultKeyName)
	opts.CAPath = defaultString(opts.CAPath, defaultCAPath)
	if opts.Logger.GetSink() == nil {
		opts.Logger = logr.Discard()
	}

	if mountedServingCert(opts) {
		opts.Logger.Info("Using the mounted xDS serving certificate",
			"cert", filepath.Join(opts.CertDir, opts.CertName))
		return nil, nil
	}

	if opts.SecretName == "" || opts.Namespace == "" {
		return nil, errors.New("no xDS serving certificate is mounted and no Secret name is configured: set --xds-cert-secret or provide the certificate files")
	}
	if opts.Client == nil {
		return nil, errors.New("no xDS serving certificate is mounted and no Kubernetes client is available to read or create the serving Secret")
	}

	secret, err := opts.Client.CoreV1().Secrets(opts.Namespace).Get(ctx, opts.SecretName, metav1.GetOptions{})
	switch {
	case err == nil:
		if servingCert, ok := parseServingCert(secret); ok {
			opts.Logger.Info("Using the operator-managed xDS serving certificate",
				"secret", opts.Namespace+"/"+opts.SecretName)
			return servingCert, nil
		}
		opts.Logger.Info("The xDS serving certificate is invalid or expiring; regenerating",
			"secret", opts.Namespace+"/"+opts.SecretName)
		generated, genErr := generateServingCert(opts)
		if genErr != nil {
			return nil, genErr
		}
		if updateErr := updateServingCert(ctx, opts, secret, generated); updateErr != nil {
			return nil, updateErr
		}
		return generated, nil
	case !apierrors.IsNotFound(err):
		return nil, fmt.Errorf("get xDS serving Secret %s/%s: %w", opts.Namespace, opts.SecretName, err)
	}

	generated, err := generateServingCert(opts)
	if err != nil {
		return nil, err
	}
	if err := createServingCert(ctx, opts, generated); err != nil {
		return nil, err
	}
	opts.Logger.Info("Generated the xDS serving certificate",
		"secret", opts.Namespace+"/"+opts.SecretName, "dnsNames", opts.DNSNames)
	return generated, nil
}

// mountedServingCert reports a parsable certificate at the mounted paths. It
// deliberately ignores expiry: a mounted Secret is rotated by its owner, and
// the operator must not silently replace material it does not manage.
func mountedServingCert(opts ServingCertOptions) bool {
	certPEM, err := os.ReadFile(filepath.Join(opts.CertDir, opts.CertName))
	if err != nil {
		return false
	}
	keyPEM, err := os.ReadFile(filepath.Join(opts.CertDir, opts.KeyName))
	if err != nil {
		return false
	}
	caPEM, err := os.ReadFile(opts.CAPath)
	if err != nil || !validCAPEM(caPEM) {
		return false
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil || len(cert.Certificate) == 0 {
		return false
	}
	_, err = x509.ParseCertificate(cert.Certificate[0])
	return err == nil
}

// parseServingCert returns the certificate stored in a Secret when it is
// valid and not close to expiry.
func parseServingCert(secret *corev1.Secret) (*ServingCert, bool) {
	certPEM, ok := secret.Data[servingCertCertKey]
	if !ok {
		return nil, false
	}
	keyPEM, ok := secret.Data[servingCertKeyKey]
	if !ok {
		return nil, false
	}
	caPEM, ok := secret.Data[servingCertCAKey]
	if !ok {
		return nil, false
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil || len(cert.Certificate) == 0 {
		return nil, false
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil || !servingCertCurrent(leaf) {
		return nil, false
	}
	caDER := certPEMBlock(caPEM)
	if caDER == nil {
		return nil, false
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil || !servingCertCurrent(ca) {
		return nil, false
	}
	return &ServingCert{Certificate: cert, CAPEM: caPEM, certPEM: certPEM, keyPEM: keyPEM}, true
}

// servingCertCurrent reports whether the certificate is valid beyond the
// renewal window, so a restart does not shorten the remaining lifetime.
func servingCertCurrent(cert *x509.Certificate) bool {
	now := time.Now()
	return now.After(cert.NotBefore) && now.Add(servingCertRenewAfter).Before(cert.NotAfter)
}

// createServingCert stores generated material. Another replica may win the
// creation race; its Secret is the shared identity, so read it back.
func createServingCert(ctx context.Context, opts ServingCertOptions, servingCert *ServingCert) error {
	secret := servingCertSecret(opts.Namespace, opts.SecretName, servingCert)
	_, err := opts.Client.CoreV1().Secrets(opts.Namespace).Create(ctx, secret, metav1.CreateOptions{})
	if err == nil {
		return nil
	}
	if !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create xDS serving Secret %s/%s: %w", opts.Namespace, opts.SecretName, err)
	}
	existing, getErr := opts.Client.CoreV1().Secrets(opts.Namespace).Get(ctx, opts.SecretName, metav1.GetOptions{})
	if getErr != nil {
		return fmt.Errorf("read xDS serving Secret %s/%s after a create race: %w", opts.Namespace, opts.SecretName, getErr)
	}
	adopted, ok := parseServingCert(existing)
	if !ok {
		return fmt.Errorf("xDS serving Secret %s/%s was created concurrently with invalid content", opts.Namespace, opts.SecretName)
	}
	*servingCert = *adopted
	return nil
}

// updateServingCert replaces invalid or expiring material. A concurrent
// renewal is adopted rather than retried blindly.
func updateServingCert(ctx context.Context, opts ServingCertOptions, existing *corev1.Secret, servingCert *ServingCert) error {
	secret := servingCertSecret(opts.Namespace, opts.SecretName, servingCert)
	secret.ResourceVersion = existing.ResourceVersion
	_, err := opts.Client.CoreV1().Secrets(opts.Namespace).Update(ctx, secret, metav1.UpdateOptions{})
	if err == nil {
		return nil
	}
	if !apierrors.IsConflict(err) {
		return fmt.Errorf("update xDS serving Secret %s/%s: %w", opts.Namespace, opts.SecretName, err)
	}
	current, getErr := opts.Client.CoreV1().Secrets(opts.Namespace).Get(ctx, opts.SecretName, metav1.GetOptions{})
	if getErr != nil {
		return fmt.Errorf("read xDS serving Secret %s/%s after a renewal race: %w", opts.Namespace, opts.SecretName, getErr)
	}
	adopted, ok := parseServingCert(current)
	if !ok {
		return fmt.Errorf("xDS serving Secret %s/%s was renewed concurrently with invalid content", opts.Namespace, opts.SecretName)
	}
	*servingCert = *adopted
	return nil
}

func servingCertSecret(namespace, name string, servingCert *ServingCert) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels: map[string]string{
				servingCertManagedByLabel: "coraza-kubernetes-operator",
			},
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			servingCertCAKey:   servingCert.CAPEM,
			servingCertCertKey: servingCert.certPEM,
			servingCertKeyKey:  servingCert.keyPEM,
		},
	}
}

func generateServingCert(opts ServingCertOptions) (*ServingCert, error) {
	if len(opts.DNSNames) == 0 && len(opts.IPAddresses) == 0 {
		return nil, errors.New("cannot generate the xDS serving certificate without a DNS name or IP address")
	}
	now := time.Now()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate xDS CA key: %w", err)
	}
	caSerial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate xDS CA serial: %w", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          caSerial,
		Subject:               pkix.Name{CommonName: "coraza-kubernetes-operator-ca", Organization: []string{"coraza-kubernetes-operator"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(servingCertValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("generate xDS CA certificate: %w", err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate xDS serving key: %w", err)
	}
	leafSerial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate xDS serving serial: %w", err)
	}
	commonName := "coraza-kubernetes-operator"
	if len(opts.DNSNames) > 0 {
		commonName = opts.DNSNames[0]
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: leafSerial,
		Subject:      pkix.Name{CommonName: commonName, Organization: []string{"coraza-kubernetes-operator"}},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(servingCertValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     opts.DNSNames,
		IPAddresses:  opts.IPAddresses,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caTemplate, &leafKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("generate xDS serving certificate: %w", err)
	}
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		return nil, fmt.Errorf("encode xDS serving key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	cert, err := tls.X509KeyPair(leafPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("load generated xDS serving certificate: %w", err)
	}
	return &ServingCert{Certificate: cert, CAPEM: caPEM, certPEM: leafPEM, keyPEM: keyPEM}, nil
}

// certPEMBlock returns the first CERTIFICATE block, or nil.
func certPEMBlock(certPEM []byte) []byte {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil
	}
	return block.Bytes
}

func validCAPEM(caPEM []byte) bool {
	pool := x509.NewCertPool()
	return pool.AppendCertsFromPEM(caPEM)
}

func defaultString(value, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}
