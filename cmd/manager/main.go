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

package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	ctrlcache "sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
	"sigs.k8s.io/controller-runtime/pkg/metrics/filters"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	wafv1alpha1 "github.com/networking-incubator/coraza-kubernetes-operator/api/v1alpha1"
	"github.com/networking-incubator/coraza-kubernetes-operator/internal/controller"
	"github.com/networking-incubator/coraza-kubernetes-operator/internal/rulesets/cache"
	"github.com/networking-incubator/coraza-kubernetes-operator/internal/xds"
	// +kubebuilder:scaffold:imports
)

// -----------------------------------------------------------------------------
// Scheme Registration
// -----------------------------------------------------------------------------

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(wafv1alpha1.AddToScheme(scheme))
	utilruntime.Must(gatewayv1.Install(scheme))
	// +kubebuilder:scaffold:scheme
}

// -----------------------------------------------------------------------------
// Vars
// -----------------------------------------------------------------------------

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

// -----------------------------------------------------------------------------
// Main
// -----------------------------------------------------------------------------

func main() {
	cfg := parseFlags()
	setupLog = ctrl.Log.WithName("setup")
	logFlags()
	setupLog.Info("Deprecated flags are accepted but ignored",
		"flags", "--default-wasm-image, --envoy-cluster-name")

	tlsOpts := buildTLSOpts()

	podNamespace := os.Getenv("POD_NAMESPACE")
	if podNamespace == "" {
		setupLog.Error(errors.New("missing required environment variable"), "POD_NAMESPACE must be set (typically via the downward API)")
		os.Exit(1)
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		Metrics:                buildMetricsServerOptions(cfg, tlsOpts),
		HealthProbeBindAddress: cfg.probeAddr,
		LeaderElection:         cfg.enableLeaderElect,
		LeaderElectionID:       "waf.k8s.coraza.io",
		Cache:                  buildCacheOptions(podNamespace),
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	kubeClient, err := kubernetes.NewForConfig(mgr.GetConfig())
	if err != nil {
		setupLog.Error(err, "unable to create kubernetes clientset")
		os.Exit(1)
	}

	rulesetCache := setupRuleSetCache(cfg)

	// Helm installs mount a chart-managed Secret and keep using it. OLM and
	// static-manifest installs have no way to mint one, so the operator loads
	// or generates its own and stores it in a Secret both paths can share.
	certCtx, cancelCert := context.WithTimeout(context.Background(), 30*time.Second)
	certDNSNames, certIPs := servingCertSANs(cfg, podNamespace)
	servingCert, err := xds.EnsureServingCert(certCtx, xds.ServingCertOptions{
		Client:      kubeClient,
		Namespace:   podNamespace,
		SecretName:  cfg.servingCertSecretName(),
		CertDir:     cfg.xdsCertDir,
		CertName:    cfg.xdsCertName,
		KeyName:     cfg.xdsKeyName,
		CAPath:      cfg.xdsCAPath,
		DNSNames:    certDNSNames,
		IPAddresses: certIPs,
		Logger:      setupLog.WithName("xds-cert"),
	})
	cancelCert()
	if err != nil {
		setupLog.Error(err, "unable to provide the xDS serving certificate")
		os.Exit(1)
	}

	xdsDeps, err := xds.NewDependencies(xds.Config{
		KubeClient:    kubeClient,
		Reader:        mgr.GetClient(),
		APIReader:     mgr.GetAPIReader(),
		Cache:         mgr.GetCache(),
		BindAddress:   cfg.xdsBindAddress,
		TokenAudience: cfg.xdsTokenAudience,
		CertDir:       cfg.xdsCertDir,
		CertName:      cfg.xdsCertName,
		KeyName:       cfg.xdsKeyName,
		CAPath:        cfg.xdsCAPath,
		ServingCert:   servingCert,
		Limits:        cfg.xdsLimits,
		Registry:      metrics.Registry,
		Logger:        ctrl.Log.WithName("xds"),
	})
	if err != nil {
		setupLog.Error(err, "unable to construct xDS serving plane")
		os.Exit(1)
	}

	ecdsConfig, assetBaseURL, err := buildECDSConfig(cfg, podNamespace, xdsDeps.CA)
	if err != nil {
		setupLog.Error(err, "invalid ECDS configuration")
		os.Exit(1)
	}
	if err := controller.SetupControllers(mgr, controller.Deps{
		KubeClient:        kubeClient,
		RuleSetCache:      rulesetCache,
		IstioRevision:     cfg.istioRevision,
		OperatorNamespace: podNamespace,
		ECDSConfig:        ecdsConfig,
		AssetBaseURL:      assetBaseURL,
		XDS:               xdsDeps,
	}); err != nil {
		setupLog.Error(err, "unable to setup controllers")
		os.Exit(1)
	}

	if err := mgr.Add(xdsDeps.Listener); err != nil {
		setupLog.Error(err, "unable to add xDS listener runnable")
		os.Exit(1)
	}
	if err := mgr.Add(xdsDeps.Streams); err != nil {
		setupLog.Error(err, "unable to add xDS revalidation runnable")
		os.Exit(1)
	}

	// +kubebuilder:scaffold:builder

	setupHealthChecks(mgr, xdsDeps)

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

type config struct {
	metricsAddr       string
	probeAddr         string
	enableLeaderElect bool
	metricsCertPath   string
	metricsCertName   string
	metricsCertKey    string
	cacheGCInterval   time.Duration
	cacheMaxAge       time.Duration
	cacheMaxSize      int
	cacheServerPort   int

	// Deprecated and ignored: kept so the chart can keep passing them until
	// Phase 7 removes the flags and the chart arguments together.
	envoyClusterName string
	defaultWasmImage string

	istioRevision string
	operatorName  string

	// ECDS settings: the address Gateways dial for config discovery, the port
	// appended when the address has none, the base URL of the WASM asset, and
	// the CA used to verify the operator certificate.
	xdsAdvertiseAddress string
	xdsPort             int
	assetBaseURL        string
	xdsCAPath           string
	operatorServiceName string

	// ECDS serving plane.
	xdsBindAddress   string
	xdsTokenAudience string
	xdsCertDir       string
	xdsCertName      string
	xdsKeyName       string
	xdsCertSecret    string
	xdsLimits        xds.Limits
}

func parseFlags() config {
	var cfg config

	flag.StringVar(&cfg.metricsAddr, "metrics-bind-address", "0", "The address the metrics endpoint binds to. "+
		"Use :8443 for HTTPS or leave as 0 to disable the metrics service.")
	flag.StringVar(&cfg.probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&cfg.enableLeaderElect, "leader-elect", false, "Enable leader election for controller manager. "+
		"Enabling this will ensure there is only one active controller manager.")
	flag.StringVar(&cfg.metricsCertPath, "metrics-cert-path", "", "The directory that contains the metrics server certificate.")
	flag.StringVar(&cfg.metricsCertName, "metrics-cert-name", "tls.crt", "The name of the metrics server certificate file.")
	flag.StringVar(&cfg.metricsCertKey, "metrics-cert-key", "tls.key", "The name of the metrics server key file.")
	// Deprecated: the RuleSet cache server is not started and nothing populates
	// the cache, so these four flags are accepted for chart compatibility only.
	flag.DurationVar(&cfg.cacheGCInterval, "cache-gc-interval", cache.CacheGCInterval, "Deprecated and ignored")
	flag.DurationVar(&cfg.cacheMaxAge, "cache-max-age", cache.CacheMaxAge, "Deprecated and ignored")
	flag.IntVar(&cfg.cacheMaxSize, "cache-max-size", cache.CacheMaxSize, "Deprecated and ignored")
	flag.IntVar(&cfg.cacheServerPort, "cache-server-port", controller.DefaultRuleSetCacheServerPort, "Deprecated and ignored")
	// Deprecated: accepted for chart compatibility until Phase 7 removes both
	// the flags and the chart arguments. Neither value is used.
	flag.StringVar(&cfg.envoyClusterName, "envoy-cluster-name", "", "Deprecated and ignored")
	flag.StringVar(&cfg.istioRevision, "istio-revision", "", "The Istio revision label value for managed Istio resources")
	flag.StringVar(&cfg.defaultWasmImage, "default-wasm-image", "", "Deprecated and ignored")
	flag.StringVar(&cfg.operatorName, "operator-name", "",
		"Helm release name; the fallback Service name for the default xDS advertise address when --operator-service-name is unset")
	flag.StringVar(&cfg.xdsAdvertiseAddress, "xds-advertise-address", "",
		"The operator address Gateways dial for ECDS; defaults to <operator-service-name>.<POD_NAMESPACE>.svc.cluster.local")
	flag.IntVar(&cfg.xdsPort, "xds-port", controller.DefaultRuleSetCacheServerPort,
		"The operator ECDS port appended to the advertise address when it has no port")
	flag.StringVar(&cfg.assetBaseURL, "asset-base-url", "",
		"The base URL Envoy fetches the WASM asset from; defaults to https://<advertise-address>")
	flag.StringVar(&cfg.xdsCAPath, "xds-ca-path", "/etc/coraza-tls/ca.crt",
		"The CA bundle Gateways use to verify the operator certificate")
	flag.StringVar(&cfg.operatorServiceName, "operator-service-name", "",
		"The operator Service name used to derive the default xDS advertise address")
	flag.StringVar(&cfg.xdsBindAddress, "xds-bind-address", ":18080",
		"The address the ECDS and WASM asset listener binds to")
	flag.StringVar(&cfg.xdsTokenAudience, "xds-token-audience", "",
		"The expected TokenReview audience; empty uses the API server default audience")
	flag.StringVar(&cfg.xdsCertDir, "xds-cert-path", "/etc/coraza-tls",
		"The directory that contains the xDS serving certificate and CA bundle")
	flag.StringVar(&cfg.xdsCertName, "xds-cert-name", "tls.crt",
		"The name of the xDS serving certificate file")
	flag.StringVar(&cfg.xdsKeyName, "xds-key-name", "tls.key",
		"The name of the xDS serving key file")
	flag.StringVar(&cfg.xdsCertSecret, "xds-cert-secret", "",
		"The Secret the operator creates and reuses for its xDS serving certificate when no certificate is mounted; defaults to <operator-name>-serving-cert")
	cfg.xdsLimits = xds.DefaultLimits()
	cfg.xdsLimits.AddFlags(flag.CommandLine)

	opts := zap.Options{Development: false}
	opts.BindFlags(flag.CommandLine)

	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	return cfg
}

// buildECDSConfig derives the ECDS endpoint and asset base URL from the flags,
// and loads the CA bundle. A missing CA is not fatal: Engine reconciliation
// reports TLSNotConfigured instead of rendering an unverified chain. A missing
// advertise address is fatal: every Engine would fail to render its EnvoyFilter.
func buildECDSConfig(cfg config, podNamespace string, ca *xds.CASource) (controller.ECDSConfig, string, error) {
	advertise := cfg.xdsAdvertiseAddress
	if advertise == "" {
		serviceName := cfg.operatorServiceName
		if serviceName == "" {
			// The chart passes the release fullname as --operator-name, which is
			// also the Service name.
			serviceName = cfg.operatorName
		}
		if serviceName != "" {
			advertise = fmt.Sprintf("%s.%s.svc.cluster.local", serviceName, podNamespace)
		}
	}
	if advertise == "" {
		return controller.ECDSConfig{}, "", fmt.Errorf("the xDS advertise address is not configured: set --xds-advertise-address, --operator-service-name, or --operator-name")
	}
	if advertise != "" {
		if _, _, err := net.SplitHostPort(advertise); err != nil {
			// A bracketed IPv6 literal is already a complete host; JoinHostPort
			// would wrap it a second time.
			host := strings.TrimSuffix(strings.TrimPrefix(advertise, "["), "]")
			advertise = net.JoinHostPort(host, strconv.Itoa(cfg.xdsPort))
		}
	}

	assetBaseURL := cfg.assetBaseURL
	if assetBaseURL == "" && advertise != "" {
		assetBaseURL = "https://" + advertise
	}

	// The listener and the Engine reconciler share one source, so a CA mounted
	// after startup reaches new EnvoyFilters without a restart.
	caPEM := ca.PEM()
	if len(caPEM) == 0 {
		setupLog.Info("xDS CA bundle unavailable; Engine reconciliation will report TLSNotConfigured",
			"path", cfg.xdsCAPath)
	}

	return controller.ECDSConfig{
		AdvertiseAddress: advertise,
		ListenPort:       listenPort(cfg.xdsBindAddress),
		CAPEM:            caPEM,
		CASource:         ca,
	}, assetBaseURL, nil
}

// servingCertSecretName is the Secret the operator writes when no certificate
// is mounted. The chart and the OLM CSV both pass --operator-name, so this is
// the same name the chart uses when it generates the Secret itself.
func (c config) servingCertSecretName() string {
	if c.xdsCertSecret != "" {
		return c.xdsCertSecret
	}
	name := c.operatorName
	if name == "" {
		name = "coraza-kubernetes-operator"
	}
	return name + "-serving-cert"
}

// servingCertSANs lists every name a Gateway may dial the operator by. The
// advertise address is included so a custom address keeps working.
func servingCertSANs(cfg config, podNamespace string) ([]string, []net.IP) {
	names := map[string]struct{}{}
	add := func(name string) {
		if name != "" {
			names[name] = struct{}{}
		}
	}
	service := cfg.operatorServiceName
	if service == "" {
		service = cfg.operatorName
	}
	if service != "" {
		add(service)
		add(service + "." + podNamespace)
		add(service + "." + podNamespace + ".svc")
		add(service + "." + podNamespace + ".svc.cluster.local")
	}

	var ips []net.IP
	if cfg.xdsAdvertiseAddress != "" {
		host := cfg.xdsAdvertiseAddress
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
		if ip := net.ParseIP(host); ip != nil {
			ips = append(ips, ip)
		} else {
			add(host)
		}
	}

	dnsNames := make([]string, 0, len(names))
	for name := range names {
		dnsNames = append(dnsNames, name)
	}
	sort.Strings(dnsNames)
	return dnsNames, ips
}

// listenPort returns the port the ECDS listener actually binds. The Engine
// NetworkPolicy must allow this port, not the advertised default.
func listenPort(address string) int32 {
	_, portText, err := net.SplitHostPort(address)
	if err != nil {
		return 0
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return 0
	}
	return int32(port)
}

func logFlags() {
	var kvs []any
	flag.VisitAll(func(f *flag.Flag) {
		kvs = append(kvs, f.Name, f.Value.String())
	})
	setupLog.Info("configuration", kvs...)
}

func buildTLSOpts() []func(*tls.Config) {
	return []func(*tls.Config){
		func(c *tls.Config) {
			c.MinVersion = tls.VersionTLS13
			// Disable HTTP/2 to mitigate HTTP/2 Rapid Reset (CVE-2023-44487)
			// and related stream-cancellation DoS attacks.
			c.NextProtos = []string{"http/1.1"}
		},
	}
}

func buildMetricsServerOptions(cfg config, tlsOpts []func(*tls.Config)) metricsserver.Options {
	opts := metricsserver.Options{
		BindAddress:    cfg.metricsAddr,
		SecureServing:  true,
		TLSOpts:        tlsOpts,
		FilterProvider: filters.WithAuthenticationAndAuthorization,
	}

	if len(cfg.metricsCertPath) > 0 {
		setupLog.Info("Initializing metrics certificate watcher using provided certificates",
			"metrics-cert-path", cfg.metricsCertPath, "metrics-cert-name", cfg.metricsCertName, "metrics-cert-key", cfg.metricsCertKey)

		opts.CertDir = cfg.metricsCertPath
		opts.CertName = cfg.metricsCertName
		opts.KeyName = cfg.metricsCertKey
	}

	return opts
}

// buildCacheOptions returns cache options that scope the NetworkPolicy informer
// to the operator namespace, and the Pod informer to Gateway data-plane pods
// (label-selected, with the churny parts of PodStatus stripped). Without this,
// the controllers would cache every Pod and NetworkPolicy in the cluster.
func buildCacheOptions(operatorNamespace string) ctrlcache.Options {
	return ctrlcache.Options{
		DefaultTransform: ctrlcache.TransformStripManagedFields(),
		ByObject: map[client.Object]ctrlcache.ByObject{
			&networkingv1.NetworkPolicy{}: {
				Namespaces: map[string]ctrlcache.Config{
					operatorNamespace: {},
				},
			},
			&corev1.Pod{}: {
				Label:     xds.GatewayPodSelector(),
				Transform: xds.GatewayPodTransform,
			},
		},
	}
}

func setupRuleSetCache(cfg config) *cache.RuleSetCache {
	rulesetCache := cache.NewRuleSetCache()
	rulesetCache.SetLogger(ctrl.Log.WithName("ruleset-cache"))
	gcConfig := &cache.GarbageCollectionConfig{
		GCInterval: cfg.cacheGCInterval,
		MaxAge:     cfg.cacheMaxAge,
		MaxSize:    cfg.cacheMaxSize,
	}

	if err := cache.RegisterUSEMetrics(metrics.Registry, rulesetCache, *gcConfig); err != nil {
		setupLog.Error(err, "unable to register USE metrics for ruleset cache")
		os.Exit(1)
	}

	// The legacy HTTP rule server is intentionally not registered: ECDS is the
	// only delivery path. The package and its tests are retained.
	return rulesetCache
}

func setupHealthChecks(mgr ctrl.Manager, deps *xds.Dependencies) {
	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	checks := map[string]func() error{
		"xds-assets":      deps.CheckAssets,
		"xds-server":      deps.CheckServer,
		"xds-publication": deps.CheckPublication,
	}
	for name, check := range checks {
		if err := mgr.AddReadyzCheck(name, func(_ *http.Request) error { return check() }); err != nil {
			setupLog.Error(err, "unable to set up xDS readiness check", "check", name)
			os.Exit(1)
		}
	}
}
