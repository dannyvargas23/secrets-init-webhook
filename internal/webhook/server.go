package webhook

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.uber.org/zap"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/dannyvargas23/secrets-init-webhook/internal/config"
	"github.com/dannyvargas23/secrets-init-webhook/internal/observability"
	"github.com/dannyvargas23/secrets-init-webhook/internal/registry"
)

// Server holds the HTTPS webhook server and the separate HTTP metrics server.
//
// Why two servers: the webhook must be HTTPS (Kubernetes API server requirement).
// The Prometheus /metrics endpoint should be HTTP on a separate port so the
// metrics scraper does not need TLS configuration, following standard practice.
type Server struct {
	cfg           *config.Config
	log           *zap.Logger
	metrics       *observability.Metrics
	secretCache   *SecretCache
	regClient     *registry.Client
	webhookServer *http.Server
	metricsServer *http.Server
}

// New constructs a Server with all routes wired and TLS loaded.
//
// It also initialises the shared AWS Secrets Manager client once here — avoiding
// the cost of config loading and credential discovery on every admission request.
func New(cfg *config.Config, log *zap.Logger, reg prometheus.Registerer) (*Server, error) {
	// Load TLS certificate from cert-manager mounted files.
	cert, err := tls.LoadX509KeyPair(cfg.TLSCertPath, cfg.TLSKeyPath)
	if err != nil {
		return nil, fmt.Errorf("server: failed to load TLS keypair from %q / %q: %w",
			cfg.TLSCertPath, cfg.TLSKeyPath, err)
	}

	// Initialise the shared SM client once at startup — safe for concurrent use.
	smClient, err := NewSMClient(context.Background(), cfg.AWSRegion)
	if err != nil {
		return nil, fmt.Errorf("server: failed to initialise Secrets Manager client: %w", err)
	}

	metrics := observability.NewMetrics(reg)

	cacheTTL := time.Duration(cfg.SecretCacheTTL) * time.Second
	secretCache := NewSecretCache(cacheTTL, log)

	// Create in-cluster K8s client for imagePullSecrets lookup (k8schain).
	var k8sClient kubernetes.Interface
	if restCfg, err := rest.InClusterConfig(); err == nil {
		k8sClient, err = kubernetes.NewForConfig(restCfg)
		if err != nil {
			log.Warn("server: failed to create k8s client, registry auth will use default keychain only", zap.Error(err))
		}
	} else {
		log.Info("server: not running in-cluster, registry auth will use default keychain only")
	}

	regClient := registry.NewClient(k8sClient, log)

	s := &Server{cfg: cfg, log: log, metrics: metrics, secretCache: secretCache, regClient: regClient}

	// ── webhook HTTPS mux ─────────────────────────────────────────────────────
	// otelhttp.NewHandler wraps the entire mux so every request gets a trace span
	// automatically — no per-handler instrumentation required.
	webhookMux := http.NewServeMux()
	webhookMux.HandleFunc("/mutate", s.handleMutateWith(smClient))
	webhookMux.HandleFunc("/healthz", s.handleHealthz)

	s.webhookServer = &http.Server{
		Addr:    fmt.Sprintf(":%d", cfg.Port),
		Handler: otelhttp.NewHandler(webhookMux, "webhook"),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
		},
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	// ── metrics HTTP mux ──────────────────────────────────────────────────────
	metricsMux := http.NewServeMux()
	metricsMux.Handle("/metrics", promhttp.HandlerFor(
		// Cast reg to prometheus.Gatherer — prometheus.Registry implements both.
		reg.(prometheus.Gatherer),
		promhttp.HandlerOpts{EnableOpenMetrics: true},
	))

	s.metricsServer = &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.MetricsPort),
		Handler:           metricsMux,
		ReadTimeout:       5 * time.Second,
		ReadHeaderTimeout: 3 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}

	return s, nil
}

// Start runs both the webhook HTTPS server and the metrics HTTP server concurrently.
//
// Why not errgroup here: errgroup is used in main.go to compose Start with other
// top-level lifecycle tasks (tracer shutdown, etc.). Start itself just manages the
// two internal servers — a select on two error channels is the idiomatic Go pattern
// for this bounded case without pulling errgroup into the server package.
//
// Graceful shutdown is initiated when ctx is cancelled (SIGTERM/SIGINT from main).
func (s *Server) Start(ctx context.Context) error {
	// ── start webhook server ──────────────────────────────────────────────────
	// We use net.Listen + tls.NewListener + Serve rather than ListenAndServeTLS.
	// ListenAndServeTLS always reads cert/key from file paths; it does not use
	// TLSConfig.Certificates even when populated. Our cert is pre-loaded above,
	// so we bypass the file-path code path entirely.
	// Start background cache cleanup — sweep interval is 2x TTL to avoid
	// constant CPU churn on the map. Expired entries are also lazily evicted
	// on read, so staleness is bounded by TTL regardless of sweep frequency.
	sweepInterval := 2 * time.Duration(s.cfg.SecretCacheTTL) * time.Second
	s.secretCache.StartCleanup(ctx, sweepInterval)

	webhookLn, err := net.Listen("tcp", s.webhookServer.Addr)
	if err != nil {
		return fmt.Errorf("server: failed to listen on %s: %w", s.webhookServer.Addr, err)
	}
	tlsLn := tls.NewListener(webhookLn, s.webhookServer.TLSConfig)

	webhookErrCh := make(chan error, 1)
	go func() {
		s.log.Info("server: webhook listening", zap.String("addr", s.webhookServer.Addr))
		if err := s.webhookServer.Serve(tlsLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
			webhookErrCh <- fmt.Errorf("server: webhook Serve: %w", err)
		}
	}()

	// ── start metrics server ──────────────────────────────────────────────────
	metricsErrCh := make(chan error, 1)
	go func() {
		s.log.Info("server: metrics listening", zap.String("addr", s.metricsServer.Addr))
		if err := s.metricsServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			metricsErrCh <- fmt.Errorf("server: metrics ListenAndServe: %w", err)
		}
	}()

	select {
	case err := <-webhookErrCh:
		return err
	case err := <-metricsErrCh:
		return err
	case <-ctx.Done():
		return s.shutdown()
	}
}

// shutdown gracefully drains both servers with a 30-second deadline.
func (s *Server) shutdown() error {
	s.log.Info("server: shutting down gracefully")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := s.webhookServer.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("server: webhook shutdown failed: %w", err)
	}
	if err := s.metricsServer.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("server: metrics shutdown failed: %w", err)
	}
	s.log.Info("server: shutdown complete")
	return nil
}

// handleHealthz responds to liveness and readiness probes.
func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}
