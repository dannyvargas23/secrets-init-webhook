package main

import (
	"context"
	"os"
	"os/signal"
	"time"
	"syscall"

	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"

	"github.com/dannyvargas23/secrets-init-webhook/internal/config"
	"github.com/dannyvargas23/secrets-init-webhook/internal/observability"
	"github.com/dannyvargas23/secrets-init-webhook/internal/webhook"
)

// main wires configuration, observability, and the server together.
//
// Why no business logic here: the prompt requires Clean Architecture —
// main.go is the composition root only. All logic lives in internal packages.
//
// Why errgroup: the prompt explicitly requires errgroup for goroutine lifecycle
// management. errgroup propagates the first error from any goroutine and cancels
// the shared context, giving clean coordinated shutdown across all components.
func main() {
	// Bootstrap logger before config is loaded so startup errors are structured.
	startupLog, _ := zap.NewProduction()
	defer startupLog.Sync() //nolint:errcheck // best-effort flush on exit

	cfg, err := config.Load()
	if err != nil {
		startupLog.Fatal("failed to load config", zap.Error(err))
	}

	log, err := buildLogger(cfg.LogLevel)
	if err != nil {
		startupLog.Fatal("failed to build logger", zap.Error(err))
	}
	defer log.Sync() //nolint:errcheck

	// Use a custom Prometheus registry rather than the default global one.
	// This makes testing safe — each test can create its own registry.
	reg := prometheus.NewRegistry()

	// Root context cancelled on SIGINT or SIGTERM — propagates to all goroutines.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Set up OpenTelemetry tracing. If OTLP_ENDPOINT is empty, a no-op provider
	// is installed and the app runs without tracing.
	shutdownTracing, err := observability.SetupTracing(ctx, cfg.OTLPEndpoint)
	if err != nil {
		log.Fatal("failed to set up tracing", zap.Error(err))
	}

	srv, err := webhook.New(cfg, log, reg)
	if err != nil {
		log.Fatal("failed to create server", zap.Error(err))
	}

	// errgroup coordinates the server goroutine lifecycle.
	// If the server exits with an error, the group context is cancelled
	// and Wait() returns that error.
	g, gCtx := errgroup.WithContext(ctx)

	g.Go(func() error {
		return srv.Start(gCtx)
	})

	if err := g.Wait(); err != nil {
		log.Error("server exited with error", zap.Error(err))
	}

	// Flush and shutdown the tracer provider after the server has drained.
	flushCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := shutdownTracing(flushCtx); err != nil {
		log.Error("tracer shutdown failed", zap.Error(err))
	}
}

// buildLogger constructs a zap production logger (structured JSON) at the given level.
//
// Why zap production config: it emits structured JSON logs required by the prompt
// and by Datadog log parsing. Development mode emits coloured console output which
// is not parseable by log aggregators.
func buildLogger(level string) (*zap.Logger, error) {
	zapLevel, err := zap.ParseAtomicLevel(level)
	if err != nil {
		return nil, err
	}
	cfg := zap.NewProductionConfig()
	cfg.Level = zapLevel
	cfg.OutputPaths = []string{"stdout"}
	cfg.ErrorOutputPaths = []string{"stderr"}
	return cfg.Build()
}
