// Copyright 2026 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package opentelemetry

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/contrib/bridges/otelslog"
	otlploggrpc "go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	otlploghttp "go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.7.0"
	"google.golang.org/grpc/credentials"

	"github.com/open-policy-agent/opa/internal/tlsutil"
	"github.com/open-policy-agent/opa/v1/plugins"
	"github.com/open-policy-agent/opa/v1/util"
)

const Name = "opentelemetry_logger"

const (
	defaultGRPCEndpoint       = "localhost:4317"
	defaultHTTPEndpoint       = "localhost:4318"
	defaultServiceName        = "opa"
	defaultEncryptionScheme   = "off"
	defaultExportIntervalMs   = 1000
	defaultExportTimeoutMs    = 30000
	defaultMaxExportBatchSize = 512
	defaultMaxQueueSize       = 2048
)

var supportedEncryptionScheme = map[string]struct{}{
	"off": {}, "tls": {}, "mtls": {},
}

type Config struct {
	Type                  string `json:"type,omitempty"`
	Endpoint              string `json:"endpoint,omitempty"`
	Address               string `json:"address,omitempty"`
	ServiceName           string `json:"service_name,omitempty"`
	Level                 string `json:"level,omitempty"`
	EncryptionScheme      string `json:"encryption,omitempty"`
	EncryptionSkipVerify  *bool  `json:"allow_insecure_tls,omitempty"`
	TLSCertFile           string `json:"tls_cert_file,omitempty"`
	TLSCertPrivateKeyFile string `json:"tls_private_key_file,omitempty"`
	TLSCACertFile         string `json:"tls_ca_cert_file,omitempty"`
	ExportIntervalMs      *int   `json:"export_interval_ms,omitempty"`
	ExportTimeoutMs       *int   `json:"export_timeout_ms,omitempty"`
	MaxExportBatchSize    *int   `json:"max_export_batch_size,omitempty"`
	MaxQueueSize          *int   `json:"max_queue_size,omitempty"`
}

type Plugin struct {
	manager  *plugins.Manager
	config   Config
	handler  slog.Handler
	provider *sdklog.LoggerProvider
	levelVar *slog.LevelVar
	mtx      sync.Mutex
}

type Factory struct{}

func (*Factory) Validate(_ *plugins.Manager, config []byte) (any, error) {
	var parsedConfig Config
	if err := util.Unmarshal(config, &parsedConfig); err != nil {
		return nil, fmt.Errorf("failed to parse OpenTelemetry logger config: %w", err)
	}

	if err := parsedConfig.validateAndInjectDefaults(); err != nil {
		return nil, err
	}

	return parsedConfig, nil
}

func (*Factory) New(manager *plugins.Manager, config any) plugins.Plugin {
	return &Plugin{
		manager: manager,
		config:  config.(Config),
	}
}

func (p *Plugin) Start(ctx context.Context) error {
	p.mtx.Lock()
	defer p.mtx.Unlock()

	if p.handler != nil {
		return errors.New("OpenTelemetry logger already started")
	}

	provider, err := newLoggerProvider(ctx, p.config)
	if err != nil {
		p.manager.UpdatePluginStatus(Name, &plugins.Status{State: plugins.StateErr, Message: err.Error()})
		return err
	}

	levelVar := new(slog.LevelVar)
	levelVar.Set(parseLevel(p.config.Level))

	base := otelslog.NewHandler(Name,
		otelslog.WithLoggerProvider(provider),
	)

	p.provider = provider
	p.levelVar = levelVar
	p.handler = &filteringHandler{
		next:     base,
		levelVar: levelVar,
	}

	p.manager.UpdatePluginStatus(Name, &plugins.Status{State: plugins.StateOK})
	return nil
}

func (p *Plugin) Stop(ctx context.Context) {
	p.mtx.Lock()
	provider := p.provider
	p.provider = nil
	p.handler = nil
	p.levelVar = nil
	p.mtx.Unlock()

	if provider != nil {
		_ = provider.ForceFlush(ctx)
		_ = provider.Shutdown(ctx)
	}

	p.manager.UpdatePluginStatus(Name, &plugins.Status{State: plugins.StateNotReady})
}

func (p *Plugin) Reconfigure(ctx context.Context, config any) {
	newConfig := config.(Config)

	p.mtx.Lock()
	oldConfig := p.config
	levelVar := p.levelVar
	p.config = newConfig
	p.mtx.Unlock()

	if requiresRestart(oldConfig, newConfig) {
		p.Stop(ctx)
		_ = p.Start(ctx)
		return
	}

	if oldConfig.Level != newConfig.Level && levelVar != nil {
		levelVar.Set(parseLevel(newConfig.Level))
	}
}

func (p *Plugin) Logger() slog.Handler {
	p.mtx.Lock()
	defer p.mtx.Unlock()
	return p.handler
}

func (c *Config) validateAndInjectDefaults() error {
	switch strings.ToLower(c.Type) {
	case "", "otlp/grpc", "otlp/http":
	default:
		return fmt.Errorf("unknown OpenTelemetry logger type %q, must be \"otlp/grpc\", \"otlp/http\" or \"\" (unset)", c.Type)
	}

	if c.Endpoint == "" {
		c.Endpoint = c.Address
	}

	if c.Endpoint == "" {
		switch strings.ToLower(c.Type) {
		case "", "otlp/grpc":
			c.Endpoint = defaultGRPCEndpoint
		case "otlp/http":
			c.Endpoint = defaultHTTPEndpoint
		}
	}

	if c.ServiceName == "" {
		c.ServiceName = defaultServiceName
	}

	if c.Level == "" {
		c.Level = "info"
	}

	if c.EncryptionScheme == "" {
		c.EncryptionScheme = defaultEncryptionScheme
	}
	if _, ok := supportedEncryptionScheme[c.EncryptionScheme]; !ok {
		return fmt.Errorf("unsupported OpenTelemetry logger encryption %q", c.EncryptionScheme)
	}

	if c.EncryptionSkipVerify == nil {
		v := false
		c.EncryptionSkipVerify = &v
	}

	if c.ExportIntervalMs == nil {
		v := defaultExportIntervalMs
		c.ExportIntervalMs = &v
	}
	if *c.ExportIntervalMs <= 0 {
		return fmt.Errorf("OpenTelemetry logger export_interval_ms must be a positive value, got %d", *c.ExportIntervalMs)
	}

	if c.ExportTimeoutMs == nil {
		v := defaultExportTimeoutMs
		c.ExportTimeoutMs = &v
	}
	if *c.ExportTimeoutMs <= 0 {
		return fmt.Errorf("OpenTelemetry logger export_timeout_ms must be a positive value, got %d", *c.ExportTimeoutMs)
	}

	if c.MaxExportBatchSize == nil {
		v := defaultMaxExportBatchSize
		c.MaxExportBatchSize = &v
	}
	if *c.MaxExportBatchSize <= 0 {
		return fmt.Errorf("OpenTelemetry logger max_export_batch_size must be a positive value, got %d", *c.MaxExportBatchSize)
	}

	if c.MaxQueueSize == nil {
		v := defaultMaxQueueSize
		c.MaxQueueSize = &v
	}
	if *c.MaxQueueSize <= 0 {
		return fmt.Errorf("OpenTelemetry logger max_queue_size must be a positive value, got %d", *c.MaxQueueSize)
	}

	return nil
}

func newLoggerProvider(ctx context.Context, cfg Config) (*sdklog.LoggerProvider, error) {
	certificate, err := tlsutil.LoadCertificate(cfg.TLSCertFile, cfg.TLSCertPrivateKeyFile)
	if err != nil {
		return nil, err
	}

	certPool, err := tlsutil.LoadCertPool(cfg.TLSCACertFile)
	if err != nil {
		return nil, err
	}

	tlsConfig, err := tlsutil.BuildTLSConfig(cfg.EncryptionScheme, *cfg.EncryptionSkipVerify, certificate, certPool)
	if err != nil {
		return nil, err
	}

	exporter, err := newExporter(ctx, cfg, tlsConfig)
	if err != nil {
		return nil, err
	}

	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceNameKey.String(cfg.ServiceName),
		),
	)
	if err != nil {
		return nil, err
	}

	processor := sdklog.NewBatchProcessor(exporter,
		sdklog.WithExportInterval(durationMs(*cfg.ExportIntervalMs)),
		sdklog.WithExportTimeout(durationMs(*cfg.ExportTimeoutMs)),
		sdklog.WithExportMaxBatchSize(*cfg.MaxExportBatchSize),
		sdklog.WithMaxQueueSize(*cfg.MaxQueueSize),
	)

	return sdklog.NewLoggerProvider(
		sdklog.WithResource(res),
		sdklog.WithProcessor(processor),
	), nil
}

func newExporter(ctx context.Context, cfg Config, tlsConfig *tls.Config) (sdklog.Exporter, error) {
	if strings.EqualFold(cfg.Type, "otlp/http") {
		opts := []otlploghttp.Option{
			otlploghttp.WithEndpoint(cfg.Endpoint),
			otlploghttp.WithTimeout(durationMs(*cfg.ExportTimeoutMs)),
		}
		if cfg.EncryptionScheme == "off" {
			opts = append(opts, otlploghttp.WithInsecure())
		} else {
			opts = append(opts, otlploghttp.WithTLSClientConfig(tlsConfig))
		}
		return otlploghttp.New(ctx, opts...)
	}

	opts := []otlploggrpc.Option{
		otlploggrpc.WithEndpoint(cfg.Endpoint),
		otlploggrpc.WithTimeout(durationMs(*cfg.ExportTimeoutMs)),
	}
	if cfg.EncryptionScheme == "off" {
		opts = append(opts, otlploggrpc.WithInsecure())
	} else {
		opts = append(opts, otlploggrpc.WithTLSCredentials(credentials.NewTLS(tlsConfig)))
	}
	return otlploggrpc.New(ctx, opts...)
}

func durationMs(value int) time.Duration {
	return time.Duration(value) * time.Millisecond
}

func requiresRestart(oldConfig, newConfig Config) bool {
	return oldConfig.Type != newConfig.Type ||
		oldConfig.Endpoint != newConfig.Endpoint ||
		oldConfig.Address != newConfig.Address ||
		oldConfig.ServiceName != newConfig.ServiceName ||
		oldConfig.EncryptionScheme != newConfig.EncryptionScheme ||
		valueOrZero(oldConfig.EncryptionSkipVerify) != valueOrZero(newConfig.EncryptionSkipVerify) ||
		oldConfig.TLSCertFile != newConfig.TLSCertFile ||
		oldConfig.TLSCertPrivateKeyFile != newConfig.TLSCertPrivateKeyFile ||
		oldConfig.TLSCACertFile != newConfig.TLSCACertFile ||
		valueOrInt(oldConfig.ExportIntervalMs) != valueOrInt(newConfig.ExportIntervalMs) ||
		valueOrInt(oldConfig.ExportTimeoutMs) != valueOrInt(newConfig.ExportTimeoutMs) ||
		valueOrInt(oldConfig.MaxExportBatchSize) != valueOrInt(newConfig.MaxExportBatchSize) ||
		valueOrInt(oldConfig.MaxQueueSize) != valueOrInt(newConfig.MaxQueueSize)
}

func valueOrZero(ptr *bool) bool {
	if ptr == nil {
		return false
	}
	return *ptr
}

func valueOrInt(ptr *int) int {
	if ptr == nil {
		return 0
	}
	return *ptr
}

type filteringHandler struct {
	next     slog.Handler
	levelVar *slog.LevelVar
}

func (h *filteringHandler) Enabled(ctx context.Context, level slog.Level) bool {
	if h.levelVar != nil && level < h.levelVar.Level() {
		return false
	}
	return h.next.Enabled(ctx, level)
}

func (h *filteringHandler) Handle(ctx context.Context, record slog.Record) error {
	if h.levelVar != nil && record.Level < h.levelVar.Level() {
		return nil
	}
	return h.next.Handle(ctx, record)
}

func (h *filteringHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &filteringHandler{next: h.next.WithAttrs(attrs), levelVar: h.levelVar}
}

func (h *filteringHandler) WithGroup(name string) slog.Handler {
	return &filteringHandler{next: h.next.WithGroup(name), levelVar: h.levelVar}
}

func parseLevel(levelStr string) slog.Level {
	switch strings.ToLower(levelStr) {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
