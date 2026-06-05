// Copyright 2026 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package opentelemetry

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"

	"github.com/open-policy-agent/opa/v1/plugins"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
)

func TestOpenTelemetryLoggerConfigValidation(t *testing.T) {
	manager := newTestManager(t)
	factory := &Factory{}

	t.Run("defaults", func(t *testing.T) {
		validated, err := factory.Validate(manager, []byte(`{}`))
		if err != nil {
			t.Fatalf("unexpected validation error: %v", err)
		}

		cfg := validated.(Config)
		if cfg.Type != "" {
			t.Fatalf("expected empty type to remain unset, got %q", cfg.Type)
		}
		if cfg.Endpoint != defaultGRPCEndpoint {
			t.Fatalf("expected default gRPC endpoint %q, got %q", defaultGRPCEndpoint, cfg.Endpoint)
		}
		if cfg.Level != "info" {
			t.Fatalf("expected default level info, got %q", cfg.Level)
		}
		if cfg.ServiceName != defaultServiceName {
			t.Fatalf("expected default service name %q, got %q", defaultServiceName, cfg.ServiceName)
		}
	})

	t.Run("invalid type", func(t *testing.T) {
		_, err := factory.Validate(manager, []byte(`{"type":"syslog"}`))
		if err == nil {
			t.Fatal("expected validation error for invalid type")
		}
	})

	t.Run("invalid interval", func(t *testing.T) {
		_, err := factory.Validate(manager, []byte(`{"export_interval_ms":0}`))
		if err == nil {
			t.Fatal("expected validation error for export_interval_ms=0")
		}
	})
}

func TestOpenTelemetryLoggerHTTPExport(t *testing.T) {
	ctx := t.Context()
	collector := newMockOTLPHTTPCollector()
	defer collector.stop()

	plugin := newTestPlugin(t, Config{
		Type:             "otlp/http",
		Endpoint:         collector.address(),
		Level:            "info",
		ServiceName:      "opa-http-test",
		EncryptionScheme: "off",
		ExportIntervalMs: intPtr(50),
		ExportTimeoutMs:  intPtr(1000),
	})

	if err := plugin.Start(ctx); err != nil {
		t.Fatalf("failed to start plugin: %v", err)
	}
	defer plugin.Stop(ctx)

	logger := slog.New(plugin.Logger()).With(slog.String("component", "runtime"))
	logger.Info("http export message", slog.String("subsystem", "server"))

	record := waitForLogRecord(t, collector.firstRecord)
	if got := record.GetBody().GetStringValue(); got != "http export message" {
		t.Fatalf("expected log body %q, got %q", "http export message", got)
	}
	if got := record.GetSeverityText(); got != "INFO" {
		t.Fatalf("expected severity text INFO, got %q", got)
	}

	attrs := attributesToMap(record.GetAttributes())
	if attrs["component"] != "runtime" {
		t.Fatalf("expected component attr runtime, got %q", attrs["component"])
	}
	if attrs["subsystem"] != "server" {
		t.Fatalf("expected subsystem attr server, got %q", attrs["subsystem"])
	}

	req := collector.firstRequest()
	if req == nil || len(req.GetResourceLogs()) == 0 {
		t.Fatal("expected resource logs in HTTP export request")
	}
	resourceAttrs := attributesToMap(req.GetResourceLogs()[0].GetResource().GetAttributes())
	if resourceAttrs["service.name"] != "opa-http-test" {
		t.Fatalf("expected service.name attr opa-http-test, got %q", resourceAttrs["service.name"])
	}
}

func TestOpenTelemetryLoggerGRPCExportAndLevelFiltering(t *testing.T) {
	ctx := t.Context()
	collector := newMockOTLPGRPCCollector(t)
	defer collector.stop()

	plugin := newTestPlugin(t, Config{
		Type:               "otlp/grpc",
		Endpoint:           collector.address(),
		Level:              "warn",
		ServiceName:        "opa-grpc-test",
		EncryptionScheme:   "off",
		ExportIntervalMs:   intPtr(50),
		ExportTimeoutMs:    intPtr(1000),
		MaxExportBatchSize: intPtr(32),
		MaxQueueSize:       intPtr(128),
	})

	if err := plugin.Start(ctx); err != nil {
		t.Fatalf("failed to start plugin: %v", err)
	}
	defer plugin.Stop(ctx)

	logger := slog.New(plugin.Logger())
	logger.Info("filtered info message")
	logger.Warn("grpc export message", slog.String("component", "decision-logs"))

	record := waitForLogRecord(t, collector.firstRecord)
	if got := record.GetBody().GetStringValue(); got != "grpc export message" {
		t.Fatalf("expected first exported log body %q, got %q", "grpc export message", got)
	}
	if got := record.GetSeverityText(); got != "WARN" {
		t.Fatalf("expected severity text WARN, got %q", got)
	}

	attrs := attributesToMap(record.GetAttributes())
	if attrs["component"] != "decision-logs" {
		t.Fatalf("expected component attr decision-logs, got %q", attrs["component"])
	}
	if count := collector.recordCount(); count != 1 {
		t.Fatalf("expected exactly one exported log record after level filtering, got %d", count)
	}
}

func newTestManager(t *testing.T) *plugins.Manager {
	t.Helper()

	manager, err := plugins.New([]byte(`{}`), "test-instance", inmem.New())
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}
	return manager
}

func newTestPlugin(t *testing.T, cfg Config) *Plugin {
	t.Helper()

	if err := cfg.validateAndInjectDefaults(); err != nil {
		t.Fatalf("failed to validate config: %v", err)
	}

	plugin := (&Factory{}).New(newTestManager(t), cfg).(*Plugin)
	plugin.manager.Register(Name, plugin)
	return plugin
}

func intPtr(value int) *int {
	return &value
}

func waitForLogRecord(t *testing.T, getter func() *logspb.LogRecord) *logspb.LogRecord {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if record := getter(); record != nil {
			return record
		}
		time.Sleep(25 * time.Millisecond)
	}

	t.Fatal("timed out waiting for exported log record")
	return nil
}

func firstRecordFromRequest(req *collogspb.ExportLogsServiceRequest) *logspb.LogRecord {
	for _, resourceLogs := range req.GetResourceLogs() {
		for _, scopeLogs := range resourceLogs.GetScopeLogs() {
			for _, record := range scopeLogs.GetLogRecords() {
				return record
			}
		}
	}
	return nil
}

func attributesToMap(attrs []*commonpb.KeyValue) map[string]string {
	out := map[string]string{}
	for _, attr := range attrs {
		out[attr.GetKey()] = anyValueString(attr.GetValue())
	}
	return out
}

func anyValueString(value *commonpb.AnyValue) string {
	if value == nil {
		return ""
	}

	switch v := value.GetValue().(type) {
	case *commonpb.AnyValue_StringValue:
		return v.StringValue
	case *commonpb.AnyValue_IntValue:
		return fmt.Sprintf("%d", v.IntValue)
	case *commonpb.AnyValue_BoolValue:
		return fmt.Sprintf("%t", v.BoolValue)
	case *commonpb.AnyValue_DoubleValue:
		return fmt.Sprintf("%v", v.DoubleValue)
	default:
		return value.String()
	}
}

type mockOTLPHTTPCollector struct {
	mu       sync.Mutex
	requests []*collogspb.ExportLogsServiceRequest
	server   *httptest.Server
}

func newMockOTLPHTTPCollector() *mockOTLPHTTPCollector {
	c := &mockOTLPHTTPCollector{}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/logs", c.handleLogs)
	c.server = httptest.NewServer(mux)
	return c
}

func (c *mockOTLPHTTPCollector) handleLogs(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	req := &collogspb.ExportLogsServiceRequest{}
	if err := proto.Unmarshal(body, req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	c.mu.Lock()
	c.requests = append(c.requests, req)
	c.mu.Unlock()

	w.WriteHeader(http.StatusOK)
}

func (c *mockOTLPHTTPCollector) stop() {
	c.server.Close()
}

func (c *mockOTLPHTTPCollector) address() string {
	return c.server.URL[len("http://"):]
}

func (c *mockOTLPHTTPCollector) firstRequest() *collogspb.ExportLogsServiceRequest {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.requests) == 0 {
		return nil
	}
	return c.requests[0]
}

func (c *mockOTLPHTTPCollector) firstRecord() *logspb.LogRecord {
	req := c.firstRequest()
	if req == nil {
		return nil
	}
	return firstRecordFromRequest(req)
}

type mockOTLPGRPCCollector struct {
	collogspb.UnimplementedLogsServiceServer
	mu       sync.Mutex
	requests []*collogspb.ExportLogsServiceRequest
	server   *grpc.Server
	addr     string
}

func newMockOTLPGRPCCollector(t *testing.T) *mockOTLPGRPCCollector {
	t.Helper()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	c := &mockOTLPGRPCCollector{
		server: grpc.NewServer(),
		addr:   lis.Addr().String(),
	}
	collogspb.RegisterLogsServiceServer(c.server, c)

	go func() {
		_ = c.server.Serve(lis)
	}()

	return c
}

func (c *mockOTLPGRPCCollector) Export(_ context.Context, req *collogspb.ExportLogsServiceRequest) (*collogspb.ExportLogsServiceResponse, error) {
	c.mu.Lock()
	c.requests = append(c.requests, req)
	c.mu.Unlock()
	return &collogspb.ExportLogsServiceResponse{}, nil
}

func (c *mockOTLPGRPCCollector) stop() {
	c.server.GracefulStop()
}

func (c *mockOTLPGRPCCollector) address() string {
	return c.addr
}

func (c *mockOTLPGRPCCollector) firstRecord() *logspb.LogRecord {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.requests) == 0 {
		return nil
	}
	return firstRecordFromRequest(c.requests[0])
}

func (c *mockOTLPGRPCCollector) recordCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	total := 0
	for _, req := range c.requests {
		for _, resourceLogs := range req.GetResourceLogs() {
			for _, scopeLogs := range resourceLogs.GetScopeLogs() {
				total += len(scopeLogs.GetLogRecords())
			}
		}
	}
	return total
}
