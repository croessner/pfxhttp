package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/propagation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc/metadata"
)

const (
	defaultPrometheusAddress = "127.0.0.1"
	defaultPrometheusPort    = 9464
	defaultPrometheusPath    = "/metrics"
	defaultOTelServiceName   = "pfxhttp"
	defaultOTelSampleRatio   = 1.0

	instrumentationName = "pfxhttp"

	componentBackendHTTP   = "backend_http"
	componentDovecotSASL   = "dovecot_sasl"
	componentOIDC          = "oidc"
	componentPolicyService = "policy_service"
	componentSocketMap     = "socket_map"

	eventAccept    = "accept"
	eventClose     = "close"
	eventQueueFull = "queue_full"

	defaultBackendName  = "default"
	statusClassError    = "error"
	postfixActionReject = "REJECT"

	labelComponent   = "component"
	labelEvent       = "event"
	labelListener    = "listener"
	labelMethod      = "method"
	labelName        = "name"
	labelOutcome     = "outcome"
	labelResult      = "result"
	labelStatus      = "status"
	labelStatusClass = "status_class"

	outcomeContinue  = "continue"
	outcomeError     = "error"
	outcomeFail      = "fail"
	outcomeNotFound  = "not_found"
	outcomeOK        = "ok"
	outcomeTempfail  = "tempfail"
	outcomeTimeout   = "timeout"
	outcomeUnknown   = "unknown"
	resultError      = "error"
	resultOK         = "ok"
	resultStatusCode = "status_code"
)

const (
	socketMapReadSpanName        = "socket_map read request"
	socketMapDecodeSpanName      = "socket_map decode request"
	socketMapBackendSpanName     = "socket_map backend exchange"
	socketMapEncodeSpanName      = "socket_map encode response"
	socketMapWriteSpanName       = "socket_map write response"
	policyServiceReadSpanName    = "policy_service read request"
	policyServiceDecodeSpanName  = "policy_service decode request"
	policyServiceBackendSpanName = "policy_service backend exchange"
	policyServiceEncodeSpanName  = "policy_service encode response"
	policyServiceWriteSpanName   = "policy_service write response"
	dovecotSASLMechanismSpanName = "dovecot_sasl mechanism step"
	dovecotSASLBackendSpanName   = "dovecot_sasl backend auth"
	dovecotSASLResponseSpanName  = "dovecot_sasl write response"
	dovecotSASLWaitSpanName      = "dovecot_sasl continuation wait"
)

const (
	observabilityContextKey ctxKey = "observability"
	backendOperationKey     ctxKey = "backend_operation"
)

// ObservabilityConfig contains all opt-in metrics and tracing settings.
type ObservabilityConfig struct {
	PrometheusEnabled        bool              `mapstructure:"prometheus_enabled"`
	PrometheusAddress        string            `mapstructure:"prometheus_address"`
	PrometheusPort           int               `mapstructure:"prometheus_port"`
	PrometheusPath           string            `mapstructure:"prometheus_path"`
	PrometheusRuntimeMetrics bool              `mapstructure:"prometheus_runtime_metrics"`
	PrometheusHTTPAuthBasic  string            `mapstructure:"prometheus_http_auth_basic"`
	PrometheusTLS            PrometheusTLS     `mapstructure:"prometheus_tls" validate:"omitempty"`
	OTelEnabled              bool              `mapstructure:"otel_enabled"`
	OTelTracesEnabled        bool              `mapstructure:"otel_traces_enabled"`
	OTelMetricsEnabled       bool              `mapstructure:"otel_metrics_enabled"`
	OTelServiceName          string            `mapstructure:"otel_service_name"`
	OTelServiceVersion       string            `mapstructure:"otel_service_version"`
	OTLPEndpoint             string            `mapstructure:"otel_exporter_otlp_endpoint"`
	OTLPHeaders              map[string]string `mapstructure:"otel_exporter_otlp_headers"`
	OTLPInsecure             bool              `mapstructure:"otel_exporter_otlp_insecure"`
	OTelSampleRatio          *float64          `mapstructure:"otel_sample_ratio"`
}

// PrometheusTLS configures server-side TLS for the optional Prometheus endpoint.
type PrometheusTLS struct {
	Enabled    bool   `mapstructure:"enabled"`
	Cert       string `mapstructure:"cert" validate:"omitempty,file"`
	Key        string `mapstructure:"key" validate:"omitempty,file"`
	MinVersion string `mapstructure:"min_tls_version" validate:"omitempty,oneof=1.2 1.3"`
}

// Observability owns Prometheus collectors and OpenTelemetry providers for the process.
type Observability struct {
	config ObservabilityConfig
	logger *slog.Logger

	registry *prometheus.Registry
	metrics  *prometheusMetrics

	tracer        trace.Tracer
	meter         metric.Meter
	traceProvider *sdktrace.TracerProvider
	meterProvider *sdkmetric.MeterProvider
	otelMetrics   *otelMetricInstruments

	prometheusServer   *http.Server
	prometheusListener net.Listener
}

// prometheusMetrics groups all Prometheus collectors owned by this process.
type prometheusMetrics struct {
	listenerConnections    *prometheus.CounterVec
	listenerActive         *prometheus.GaugeVec
	listenerDuration       *prometheus.HistogramVec
	applicationRequests    *prometheus.CounterVec
	applicationDuration    *prometheus.HistogramVec
	backendHTTPRequests    *prometheus.CounterVec
	backendHTTPDuration    *prometheus.HistogramVec
	backendGRPCRequests    *prometheus.CounterVec
	backendGRPCDuration    *prometheus.HistogramVec
	observabilityStartups  *prometheus.CounterVec
	observabilityShutdowns *prometheus.CounterVec
}

// otelMetricInstruments mirrors key Prometheus signals to an OTLP metrics exporter.
type otelMetricInstruments struct {
	listenerConnections metric.Int64Counter
	listenerActive      metric.Int64UpDownCounter
	listenerDuration    metric.Float64Histogram
	applicationRequests metric.Int64Counter
	applicationDuration metric.Float64Histogram
	backendHTTPRequests metric.Int64Counter
	backendHTTPDuration metric.Float64Histogram
	backendGRPCRequests metric.Int64Counter
	backendGRPCDuration metric.Float64Histogram
}

type prometheusCounterDuration struct {
	counter  *prometheus.CounterVec
	duration *prometheus.HistogramVec
}

type otelCounterDuration struct {
	counter  metric.Int64Counter
	duration metric.Float64Histogram
}

type backendOperation struct {
	component string
	name      string
}

// NewObservability initializes enabled Prometheus and OpenTelemetry components.
func NewObservability(ctx context.Context, cfg ObservabilityConfig, serviceVersion string, logger *slog.Logger) (*Observability, error) {
	cfg = normalizeObservabilityConfig(cfg, serviceVersion)

	if logger == nil {
		logger = slog.Default()
	}

	obs := &Observability{
		config: cfg,
		logger: logger,
		tracer: otel.Tracer(instrumentationName),
		meter:  otel.Meter(instrumentationName),
	}

	otel.SetTextMapPropagator(propagation.TraceContext{})

	if cfg.PrometheusEnabled {
		obs.registry = prometheus.NewRegistry()
		obs.metrics = newPrometheusMetrics(obs.registry, cfg.PrometheusRuntimeMetrics)
	}

	if cfg.OTelEnabled {
		if err := obs.initializeOpenTelemetry(ctx); err != nil {
			return nil, err
		}
	}

	return obs, nil
}

// newTraceTestObservabilityWithProvider builds a test runtime around a supplied tracer provider.
func newTraceTestObservabilityWithProvider(provider *sdktrace.TracerProvider) *Observability {
	otel.SetTextMapPropagator(propagation.TraceContext{})

	return &Observability{
		config: ObservabilityConfig{
			OTelEnabled:       true,
			OTelTracesEnabled: true,
		},
		tracer:        provider.Tracer(instrumentationName),
		traceProvider: provider,
	}
}

// normalizeObservabilityConfig applies runtime defaults that cannot be represented through zero values.
func normalizeObservabilityConfig(cfg ObservabilityConfig, serviceVersion string) ObservabilityConfig {
	if cfg.PrometheusAddress == "" {
		cfg.PrometheusAddress = defaultPrometheusAddress
	}

	if cfg.PrometheusPort == 0 {
		cfg.PrometheusPort = defaultPrometheusPort
	}

	if cfg.PrometheusPath == "" {
		cfg.PrometheusPath = defaultPrometheusPath
	}

	if !strings.HasPrefix(cfg.PrometheusPath, "/") {
		cfg.PrometheusPath = "/" + cfg.PrometheusPath
	}

	if cfg.OTelServiceName == "" {
		cfg.OTelServiceName = defaultOTelServiceName
	}

	if cfg.OTelServiceVersion == "" {
		cfg.OTelServiceVersion = serviceVersion
	}

	if cfg.OTelSampleRatio == nil {
		defaultRatio := defaultOTelSampleRatio
		cfg.OTelSampleRatio = &defaultRatio
	}

	if cfg.OTLPHeaders == nil {
		cfg.OTLPHeaders = make(map[string]string)
	}

	return cfg
}

// defaultedOTelSampleRatio returns the configured ratio after applying the runtime default.
func defaultedOTelSampleRatio(cfg ObservabilityConfig) float64 {
	if cfg.OTelSampleRatio == nil {
		return defaultOTelSampleRatio
	}

	return *cfg.OTelSampleRatio
}

// initializeOpenTelemetry configures OTLP HTTP tracing and metrics exporters.
func (o *Observability) initializeOpenTelemetry(ctx context.Context) error {
	res, err := resource.New(ctx,
		resource.WithAttributes(
			attribute.String("service.name", o.config.OTelServiceName),
			attribute.String("service.version", o.config.OTelServiceVersion),
		),
	)
	if err != nil {
		return fmt.Errorf("creating OpenTelemetry resource: %w", err)
	}

	if o.config.OTelTracesEnabled {
		if err = o.initializeOpenTelemetryTracing(ctx, res); err != nil {
			return err
		}
	}

	if o.config.OTelMetricsEnabled {
		if err = o.initializeOpenTelemetryMetrics(ctx, res); err != nil {
			return err
		}
	}

	return nil
}

// initializeOpenTelemetryTracing starts a batch trace provider backed by OTLP HTTP.
func (o *Observability) initializeOpenTelemetryTracing(ctx context.Context, res *resource.Resource) error {
	exporter, err := otlptracehttp.New(ctx, traceHTTPOptions(o.config)...)
	if err != nil {
		return fmt.Errorf("creating OTLP trace exporter: %w", err)
	}

	sampler := sdktrace.ParentBased(sdktrace.TraceIDRatioBased(defaultedOTelSampleRatio(o.config)))
	o.traceProvider = sdktrace.NewTracerProvider(
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sampler),
		sdktrace.WithBatcher(exporter),
	)
	o.tracer = o.traceProvider.Tracer(instrumentationName)
	otel.SetTracerProvider(o.traceProvider)

	return nil
}

// initializeOpenTelemetryMetrics starts a periodic OTLP HTTP metric reader.
func (o *Observability) initializeOpenTelemetryMetrics(ctx context.Context, res *resource.Resource) error {
	exporter, err := otlpmetrichttp.New(ctx, metricHTTPOptions(o.config)...)
	if err != nil {
		return fmt.Errorf("creating OTLP metric exporter: %w", err)
	}

	o.meterProvider = sdkmetric.NewMeterProvider(
		sdkmetric.WithResource(res),
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(exporter)),
	)
	o.meter = o.meterProvider.Meter(instrumentationName)
	otel.SetMeterProvider(o.meterProvider)

	return o.initializeOpenTelemetryInstruments()
}

// traceHTTPOptions converts local config into OTLP trace HTTP exporter options.
func traceHTTPOptions(cfg ObservabilityConfig) []otlptracehttp.Option {
	endpoint, insecure := normalizedOTLPEndpoint(cfg)

	options := []otlptracehttp.Option{otlptracehttp.WithEndpoint(endpoint)}
	if insecure {
		options = append(options, otlptracehttp.WithInsecure())
	}

	if len(cfg.OTLPHeaders) > 0 {
		options = append(options, otlptracehttp.WithHeaders(cfg.OTLPHeaders))
	}

	return options
}

// metricHTTPOptions converts local config into OTLP metric HTTP exporter options.
func metricHTTPOptions(cfg ObservabilityConfig) []otlpmetrichttp.Option {
	endpoint, insecure := normalizedOTLPEndpoint(cfg)

	options := []otlpmetrichttp.Option{otlpmetrichttp.WithEndpoint(endpoint)}
	if insecure {
		options = append(options, otlpmetrichttp.WithInsecure())
	}

	if len(cfg.OTLPHeaders) > 0 {
		options = append(options, otlpmetrichttp.WithHeaders(cfg.OTLPHeaders))
	}

	return options
}

// normalizedOTLPEndpoint accepts either host:port or a base URL and returns exporter host:port settings.
func normalizedOTLPEndpoint(cfg ObservabilityConfig) (string, bool) {
	if parsed, err := url.Parse(cfg.OTLPEndpoint); err == nil && parsed.Host != "" {
		return parsed.Host, cfg.OTLPInsecure || parsed.Scheme == "http"
	}

	return cfg.OTLPEndpoint, cfg.OTLPInsecure
}

// initializeOpenTelemetryInstruments creates the OTLP metric instruments.
func (o *Observability) initializeOpenTelemetryInstruments() error {
	instruments := &otelMetricInstruments{}

	var err error

	if instruments.listenerConnections, err = o.meter.Int64Counter("pfxhttp_listener_connections"); err != nil {
		return err
	}

	if instruments.listenerActive, err = o.meter.Int64UpDownCounter("pfxhttp_listener_active_connections"); err != nil {
		return err
	}

	if instruments.listenerDuration, err = o.meter.Float64Histogram("pfxhttp_listener_connection_duration", metric.WithUnit("s")); err != nil {
		return err
	}

	if instruments.applicationRequests, err = o.meter.Int64Counter("pfxhttp_application_requests"); err != nil {
		return err
	}

	if instruments.applicationDuration, err = o.meter.Float64Histogram("pfxhttp_application_request_duration", metric.WithUnit("s")); err != nil {
		return err
	}

	if instruments.backendHTTPRequests, err = o.meter.Int64Counter("pfxhttp_backend_http_requests"); err != nil {
		return err
	}

	if instruments.backendHTTPDuration, err = o.meter.Float64Histogram("pfxhttp_backend_http_request_duration", metric.WithUnit("s")); err != nil {
		return err
	}

	if instruments.backendGRPCRequests, err = o.meter.Int64Counter("pfxhttp_backend_grpc_requests"); err != nil {
		return err
	}

	if instruments.backendGRPCDuration, err = o.meter.Float64Histogram("pfxhttp_backend_grpc_request_duration", metric.WithUnit("s")); err != nil {
		return err
	}

	o.otelMetrics = instruments

	return nil
}

// newPrometheusMetrics registers process, runtime, and application collectors.
func newPrometheusMetrics(registry *prometheus.Registry, runtimeMetrics bool) *prometheusMetrics {
	metrics := buildPrometheusMetrics()

	if runtimeMetrics {
		registry.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	}

	registry.MustRegister(
		metrics.listenerConnections,
		metrics.listenerActive,
		metrics.listenerDuration,
		metrics.applicationRequests,
		metrics.applicationDuration,
		metrics.backendHTTPRequests,
		metrics.backendHTTPDuration,
		metrics.backendGRPCRequests,
		metrics.backendGRPCDuration,
		metrics.observabilityStartups,
		metrics.observabilityShutdowns,
	)

	return metrics
}

// buildPrometheusMetrics creates all application collectors without registering them.
func buildPrometheusMetrics() *prometheusMetrics {
	return &prometheusMetrics{
		listenerConnections: newCounterVec("pfxhttp_listener_connections_total", "Total listener connection events.", labelComponent, labelName, labelEvent, labelResult),
		listenerActive:      newGaugeVec("pfxhttp_listener_active_connections", "Currently active listener connections.", labelComponent, labelName),
		listenerDuration:    newDurationVec("pfxhttp_listener_connection_duration_seconds", "Listener connection duration in seconds.", labelComponent, labelName, labelResult),
		applicationRequests: newCounterVec(
			"pfxhttp_application_requests_total",
			"Total application-level requests by component, name, and outcome.",
			labelComponent,
			labelName,
			labelListener,
			labelOutcome,
		),
		applicationDuration:    newDurationVec("pfxhttp_application_request_duration_seconds", "Application-level request duration in seconds.", labelComponent, labelName, labelListener, labelOutcome),
		backendHTTPRequests:    newCounterVec("pfxhttp_backend_http_requests_total", "Total outgoing HTTP backend requests.", labelComponent, labelName, labelMethod, labelStatusClass, labelResult),
		backendHTTPDuration:    newDurationVec("pfxhttp_backend_http_request_duration_seconds", "Outgoing HTTP backend request duration in seconds.", labelComponent, labelName, labelMethod, labelStatusClass, labelResult),
		backendGRPCRequests:    newCounterVec("pfxhttp_backend_grpc_requests_total", "Total outgoing gRPC backend requests.", labelComponent, labelName, labelMethod, labelStatus, labelResult),
		backendGRPCDuration:    newDurationVec("pfxhttp_backend_grpc_request_duration_seconds", "Outgoing gRPC backend request duration in seconds.", labelComponent, labelName, labelMethod, labelStatus, labelResult),
		observabilityStartups:  newCounterVec("pfxhttp_observability_startups_total", "Prometheus endpoint startup attempts.", labelResult),
		observabilityShutdowns: newCounterVec("pfxhttp_observability_shutdowns_total", "Observability shutdown attempts.", labelResult),
	}
}

// newCounterVec builds a Prometheus counter vector with a consistent option shape.
func newCounterVec(name, help string, labels ...string) *prometheus.CounterVec {
	return prometheus.NewCounterVec(prometheus.CounterOpts{Name: name, Help: help}, labels)
}

// newDurationVec builds a Prometheus duration histogram vector with default buckets.
func newDurationVec(name, help string, labels ...string) *prometheus.HistogramVec {
	return prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    name,
		Help:    help,
		Buckets: prometheus.DefBuckets,
	}, labels)
}

// newGaugeVec builds a Prometheus gauge vector with a consistent option shape.
func newGaugeVec(name, help string, labels ...string) *prometheus.GaugeVec {
	return prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: name, Help: help}, labels)
}

// StartPrometheusServer starts the optional Prometheus HTTP endpoint.
func (o *Observability) StartPrometheusServer() error {
	if o == nil || !o.PrometheusEnabled() {
		return nil
	}

	address := net.JoinHostPort(o.config.PrometheusAddress, fmt.Sprintf("%d", o.config.PrometheusPort))

	listener, err := net.Listen("tcp", address)
	if err != nil {
		o.observeObservabilityStartup(resultError)

		return fmt.Errorf("listen prometheus endpoint %s: %w", address, err)
	}

	mux := http.NewServeMux()
	mux.Handle(o.PrometheusPath(), o.PrometheusHandler())

	tlsConfig, err := buildPrometheusServerTLSConfig(o.config.PrometheusTLS)
	if err != nil {
		_ = listener.Close()

		o.observeObservabilityStartup(resultError)

		return err
	}

	server := &http.Server{
		Addr:              address,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		TLSConfig:         tlsConfig,
	}

	o.prometheusListener = listener
	o.prometheusServer = server
	o.observeObservabilityStartup(resultOK)

	go func() {
		var serveErr error
		if tlsConfig != nil {
			serveErr = server.ServeTLS(listener, "", "")
		} else {
			serveErr = server.Serve(listener)
		}

		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			o.logger.Error("Prometheus endpoint stopped", slog.String("error", serveErr.Error()))
		}
	}()

	o.logger.Info(
		"Prometheus metrics endpoint started",
		slog.String("address", address),
		slog.String("path", o.PrometheusPath()),
		slog.Bool("tls", tlsConfig != nil),
		slog.Bool("basic_auth", o.config.PrometheusHTTPAuthBasic != ""),
	)

	return nil
}

// PrometheusHandler returns the HTTP handler for this runtime's Prometheus registry.
func (o *Observability) PrometheusHandler() http.Handler {
	if o == nil || o.registry == nil {
		return http.NotFoundHandler()
	}

	handler := promhttp.HandlerFor(o.registry, promhttp.HandlerOpts{})
	if o.config.PrometheusHTTPAuthBasic == "" {
		return handler
	}

	username, password, err := splitBasicAuthCredentials(o.config.PrometheusHTTPAuthBasic)
	if err != nil {
		return http.HandlerFunc(func(responseWriter http.ResponseWriter, _ *http.Request) {
			http.Error(responseWriter, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		})
	}

	return requireHTTPBasicAuth(username, password, handler)
}

// buildPrometheusServerTLSConfig creates the server-side TLS settings for the scrape endpoint.
func buildPrometheusServerTLSConfig(cfg PrometheusTLS) (*tls.Config, error) {
	if !cfg.Enabled {
		return nil, nil
	}

	if cfg.Cert == "" || cfg.Key == "" {
		return nil, errors.New("observability prometheus_tls requires cert and key when enabled")
	}

	minVersion, err := resolveTLSMinVersion(cfg.MinVersion)
	if err != nil {
		return nil, fmt.Errorf("observability prometheus_tls: %w", err)
	}

	cert, err := tls.LoadX509KeyPair(cfg.Cert, cfg.Key)
	if err != nil {
		return nil, fmt.Errorf("observability prometheus_tls load cert/key: %w", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   minVersion,
	}, nil
}

// requireHTTPBasicAuth protects an HTTP handler with constant-time Basic auth checks.
func requireHTTPBasicAuth(username, password string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		gotUser, gotPassword, ok := request.BasicAuth()
		if !ok || !secureStringEqual(gotUser, username) || !secureStringEqual(gotPassword, password) {
			responseWriter.Header().Set("WWW-Authenticate", `Basic realm="pfxhttp metrics"`)
			http.Error(responseWriter, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)

			return
		}

		next.ServeHTTP(responseWriter, request)
	})
}

// secureStringEqual compares strings without leaking useful timing information about their contents.
func secureStringEqual(got, want string) bool {
	gotHash := sha256.Sum256([]byte(got))
	wantHash := sha256.Sum256([]byte(want))

	return subtle.ConstantTimeCompare(gotHash[:], wantHash[:]) == 1
}

// PrometheusEnabled reports whether the Prometheus endpoint should be started.
func (o *Observability) PrometheusEnabled() bool {
	return o != nil && o.config.PrometheusEnabled && o.registry != nil
}

// PrometheusPath returns the configured metrics path with its runtime default applied.
func (o *Observability) PrometheusPath() string {
	if o == nil || o.config.PrometheusPath == "" {
		return defaultPrometheusPath
	}

	return o.config.PrometheusPath
}

// Shutdown flushes OpenTelemetry providers and stops the optional Prometheus endpoint.
func (o *Observability) Shutdown(ctx context.Context) error {
	if o == nil {
		return nil
	}

	var shutdownErrors []error
	if o.prometheusServer != nil {
		shutdownErrors = append(shutdownErrors, o.prometheusServer.Shutdown(ctx))
	}

	if o.meterProvider != nil {
		shutdownErrors = append(shutdownErrors, o.meterProvider.Shutdown(ctx))
	}

	if o.traceProvider != nil {
		shutdownErrors = append(shutdownErrors, o.traceProvider.Shutdown(ctx))
	}

	err := errors.Join(shutdownErrors...)
	if err != nil {
		o.observeObservabilityShutdown(resultError)
	} else {
		o.observeObservabilityShutdown(resultOK)
	}

	return err
}

// StartSpan creates an internal trace span when tracing is enabled.
func (o *Observability) StartSpan(ctx context.Context, name string, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
	return o.StartSpanWithKind(ctx, name, trace.SpanKindInternal, attrs...)
}

func (o *Observability) traceSpansEnabled() bool {
	return o != nil && o.config.OTelEnabled && o.config.OTelTracesEnabled && o.tracer != nil
}

// StartSpanWithKind creates a trace span with the supplied kind when tracing is enabled.
func (o *Observability) StartSpanWithKind(ctx context.Context, name string, kind trace.SpanKind, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
	if ctx == nil {
		ctx = context.Background()
	}

	if !o.traceSpansEnabled() {
		return ctx, trace.SpanFromContext(ctx)
	}

	return o.tracer.Start(ctx, name, trace.WithSpanKind(kind), trace.WithAttributes(attrs...))
}

func startInternalSpanFromContext(ctx context.Context, name string, attrs ...attribute.KeyValue) (context.Context, *Observability, trace.Span) {
	obs := ObservabilityFromContext(ctx)
	if obs == nil || !obs.traceSpansEnabled() {
		return ctx, nil, nil
	}

	spanCtx, span := obs.StartSpan(ctx, name, attrs...)

	return spanCtx, obs, span
}

func finishObservedSpan(obs *Observability, span trace.Span, err error) {
	if span == nil {
		return
	}

	if err != nil && obs != nil {
		obs.RecordSpanError(span, err)
	}

	span.End()
}

func setSpanAttributes(span trace.Span, attrs ...attribute.KeyValue) {
	if span == nil {
		return
	}

	span.SetAttributes(attrs...)
}

// RecordSpanError annotates a span with an error and marks it failed.
func (o *Observability) RecordSpanError(span trace.Span, err error) {
	if span == nil || err == nil {
		return
	}

	span.RecordError(err)
	span.SetStatus(codes.Error, err.Error())
}

// InstrumentHTTPClient wraps a client transport with outbound HTTP metrics, spans, and trace propagation.
func (o *Observability) InstrumentHTTPClient(client *http.Client) {
	if o == nil || client == nil {
		return
	}

	if _, ok := client.Transport.(*observabilityRoundTripper); ok {
		return
	}

	if client.Transport == nil {
		client.Transport = http.DefaultTransport
	}

	client.Transport = &observabilityRoundTripper{base: client.Transport, obs: o}
}

// ObserveListenerConnection records listener connection events and active connection deltas.
func (o *Observability) ObserveListenerConnection(ctx context.Context, component, name, event, result string, activeDelta int64) {
	if o == nil {
		return
	}

	if o.metrics != nil {
		o.metrics.listenerConnections.WithLabelValues(component, name, event, result).Inc()

		if activeDelta != 0 {
			o.metrics.listenerActive.WithLabelValues(component, name).Add(float64(activeDelta))
		}
	}

	if o.otelMetrics != nil {
		attrs := []attribute.KeyValue{
			attribute.String(labelComponent, component),
			attribute.String(labelName, name),
			attribute.String(labelEvent, event),
			attribute.String(labelResult, result),
		}
		o.otelMetrics.listenerConnections.Add(ctx, 1, metric.WithAttributes(attrs...))

		if activeDelta != 0 {
			o.otelMetrics.listenerActive.Add(ctx, activeDelta, metric.WithAttributes(attribute.String(labelComponent, component), attribute.String(labelName, name)))
		}
	}
}

// ObserveListenerDuration records how long a connection remained active.
func (o *Observability) ObserveListenerDuration(ctx context.Context, component, name, result string, duration time.Duration) {
	if o == nil {
		return
	}

	if o.metrics != nil {
		o.metrics.listenerDuration.WithLabelValues(component, name, result).Observe(duration.Seconds())
	}

	if o.otelMetrics != nil {
		o.otelMetrics.listenerDuration.Record(ctx, duration.Seconds(), metric.WithAttributes(
			attribute.String(labelComponent, component),
			attribute.String(labelName, name),
			attribute.String(labelResult, result),
		))
	}
}

// ObserveApplicationRequest records one protocol-level application request outcome and duration.
func (o *Observability) ObserveApplicationRequest(ctx context.Context, component, name, listener, outcome string, duration time.Duration) {
	attrs := []attribute.KeyValue{
		attribute.String(labelComponent, component),
		attribute.String(labelName, name),
		attribute.String(labelListener, listener),
		attribute.String(labelOutcome, outcome),
	}
	o.observeCounterDuration(
		ctx,
		o.applicationPrometheusPair(),
		o.applicationOTelPair(),
		[]string{component, name, listener, outcome},
		attrs,
		duration,
	)
}

// ObserveBackendHTTPRequest records one outgoing HTTP backend request.
func (o *Observability) ObserveBackendHTTPRequest(ctx context.Context, component, name, method, statusClass, result string, duration time.Duration) {
	attrs := backendRequestAttributes(component, name, method, labelStatusClass, statusClass, result)
	o.observeCounterDuration(ctx, o.backendHTTPPrometheusPair(), o.backendHTTPOTelPair(), []string{component, name, method, statusClass, result}, attrs, duration)
}

// ObserveBackendGRPCRequest records one outgoing gRPC backend request.
func (o *Observability) ObserveBackendGRPCRequest(ctx context.Context, component, name, method, status, result string, duration time.Duration) {
	attrs := backendRequestAttributes(component, name, method, labelStatus, status, result)
	o.observeCounterDuration(ctx, o.backendGRPCPrometheusPair(), o.backendGRPCOTelPair(), []string{component, name, method, status, result}, attrs, duration)
}

// backendRequestAttributes returns common attributes for outbound backend metrics.
func backendRequestAttributes(component, name, method, statusKey, statusValue, result string) []attribute.KeyValue {
	attrs := []attribute.KeyValue{
		attribute.String(labelComponent, component),
		attribute.String(labelName, name),
		attribute.String(labelMethod, method),
		attribute.String(statusKey, statusValue),
		attribute.String(labelResult, result),
	}

	return attrs
}

// observeCounterDuration records the same event in Prometheus and OpenTelemetry.
func (o *Observability) observeCounterDuration(ctx context.Context, prom prometheusCounterDuration, otelPair otelCounterDuration, labelValues []string, attrs []attribute.KeyValue, duration time.Duration) {
	if o == nil {
		return
	}

	if prom.counter != nil && prom.duration != nil {
		prom.counter.WithLabelValues(labelValues...).Inc()
		prom.duration.WithLabelValues(labelValues...).Observe(duration.Seconds())
	}

	if otelPair.counter != nil && otelPair.duration != nil {
		otelPair.counter.Add(ctx, 1, metric.WithAttributes(attrs...))
		otelPair.duration.Record(ctx, duration.Seconds(), metric.WithAttributes(attrs...))
	}
}

// applicationPrometheusPair returns the application request Prometheus collectors.
func (o *Observability) applicationPrometheusPair() prometheusCounterDuration {
	if o == nil || o.metrics == nil {
		return prometheusCounterDuration{}
	}

	return prometheusCounterDuration{o.metrics.applicationRequests, o.metrics.applicationDuration}
}

// applicationOTelPair returns the application request OTel instruments.
func (o *Observability) applicationOTelPair() otelCounterDuration {
	if o == nil || o.otelMetrics == nil {
		return otelCounterDuration{}
	}

	return otelCounterDuration{o.otelMetrics.applicationRequests, o.otelMetrics.applicationDuration}
}

// backendHTTPPrometheusPair returns the backend HTTP Prometheus collectors.
func (o *Observability) backendHTTPPrometheusPair() prometheusCounterDuration {
	if o == nil || o.metrics == nil {
		return prometheusCounterDuration{}
	}

	return prometheusCounterDuration{o.metrics.backendHTTPRequests, o.metrics.backendHTTPDuration}
}

// backendHTTPOTelPair returns the backend HTTP OTel instruments.
func (o *Observability) backendHTTPOTelPair() otelCounterDuration {
	if o == nil || o.otelMetrics == nil {
		return otelCounterDuration{}
	}

	return otelCounterDuration{o.otelMetrics.backendHTTPRequests, o.otelMetrics.backendHTTPDuration}
}

// backendGRPCPrometheusPair returns the backend gRPC Prometheus collectors.
func (o *Observability) backendGRPCPrometheusPair() prometheusCounterDuration {
	if o == nil || o.metrics == nil {
		return prometheusCounterDuration{}
	}

	return prometheusCounterDuration{o.metrics.backendGRPCRequests, o.metrics.backendGRPCDuration}
}

// backendGRPCOTelPair returns the backend gRPC OTel instruments.
func (o *Observability) backendGRPCOTelPair() otelCounterDuration {
	if o == nil || o.otelMetrics == nil {
		return otelCounterDuration{}
	}

	return otelCounterDuration{o.otelMetrics.backendGRPCRequests, o.otelMetrics.backendGRPCDuration}
}

// observeObservabilityStartup records Prometheus endpoint startup attempts.
func (o *Observability) observeObservabilityStartup(result string) {
	if o != nil && o.metrics != nil {
		o.metrics.observabilityStartups.WithLabelValues(result).Inc()
	}
}

// observeObservabilityShutdown records observability shutdown attempts.
func (o *Observability) observeObservabilityShutdown(result string) {
	if o != nil && o.metrics != nil {
		o.metrics.observabilityShutdowns.WithLabelValues(result).Inc()
	}
}

// ContextWithObservability attaches the runtime to a request context for code paths without direct deps access.
func ContextWithObservability(ctx context.Context, obs *Observability) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}

	if obs == nil {
		return ctx
	}

	return context.WithValue(ctx, observabilityContextKey, obs)
}

// ObservabilityFromContext returns the runtime attached to the context.
func ObservabilityFromContext(ctx context.Context) *Observability {
	if ctx == nil {
		return nil
	}

	obs, _ := ctx.Value(observabilityContextKey).(*Observability)

	return obs
}

// ContextWithBackendOperation labels outbound HTTP client work with the originating component and entry name.
func ContextWithBackendOperation(ctx context.Context, component, name string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}

	return context.WithValue(ctx, backendOperationKey, backendOperation{component: component, name: name})
}

// backendOperationFromContext returns low-cardinality labels for outbound backend calls.
func backendOperationFromContext(ctx context.Context) backendOperation {
	if ctx == nil {
		return backendOperation{component: componentBackendHTTP, name: defaultBackendName}
	}

	if op, ok := ctx.Value(backendOperationKey).(backendOperation); ok {
		if op.component == "" {
			op.component = componentBackendHTTP
		}

		if op.name == "" {
			op.name = defaultBackendName
		}

		return op
	}

	return backendOperation{component: componentBackendHTTP, name: defaultBackendName}
}

// InjectGRPCTraceContext copies the current W3C trace context into outgoing gRPC metadata.
func InjectGRPCTraceContext(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}

	md, _ := metadata.FromOutgoingContext(ctx)
	carrier := grpcMetadataCarrier(md.Copy())
	otel.GetTextMapPropagator().Inject(ctx, carrier)

	return metadata.NewOutgoingContext(ctx, metadata.MD(carrier))
}

type grpcMetadataCarrier metadata.MD

// Get returns the first metadata value for key.
func (c grpcMetadataCarrier) Get(key string) string {
	values := metadata.MD(c).Get(key)
	if len(values) == 0 {
		return ""
	}

	return values[0]
}

// Set replaces metadata values for key.
func (c grpcMetadataCarrier) Set(key, value string) {
	metadata.MD(c).Set(strings.ToLower(key), value)
}

// Keys returns all metadata keys.
func (c grpcMetadataCarrier) Keys() []string {
	keys := make([]string, 0, len(c))
	for key := range c {
		keys = append(keys, key)
	}

	return keys
}

type observabilityRoundTripper struct {
	base http.RoundTripper
	obs  *Observability
}

// RoundTrip records outbound HTTP metrics, creates a client span, and propagates trace context.
func (rt *observabilityRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if rt == nil || rt.base == nil || rt.obs == nil {
		return http.DefaultTransport.RoundTrip(req)
	}

	op := backendOperationFromContext(req.Context())
	ctx, span := rt.obs.StartSpanWithKind(req.Context(),
		httpClientSpanName(req.Method),
		trace.SpanKindClient,
		attribute.String("http.request.method", req.Method),
		attribute.String("server.address", req.URL.Hostname()),
		attribute.String("url.scheme", req.URL.Scheme),
		attribute.String("url.path", req.URL.EscapedPath()),
		attribute.String("pfxhttp.component", op.component),
		attribute.String("pfxhttp.name", op.name),
	)

	req = req.WithContext(ctx)
	otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(req.Header))

	start := time.Now()
	resp, err := rt.base.RoundTrip(req)
	statusClass := statusClassError
	result := resultOK
	statusCode := 0

	if resp != nil {
		statusCode = resp.StatusCode
		statusClass = httpStatusClass(resp.StatusCode)

		if resp.StatusCode >= http.StatusInternalServerError {
			result = resultStatusCode

			span.SetStatus(codes.Error, http.StatusText(resp.StatusCode))
		}
	} else if err != nil {
		result = resultError
	}

	if err != nil {
		rt.obs.RecordSpanError(span, err)
	}

	span.SetAttributes(
		attribute.Int("http.response.status_code", statusCode),
		attribute.String(labelResult, result),
	)
	rt.obs.ObserveBackendHTTPRequest(ctx, op.component, op.name, req.Method, statusClass, result, time.Since(start))
	span.End()

	return resp, err
}

// httpClientSpanName returns a low-cardinality span name for outbound HTTP requests.
func httpClientSpanName(method string) string {
	return fmt.Sprintf("HTTP %s", method)
}

// socketMapSpanName returns a low-cardinality server span name for socket-map requests.
func socketMapSpanName(name string) string {
	return fmt.Sprintf("socket_map %s", safeMetricName(name))
}

// policyServiceSpanName returns a low-cardinality server span name for policy-service requests.
func policyServiceSpanName(name string) string {
	return fmt.Sprintf("policy_service %s", safeMetricName(name))
}

// dovecotSASLSpanName returns a low-cardinality server span name for Dovecot SASL auth requests.
func dovecotSASLSpanName(name string) string {
	return fmt.Sprintf("dovecot_sasl %s", safeMetricName(name))
}

// grpcClientSpanName returns a low-cardinality span name for outbound gRPC requests.
func grpcClientSpanName(method string) string {
	return fmt.Sprintf("gRPC %s", method)
}

// safeMetricName keeps empty entry names out of labels and span names.
func safeMetricName(name string) string {
	if name == "" {
		return defaultBackendName
	}

	return name
}

// httpStatusClass maps a concrete status code to a low-cardinality class label.
func httpStatusClass(status int) string {
	if status <= 0 {
		return "0xx"
	}

	return fmt.Sprintf("%dxx", status/100)
}

// outcomeFromSender normalizes Postfix sender statuses for metrics.
func outcomeFromSender(sender Sender) string {
	if sender == nil {
		return outcomeUnknown
	}

	if ps, ok := sender.(*PostfixSender); ok {
		return normalizeOutcome(ps.status)
	}

	fields := strings.Fields(sender.String())
	if len(fields) == 0 {
		return outcomeUnknown
	}

	return normalizeOutcome(fields[0])
}

// outcomeFromSASLResult converts SASL results into low-cardinality outcomes.
func outcomeFromSASLResult(result *SASLAuthResult, err error) string {
	if err != nil {
		return outcomeError
	}

	if result == nil {
		return outcomeUnknown
	}

	if result.NeedContinuation {
		return outcomeContinue
	}

	if result.Success {
		return outcomeOK
	}

	if result.Temporary {
		return outcomeTempfail
	}

	return outcomeFail
}

// normalizeOutcome maps protocol statuses and backend errors into stable metric labels.
func normalizeOutcome(status string) string {
	switch strings.ToUpper(strings.TrimSpace(status)) {
	case string(DovecotCmdOK), "DUNNO", postfixActionReject, "PREPEND", "DISCARD", "HOLD", "FILTER", "REDIRECT":
		return strings.ToLower(strings.TrimSpace(status))
	case "NOTFOUND":
		return outcomeNotFound
	case "TEMP", "DEFER":
		return outcomeTempfail
	case "TIMEOUT":
		return outcomeTimeout
	case "PERM", "FAIL":
		return outcomeFail
	case "":
		return outcomeUnknown
	default:
		return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(status), " ", "_"))
	}
}
