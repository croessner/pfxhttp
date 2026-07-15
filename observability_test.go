package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	oteltrace "go.opentelemetry.io/otel/trace"
)

const (
	testMapName    = "map1"
	testMapPayload = `{"key":"{{ .Key }}"}`
	testValueField = "value"
	testListener   = "listener1"

	testMetricsUsername    = "metrics"
	testMetricsPassword    = "secret"
	testMetricsCredentials = testMetricsUsername + ":" + testMetricsPassword
	testWrongPassword      = "wrong"
	testTLS13Version       = "1.3"
	testMetricsLocalhost   = "localhost"
	testRSAPrivateKeyBlock = "RSA PRIVATE KEY"
	testSocketMapLabel     = "SocketMap"
	testPartialPolicyFrame = "request=smtpd_access_policy\n"
)

type recordedSpan struct {
	name    string
	traceID oteltrace.TraceID
	spanID  oteltrace.SpanID
	parent  oteltrace.SpanContext
	kind    oteltrace.SpanKind
	start   time.Time
	end     time.Time
	attrs   []attribute.KeyValue
	status  string
}

type spanRecorder struct {
	mu    sync.Mutex
	spans []recordedSpan
}

// OnStart implements sdktrace.SpanProcessor without mutating started spans.
func (r *spanRecorder) OnStart(_ context.Context, _ sdktrace.ReadWriteSpan) {}

// OnEnd stores immutable span relationship data for assertions.
func (r *spanRecorder) OnEnd(span sdktrace.ReadOnlySpan) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.spans = append(r.spans, recordedSpan{
		name:    span.Name(),
		traceID: span.SpanContext().TraceID(),
		spanID:  span.SpanContext().SpanID(),
		parent:  span.Parent(),
		kind:    span.SpanKind(),
		start:   span.StartTime(),
		end:     span.EndTime(),
		attrs:   append([]attribute.KeyValue(nil), span.Attributes()...),
		status:  span.Status().Description,
	})
}

// Shutdown implements sdktrace.SpanProcessor.
func (r *spanRecorder) Shutdown(context.Context) error {
	return nil
}

// ForceFlush implements sdktrace.SpanProcessor.
func (r *spanRecorder) ForceFlush(context.Context) error {
	return nil
}

// findSpan returns the first recorded span with the supplied name.
func (r *spanRecorder) findSpan(name string) (recordedSpan, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, span := range r.spans {
		if span.name == name {
			return span, true
		}
	}

	return recordedSpan{}, false
}

// countSpans returns the number of ended spans with the supplied name.
func (r *spanRecorder) countSpans(name string) int {
	r.mu.Lock()
	defer r.mu.Unlock()

	count := 0

	for _, span := range r.spans {
		if span.name == name {
			count++
		}
	}

	return count
}

func (r *spanRecorder) snapshot() []recordedSpan {
	r.mu.Lock()
	defer r.mu.Unlock()

	return append([]recordedSpan(nil), r.spans...)
}

func assertChildSpan(t *testing.T, recorder *spanRecorder, parent recordedSpan, name string) recordedSpan {
	t.Helper()

	child, ok := recorder.findSpan(name)
	if !ok {
		t.Fatalf("child span %q not recorded", name)
	}

	if child.traceID != parent.traceID {
		t.Fatalf("child span %q trace ID = %s, want %s", name, child.traceID, parent.traceID)
	}

	if child.parent.SpanID() != parent.spanID {
		t.Fatalf("child span %q parent span ID = %s, want %s", name, child.parent.SpanID(), parent.spanID)
	}

	return child
}

func assertSpanOmitsAttribute(t *testing.T, span recordedSpan, key string) {
	t.Helper()

	for _, attr := range span.attrs {
		if string(attr.Key) == key {
			t.Fatalf("span %q contains forbidden attribute %q", span.name, key)
		}
	}
}

// newTraceTestObservability returns a runtime backed by an in-memory span recorder.
func newTraceTestObservability(t *testing.T) (*Observability, *spanRecorder) {
	t.Helper()

	recorder := &spanRecorder{}
	provider := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
		sdktrace.WithSpanProcessor(recorder),
	)

	t.Cleanup(func() {
		_ = provider.Shutdown(context.Background())
	})

	return newTraceTestObservabilityWithProvider(provider), recorder
}

func newPrometheusTestObservability(t *testing.T) *Observability {
	t.Helper()

	obs, err := NewObservability(t.Context(), ObservabilityConfig{PrometheusEnabled: true}, "test-version", slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("NewObservability() error = %v", err)
	}

	return obs
}

func waitForMetricValue(t *testing.T, collector prometheus.Collector, want float64) {
	t.Helper()

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if got := testutil.ToFloat64(collector); got == want {
			return
		}

		time.Sleep(time.Millisecond)
	}

	t.Fatalf("metric value = %v, want %v", testutil.ToFloat64(collector), want)
}

func histogramSampleCount(t *testing.T, observer prometheus.Observer) uint64 {
	t.Helper()

	metricValue, ok := observer.(prometheus.Metric)
	if !ok {
		t.Fatalf("histogram observer type = %T, want prometheus.Metric", observer)
	}

	metric := &dto.Metric{}
	if err := metricValue.Write(metric); err != nil {
		t.Fatalf("write histogram metric: %v", err)
	}

	return metric.GetHistogram().GetSampleCount()
}

func TestObservabilityRecordsApplicationRequestMetric(t *testing.T) {
	obs, err := NewObservability(t.Context(), ObservabilityConfig{
		PrometheusEnabled:        true,
		PrometheusRuntimeMetrics: false,
	}, "test-version", slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("NewObservability() error = %v", err)
	}

	obs.ObserveApplicationRequest(t.Context(), componentSocketMap, testMapName, testListener, outcomeOK, 25*time.Millisecond)

	got := testutil.ToFloat64(obs.metrics.applicationRequests.WithLabelValues(componentSocketMap, testMapName, testListener, outcomeOK))
	if got != 1 {
		t.Fatalf("applicationRequests = %v, want 1", got)
	}
}

func TestProtocolConnectionStateMetricsSeparateIdleAndPartial(t *testing.T) {
	obs := newPrometheusTestObservability(t)
	serverConn, clientConn := net.Pipe()

	t.Cleanup(func() { _ = serverConn.Close() })
	t.Cleanup(func() { _ = clientConn.Close() })

	reader := newSocketMapReader(serverConn, socketMapFramingLimits{
		partialTimeout:  time.Second,
		maxRequestBytes: 16,
		maxLengthDigits: 2,
	})
	reader.SetStateObserver(func(state string, delta int64) {
		obs.ObserveListenerState(t.Context(), componentSocketMap, testListener, state, delta)
	})

	result := make(chan error, 1)

	go func() {
		_, err := reader.Read(t.Context())
		result <- err
	}()

	waitForMetricValue(t, obs.metrics.listenerState.WithLabelValues(componentSocketMap, testListener, "idle"), 1)

	if _, err := io.WriteString(clientConn, "4"); err != nil {
		t.Fatalf("write first frame byte: %v", err)
	}

	waitForMetricValue(t, obs.metrics.listenerState.WithLabelValues(componentSocketMap, testListener, "idle"), 0)
	waitForMetricValue(t, obs.metrics.listenerState.WithLabelValues(componentSocketMap, testListener, "partial"), 1)

	if _, err := io.WriteString(clientConn, ":test,"); err != nil {
		t.Fatalf("finish frame: %v", err)
	}

	if err := <-result; err != nil {
		t.Fatalf("read complete frame: %v", err)
	}

	waitForMetricValue(t, obs.metrics.listenerState.WithLabelValues(componentSocketMap, testListener, "partial"), 0)
}

func TestRequestLimiterMetricsRecoverAfterQueuedWork(t *testing.T) {
	obs := newPrometheusTestObservability(t)
	limiter := NewRequestLimiter(t.Context(), 1, 1, time.Second)
	limiter.SetObserver(func(event requestLimiterEvent) {
		obs.ObserveRequestLimiter(t.Context(), componentSocketMap, testListener, event)
	})

	first, _ := limiter.Acquire(t.Context())
	second := make(chan *RequestPermit, 1)

	go func() {
		permit, _ := limiter.Acquire(t.Context())
		second <- permit
	}()

	waitForLimiterSnapshot(t, limiter, 1, 1)
	waitForMetricValue(t, obs.metrics.requestState.WithLabelValues(componentSocketMap, testListener, "inflight"), 1)
	waitForMetricValue(t, obs.metrics.requestState.WithLabelValues(componentSocketMap, testListener, "queued"), 1)

	first.Release()
	(<-second).Release()
	waitForMetricValue(t, obs.metrics.requestState.WithLabelValues(componentSocketMap, testListener, "inflight"), 0)
	waitForMetricValue(t, obs.metrics.requestState.WithLabelValues(componentSocketMap, testListener, "queued"), 0)

	if got := testutil.ToFloat64(obs.metrics.requestAdmissions.WithLabelValues(componentSocketMap, testListener, string(requestQueued))); got != 1 {
		t.Fatalf("queued admission counter = %v, want 1", got)
	}

	queueWait := obs.metrics.requestQueueWait.WithLabelValues(componentSocketMap, testListener, string(requestQueued))
	if got := histogramSampleCount(t, queueWait); got != 1 {
		t.Fatalf("queue wait samples = %d, want 1", got)
	}
}

func TestMultiServerStopRecordsOneDrainOutcome(t *testing.T) {
	obs := newPrometheusTestObservability(t)
	deps := &Deps{Logger: slog.New(slog.DiscardHandler), Observability: obs}
	server := NewMultiServer(t.Context(), deps, nil).(*MultiServer)
	server.kind = listenKindPolicyService
	server.name = testListener

	server.Stop()
	server.Stop()

	if got := testutil.ToFloat64(obs.metrics.listenerDrains.WithLabelValues(listenKindPolicyService, testListener, resultOK)); got != 1 {
		t.Fatalf("successful drain outcomes = %v, want 1", got)
	}
}

func TestConfiguredSocketMapNameBoundsUnknownInput(t *testing.T) {
	const attackerControlledName = "secret-user-supplied-map-name"

	config := &Config{SocketMaps: map[string]Request{testMapName: {}}}
	if got := configuredSocketMapName(config, attackerControlledName); got != unknownBackendName {
		t.Fatalf("unknown SocketMap telemetry name = %q, want %q", got, unknownBackendName)
	}

	if got := configuredSocketMapName(config, testMapName); got != testMapName {
		t.Fatalf("configured SocketMap telemetry name = %q, want %q", got, testMapName)
	}
}

func TestProtocolTelemetryAndLogsOmitRawTrafficValues(t *testing.T) {
	const (
		rawKey     = "raw-secret-socketmap-key"
		rawError   = "raw-secret-backend-error"
		rawPayload = `{"credential":"raw-secret-password"}`
	)

	var logOutput bytes.Buffer

	obs, recorder := newTraceTestObservability(t)
	logger := slog.New(slog.NewTextHandler(&logOutput, nil))
	deps := &Deps{
		Config: &Config{
			Server: Server{SockmapMaxReplySize: 1024},
			SocketMaps: map[string]Request{
				testMapName: {
					Target:     lifecycleBackendURL,
					Payload:    rawPayload,
					StatusCode: http.StatusOK,
					ValueField: testValueField,
				},
			},
		},
		Logger: logger,
		HTTPClient: newTestHTTPClient(func(*http.Request) (*http.Response, error) {
			return nil, errors.New(rawError)
		}),
		Observability: obs,
	}
	server := &MultiServer{
		name:           testListener,
		kind:           listenKindSocketMap,
		deps:           deps,
		ctx:            ContextWithObservability(t.Context(), obs),
		limiter:        NewRequestLimiter(t.Context(), 1, 1, time.Second),
		requestTimeout: time.Second,
	}

	response := runNetStringHandlerForTest(t, server, testMapName+" "+rawKey)
	if response.String() != socketMapTemporaryResponse {
		t.Fatalf("backend failure response = %q, want bounded temporary response", response.String())
	}

	observedOutput := logOutput.String() + fmt.Sprint(recorder.snapshot())
	for _, forbidden := range []string{
		rawKey,
		rawError,
		rawPayload,
		"raw-secret-password",
		"pipe",
		"session=",
		"sub_session=",
		" error=",
	} {
		if strings.Contains(observedOutput, forbidden) {
			t.Fatalf("telemetry or logs expose forbidden value %q: %s", forbidden, observedOutput)
		}
	}
}

func TestRequestLimiterMetricsRecoverAfterCancellationAndShutdown(t *testing.T) {
	obs := newPrometheusTestObservability(t)
	limiter := NewRequestLimiter(context.Background(), 1, 1, time.Second)
	limiter.SetObserver(func(event requestLimiterEvent) {
		obs.ObserveRequestLimiter(t.Context(), componentPolicyService, testListener, event)
	})
	occupied, _ := limiter.Acquire(context.Background())

	canceledCtx, cancel := context.WithCancel(context.Background())
	canceled := make(chan RequestAdmissionOutcome, 1)

	go func() {
		_, outcome := limiter.Acquire(canceledCtx)
		canceled <- outcome
	}()

	waitForLimiterSnapshot(t, limiter, 1, 1)
	cancel()

	if outcome := <-canceled; outcome != requestCallerCanceled {
		t.Fatalf("canceled outcome = %q", outcome)
	}

	waitForMetricValue(t, obs.metrics.requestState.WithLabelValues(componentPolicyService, testListener, "queued"), 0)

	shutdown := make(chan RequestAdmissionOutcome, 1)

	go func() {
		_, outcome := limiter.Acquire(context.Background())
		shutdown <- outcome
	}()

	waitForLimiterSnapshot(t, limiter, 1, 1)
	limiter.Stop()

	if outcome := <-shutdown; outcome != requestServerShutdown {
		t.Fatalf("shutdown outcome = %q", outcome)
	}

	occupied.Release()
	waitForMetricValue(t, obs.metrics.requestState.WithLabelValues(componentPolicyService, testListener, "queued"), 0)
	waitForMetricValue(t, obs.metrics.requestState.WithLabelValues(componentPolicyService, testListener, "inflight"), 0)
}

func TestRequestLimiterFailureCountersUseBoundedOutcomes(t *testing.T) {
	obs := newPrometheusTestObservability(t)
	limiter := NewRequestLimiter(t.Context(), 1, 1, 20*time.Millisecond)
	limiter.SetObserver(func(event requestLimiterEvent) {
		obs.ObserveRequestLimiter(t.Context(), componentPolicyService, testListener, event)
	})

	occupied, _ := limiter.Acquire(t.Context())
	defer occupied.Release()

	timedOut := make(chan RequestAdmissionOutcome, 1)

	go func() {
		_, outcome := limiter.Acquire(t.Context())
		timedOut <- outcome
	}()

	waitForLimiterSnapshot(t, limiter, 1, 1)

	if _, outcome := limiter.Acquire(t.Context()); outcome != requestQueueFull {
		t.Fatalf("full outcome = %q", outcome)
	}

	if outcome := <-timedOut; outcome != requestQueueTimeout {
		t.Fatalf("timeout outcome = %q", outcome)
	}

	for _, outcome := range []RequestAdmissionOutcome{requestQueueFull, requestQueueTimeout} {
		if got := testutil.ToFloat64(obs.metrics.requestAdmissions.WithLabelValues(componentPolicyService, testListener, string(outcome))); got != 1 {
			t.Fatalf("%s counter = %v, want 1", outcome, got)
		}
	}
}

func TestPrometheusHandlerRequiresBasicAuth(t *testing.T) {
	obs, err := NewObservability(t.Context(), ObservabilityConfig{
		PrometheusEnabled:       true,
		PrometheusHTTPAuthBasic: testMetricsCredentials,
	}, "test-version", slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("NewObservability() error = %v", err)
	}

	handler := obs.PrometheusHandler()
	tests := []struct {
		name       string
		username   string
		password   string
		wantStatus int
	}{
		{
			name:       "missing",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "wrong credentials",
			username:   testMetricsUsername,
			password:   testWrongPassword,
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "valid",
			username:   testMetricsUsername,
			password:   testMetricsPassword,
			wantStatus: http.StatusOK,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, defaultPrometheusPath, nil)
			if tc.username != "" || tc.password != "" {
				request.SetBasicAuth(tc.username, tc.password)
			}

			responseRecorder := httptest.NewRecorder()
			handler.ServeHTTP(responseRecorder, request)

			if responseRecorder.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", responseRecorder.Code, tc.wantStatus)
			}

			if tc.wantStatus == http.StatusUnauthorized && responseRecorder.Header().Get("WWW-Authenticate") == "" {
				t.Fatal("missing WWW-Authenticate challenge")
			}
		})
	}
}

func TestBuildPrometheusServerTLSConfig(t *testing.T) {
	certFile, keyFile, _ := writeTestServerCertificate(t)

	tlsConfig, err := buildPrometheusServerTLSConfig(PrometheusTLS{
		Enabled:    true,
		Cert:       certFile,
		Key:        keyFile,
		MinVersion: testTLS13Version,
	})
	if err != nil {
		t.Fatalf("buildPrometheusServerTLSConfig() error = %v", err)
	}

	if tlsConfig.MinVersion != tls.VersionTLS13 {
		t.Fatalf("MinVersion = %x, want %x", tlsConfig.MinVersion, tls.VersionTLS13)
	}

	if len(tlsConfig.Certificates) != 1 {
		t.Fatalf("certificates = %d, want 1", len(tlsConfig.Certificates))
	}
}

func TestStartPrometheusServerWithTLSAndBasicAuth(t *testing.T) {
	certFile, keyFile, certPEM := writeTestServerCertificate(t)
	port := freeLocalTCPPort(t)

	obs, err := NewObservability(t.Context(), ObservabilityConfig{
		PrometheusEnabled:       true,
		PrometheusAddress:       defaultPrometheusAddress,
		PrometheusPort:          port,
		PrometheusHTTPAuthBasic: testMetricsCredentials,
		PrometheusTLS: PrometheusTLS{
			Enabled: true,
			Cert:    certFile,
			Key:     keyFile,
		},
	}, "test-version", slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("NewObservability() error = %v", err)
	}

	if err = obs.StartPrometheusServer(); err != nil {
		t.Fatalf("StartPrometheusServer() error = %v", err)
	}

	t.Cleanup(func() {
		_ = obs.Shutdown(context.Background())
	})

	rootCAs := x509.NewCertPool()
	if !rootCAs.AppendCertsFromPEM(certPEM) {
		t.Fatal("append test certificate to RootCAs")
	}

	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: rootCAs, MinVersion: tls.VersionTLS12}},
		Timeout:   5 * time.Second,
	}

	request, err := http.NewRequest(http.MethodGet, fmt.Sprintf("https://%s:%d%s", defaultPrometheusAddress, port, defaultPrometheusPath), nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	request.SetBasicAuth(testMetricsUsername, testMetricsPassword)

	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("scrape metrics over TLS: %v", err)
	}

	defer func() {
		_ = response.Body.Close()
	}()

	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusOK)
	}
}

func TestInstrumentedHTTPClientPropagatesTraceContext(t *testing.T) {
	obs, recorder := newTraceTestObservability(t)
	client, traceparent := newObservedMapClient(t, obs)

	ctx, parentSpan := obs.StartSpanWithKind(t.Context(), socketMapSpanName(testMapName), oteltrace.SpanKindServer)
	if err := client.SendAndReceiveContext(ctx); err != nil {
		t.Fatalf("SendAndReceiveContext() error = %v", err)
	}

	parentSpan.End()

	if *traceparent == "" {
		t.Fatal("backend request did not receive traceparent header")
	}

	parent, ok := recorder.findSpan(socketMapSpanName(testMapName))
	if !ok {
		t.Fatalf("parent span %q not recorded", socketMapSpanName(testMapName))
	}

	child, ok := recorder.findSpan(httpClientSpanName(http.MethodPost))
	if !ok {
		t.Fatalf("child span %q not recorded", httpClientSpanName(http.MethodPost))
	}

	if child.traceID != parent.traceID {
		t.Fatalf("child trace ID = %s, want %s", child.traceID, parent.traceID)
	}

	if child.parent.SpanID() != parent.spanID {
		t.Fatalf("child parent span ID = %s, want %s", child.parent.SpanID(), parent.spanID)
	}
}

func TestHandleNetStringConnectionRecordsSocketMapProtocolSpans(t *testing.T) {
	obs, recorder := newTraceTestObservability(t)
	client, _ := newObservedMapClient(t, obs)

	mapClient, ok := client.(*MapClient)
	if !ok {
		t.Fatalf("observed map client type = %T, want *MapClient", client)
	}

	deps := &Deps{
		Config:        mapClient.config,
		Logger:        slog.New(slog.DiscardHandler),
		HTTPClient:    mapClient.httpClient,
		Observability: obs,
	}
	server := &MultiServer{
		name:    testListener,
		kind:    listenKindSocketMap,
		deps:    deps,
		ctx:     context.Background(),
		limiter: NewRequestLimiter(context.Background(), 1, 1, time.Second),
	}

	response := runNetStringHandlerForTest(t, server, testMapName+" user@example.test")
	if response.String() != "OK mapped" {
		t.Fatalf("socket-map response = %q, want %q", response.String(), "OK mapped")
	}

	parent, ok := recorder.findSpan(socketMapSpanName(testMapName))
	if !ok {
		t.Fatalf("parent span %q not recorded", socketMapSpanName(testMapName))
	}

	for _, name := range []string{
		socketMapDecodeSpanName,
		requestQueueSpanName,
		socketMapBackendSpanName,
		socketMapEncodeSpanName,
		socketMapWriteSpanName,
	} {
		assertChildSpan(t, recorder, parent, name)
	}

	ordered := []string{socketMapDecodeSpanName, requestQueueSpanName, socketMapBackendSpanName, socketMapEncodeSpanName, socketMapWriteSpanName}
	for index := 1; index < len(ordered); index++ {
		previous, _ := recorder.findSpan(ordered[index-1])

		current, _ := recorder.findSpan(ordered[index])
		if previous.end.After(current.start) {
			t.Fatalf("span %q ended after %q started", previous.name, current.name)
		}
	}
}

func TestHandlePolicyServiceConnectionRecordsProtocolSpans(t *testing.T) {
	obs, recorder := newTraceTestObservability(t)
	deps := newObservedPolicyDeps(t, obs)
	server := &MultiServer{
		name: testListener,
		deps: deps,
		ctx:  context.Background(),
	}

	response := runPolicyHandlerForTest(t, server, "request=smtpd_access_policy\nclient_address=192.0.2.10\n\n")
	if response != "action=DUNNO\n\n" {
		t.Fatalf("policy response = %q, want %q", response, "action=DUNNO\n\n")
	}

	parent, ok := recorder.findSpan(policyServiceSpanName(testListener))
	if !ok {
		t.Fatalf("parent span %q not recorded", policyServiceSpanName(testListener))
	}

	for _, name := range []string{
		policyServiceDecodeSpanName,
		policyServiceBackendSpanName,
		policyServiceEncodeSpanName,
		policyServiceWriteSpanName,
	} {
		assertChildSpan(t, recorder, parent, name)
	}
}

func TestIncompleteProtocolFramesDoNotRecordApplicationSpans(t *testing.T) {
	tests := []struct {
		name     string
		payload  string
		spanName string
		handler  func(*MultiServer, net.Conn)
	}{
		{
			name:     "SocketMap idle close",
			spanName: socketMapSpanName(defaultBackendName),
			handler:  func(server *MultiServer, conn net.Conn) { server.HandleNetStringConnection(conn) },
		},
		{
			name:     "SocketMap partial frame",
			payload:  "4:ab",
			spanName: socketMapSpanName(defaultBackendName),
			handler:  func(server *MultiServer, conn net.Conn) { server.HandleNetStringConnection(conn) },
		},
		{
			name:     "policy idle close",
			spanName: policyServiceSpanName(testListener),
			handler:  func(server *MultiServer, conn net.Conn) { server.HandlePolicyServiceConnection(conn) },
		},
		{
			name:     "policy partial frame",
			payload:  testPartialPolicyFrame,
			spanName: policyServiceSpanName(testListener),
			handler:  func(server *MultiServer, conn net.Conn) { server.HandlePolicyServiceConnection(conn) },
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assertIncompleteFrameHasNoApplicationSpan(t, test.payload, test.spanName, test.handler)
		})
	}
}

func TestPublicListenerGaugesRecoverAfterClientClose(t *testing.T) {
	obs := newPrometheusTestObservability(t)
	deps := newObservedPolicyDeps(t, obs)
	listener := startObservedServer(t, deps, 2, Listen{
		Kind: listenKindPolicyService,
		Name: testListener,
		Type: listenTypeTCP,
		Limits: LimitsConfig{
			MaxInflightRequests: 1,
			MaxQueuedRequests:   new(1),
			RequestTimeout:      time.Second,
		},
	})

	conn, accepted := dialObservedConnection(t, listener)
	setLifecycleDeadline(t, conn)

	if _, err := io.WriteString(conn, lifecyclePolicyRequest("192.0.2.40")); err != nil {
		t.Fatalf("write observed policy request: %v", err)
	}

	if response := readPolicyResponse(t, bufio.NewReader(conn)); response != "action=DUNNO\n\n" {
		t.Fatalf("observed policy response = %q, want DUNNO", response)
	}

	waitForActiveRead(t, accepted)

	if err := conn.Close(); err != nil {
		t.Fatalf("close observed policy client: %v", err)
	}

	waitForMetricValue(t, obs.metrics.listenerActive.WithLabelValues(listenKindPolicyService, testListener), 0)
	waitForMetricValue(t, obs.metrics.listenerState.WithLabelValues(listenKindPolicyService, testListener, "idle"), 0)
	waitForMetricValue(t, obs.metrics.requestState.WithLabelValues(listenKindPolicyService, testListener, "inflight"), 0)
	waitForMetricValue(t, obs.metrics.requestState.WithLabelValues(listenKindPolicyService, testListener, "queued"), 0)
}

func TestDovecotListenerStateTracksPartialCommand(t *testing.T) {
	obs := newPrometheusTestObservability(t)
	deps := newLifecycleSASLDeps(t)
	deps.Observability = obs

	listener := startObservedServer(t, deps, 1, Listen{
		Kind: listenKindDovecotSASL,
		Name: concurrencyTestSASL,
		Type: listenTypeTCP,
		Limits: LimitsConfig{
			MaxInflightRequests: 1,
			MaxQueuedRequests:   new(1),
			RequestTimeout:      time.Second,
		},
	})

	conn, _ := dialObservedConnection(t, listener)
	_ = completeDovecotHandshakeWithReader(t, conn)

	if _, err := io.WriteString(conn, "AUTH\tpartial"); err != nil {
		t.Fatalf("write partial Dovecot command: %v", err)
	}

	partial := obs.metrics.listenerState.WithLabelValues(listenKindDovecotSASL, concurrencyTestSASL, "partial")
	waitForMetricValue(t, partial, 1)

	if err := conn.Close(); err != nil {
		t.Fatalf("close partial Dovecot client: %v", err)
	}

	waitForMetricValue(t, partial, 0)
	waitForMetricValue(t, obs.metrics.listenerState.WithLabelValues(listenKindDovecotSASL, concurrencyTestSASL, "idle"), 0)
}

func TestListenerStartupLogIncludesEffectiveLimits(t *testing.T) {
	var output bytes.Buffer

	logger := slog.New(slog.NewTextHandler(&output, nil))
	deps := &Deps{Logger: logger}
	server := NewMultiServer(t.Context(), deps, nil)

	listener, err := net.Listen(listenTypeTCP, "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for startup log test: %v", err)
	}

	limits := LimitsConfig{
		MaxConnections:       7,
		MaxInflightRequests:  3,
		MaxQueuedRequests:    new(5),
		RequestQueueTimeout:  250 * time.Millisecond,
		RequestTimeout:       2 * time.Second,
		ResponseWriteReserve: 100 * time.Millisecond,
	}
	if err = server.Listen(Listen{Kind: listenKindPolicyService, Name: testListener, Type: listenTypeTCP, Limits: limits}, listener); err != nil {
		t.Fatalf("Listen() error = %v", err)
	}

	t.Cleanup(server.Stop)

	for _, expected := range []string{
		"max_connections=7",
		"max_inflight_requests=3",
		"max_queued_requests=5",
		"request_queue_timeout=250ms",
		"request_timeout=2s",
		"response_write_reserve=100ms",
	} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("startup log %q does not contain %q", output.String(), expected)
		}
	}
}

func TestProtocolHandlersReturnAfterIdleEOF(t *testing.T) {
	server := &MultiServer{
		name: testListener,
		deps: &Deps{Logger: slog.New(slog.DiscardHandler)},
		ctx:  t.Context(),
	}

	for _, test := range []struct {
		name    string
		handler func(net.Conn)
	}{
		{name: testSocketMapLabel, handler: server.HandleNetStringConnection},
		{name: testSocketName, handler: server.HandlePolicyServiceConnection},
	} {
		t.Run(test.name, func(t *testing.T) {
			conn := &idleEOFConn{}
			test.handler(conn)

			if conn.reads != 1 {
				t.Fatalf("idle EOF reads = %d, want 1", conn.reads)
			}
		})
	}
}

type idleEOFConn struct {
	reads int
}

func (c *idleEOFConn) Read([]byte) (int, error) {
	c.reads++

	return 0, io.EOF
}

func (*idleEOFConn) Write(buffer []byte) (int, error) { return len(buffer), nil }
func (*idleEOFConn) Close() error                     { return nil }
func (*idleEOFConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (*idleEOFConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (*idleEOFConn) SetDeadline(time.Time) error      { return nil }
func (*idleEOFConn) SetReadDeadline(time.Time) error  { return nil }
func (*idleEOFConn) SetWriteDeadline(time.Time) error { return nil }

var _ net.Conn = (*idleEOFConn)(nil)

func assertIncompleteFrameHasNoApplicationSpan(
	t *testing.T,
	payload string,
	spanName string,
	handler func(*MultiServer, net.Conn),
) {
	t.Helper()

	obs, recorder := newTraceTestObservability(t)
	server := &MultiServer{
		name: testListener,
		deps: &Deps{Logger: slog.New(slog.DiscardHandler), Observability: obs},
		ctx:  t.Context(),
	}
	serverConn, clientConn := net.Pipe()

	done := make(chan struct{})

	go func() {
		defer close(done)

		handler(server, serverConn)
	}()

	if payload != "" {
		if _, err := io.WriteString(clientConn, payload); err != nil {
			t.Fatalf("write partial frame: %v", err)
		}
	}

	_ = clientConn.Close()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("protocol handler did not return")
	}

	if got := recorder.countSpans(spanName); got != 0 {
		t.Fatalf("application spans = %d, want 0", got)
	}
}

func runNetStringHandlerForTest(t *testing.T, server *MultiServer, payload string) NetData {
	t.Helper()

	serverConn, clientConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()

	done := make(chan struct{})
	go func() {
		defer close(done)

		server.HandleNetStringConnection(serverConn)
	}()

	if err := clientConn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}

	request := NewNetStringFromString(payload)

	message := fmt.Sprintf("%d:%s,", request.Length(), request.String())
	if _, err := clientConn.Write([]byte(message)); err != nil {
		t.Fatalf("write netstring request: %v", err)
	}

	response, err := server.readNetString(clientConn)
	if err != nil {
		t.Fatalf("read netstring response: %v", err)
	}

	if response == nil {
		t.Fatal("missing netstring response")
	}

	_ = clientConn.Close()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("HandleNetStringConnection did not return")
	}

	return response
}

func runPolicyHandlerForTest(t *testing.T, server *MultiServer, payload string) string {
	t.Helper()

	serverConn, clientConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()

	done := make(chan struct{})
	go func() {
		defer close(done)

		server.HandlePolicyServiceConnection(serverConn)
	}()

	if err := clientConn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}

	if _, err := clientConn.Write([]byte(payload)); err != nil {
		t.Fatalf("write policy request: %v", err)
	}

	reader := bufio.NewReader(clientConn)

	first, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read policy response line: %v", err)
	}

	second, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read policy response terminator: %v", err)
	}

	_ = clientConn.Close()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("HandlePolicyServiceConnection did not return")
	}

	return first + second
}

// newObservedMapClient returns a map client wired to an instrumented test backend.
func newObservedMapClient(t *testing.T, obs *Observability) (GenericClient, *string) {
	t.Helper()

	var traceparent string

	backend := httptest.NewServer(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		traceparent = request.Header.Get("traceparent")

		responseWriter.WriteHeader(http.StatusOK)
		_, _ = responseWriter.Write([]byte(`{"value":"mapped"}`))
	}))
	t.Cleanup(backend.Close)

	httpClient := backend.Client()
	obs.InstrumentHTTPClient(httpClient)

	deps := newObservedMapDeps(backend.URL, httpClient, obs)

	receiver := &PostfixMapReceiver{}
	if err := receiver.ReadNetString(NewNetStringFromString(testMapName + " user@example.test")); err != nil {
		t.Fatalf("ReadNetString() error = %v", err)
	}

	client := NewMapClient(deps, deps.GetLogger())
	client.SetReceiver(receiver)

	return client, &traceparent
}

// newObservedMapDeps returns dependencies for one observed socket-map backend.
func newObservedMapDeps(target string, httpClient *http.Client, obs *Observability) *Deps {
	cfg := &Config{
		Server: Server{SockmapMaxReplySize: 1000000},
		SocketMaps: map[string]Request{
			testMapName: {
				Target:     target,
				Payload:    testMapPayload,
				StatusCode: http.StatusOK,
				ValueField: testValueField,
			},
		},
	}

	return &Deps{
		Config:        cfg,
		Logger:        slog.New(slog.DiscardHandler),
		HTTPClient:    httpClient,
		Observability: obs,
	}
}

func newObservedPolicyDeps(t *testing.T, obs *Observability) *Deps {
	t.Helper()

	backend := httptest.NewServer(http.HandlerFunc(func(responseWriter http.ResponseWriter, _ *http.Request) {
		responseWriter.WriteHeader(http.StatusOK)
		_, _ = responseWriter.Write([]byte(`{"action":"DUNNO"}`))
	}))
	t.Cleanup(backend.Close)

	httpClient := backend.Client()
	obs.InstrumentHTTPClient(httpClient)

	cfg := &Config{
		PolicyServices: map[string]Request{
			testListener: {
				Target:     backend.URL,
				Payload:    testPolicyPayload,
				StatusCode: http.StatusOK,
				ValueField: testPolicyActionField,
			},
		},
	}

	return &Deps{
		Config:        cfg,
		Logger:        slog.New(slog.DiscardHandler),
		HTTPClient:    httpClient,
		Observability: obs,
	}
}

// writeTestServerCertificate creates a temporary self-signed certificate valid for localhost.
func writeTestServerCertificate(t *testing.T) (string, string, []byte) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate private key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: testMetricsLocalhost,
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{testMetricsLocalhost},
		IPAddresses:           []net.IP{net.ParseIP(defaultPrometheusAddress)},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: testRSAPrivateKeyBlock, Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "server.crt")
	keyFile := filepath.Join(tmpDir, "server.key")

	if err = os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatalf("write certificate: %v", err)
	}

	if err = os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatalf("write private key: %v", err)
	}

	return certFile, keyFile, certPEM
}

// freeLocalTCPPort returns an available loopback TCP port for listener smoke tests.
func freeLocalTCPPort(t *testing.T) int {
	t.Helper()

	listener, err := net.Listen("tcp", defaultPrometheusAddress+":0")
	if err != nil {
		t.Fatalf("listen on loopback: %v", err)
	}

	defer func() {
		_ = listener.Close()
	}()

	addr, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("unexpected listener address type %T", listener.Addr())
	}

	return addr.Port
}
