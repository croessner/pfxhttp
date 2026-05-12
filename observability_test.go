package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
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
)

type recordedSpan struct {
	name    string
	traceID oteltrace.TraceID
	spanID  oteltrace.SpanID
	parent  oteltrace.SpanContext
	kind    oteltrace.SpanKind
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
