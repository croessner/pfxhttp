package main

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
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
