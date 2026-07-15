package main

import (
	"bufio"
	"encoding/base64"
	"log/slog"
	"net"
	"net/http"
	"testing"
	"time"
)

const testPolicyPayload = "{{ .Key }}"
const testPolicyActionField = "action"

func TestIdleConnectionsConsumeNoRequestPermits(t *testing.T) {
	limiter := NewRequestLimiter(t.Context(), 1, 1, time.Second)
	server := &MultiServer{
		name:    testListener,
		deps:    &Deps{Logger: slog.New(slog.DiscardHandler)},
		ctx:     t.Context(),
		limiter: limiter,
	}
	serverConn, clientConn := net.Pipe()

	done := make(chan struct{})

	go func() {
		defer close(done)

		server.HandleNetStringConnection(serverConn)
	}()

	inFlight, queued := limiter.Snapshot()
	if inFlight != 0 || queued != 0 {
		t.Fatalf("idle limiter snapshot = (%d, %d), want (0, 0)", inFlight, queued)
	}

	_ = clientConn.Close()

	<-done
}

func TestSocketMapQueueFullReturnsValidTemporaryNetstring(t *testing.T) {
	deps, _ := newConcurrencyTestDeps(t)
	limiter := NewRequestLimiter(t.Context(), 1, 0, time.Second)

	occupied, _ := limiter.Acquire(t.Context())
	defer occupied.Release()

	server := &MultiServer{
		name:           concurrencyTestMap,
		deps:           deps,
		ctx:            t.Context(),
		limiter:        limiter,
		requestTimeout: time.Second,
	}

	response := runNetStringHandlerForTest(t, server, concurrencyTestMap+" user@example.test")
	if response.String() != socketMapTemporaryResponse {
		t.Fatalf("SocketMap overload response = %q, want %q", response.String(), socketMapTemporaryResponse)
	}
}

func TestPolicyQueueFullReturnsFailClosedTemporaryAction(t *testing.T) {
	obs, _ := newTraceTestObservability(t)
	deps := newObservedPolicyDeps(t, obs)
	limiter := NewRequestLimiter(t.Context(), 1, 0, time.Second)

	occupied, _ := limiter.Acquire(t.Context())
	defer occupied.Release()

	server := &MultiServer{
		name:           testListener,
		deps:           deps,
		ctx:            t.Context(),
		limiter:        limiter,
		requestTimeout: time.Second,
	}

	response := runPolicyHandlerForTest(t, server, "request=smtpd_access_policy\nclient_address=192.0.2.10\n\n")
	if response != policyTemporaryResponse {
		t.Fatalf("policy overload response = %q, want %q", response, policyTemporaryResponse)
	}
}

func TestDovecotSASLQueueFullReturnsSecretSafeTemporaryFailure(t *testing.T) {
	limiter := NewRequestLimiter(t.Context(), 1, 0, time.Second)

	occupied, _ := limiter.Acquire(t.Context())
	defer occupied.Release()

	deps := &Deps{
		Config: &Config{DovecotSASL: map[string]Request{
			concurrencyTestSASL: {Mechanisms: []string{saslMechanismPlain}},
		}},
		Logger: slog.New(slog.DiscardHandler),
	}
	server := &MultiServer{
		name:           concurrencyTestSASL,
		deps:           deps,
		ctx:            t.Context(),
		limiter:        limiter,
		requestTimeout: time.Second,
	}
	serverConn, clientConn := net.Pipe()

	done := make(chan struct{})

	go func() {
		defer close(done)

		server.HandleDovecotSASLConnection(serverConn)
	}()

	completeDovecotClientHandshake(t, clientConn)

	credentials := "synthetic-user\x00synthetic-password"

	plain := base64.StdEncoding.EncodeToString([]byte("\x00" + credentials))
	if _, err := clientConn.Write([]byte("AUTH\t1\tPLAIN\tservice=smtp\tresp=" + plain + "\n")); err != nil {
		t.Fatalf("write AUTH request: %v", err)
	}

	if err := clientConn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set SASL response deadline: %v", err)
	}

	response, err := bufio.NewReader(clientConn).ReadString('\n')
	if err != nil {
		t.Fatalf("read SASL overload response: %v", err)
	}

	want := "FAIL\t1\treason=temporary failure\ttemp\n"
	if response != want {
		t.Fatalf("SASL overload response = %q, want %q", response, want)
	}

	_ = clientConn.Close()

	<-done
}

func TestPolicyBudgetCancelsSlowHTTPAndReservesTemporaryResponse(t *testing.T) {
	backendCanceled := make(chan struct{}, 1)
	backendBudget := make(chan time.Duration, 1)
	httpClient := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		deadline, ok := request.Context().Deadline()
		if !ok {
			t.Error("backend request has no propagated deadline")
		} else {
			backendBudget <- time.Until(deadline)
		}

		<-request.Context().Done()

		backendCanceled <- struct{}{}

		return nil, request.Context().Err()
	})}

	deps := &Deps{
		Config: &Config{PolicyServices: map[string]Request{
			testListener: {
				Target:     "http://backend.example.test/policy",
				Payload:    testPolicyPayload,
				StatusCode: http.StatusOK,
				ValueField: testPolicyActionField,
			},
		}},
		Logger:     slog.New(slog.DiscardHandler),
		HTTPClient: httpClient,
	}
	server := &MultiServer{
		name:                 testListener,
		deps:                 deps,
		ctx:                  t.Context(),
		limiter:              NewRequestLimiter(t.Context(), 1, 1, 50*time.Millisecond),
		requestTimeout:       250 * time.Millisecond,
		responseWriteReserve: 75 * time.Millisecond,
	}

	started := time.Now()

	response := runPolicyHandlerForTest(t, server, "request=smtpd_access_policy\nclient_address=192.0.2.10\n\n")
	if elapsed := time.Since(started); elapsed >= server.requestTimeout {
		t.Fatalf("temporary response took %s, want less than total budget %s", elapsed, server.requestTimeout)
	}

	if response != "action=DEFER "+TempServerProblem+"\n\n" {
		t.Fatalf("slow-backend response = %q, want temporary DEFER", response)
	}

	assertObservedBackendBudget(t, backendBudget, server.requestTimeout-server.responseWriteReserve)

	select {
	case <-backendCanceled:
	case <-time.After(time.Second):
		t.Fatal("slow HTTP backend outlived request budget")
	}
}

func assertObservedBackendBudget(t *testing.T, observed <-chan time.Duration, maximum time.Duration) {
	t.Helper()

	select {
	case budget := <-observed:
		if budget <= 0 || budget > maximum {
			t.Fatalf("backend budget = %s, want positive and at most %s", budget, maximum)
		}
	case <-time.After(time.Second):
		t.Fatal("backend deadline was not observed")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

var _ http.RoundTripper = roundTripFunc(nil)
