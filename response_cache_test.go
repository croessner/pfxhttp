package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func newTestHTTPClient(fn roundTripperFunc) *http.Client {
	return &http.Client{Transport: fn}
}

func TestInMemoryResponseCache_Basic(t *testing.T) {
	cache := NewInMemoryResponseCache(50 * time.Millisecond)

	if _, ok := cache.Get("name", "key"); ok {
		t.Fatalf("expected empty cache miss")
	}

	cache.Set("name", "key", CachedResponse{Status: "OK", Data: "hello"})

	if got, ok := cache.Get("name", "key"); !ok || got.Status != "OK" || got.Data != "hello" {
		t.Fatalf("unexpected cache get: %+v ok=%v", got, ok)
	}

	time.Sleep(60 * time.Millisecond)

	if _, ok := cache.Get("name", "key"); ok {
		t.Fatalf("expected cache entry to expire")
	}
}

func minimalConfig() *Config {
	return &Config{
		Server: Server{
			SockmapMaxReplySize: 1000000,
			ResponseCache:       ResponseCacheConfig{Enabled: true, TTL: time.Second},
		},
		SocketMaps: map[string]Request{
			"map1": {Target: "http://example", Payload: `{"key":"{{.Key}}"}`, StatusCode: 200, ValueField: "value"},
		},
		PolicyServices: map[string]Request{
			"policyA": {Target: "http://example", Payload: `{"k":"{{.Key}}"}`, StatusCode: 200, ValueField: "value"},
		},
	}
}

func TestMapClient_UsesCacheOnBackendFailure(t *testing.T) {
	cfg := minimalConfig()
	respCache = NewInMemoryResponseCache(time.Second)

	// Backend returns error
	httpClient = newTestHTTPClient(func(r *http.Request) (*http.Response, error) {
		return nil, errors.New("backend down")
	})

	// Seed cache
	respCache.Set("map1", "key-123", CachedResponse{Status: "OK", Data: "cached"})

	recv := &PostfixMapReceiver{}
	_ = recv.ReadNetString(NewNetStringFromString("map1 key-123"))
	client := NewMapClient(NewContext(), cfg)
	client.SetReceiver(recv)

	if err := client.SendAndReceive(); err != nil {
		t.Fatalf("SendAndReceive error: %v", err)
	}

	if client.GetSender().String() != "OK cached" {
		t.Fatalf("expected cached response, got %q", client.GetSender().String())
	}
}

func TestPolicyClient_UsesCacheOnBackendFailure(t *testing.T) {
	cfg := minimalConfig()
	respCache = NewInMemoryResponseCache(time.Second)

	// Backend returns error
	httpClient = newTestHTTPClient(func(r *http.Request) (*http.Response, error) {
		return nil, errors.New("backend down")
	})

	// Seed cache. Key is JSON of policy
	pol := NewPostfixPolicy()
	pol.SetData("sender", "a@b")
	pol.SetData("recipient", "c@d")
	recv := NewPostfixPolicyReceiver("policyA")
	_ = recv.ReadPolcy(pol)

	respCache.Set("policyA", recv.GetKey(), CachedResponse{Status: "REJECT", Data: "blocked"})

	client := NewPolicyClient(NewContext(), cfg)
	client.SetReceiver(recv)

	if err := client.SendAndReceive(); err != nil {
		t.Fatalf("SendAndReceive error: %v", err)
	}

	if client.GetSender().String() != "REJECT blocked" {
		t.Fatalf("expected cached policy response, got %q", client.GetSender().String())
	}
}

func TestClients_UpdateCacheOnSuccess(t *testing.T) {
	cfg := minimalConfig()
	respCache = NewInMemoryResponseCache(time.Second)

	// Backend responds successfully with JSON
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"value":"OK done"}`))
	}))

	defer ts.Close()

	cfg.SocketMaps["map1"] = Request{Target: ts.URL, Payload: `{"key":"{{.Key}}"}`, StatusCode: 200, ValueField: "value"}

	httpClient = ts.Client()

	recv := &PostfixMapReceiver{}
	_ = recv.ReadNetString(NewNetStringFromString("map1 key-xyz"))
	client := NewMapClient(NewContext(), cfg)
	client.SetReceiver(recv)

	if err := client.SendAndReceive(); err != nil {
		t.Fatalf("SendAndReceive error: %v", err)
	}

	// Check that cache has the entry
	if entry, ok := respCache.Get("map1", "key-xyz"); !ok || entry.Status != "OK" || entry.Data != "OK done" {
		t.Fatalf("expected cache updated with OK done, got ok=%v entry=%+v", ok, entry)
	}
}

func TestMapClient_DoesNotCacheOnNotFoundOrPerm(t *testing.T) {
	cfg := minimalConfig()
	respCache = NewInMemoryResponseCache(time.Second)

	// Backend responds 200 but missing value -> NOTFOUND
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"other":"x"}`))
	}))
	defer ts.Close()
	cfg.SocketMaps["map1"] = Request{Target: ts.URL, Payload: `{"key":"{{.Key}}"}`, StatusCode: 200, ValueField: "value"}
	httpClient = ts.Client()

	recv := &PostfixMapReceiver{}
	_ = recv.ReadNetString(NewNetStringFromString("map1 key-no-cache"))
	client := NewMapClient(NewContext(), cfg)
	client.SetReceiver(recv)
	_ = client.SendAndReceive()
	if _, ok := respCache.Get("map1", "key-no-cache"); ok {
		t.Fatalf("expected NOTFOUND result not to be cached")
	}
}
