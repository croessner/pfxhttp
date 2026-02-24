package main

import (
	"net/http"
	"testing"
	"time"
)

func TestHttpClientConfiguration(t *testing.T) {
	cfg := &Config{
		Server: Server{
			HTTPClient: HTTPClient{
				Timeout: 15 * time.Second,
			},
			TLS: TLS{
				Enabled:    true,
				SkipVerify: true,
			},
		},
	}

	InitializeHttpClient(cfg)

	if httpClient.Timeout != 15*time.Second {
		t.Errorf("Expected timeout 15s, got %v", httpClient.Timeout)
	}

	rt, ok := httpClient.Transport.(*userAgentRoundTripper)
	if !ok {
		t.Fatal("Transport is not userAgentRoundTripper")
	}
	transport, ok := rt.base.(*http.Transport)
	if !ok {
		t.Fatal("Base transport is not *http.Transport")
	}

	if transport.TLSClientConfig == nil {
		t.Fatal("TLSClientConfig is nil")
	}

	if !transport.TLSClientConfig.InsecureSkipVerify {
		t.Error("Expected InsecureSkipVerify to be true")
	}
}

func TestHttpClientDefaultTimeout(t *testing.T) {
	cfg := &Config{}
	InitializeHttpClient(cfg)

	if httpClient.Timeout != 60*time.Second {
		t.Errorf("Expected default timeout 60s, got %v", httpClient.Timeout)
	}
}

func TestHttpClientProxyConfiguration(t *testing.T) {
	proxyURL := "http://proxy.example.com:8080"
	cfg := &Config{
		Server: Server{
			HTTPClient: HTTPClient{
				Proxy: proxyURL,
			},
		},
	}

	InitializeHttpClient(cfg)

	rt, ok := httpClient.Transport.(*userAgentRoundTripper)
	if !ok {
		t.Fatal("Transport is not userAgentRoundTripper")
	}
	transport, ok := rt.base.(*http.Transport)
	if !ok {
		t.Fatal("Base transport is not *http.Transport")
	}

	if transport.Proxy == nil {
		t.Fatal("Proxy function is nil")
	}

	req, _ := http.NewRequest("GET", "http://example.com", nil)
	url, err := transport.Proxy(req)
	if err != nil {
		t.Fatalf("Failed to get proxy URL: %v", err)
	}

	if url == nil {
		t.Fatal("Expected proxy URL, got nil")
	}

	if url.String() != proxyURL {
		t.Errorf("Expected proxy URL %s, got %s", proxyURL, url.String())
	}
}
