package main

import (
	"runtime"
	"slices"
	"strings"
	"testing"
)

func TestWorkerPoolDefaults(t *testing.T) {
	cfg := &Config{
		Server: Server{
			Listen: []Listen{
				{
					Kind:    "socket_map",
					Name:    "test",
					Type:    "tcp",
					Address: "127.0.0.1",
					Port:    23450,
				},
			},
		},
	}

	err := cfg.HandleConfig()
	if err != nil {
		t.Fatalf("HandleConfig failed: %v", err)
	}

	numCPU := runtime.GOMAXPROCS(0)
	expectedMaxWorkers := numCPU * 2
	expectedMaxQueue := expectedMaxWorkers * 10

	if cfg.Server.WorkerPool.MaxWorkers != expectedMaxWorkers {
		t.Errorf("Expected MaxWorkers %d, got %d", expectedMaxWorkers, cfg.Server.WorkerPool.MaxWorkers)
	}

	if cfg.Server.WorkerPool.MaxQueue != expectedMaxQueue {
		t.Errorf("Expected MaxQueue %d, got %d", expectedMaxQueue, cfg.Server.WorkerPool.MaxQueue)
	}
}

func TestResolveDefaultsMergesAllFields(t *testing.T) {
	raw := map[string]Request{
		"defaults": {
			Target:                  "https://example.com/api",
			HTTPAuthBasic:           "user:pass",
			CustomHeaders:           []string{"X-Common: yes"},
			Payload:                 `{"key": "{{ .Key }}"}`,
			StatusCode:              200,
			ValueField:              "result",
			ErrorField:              "error",
			NoErrorValue:            "not-found",
			HTTPRequestCompression:  true,
			HTTPResponseCompression: true,
			DefaultLocalPort:        "587",
		},
		"entry_a": {
			CustomHeaders: []string{"X-Pfx-Name: entry_a"},
		},
		"entry_b": {
			Target:        "https://other.com/api",
			CustomHeaders: []string{"X-Pfx-Name: entry_b"},
			StatusCode:    201,
		},
	}

	result := resolveDefaults(raw)

	// "defaults" key must be removed
	if _, ok := result["defaults"]; ok {
		t.Fatal("expected 'defaults' key to be removed")
	}

	// entry_a should inherit all defaults
	a := result["entry_a"]
	if a.Target != "https://example.com/api" {
		t.Errorf("entry_a.Target = %q, want %q", a.Target, "https://example.com/api")
	}
	if a.HTTPAuthBasic != "user:pass" {
		t.Errorf("entry_a.HTTPAuthBasic = %q, want %q", a.HTTPAuthBasic, "user:pass")
	}
	if a.Payload != `{"key": "{{ .Key }}"}` {
		t.Errorf("entry_a.Payload not inherited")
	}
	if a.StatusCode != 200 {
		t.Errorf("entry_a.StatusCode = %d, want 200", a.StatusCode)
	}
	if a.ValueField != "result" {
		t.Errorf("entry_a.ValueField = %q, want %q", a.ValueField, "result")
	}
	if a.ErrorField != "error" {
		t.Errorf("entry_a.ErrorField = %q, want %q", a.ErrorField, "error")
	}
	if a.NoErrorValue != "not-found" {
		t.Errorf("entry_a.NoErrorValue = %q, want %q", a.NoErrorValue, "not-found")
	}
	if !a.HTTPRequestCompression {
		t.Error("entry_a.HTTPRequestCompression should be true")
	}
	if !a.HTTPResponseCompression {
		t.Error("entry_a.HTTPResponseCompression should be true")
	}
	if a.DefaultLocalPort != "587" {
		t.Errorf("entry_a.DefaultLocalPort = %q, want %q", a.DefaultLocalPort, "587")
	}

	// entry_a custom_headers: defaults + entry-specific (additive)
	expectedHeaders := []string{"X-Common: yes", "X-Pfx-Name: entry_a"}
	if !slices.Equal(a.CustomHeaders, expectedHeaders) {
		t.Errorf("entry_a.CustomHeaders = %v, want %v", a.CustomHeaders, expectedHeaders)
	}

	// entry_b should use its own Target and StatusCode, but inherit the rest
	b := result["entry_b"]
	if b.Target != "https://other.com/api" {
		t.Errorf("entry_b.Target = %q, want %q", b.Target, "https://other.com/api")
	}
	if b.StatusCode != 201 {
		t.Errorf("entry_b.StatusCode = %d, want 201", b.StatusCode)
	}
	if b.ValueField != "result" {
		t.Errorf("entry_b.ValueField not inherited")
	}
}

func TestResolveDefaultsNilMap(t *testing.T) {
	result := resolveDefaults(nil)
	if result != nil {
		t.Errorf("expected nil, got %v", result)
	}
}

func TestResolveDefaultsNoDefaultsKey(t *testing.T) {
	raw := map[string]Request{
		"entry": {
			Target: "https://example.com",
		},
	}

	result := resolveDefaults(raw)
	if result["entry"].Target != "https://example.com" {
		t.Errorf("entry should remain unchanged without defaults")
	}
}

func TestResolveHTTPAuthBasic(t *testing.T) {
	section := map[string]Request{
		"test": {
			Target:        "https://example.com",
			HTTPAuthBasic: "user:secret",
			CustomHeaders: []string{"X-Custom: value"},
		},
	}

	resolveHTTPAuthBasic(section)

	entry := section["test"]
	if entry.HTTPAuthBasic != "" {
		t.Error("HTTPAuthBasic should be cleared after resolution")
	}
	if len(entry.CustomHeaders) != 2 {
		t.Fatalf("expected 2 custom headers, got %d", len(entry.CustomHeaders))
	}
	if !strings.HasPrefix(entry.CustomHeaders[0], "Authorization: Basic ") {
		t.Errorf("first header should be Authorization, got %q", entry.CustomHeaders[0])
	}
	if entry.CustomHeaders[1] != "X-Custom: value" {
		t.Errorf("second header should be X-Custom, got %q", entry.CustomHeaders[1])
	}
}

func TestValidateNoReservedKeys(t *testing.T) {
	cfg := &Config{
		Server: Server{
			Listen: []Listen{
				{
					Kind:    "socket_map",
					Name:    "defaults",
					Type:    "tcp",
					Address: "127.0.0.1",
					Port:    23450,
				},
			},
		},
	}

	err := cfg.HandleConfig()
	if err == nil {
		t.Fatal("expected error for reserved listener name 'defaults'")
	}
	if !strings.Contains(err.Error(), "reserved") {
		t.Errorf("error should mention 'reserved', got: %v", err)
	}
}

func TestValidateTargetsMissing(t *testing.T) {
	cfg := &Config{
		Server: Server{
			Listen: []Listen{
				{
					Kind:    "socket_map",
					Type:    "tcp",
					Address: "127.0.0.1",
					Port:    23450,
				},
			},
		},
		SocketMaps: map[string]Request{
			"no_target": {
				Payload: `{"key": "test"}`,
			},
		},
	}

	err := cfg.HandleConfig()
	if err == nil {
		t.Fatal("expected error for missing target")
	}
	if !strings.Contains(err.Error(), "missing a required 'target'") {
		t.Errorf("error should mention missing target, got: %v", err)
	}
}

func TestDefaultsInheritanceEndToEnd(t *testing.T) {
	cfg := &Config{
		Server: Server{
			Listen: []Listen{
				{
					Kind:    "socket_map",
					Type:    "tcp",
					Address: "127.0.0.1",
					Port:    23450,
				},
			},
		},
		SocketMaps: map[string]Request{
			"defaults": {
				Target:                  "http://example.com/api",
				HTTPAuthBasic:           "admin:secret",
				HTTPResponseCompression: true,
				Payload:                 `{"key": "{{ .Key }}"}`,
				StatusCode:              200,
				ValueField:              "result",
				ErrorField:              "error",
			},
			"relay_domains": {
				CustomHeaders: []string{"X-Pfx-Name: relay_domains"},
			},
			"transport_maps": {
				CustomHeaders: []string{"X-Pfx-Name: transport_maps"},
			},
		},
	}

	err := cfg.HandleConfig()
	if err != nil {
		t.Fatalf("HandleConfig failed: %v", err)
	}

	// "defaults" key must be gone
	if _, ok := cfg.SocketMaps["defaults"]; ok {
		t.Fatal("'defaults' key should be removed after processing")
	}

	// relay_domains should have inherited target, auth, compression, etc.
	rd := cfg.SocketMaps["relay_domains"]
	if rd.Target != "http://example.com/api" {
		t.Errorf("relay_domains.Target = %q, want %q", rd.Target, "http://example.com/api")
	}
	if !rd.HTTPResponseCompression {
		t.Error("relay_domains.HTTPResponseCompression should be true")
	}
	// HTTPAuthBasic should be resolved into Authorization header
	if rd.HTTPAuthBasic != "" {
		t.Error("HTTPAuthBasic should be cleared")
	}
	// First header should be Authorization, then X-Pfx-Name
	if len(rd.CustomHeaders) < 2 {
		t.Fatalf("expected at least 2 headers, got %d", len(rd.CustomHeaders))
	}
	if !strings.HasPrefix(rd.CustomHeaders[0], "Authorization: Basic ") {
		t.Errorf("first header should be Authorization, got %q", rd.CustomHeaders[0])
	}
	if rd.CustomHeaders[1] != "X-Pfx-Name: relay_domains" {
		t.Errorf("second header should be X-Pfx-Name, got %q", rd.CustomHeaders[1])
	}
}

func TestWorkerPoolPartialDefaults(t *testing.T) {
	cfg := &Config{
		Server: Server{
			WorkerPool: WorkerPoolConfig{
				MaxWorkers: 5,
			},
			Listen: []Listen{
				{
					Kind:    "socket_map",
					Name:    "test",
					Type:    "tcp",
					Address: "127.0.0.1",
					Port:    23450,
					WorkerPool: WorkerPoolConfig{
						MaxWorkers: 3,
					},
				},
			},
		},
	}

	err := cfg.HandleConfig()
	if err != nil {
		t.Fatalf("HandleConfig failed: %v", err)
	}

	if cfg.Server.WorkerPool.MaxWorkers != 5 {
		t.Errorf("Expected MaxWorkers 5, got %d", cfg.Server.WorkerPool.MaxWorkers)
	}
	if cfg.Server.WorkerPool.MaxQueue != 50 {
		t.Errorf("Expected MaxQueue 50, got %d", cfg.Server.WorkerPool.MaxQueue)
	}

	if cfg.Server.Listen[0].WorkerPool.MaxWorkers != 3 {
		t.Errorf("Expected per-listener MaxWorkers 3, got %d", cfg.Server.Listen[0].WorkerPool.MaxWorkers)
	}
	if cfg.Server.Listen[0].WorkerPool.MaxQueue != 30 {
		t.Errorf("Expected per-listener MaxQueue 30, got %d", cfg.Server.Listen[0].WorkerPool.MaxQueue)
	}
}
