package main

import (
	"os"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/spf13/viper"
)

//go:fix inline
func TestIndependentLimitDefaults(t *testing.T) {
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

	if cfg.Server.WorkerPool != (WorkerPoolConfig{}) {
		t.Fatalf("worker_pool must remain absent when not configured: %+v", cfg.Server.WorkerPool)
	}

	if cfg.Server.SockmapMaxReplySize != defaultSockmapMaxReplySize {
		t.Fatalf("socketmap_max_reply_size = %d, want %d", cfg.Server.SockmapMaxReplySize, defaultSockmapMaxReplySize)
	}

	if cfg.Server.Limits.MaxConnections != defaultMaxConnections ||
		cfg.Server.Limits.MaxInflightRequests != expectedMaxWorkers ||
		maxQueuedRequests(cfg.Server.Limits) != expectedMaxQueue {
		t.Fatalf("independent defaults = %+v", cfg.Server.Limits)
	}
}

func TestProtocolLimitDefaultsAndZeroSemantics(t *testing.T) {
	cfg := &Config{Server: Server{Listen: []Listen{{
		Kind: listenKindSocketMap, Name: testFirst, Type: listenTypeTCP, Address: concurrencyTestHost, Port: 23450,
	}}}}

	if err := cfg.HandleConfig(); err != nil {
		t.Fatalf("HandleConfig failed: %v", err)
	}

	want := ProtocolLimitsConfig{
		SocketMap: SocketMapProtocolLimits{
			IdleTimeout: new(15 * time.Second), PartialRequestTimeout: 10 * time.Second,
			WriteTimeout: 10 * time.Second, MaxRequestBytes: 1048576, MaxLengthDigits: 10,
		},
		PolicyService: PolicyServiceProtocolLimits{
			IdleTimeout: new(time.Duration(0)), PartialRequestTimeout: 10 * time.Second,
			WriteTimeout: 10 * time.Second, MaxRequestBytes: 1048576, MaxLineBytes: 65536, MaxAttributes: 256,
		},
		DovecotSASL: DovecotSASLProtocolLimits{
			IdleTimeout: new(time.Duration(0)), PartialRequestTimeout: 30 * time.Second,
			WriteTimeout: 10 * time.Second, MaxLineBytes: 16384,
		},
	}

	if !reflect.DeepEqual(cfg.Server.ProtocolLimits, want) {
		t.Fatalf("protocol defaults = %+v, want %+v", cfg.Server.ProtocolLimits, want)
	}
}

func TestConnectionLimitDefaultsAreInheritedByValue(t *testing.T) {
	cfg := &Config{Server: Server{
		Limits: LimitsConfig{MaxConnections: 37},
		Listen: []Listen{
			{Kind: listenKindSocketMap, Name: testFirst, Type: listenTypeTCP, Address: concurrencyTestHost, Port: 23450},
			{Kind: listenKindSocketMap, Name: testSecond, Type: listenTypeTCP, Address: concurrencyTestHost, Port: 23451},
		},
	}}

	if err := cfg.HandleConfig(); err != nil {
		t.Fatalf("HandleConfig failed: %v", err)
	}

	for index, listener := range cfg.Server.Listen {
		if listener.Limits.MaxConnections != 37 {
			t.Fatalf("listener %d max connections = %d, want 37", index, listener.Limits.MaxConnections)
		}
	}

	cfg.Server.Listen[0].Limits.MaxConnections = 5
	if cfg.Server.Listen[1].Limits.MaxConnections != 37 {
		t.Fatal("listener connection limits share mutable runtime state")
	}
}

func TestWorkerPoolCompatibilityMapsConservativelyToLimits(t *testing.T) {
	cfg := &Config{Server: Server{
		WorkerPool: WorkerPoolConfig{MaxWorkers: 10, MaxQueue: 20},
		Listen: []Listen{{
			Kind:       listenKindSocketMap,
			Name:       testFirst,
			Type:       listenTypeTCP,
			Address:    "127.0.0.1",
			Port:       23450,
			WorkerPool: WorkerPoolConfig{MaxWorkers: 3, MaxQueue: 4},
		}},
	}}

	if err := cfg.HandleConfig(); err != nil {
		t.Fatalf("HandleConfig failed: %v", err)
	}

	if cfg.Server.Limits.MaxConnections != 30 || cfg.Server.Limits.MaxInflightRequests != 10 || maxQueuedRequests(cfg.Server.Limits) != 20 {
		t.Fatalf("server compatibility limits = %+v", cfg.Server.Limits)
	}

	listenerLimits := cfg.Server.Listen[0].Limits
	if listenerLimits.MaxConnections != 7 || listenerLimits.MaxInflightRequests != 3 || maxQueuedRequests(listenerLimits) != 4 {
		t.Fatalf("listener compatibility limits = %+v", listenerLimits)
	}
}

func TestLimitAndProtocolDefaultsInheritWithoutSharedPointers(t *testing.T) {
	serverSocketIdle := 20 * time.Second
	serverPolicyIdle := 45 * time.Second
	zeroQueue := 0
	cfg := &Config{Server: Server{
		Limits: LimitsConfig{
			MaxConnections:       80,
			MaxInflightRequests:  12,
			MaxQueuedRequests:    &zeroQueue,
			RequestQueueTimeout:  3 * time.Second,
			RequestTimeout:       6 * time.Second,
			BackendTimeout:       2 * time.Second,
			ResponseWriteReserve: time.Second,
		},
		ProtocolLimits: ProtocolLimitsConfig{
			SocketMap:     SocketMapProtocolLimits{IdleTimeout: &serverSocketIdle, MaxRequestBytes: 2048},
			PolicyService: PolicyServiceProtocolLimits{IdleTimeout: &serverPolicyIdle, MaxAttributes: 40},
		},
		Listen: []Listen{
			{Kind: listenKindSocketMap, Name: testFirst, Type: listenTypeTCP, Address: "127.0.0.1", Port: 23450},
			{Kind: listenKindSocketMap, Name: testSecond, Type: listenTypeTCP, Address: "127.0.0.1", Port: 23451},
		},
	}}

	if err := cfg.HandleConfig(); err != nil {
		t.Fatalf("HandleConfig failed: %v", err)
	}

	for index := range cfg.Server.Listen {
		listener := cfg.Server.Listen[index]
		if !reflect.DeepEqual(listener.Limits, cfg.Server.Limits) {
			t.Fatalf("listener %d limits = %+v", index, listener.Limits)
		}

		if !reflect.DeepEqual(listener.ProtocolLimits, cfg.Server.ProtocolLimits) {
			t.Fatalf("listener %d protocol limits = %+v", index, listener.ProtocolLimits)
		}
	}

	if cfg.Server.Listen[0].Limits.MaxQueuedRequests == cfg.Server.Listen[1].Limits.MaxQueuedRequests ||
		cfg.Server.Listen[0].ProtocolLimits.SocketMap.IdleTimeout == cfg.Server.Listen[1].ProtocolLimits.SocketMap.IdleTimeout {
		t.Fatal("listeners inherited shared configuration pointers")
	}

	*cfg.Server.Listen[0].Limits.MaxQueuedRequests = 7
	*cfg.Server.Listen[0].ProtocolLimits.SocketMap.IdleTimeout = time.Second

	if maxQueuedRequests(cfg.Server.Listen[1].Limits) != 0 ||
		protocolIdleTimeout(cfg.Server.Listen[1].ProtocolLimits.SocketMap.IdleTimeout) != 20*time.Second {
		t.Fatal("mutating one listener changed another listener")
	}
}

func TestProtocolIdleTimeoutExplicitZeroOverridesInheritedValue(t *testing.T) {
	serverIdle := 30 * time.Second
	disabled := time.Duration(0)
	cfg := &Config{Server: Server{
		ProtocolLimits: ProtocolLimitsConfig{SocketMap: SocketMapProtocolLimits{IdleTimeout: &serverIdle}},
		Listen: []Listen{{
			Kind: listenKindSocketMap, Name: testFirst, Type: listenTypeTCP, Address: "127.0.0.1", Port: 23450,
			ProtocolLimits: ProtocolLimitsConfig{SocketMap: SocketMapProtocolLimits{IdleTimeout: &disabled}},
		}},
	}}

	if err := cfg.HandleConfig(); err != nil {
		t.Fatalf("HandleConfig failed: %v", err)
	}

	if got := protocolIdleTimeout(cfg.Server.Listen[0].ProtocolLimits.SocketMap.IdleTimeout); got != 0 {
		t.Fatalf("explicit idle_timeout=0 = %s, want disabled", got)
	}
}

func TestExplicitNewLimitsOverrideLegacyCompatibilityValues(t *testing.T) {
	queued := 2
	cfg := &Config{Server: Server{
		WorkerPool: WorkerPoolConfig{MaxWorkers: 20, MaxQueue: 40},
		Limits: LimitsConfig{
			MaxConnections:      9,
			MaxInflightRequests: 4,
			MaxQueuedRequests:   &queued,
		},
		Listen: []Listen{{Kind: listenKindSocketMap, Name: testFirst, Type: listenTypeTCP, Address: "127.0.0.1", Port: 23450}},
	}}

	if err := cfg.HandleConfig(); err != nil {
		t.Fatalf("HandleConfig failed: %v", err)
	}

	limits := cfg.Server.Listen[0].Limits
	if limits.MaxConnections != 9 || limits.MaxInflightRequests != 4 || maxQueuedRequests(limits) != 2 {
		t.Fatalf("explicit limits were overwritten by worker_pool migration: %+v", limits)
	}
}

func TestZeroValuedLegacyWorkerPoolBlockIsDetectedAsConfigured(t *testing.T) {
	viper.Reset()
	defer viper.Reset()

	viper.SetConfigType("yaml")

	if err := viper.ReadConfig(strings.NewReader(`
server:
  worker_pool:
    max_workers: 0
  listen:
    - kind: socket_map
      name: first
      type: tcp
      address: 127.0.0.1
      port: 23450
      worker_pool:
        max_queue: 0
`)); err != nil {
		t.Fatalf("ReadConfig failed: %v", err)
	}

	cfg := &Config{}
	if err := cfg.HandleConfig(); err != nil {
		t.Fatalf("HandleConfig failed: %v", err)
	}

	if !cfg.Server.LegacyWorkerPool || !cfg.Server.Listen[0].LegacyWorkerPool {
		t.Fatalf("zero-valued legacy blocks were not marked: server=%t listener=%t", cfg.Server.LegacyWorkerPool, cfg.Server.Listen[0].LegacyWorkerPool)
	}
}

func TestObservabilityDefaultsAreOptIn(t *testing.T) {
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

	if err := cfg.HandleConfig(); err != nil {
		t.Fatalf("HandleConfig failed: %v", err)
	}

	if cfg.Server.Observability.PrometheusEnabled {
		t.Fatal("prometheus_enabled must default to false")
	}

	if cfg.Server.Observability.PrometheusRuntimeMetrics {
		t.Fatal("prometheus_runtime_metrics must default to false")
	}

	if cfg.Server.Observability.PrometheusHTTPAuthBasic != "" {
		t.Fatal("prometheus_http_auth_basic must default to empty")
	}

	if cfg.Server.Observability.PrometheusTLS.Enabled {
		t.Fatal("prometheus_tls.enabled must default to false")
	}

	if cfg.Server.Observability.OTelEnabled {
		t.Fatal("otel_enabled must default to false")
	}

	if cfg.Server.Observability.OTelTracesEnabled {
		t.Fatal("otel_traces_enabled must default to false")
	}

	if cfg.Server.Observability.OTelMetricsEnabled {
		t.Fatal("otel_metrics_enabled must default to false")
	}

	if cfg.Server.Observability.PrometheusAddress != defaultPrometheusAddress {
		t.Fatalf("PrometheusAddress = %q, want %q", cfg.Server.Observability.PrometheusAddress, defaultPrometheusAddress)
	}

	if cfg.Server.Observability.PrometheusPort != defaultPrometheusPort {
		t.Fatalf("PrometheusPort = %d, want %d", cfg.Server.Observability.PrometheusPort, defaultPrometheusPort)
	}

	if cfg.Server.Observability.PrometheusPath != defaultPrometheusPath {
		t.Fatalf("PrometheusPath = %q, want %q", cfg.Server.Observability.PrometheusPath, defaultPrometheusPath)
	}
}

func TestObservabilityPreservesExplicitZeroSampleRatio(t *testing.T) {
	zeroRatio := 0.0
	cfg := normalizeObservabilityConfig(ObservabilityConfig{
		OTelEnabled:       true,
		OTelTracesEnabled: true,
		OTLPEndpoint:      "http://127.0.0.1:4318",
		OTelSampleRatio:   &zeroRatio,
	}, "test")

	if got := defaultedOTelSampleRatio(cfg); got != 0 {
		t.Fatalf("OTelSampleRatio = %v, want 0", got)
	}

	if err := validateObservabilityConfig(cfg); err != nil {
		t.Fatalf("validateObservabilityConfig() error = %v", err)
	}
}

func TestSASLOIDCAuthDefaultsPreferPrivateKeyJWT(t *testing.T) {
	const testDovecotSASLEntry = "smtp_auth"

	keyFile := t.TempDir() + "/client.key"
	if err := os.WriteFile(keyFile, []byte("test-key"), 0o600); err != nil {
		t.Fatalf("write private key fixture: %v", err)
	}

	cfg := &Config{
		Server: Server{
			Listen: []Listen{
				{
					Kind:    componentDovecotSASL,
					Type:    "tcp",
					Address: "127.0.0.1",
					Port:    34000,
				},
			},
		},
		DovecotSASL: map[string]Request{
			testDovecotSASLEntry: {
				Target:     testDovecotTargetURL,
				Mechanisms: []string{saslMechanismXOAuth2},
				SASLOIDCAuth: SASLOIDCAuth{
					Enabled:          true,
					ConfigurationURI: testIDPConfigURI,
					ClientID:         testPfxhttpClientID,
					PrivateKeyFile:   keyFile,
				},
			},
		},
	}

	if err := cfg.HandleConfig(); err != nil {
		t.Fatalf("HandleConfig failed: %v", err)
	}

	got := cfg.DovecotSASL[testDovecotSASLEntry].SASLOIDCAuth.AuthMethod
	if got != oidcAuthMethodPrivateKeyJWT {
		t.Fatalf("SASL OIDC auth_method = %q, want %q", got, oidcAuthMethodPrivateKeyJWT)
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
			Mechanisms:              []string{saslMechanismPlain},
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

	if !slices.Equal(a.Mechanisms, []string{saslMechanismPlain}) {
		t.Errorf("entry_a.Mechanisms = %v, want [PLAIN]", a.Mechanisms)
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

	if !slices.Equal(b.Mechanisms, []string{saslMechanismPlain}) {
		t.Errorf("entry_b.Mechanisms = %v, want inherited [PLAIN]", b.Mechanisms)
	}
}

func TestResolveDefaultsMergesGRPCFields(t *testing.T) {
	raw := map[string]Request{
		"defaults": {
			Transport: transportGRPC,
			GRPC: GRPCRequest{
				Address: "nauthilus.example:9444",
				Metadata: map[string][]string{
					"accept-language": {"de"},
					"x-default":       {"default"},
				},
				Timeout: 0,
				TLS: GRPCTLS{
					Enabled:    new(true),
					RootCA:     "/etc/pfxhttp/ca.pem",
					ServerName: "nauthilus.example",
				},
			},
		},
		"smtp_auth": {},
		"submission_auth": {
			GRPC: GRPCRequest{
				Metadata: map[string][]string{
					"x-default": {"entry"},
					"x-entry":   {"yes"},
				},
				TLS: GRPCTLS{ServerName: "override.example"},
			},
		},
	}

	result := resolveDefaults(raw)

	if _, ok := result["defaults"]; ok {
		t.Fatal("expected 'defaults' key to be removed")
	}

	a := result["smtp_auth"]
	if a.Transport != transportGRPC {
		t.Errorf("smtp_auth.Transport = %q, want %q", a.Transport, transportGRPC)
	}
	if a.GRPC.Address != "nauthilus.example:9444" {
		t.Errorf("smtp_auth.GRPC.Address = %q, want inherited value", a.GRPC.Address)
	}
	if !boolValue(a.GRPC.TLS.Enabled) || a.GRPC.TLS.RootCA != "/etc/pfxhttp/ca.pem" || a.GRPC.TLS.ServerName != "nauthilus.example" {
		t.Errorf("smtp_auth TLS fields not inherited: %+v", a.GRPC.TLS)
	}
	if !slices.Equal(a.GRPC.Metadata["accept-language"], []string{"de"}) {
		t.Errorf("smtp_auth.GRPC.Metadata[accept-language] = %v, want [de]", a.GRPC.Metadata["accept-language"])
	}

	b := result["submission_auth"]
	if b.Transport != transportGRPC {
		t.Errorf("submission_auth.Transport = %q, want inherited %q", b.Transport, transportGRPC)
	}
	if b.GRPC.Address != "nauthilus.example:9444" {
		t.Errorf("submission_auth.GRPC.Address = %q, want inherited", b.GRPC.Address)
	}
	if b.GRPC.TLS.ServerName != "override.example" {
		t.Errorf("submission_auth.GRPC.TLS.ServerName = %q, want explicit override", b.GRPC.TLS.ServerName)
	}
	if b.GRPC.TLS.RootCA != "/etc/pfxhttp/ca.pem" {
		t.Errorf("submission_auth.GRPC.TLS.RootCA = %q, want inherited from defaults", b.GRPC.TLS.RootCA)
	}
	if !slices.Equal(b.GRPC.Metadata["accept-language"], []string{"de"}) {
		t.Errorf("submission_auth.GRPC.Metadata[accept-language] = %v, want inherited [de]", b.GRPC.Metadata["accept-language"])
	}
	if !slices.Equal(b.GRPC.Metadata["x-default"], []string{"entry"}) {
		t.Errorf("submission_auth.GRPC.Metadata[x-default] = %v, want entry override", b.GRPC.Metadata["x-default"])
	}
	if !slices.Equal(b.GRPC.Metadata["x-entry"], []string{"yes"}) {
		t.Errorf("submission_auth.GRPC.Metadata[x-entry] = %v, want [yes]", b.GRPC.Metadata["x-entry"])
	}
}

func TestResolveDefaultsAllowsGRPCTLSBooleanOverrides(t *testing.T) {
	raw := map[string]Request{
		"defaults": {
			Transport: transportGRPC,
			GRPC: GRPCRequest{
				TLS: GRPCTLS{
					Enabled:    new(true),
					SkipVerify: new(true),
				},
			},
		},
		"smtp_auth": {
			GRPC: GRPCRequest{
				TLS: GRPCTLS{
					Enabled:    new(false),
					SkipVerify: new(false),
				},
			},
		},
		"submission_auth": {},
	}

	result := resolveDefaults(raw)

	if boolValue(result["smtp_auth"].GRPC.TLS.Enabled) {
		t.Fatal("explicit grpc.tls.enabled=false must override defaults")
	}
	if boolValue(result["smtp_auth"].GRPC.TLS.SkipVerify) {
		t.Fatal("explicit grpc.tls.skip_verify=false must override defaults")
	}
	if !boolValue(result["submission_auth"].GRPC.TLS.Enabled) {
		t.Fatal("missing grpc.tls.enabled should inherit defaults")
	}
	if !boolValue(result["submission_auth"].GRPC.TLS.SkipVerify) {
		t.Fatal("missing grpc.tls.skip_verify should inherit defaults")
	}
}

func TestGRPCTLSBooleanPointersDecodeExplicitFalse(t *testing.T) {
	v := viper.New()
	v.Set("tls.enabled", false)
	v.Set("tls.skip_verify", false)

	var got GRPCRequest
	if err := v.Unmarshal(&got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if got.TLS.Enabled == nil {
		t.Fatal("tls.enabled=false should decode as an explicit value")
	}
	if boolValue(got.TLS.Enabled) {
		t.Fatal("tls.enabled=false decoded as true")
	}
	if got.TLS.SkipVerify == nil {
		t.Fatal("tls.skip_verify=false should decode as an explicit value")
	}
	if boolValue(got.TLS.SkipVerify) {
		t.Fatal("tls.skip_verify=false decoded as true")
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
		t.Error("HTTPAuthBasic should be cleared after HTTP header resolution")
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

func TestResolveDovecotSASLHTTPAuthBasicLeavesGRPCAuth(t *testing.T) {
	section := map[string]Request{
		"json": {
			Transport:     transportJSON,
			HTTPAuthBasic: "json:secret",
		},
		"grpc": {
			Transport:     transportGRPC,
			HTTPAuthBasic: "grpc:secret",
		},
	}

	resolveDovecotSASLHTTPBasicAuth(section)

	jsonEntry := section["json"]
	if jsonEntry.HTTPAuthBasic != "" {
		t.Fatal("JSON transport should resolve http_auth_basic into an HTTP header")
	}
	if len(jsonEntry.CustomHeaders) != 1 || !strings.HasPrefix(jsonEntry.CustomHeaders[0], "Authorization: Basic ") {
		t.Fatalf("JSON transport Authorization header not generated: %+v", jsonEntry.CustomHeaders)
	}

	grpcEntry := section["grpc"]
	if grpcEntry.HTTPAuthBasic != "grpc:secret" {
		t.Fatalf("gRPC transport must keep http_auth_basic for outgoing metadata, got %q", grpcEntry.HTTPAuthBasic)
	}
	if len(grpcEntry.CustomHeaders) != 0 {
		t.Fatalf("gRPC transport must not synthesize HTTP custom headers, got %+v", grpcEntry.CustomHeaders)
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
	// HTTPAuthBasic should be resolved into Authorization header for HTTP targets.
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
