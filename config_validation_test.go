package main

import (
	"slices"
	"strings"
	"testing"
	"time"
)

const (
	testPrometheusTLSKey = "prometheus_tls"
	testMetricsCertPath  = "/tmp/metrics.crt"
	testMetricsKeyPath   = "/tmp/metrics.key"
	testDovecotTargetURL = "https://nauthilus.example.com/api/v1/auth/json"
	testLowerPlain       = "plain"
	testMechanismsKey    = "mechanisms"
	testCramMD5          = "CRAM-MD5"
	testIDPConfigURI     = "https://idp.example.com/.well-known/openid-configuration"
	testPfxhttpClientID  = "pfxhttp"
)

func TestConfigValidation(t *testing.T) {
	invalidSampleRatio := 1.5
	tests := []struct {
		name        string
		cfg         Config
		wantErr     bool
		errContains []string
	}{
		{
			name: "Valid Minimal Config",
			cfg: Config{
				Server: Server{
					Listen: []Listen{
						{
							Kind:    "socket_map",
							Type:    "tcp",
							Address: "127.0.0.1",
							Port:    23456,
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Missing Listen Config",
			cfg: Config{
				Server: Server{
					Listen: []Listen{},
				},
			},
			wantErr:     true,
			errContains: []string{"field 'listen' (struct field: 'Listen') failed on the 'min' validation rule"},
		},
		{
			name: "Invalid Listen Kind",
			cfg: Config{
				Server: Server{
					Listen: []Listen{
						{
							Kind:    "invalid",
							Type:    "tcp",
							Address: "127.0.0.1",
						},
					},
				},
			},
			wantErr:     true,
			errContains: []string{"field 'kind' (struct field: 'Kind') failed on the 'oneof' validation rule"},
		},
		{
			name: "Invalid Port",
			cfg: Config{
				Server: Server{
					Listen: []Listen{
						{
							Kind:    "socket_map",
							Type:    "tcp",
							Address: "127.0.0.1",
							Port:    70000,
						},
					},
				},
			},
			wantErr:     true,
			errContains: []string{"field 'port' (struct field: 'Port') failed on the 'max' validation rule"},
		},
		{
			name: "Invalid systemd socket name",
			cfg: Config{
				Server: Server{
					Listen: []Listen{
						{
							Kind:              "socket_map",
							Type:              "tcp",
							Address:           "127.0.0.1",
							Port:              23456,
							SystemdSocketName: "map:extra",
						},
					},
				},
			},
			wantErr:     true,
			errContains: []string{"systemd_socket_name"},
		},
		{
			name: "OIDC Auth Missing ConfigurationURI",
			cfg: Config{
				Server: Server{
					Listen: []Listen{
						{
							Kind:    "socket_map",
							Type:    "tcp",
							Address: "127.0.0.1",
						},
					},
				},
				SocketMaps: map[string]Request{
					"test": {
						Target: "http://example.com",
						BackendOIDCAuth: BackendOIDCAuth{
							Enabled: true,
						},
					},
				},
			},
			wantErr:     true,
			errContains: []string{"field 'configuration_uri' (struct field: 'ConfigurationURI') failed on the 'required_if' validation rule"},
		},
		{
			name: "Invalid Worker Pool MaxWorkers",
			cfg: Config{
				Server: Server{
					Listen: []Listen{
						{
							Kind:    "socket_map",
							Type:    "tcp",
							Address: "127.0.0.1",
						},
					},
					WorkerPool: WorkerPoolConfig{
						MaxWorkers: -1,
					},
				},
			},
			wantErr:     true,
			errContains: []string{"server.worker_pool values must be between 0 and 1048576"},
		},
		{
			name: "DovecotSASL gRPC transport without address",
			cfg: Config{
				Server: Server{
					Listen: []Listen{
						{
							Kind:    "dovecot_sasl",
							Type:    "tcp",
							Address: "127.0.0.1",
							Port:    34000,
						},
					},
				},
				DovecotSASL: map[string]Request{
					"smtp_auth": {
						Transport: transportGRPC,
					},
				},
			},
			wantErr:     true,
			errContains: []string{"transport 'grpc'", "grpc.address"},
		},
		{
			name: "DovecotSASL gRPC transport with address",
			cfg: Config{
				Server: Server{
					Listen: []Listen{
						{
							Kind:    "dovecot_sasl",
							Type:    "tcp",
							Address: "127.0.0.1",
							Port:    34000,
						},
					},
				},
				DovecotSASL: map[string]Request{
					"smtp_auth": {
						Transport: transportGRPC,
						GRPC: GRPCRequest{
							Address: "nauthilus.example.com:9444",
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "DovecotSASL gRPC rejects HTTP custom headers",
			cfg: Config{
				Server: Server{
					Listen: []Listen{
						{
							Kind:    "dovecot_sasl",
							Type:    "tcp",
							Address: "127.0.0.1",
							Port:    34000,
						},
					},
				},
				DovecotSASL: map[string]Request{
					"smtp_auth": {
						Transport:     transportGRPC,
						CustomHeaders: []string{"Accept-Language: de"},
						GRPC:          GRPCRequest{Address: "nauthilus.example.com:9444"},
					},
				},
			},
			wantErr:     true,
			errContains: []string{"custom_headers", "grpc.metadata"},
		},
		{
			name: "DovecotSASL gRPC rejects reserved authorization metadata",
			cfg: Config{
				Server: Server{
					Listen: []Listen{
						{
							Kind:    "dovecot_sasl",
							Type:    "tcp",
							Address: "127.0.0.1",
							Port:    34000,
						},
					},
				},
				DovecotSASL: map[string]Request{
					"smtp_auth": {
						Transport: transportGRPC,
						GRPC: GRPCRequest{
							Address:  "nauthilus.example.com:9444",
							Metadata: map[string][]string{"authorization": {"Basic abc"}},
						},
					},
				},
			},
			wantErr:     true,
			errContains: []string{"grpc.metadata", "authorization", "reserved"},
		},
		{
			name: "DovecotSASL gRPC accepts and normalizes request metadata",
			cfg: Config{
				Server: Server{
					Listen: []Listen{
						{
							Kind:    "dovecot_sasl",
							Type:    "tcp",
							Address: "127.0.0.1",
							Port:    34000,
						},
					},
				},
				DovecotSASL: map[string]Request{
					"smtp_auth": {
						Transport:     transportGRPC,
						HTTPAuthBasic: "admin:secret",
						GRPC: GRPCRequest{
							Address:  "nauthilus.example.com:9444",
							Metadata: map[string][]string{"Accept-Language": {"de"}},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "DovecotSASL HTTP accepts and normalizes mechanisms",
			cfg: Config{
				Server: Server{
					Listen: []Listen{
						{
							Kind:    "dovecot_sasl",
							Type:    "tcp",
							Address: "127.0.0.1",
							Port:    34000,
						},
					},
				},
				DovecotSASL: map[string]Request{
					"smtp_auth": {
						Target:     testDovecotTargetURL,
						Mechanisms: []string{testLowerPlain},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "DovecotSASL rejects empty mechanisms",
			cfg: Config{
				Server: Server{
					Listen: []Listen{
						{
							Kind:    "dovecot_sasl",
							Type:    "tcp",
							Address: "127.0.0.1",
							Port:    34000,
						},
					},
				},
				DovecotSASL: map[string]Request{
					"smtp_auth": {
						Target:     testDovecotTargetURL,
						Mechanisms: []string{},
					},
				},
			},
			wantErr:     true,
			errContains: []string{testMechanismsKey, "at least one"},
		},
		{
			name: "DovecotSASL rejects unknown mechanisms",
			cfg: Config{
				Server: Server{
					Listen: []Listen{
						{
							Kind:    "dovecot_sasl",
							Type:    "tcp",
							Address: "127.0.0.1",
							Port:    34000,
						},
					},
				},
				DovecotSASL: map[string]Request{
					"smtp_auth": {
						Target:     testDovecotTargetURL,
						Mechanisms: []string{saslMechanismPlain, testCramMD5},
					},
				},
			},
			wantErr:     true,
			errContains: []string{testMechanismsKey, "unsupported mechanism", testCramMD5},
		},
		{
			name: "DovecotSASL rejects OAuth mechanisms without SASL OIDC",
			cfg: Config{
				Server: Server{
					Listen: []Listen{
						{
							Kind:    "dovecot_sasl",
							Type:    "tcp",
							Address: "127.0.0.1",
							Port:    34000,
						},
					},
				},
				DovecotSASL: map[string]Request{
					"smtp_auth": {
						Transport:  transportGRPC,
						GRPC:       GRPCRequest{Address: "nauthilus.example.com:9444"},
						Mechanisms: []string{saslMechanismPlain, saslMechanismXOAuth2},
					},
				},
			},
			wantErr:     true,
			errContains: []string{saslMechanismXOAuth2, "sasl_oidc_auth.enabled"},
		},
		{
			name: "DovecotSASL gRPC accepts OAuth mechanisms with SASL OIDC",
			cfg: Config{
				Server: Server{
					Listen: []Listen{
						{
							Kind:    "dovecot_sasl",
							Type:    "tcp",
							Address: "127.0.0.1",
							Port:    34000,
						},
					},
				},
				DovecotSASL: map[string]Request{
					"smtp_auth": {
						Transport:  transportGRPC,
						GRPC:       GRPCRequest{Address: "nauthilus.example.com:9444"},
						Mechanisms: []string{saslMechanismPlain, saslMechanismXOAuth2, saslMechanismOAuthBearer},
						SASLOIDCAuth: SASLOIDCAuth{
							Enabled:          true,
							ConfigurationURI: testIDPConfigURI,
							ClientID:         testPfxhttpClientID,
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "HTTP basic auth conflicts with backend OIDC auth",
			cfg: Config{
				Server: Server{
					Listen: []Listen{
						{
							Kind:    "socket_map",
							Type:    "tcp",
							Address: "127.0.0.1",
							Port:    23456,
						},
					},
				},
				SocketMaps: map[string]Request{
					"conflict": {
						Target:        "http://example.com",
						HTTPAuthBasic: "user:secret",
						BackendOIDCAuth: BackendOIDCAuth{
							Enabled:          true,
							ConfigurationURI: "https://idp.example.com/.well-known/openid-configuration",
							ClientID:         "pfxhttp",
						},
					},
				},
			},
			wantErr:     true,
			errContains: []string{"http_auth_basic", "backend_oidc_auth"},
		},
		{
			name: "DovecotSASL gRPC accepts min_tls_version=1.3",
			cfg: Config{
				Server: Server{
					Listen: []Listen{
						{
							Kind:    "dovecot_sasl",
							Type:    "tcp",
							Address: "127.0.0.1",
							Port:    34000,
						},
					},
				},
				DovecotSASL: map[string]Request{
					"smtp_auth": {
						Transport: transportGRPC,
						GRPC: GRPCRequest{
							Address: "nauthilus.example.com:9444",
							TLS:     GRPCTLS{Enabled: new(true), MinVersion: "1.3"},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "DovecotSASL gRPC rejects min_tls_version=1.1",
			cfg: Config{
				Server: Server{
					Listen: []Listen{
						{
							Kind:    "dovecot_sasl",
							Type:    "tcp",
							Address: "127.0.0.1",
							Port:    34000,
						},
					},
				},
				DovecotSASL: map[string]Request{
					"smtp_auth": {
						Transport: transportGRPC,
						GRPC: GRPCRequest{
							Address: "nauthilus.example.com:9444",
							TLS:     GRPCTLS{Enabled: new(true), MinVersion: "1.1"},
						},
					},
				},
			},
			wantErr:     true,
			errContains: []string{"min_version", "oneof"},
		},
		{
			name: "OTel enabled requires trace or metric export",
			cfg: Config{
				Server: Server{
					Listen: []Listen{
						{
							Kind:    "socket_map",
							Type:    "tcp",
							Address: "127.0.0.1",
							Port:    23456,
						},
					},
					Observability: ObservabilityConfig{
						OTelEnabled: true,
					},
				},
			},
			wantErr:     true,
			errContains: []string{"otel_enabled", "otel_traces_enabled", "otel_metrics_enabled"},
		},
		{
			name: "OTel enabled requires OTLP endpoint",
			cfg: Config{
				Server: Server{
					Listen: []Listen{
						{
							Kind:    "socket_map",
							Type:    "tcp",
							Address: "127.0.0.1",
							Port:    23456,
						},
					},
					Observability: ObservabilityConfig{
						OTelEnabled:       true,
						OTelTracesEnabled: true,
					},
				},
			},
			wantErr:     true,
			errContains: []string{"otel_exporter_otlp_endpoint"},
		},
		{
			name: "OTel sample ratio must stay in range",
			cfg: Config{
				Server: Server{
					Listen: []Listen{
						{
							Kind:    "socket_map",
							Type:    "tcp",
							Address: "127.0.0.1",
							Port:    23456,
						},
					},
					Observability: ObservabilityConfig{
						OTelEnabled:       true,
						OTelTracesEnabled: true,
						OTLPEndpoint:      "http://collector.example:4318",
						OTelSampleRatio:   &invalidSampleRatio,
					},
				},
			},
			wantErr:     true,
			errContains: []string{"otel_sample_ratio"},
		},
		{
			name: "Prometheus basic auth requires user password form",
			cfg: Config{
				Server: Server{
					Listen: []Listen{
						{
							Kind:    "socket_map",
							Type:    "tcp",
							Address: "127.0.0.1",
							Port:    23456,
						},
					},
					Observability: ObservabilityConfig{
						PrometheusEnabled:       true,
						PrometheusHTTPAuthBasic: "metrics-only",
					},
				},
			},
			wantErr:     true,
			errContains: []string{"prometheus_http_auth_basic", "user:password"},
		},
		{
			name: "Prometheus TLS requires certificate pair",
			cfg: Config{
				Server: Server{
					Listen: []Listen{
						{
							Kind:    "socket_map",
							Type:    "tcp",
							Address: "127.0.0.1",
							Port:    23456,
						},
					},
					Observability: ObservabilityConfig{
						PrometheusEnabled: true,
						PrometheusTLS: PrometheusTLS{
							Enabled: true,
							Cert:    testMetricsCertPath,
						},
					},
				},
			},
			wantErr:     true,
			errContains: []string{testPrometheusTLSKey, "cert and key"},
		},
		{
			name: "Prometheus TLS rejects legacy min version",
			cfg: Config{
				Server: Server{
					Listen: []Listen{
						{
							Kind:    "socket_map",
							Type:    "tcp",
							Address: "127.0.0.1",
							Port:    23456,
						},
					},
					Observability: ObservabilityConfig{
						PrometheusEnabled: true,
						PrometheusTLS: PrometheusTLS{
							Enabled:    true,
							Cert:       testMetricsCertPath,
							Key:        testMetricsKeyPath,
							MinVersion: "1.1",
						},
					},
				},
			},
			wantErr:     true,
			errContains: []string{testPrometheusTLSKey, "min_tls_version"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.HandleConfig()
			if (err != nil) != tt.wantErr {
				t.Errorf("HandleConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				for _, msg := range tt.errContains {
					if !strings.Contains(err.Error(), msg) {
						t.Errorf("HandleConfig() error = %v, want error to contain %q", err, msg)
					}
				}
			}
		})
	}
}

const (
	testMaxConnectionsKey = "max_connections"
	testMaxQueuedKey      = "max_queued_requests"
	testBudgetError       = "request timeout must exceed"
	testMaxLineBytesKey   = "max_line_bytes"
)

type limitValidationCase struct {
	name   string
	mutate func(*Config)
	match  string
}

func TestConnectionRequestAndProtocolLimitValidation(t *testing.T) {
	for _, test := range newLimitValidationCases() {
		t.Run(test.name, func(t *testing.T) {
			cfg := newLimitValidationConfig()
			test.mutate(&cfg)

			err := cfg.HandleConfig()
			if err == nil || !strings.Contains(err.Error(), test.match) {
				t.Fatalf("HandleConfig() error = %v, want substring %q", err, test.match)
			}
		})
	}
}

func newLimitValidationConfig() Config {
	return Config{Server: Server{Listen: []Listen{{
		Kind: listenKindSocketMap, Name: testFirst, Type: listenTypeTCP, Address: concurrencyTestHost, Port: 23456,
	}}}}
}

func newLimitValidationCases() []limitValidationCase {
	return []limitValidationCase{
		{name: "negative connections", mutate: func(cfg *Config) { cfg.Server.Limits.MaxConnections = -1 }, match: testMaxConnectionsKey},
		{name: "connections above maximum", mutate: func(cfg *Config) { cfg.Server.Limits.MaxConnections = 1048577 }, match: testMaxConnectionsKey},
		{name: "negative inflight", mutate: func(cfg *Config) { cfg.Server.Limits.MaxInflightRequests = -1 }, match: "max_inflight_requests"},
		{name: "negative queue", mutate: func(cfg *Config) { cfg.Server.Limits.MaxQueuedRequests = new(-1) }, match: testMaxQueuedKey},
		{name: "queue above maximum", mutate: func(cfg *Config) { cfg.Server.Limits.MaxQueuedRequests = new(1048577) }, match: testMaxQueuedKey},
		{name: "negative queue timeout", mutate: func(cfg *Config) { cfg.Server.Limits.RequestQueueTimeout = -time.Second }, match: "request_queue_timeout"},
		{name: "request timeout above maximum", mutate: func(cfg *Config) { cfg.Server.Limits.RequestTimeout = time.Hour + time.Nanosecond }, match: "request_timeout"},
		{name: "backend timeout above maximum", mutate: func(cfg *Config) { cfg.Server.Limits.BackendTimeout = time.Hour + time.Nanosecond }, match: testBudgetError},
		{name: "write reserve above maximum", mutate: func(cfg *Config) { cfg.Server.Limits.ResponseWriteReserve = time.Minute + time.Nanosecond }, match: testBudgetError},
		{name: "impossible total budget", mutate: impossibleTotalBudget, match: testBudgetError},
		{name: "negative socket idle", mutate: func(cfg *Config) { cfg.Server.ProtocolLimits.SocketMap.IdleTimeout = new(-time.Second) }, match: "idle_timeout"},
		{name: "socket payload above maximum", mutate: func(cfg *Config) { cfg.Server.ProtocolLimits.SocketMap.MaxRequestBytes = 67108865 }, match: "max_request_bytes"},
		{name: "socket length digits above maximum", mutate: func(cfg *Config) { cfg.Server.ProtocolLimits.SocketMap.MaxLengthDigits = 11 }, match: "max_length_digits"},
		{name: "policy line above maximum", mutate: policyLineAboveMaximum, match: testMaxLineBytesKey},
		{name: "policy line exceeds request", mutate: policyLineExceedsRequest, match: "max line bytes must not exceed"},
		{name: "policy attributes above maximum", mutate: func(cfg *Config) { cfg.Server.ProtocolLimits.PolicyService.MaxAttributes = 1048577 }, match: "max_attributes"},
		{name: "dovecot line above maximum", mutate: func(cfg *Config) { cfg.Server.ProtocolLimits.DovecotSASL.MaxLineBytes = 1048577 }, match: testMaxLineBytesKey},
		{name: "protocol partial timeout above maximum", mutate: func(cfg *Config) {
			cfg.Server.ProtocolLimits.SocketMap.PartialRequestTimeout = time.Hour + time.Nanosecond
		}, match: "partial_request_timeout"},
		{name: "protocol write timeout above maximum", mutate: func(cfg *Config) { cfg.Server.ProtocolLimits.DovecotSASL.WriteTimeout = time.Hour + time.Nanosecond }, match: "write_timeout"},
	}
}

func impossibleTotalBudget(cfg *Config) {
	cfg.Server.Limits.RequestQueueTimeout = 2 * time.Second
	cfg.Server.Limits.BackendTimeout = 2 * time.Second
	cfg.Server.Limits.ResponseWriteReserve = time.Second
	cfg.Server.Limits.RequestTimeout = 5 * time.Second
}

func policyLineAboveMaximum(cfg *Config) {
	cfg.Server.ProtocolLimits.PolicyService.MaxRequestBytes = 16777217
	cfg.Server.ProtocolLimits.PolicyService.MaxLineBytes = 16777217
}

func policyLineExceedsRequest(cfg *Config) {
	cfg.Server.ProtocolLimits.PolicyService.MaxRequestBytes = 1024
	cfg.Server.ProtocolLimits.PolicyService.MaxLineBytes = 2048
}

func TestZeroQueueRemovesQueueStageFromDeadlineBudget(t *testing.T) {
	cfg := Config{Server: Server{
		Limits: LimitsConfig{
			MaxQueuedRequests:    new(0),
			RequestQueueTimeout:  20 * time.Second,
			RequestTimeout:       3 * time.Second,
			BackendTimeout:       2 * time.Second,
			ResponseWriteReserve: 500 * time.Millisecond,
		},
		Listen: []Listen{{Kind: listenKindSocketMap, Name: testFirst, Type: listenTypeTCP, Address: "127.0.0.1", Port: 23456}},
	}}

	if err := cfg.HandleConfig(); err != nil {
		t.Fatalf("HandleConfig() rejected a disabled queue budget: %v", err)
	}

	if got := maxQueuedRequests(cfg.Server.Listen[0].Limits); got != 0 {
		t.Fatalf("max_queued_requests = %d, want 0", got)
	}
}

func TestMaximumCapacityAndProtocolLimitsAreAccepted(t *testing.T) {
	cfg := newLimitValidationConfig()
	cfg.Server.Limits = LimitsConfig{
		MaxConnections:       1048576,
		MaxInflightRequests:  1048576,
		MaxQueuedRequests:    new(1048576),
		RequestQueueTimeout:  time.Millisecond,
		RequestTimeout:       time.Hour,
		BackendTimeout:       time.Second,
		ResponseWriteReserve: time.Minute,
	}
	cfg.Server.ProtocolLimits = maximumProtocolLimits()

	if err := cfg.HandleConfig(); err != nil {
		t.Fatalf("HandleConfig() rejected documented maxima: %v", err)
	}
}

func TestMaximumQueueTimeoutIsAcceptedWhenQueueIsDisabled(t *testing.T) {
	cfg := newLimitValidationConfig()
	cfg.Server.Limits = LimitsConfig{
		MaxQueuedRequests:    new(0),
		RequestQueueTimeout:  time.Hour,
		RequestTimeout:       time.Hour,
		BackendTimeout:       58 * time.Minute,
		ResponseWriteReserve: time.Minute,
	}

	if err := cfg.HandleConfig(); err != nil {
		t.Fatalf("HandleConfig() rejected maximum unused queue timeout: %v", err)
	}
}

func TestMaximumBackendTimeoutIsRejectedByTotalBudget(t *testing.T) {
	cfg := newLimitValidationConfig()
	cfg.Server.Limits.MaxQueuedRequests = new(0)
	cfg.Server.Limits.RequestTimeout = time.Hour
	cfg.Server.Limits.BackendTimeout = time.Hour

	err := cfg.HandleConfig()
	if err == nil || !strings.Contains(err.Error(), testBudgetError) {
		t.Fatalf("HandleConfig() error = %v, want total-budget rejection", err)
	}
}

func maximumProtocolLimits() ProtocolLimitsConfig {
	return ProtocolLimitsConfig{
		SocketMap: SocketMapProtocolLimits{
			IdleTimeout: new(time.Hour), PartialRequestTimeout: time.Hour,
			WriteTimeout: time.Hour, MaxRequestBytes: 67108864, MaxLengthDigits: 10,
		},
		PolicyService: PolicyServiceProtocolLimits{
			IdleTimeout: new(time.Hour), PartialRequestTimeout: time.Hour,
			WriteTimeout: time.Hour, MaxRequestBytes: 67108864, MaxLineBytes: 16777216, MaxAttributes: 1048576,
		},
		DovecotSASL: DovecotSASLProtocolLimits{
			IdleTimeout: new(time.Hour), PartialRequestTimeout: time.Hour,
			WriteTimeout: time.Hour, MaxLineBytes: 1048576,
		},
	}
}

func TestHandleConfigNormalizesGRPCMetadataKeys(t *testing.T) {
	cfg := Config{
		Server: Server{
			Listen: []Listen{
				{
					Kind:    "dovecot_sasl",
					Type:    "tcp",
					Address: "127.0.0.1",
					Port:    34000,
				},
			},
		},
		DovecotSASL: map[string]Request{
			"smtp_auth": {
				Transport: transportGRPC,
				GRPC: GRPCRequest{
					Address:  "nauthilus.example.com:9444",
					Metadata: map[string][]string{"Accept-Language": {"de"}},
				},
			},
		},
	}

	if err := cfg.HandleConfig(); err != nil {
		t.Fatalf("HandleConfig: %v", err)
	}

	md := cfg.DovecotSASL["smtp_auth"].GRPC.Metadata
	if _, ok := md["Accept-Language"]; ok {
		t.Fatalf("metadata key was not normalized: %v", md)
	}
	if values := md["accept-language"]; len(values) != 1 || values[0] != "de" {
		t.Fatalf("accept-language metadata = %v, want [de]", values)
	}
}

func TestHandleConfigNormalizesDovecotSASLMechanisms(t *testing.T) {
	cfg := Config{
		Server: Server{
			Listen: []Listen{
				{
					Kind:    "dovecot_sasl",
					Type:    "tcp",
					Address: "127.0.0.1",
					Port:    34000,
				},
			},
		},
		DovecotSASL: map[string]Request{
			"smtp_auth": {
				Target:     testDovecotTargetURL,
				Mechanisms: []string{testLowerPlain, "login"},
			},
		},
	}

	if err := cfg.HandleConfig(); err != nil {
		t.Fatalf("HandleConfig: %v", err)
	}

	mechanisms := cfg.DovecotSASL["smtp_auth"].Mechanisms
	if !slices.Equal(mechanisms, []string{saslMechanismPlain, saslMechanismLogin}) {
		t.Fatalf("mechanisms = %v, want [PLAIN LOGIN]", mechanisms)
	}
}
