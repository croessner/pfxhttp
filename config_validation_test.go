package main

import (
	"strings"
	"testing"
)

func TestConfigValidation(t *testing.T) {
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
			errContains: []string{"field 'max_workers' (struct field: 'MaxWorkers') failed on the 'min' validation rule"},
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
