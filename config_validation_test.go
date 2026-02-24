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
						OIDCAuth: OIDCAuth{
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
