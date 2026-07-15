package main

import (
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/spf13/viper"
)

const packagedInfoLogLevel = "info"
const packagedPolicySocketPath = "/var/spool/postfix/private/pfxhttp-policy"

func TestPackagedDefaultConfigIsValidAndConservative(t *testing.T) {
	viper.Reset()
	defer viper.Reset()

	viper.SetConfigFile("packaging/pfxhttp.yml")

	if err := viper.ReadInConfig(); err != nil {
		t.Fatalf("ReadInConfig() error = %v", err)
	}

	cfg := &Config{}
	if err := cfg.HandleConfig(); err != nil {
		t.Fatalf("HandleConfig() error = %v", err)
	}

	assertPackagedPolicySocketConfig(t, cfg)
	assertPackagedConservativeDefaults(t, cfg)
}

func TestShippedConfigsShareLimitSemanticsAndContainNoCredentials(t *testing.T) {
	defer viper.Reset()

	load := func(path string) *Config {
		t.Helper()
		viper.Reset()
		viper.SetConfigFile(path)

		if err := viper.ReadInConfig(); err != nil {
			t.Fatalf("ReadInConfig(%s) error = %v", path, err)
		}

		cfg := &Config{}
		if err := cfg.HandleConfig(); err != nil {
			t.Fatalf("HandleConfig(%s) error = %v", path, err)
		}

		return cfg
	}

	demo := load("pfxhttp.yml")
	packaged := load("packaging/pfxhttp.yml")

	if !reflect.DeepEqual(demo.Server.Limits, packaged.Server.Limits) {
		t.Fatalf("shipped limit defaults differ: demo=%+v packaged=%+v", demo.Server.Limits, packaged.Server.Limits)
	}

	if !reflect.DeepEqual(demo.Server.ProtocolLimits, packaged.Server.ProtocolLimits) {
		t.Fatalf("shipped protocol limits differ: demo=%+v packaged=%+v", demo.Server.ProtocolLimits, packaged.Server.ProtocolLimits)
	}

	if legacyWorkerPoolConfigured(demo) || legacyWorkerPoolConfigured(packaged) {
		t.Fatal("shipped configurations must not use deprecated worker_pool input")
	}

	for _, path := range []string{"pfxhttp.yml", "packaging/pfxhttp.yml"} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile(%s) error = %v", path, err)
		}

		text := string(data)
		for _, forbidden := range []string{"Authorization: Basic ", "client_secret:", "http_auth_basic:"} {
			if strings.Contains(text, forbidden) {
				t.Fatalf("%s contains credential-shaped example %q", path, forbidden)
			}
		}
	}
}

func assertPackagedPolicySocketConfig(t *testing.T, cfg *Config) {
	t.Helper()

	if len(cfg.Server.Listen) != 1 {
		t.Fatalf("packaged listener count = %d, want 1", len(cfg.Server.Listen))
	}

	listener := cfg.Server.Listen[0]
	if listener.Kind != listenKindPolicyService {
		t.Fatalf("packaged listener kind = %q, want %q", listener.Kind, listenKindPolicyService)
	}

	if listener.Name != testSocketName {
		t.Fatalf("packaged listener name = %q, want %s", listener.Name, testSocketName)
	}

	if listener.Type != listenTypeUnix {
		t.Fatalf("packaged listener type = %q, want %q", listener.Type, listenTypeUnix)
	}

	if listener.Address != packagedPolicySocketPath {
		t.Fatalf("packaged listener address = %q, want %q", listener.Address, packagedPolicySocketPath)
	}

	if listener.SystemdSocketName != testSocketName {
		t.Fatalf("packaged systemd_socket_name = %q, want %s", listener.SystemdSocketName, testSocketName)
	}

	if _, ok := cfg.PolicyServices[testSocketName]; !ok {
		t.Fatal("packaged policy listener must have a matching policy_services.policy entry")
	}
}

func assertPackagedConservativeDefaults(t *testing.T, cfg *Config) {
	t.Helper()

	if cfg.Server.TLS.SkipVerify {
		t.Fatal("packaged config must not skip TLS verification")
	}

	if cfg.Server.Logging.Level != packagedInfoLogLevel {
		t.Fatalf("packaged logging level = %q, want %s", cfg.Server.Logging.Level, packagedInfoLogLevel)
	}

	if !cfg.Server.Logging.UseSystemd {
		t.Fatal("packaged config should use systemd-style logging")
	}
}
