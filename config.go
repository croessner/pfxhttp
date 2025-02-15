package main

import (
	"log/slog"
	"strings"
	"time"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

type Config struct {
	Server         Server             `mapstructure:"server"`
	SocketMaps     map[string]Request `mapstructure:"socket_maps"`
	PolicyServices map[string]Request `mapstructure:"policy_services"`
}

type Server struct {
	Listen              []Listen   `mapstructure:"listen"`
	Logging             Logging    `mapstructure:"logging"`
	HTTPClient          HTTPClient `mapstructure:"http_client"`
	TLS                 TLS        `mapstructure:"tls"`
	SockmapMaxReplySize int        `mapstructure:"socketmap_max_reply_size"`
}

type Listen struct {
	Kind    string `mapstructure:"kind"`
	Name    string `mapstructure:"name"`
	Type    string `mapstructure:"type"`
	Address string `mapstructure:"address"`
	Port    int    `mapstructure:"port"`
	Mode    string `mapstructure:"mode"`
}

type Logging struct {
	JSON  bool   `mapstructure:"json"`
	Level string `mapstructure:"level"`
}

type HTTPClient struct {
	MaxConnsPerHost     int           `mapstructure:"max_connections_per_host"`
	MaxIdleConns        int           `mapstructure:"max_idle_connections"`
	MaxIdleConnsPerHost int           `mapstructure:"max_idle_connections_per_host"`
	IdleConnTimeout     time.Duration `mapstructure:"idle_connection_timeout"`
	Proxy               string        `mapstructure:"proxy"`
}

type TLS struct {
	Enabled    bool   `mapstructure:"enabled"`
	Cert       string `mapstructure:"cert"`
	Key        string `mapstructure:"key"`
	SkipVerify bool   `mapstructure:"http_client_skip_verify"`
}

type Request struct {
	Target        string   `mapstructure:"target"`
	CustomHeaders []string `mapstructure:"custom_headers"`
	Payload       string   `mapstructure:"payload"`
	StatusCode    int      `mapstructure:"status_code"`
	ValueField    string   `mapstructure:"value_field"`
	ErrorField    string   `mapstructure:"error_field"`
	NoErrorValue  string   `mapstructure:"no_error_value"`
}

func (cfg *Config) HandleConfig() error {
	if cfg.Server.SockmapMaxReplySize <= 0 {
		cfg.Server.SockmapMaxReplySize = 100000
	}

	return viper.Unmarshal(cfg)
}

func NewConfigFile() (cfg *Config, err error) {
	cfg = &Config{}

	// Define command-line flags for config file and format
	pflag.String("config", "", "Path to the configuration file")
	pflag.String("format", "yaml", "Format of the configuration file (e.g., yaml, json, toml)")
	pflag.Parse()

	// Bind flags to Viper
	err = viper.BindPFlags(pflag.CommandLine)
	if err != nil {
		return nil, err
	}

	// Read values from the flags
	configPath := viper.GetString("config")
	configFormat := viper.GetString("format")

	// Use the passed --config and --format values
	if configPath != "" {
		viper.SetConfigFile(configPath)
		viper.SetConfigType(configFormat)
	} else {
		// Default case: look up in standard paths
		viper.SetConfigName("pfxhttp")
		viper.SetConfigType(configFormat)

		viper.AddConfigPath("/usr/local/etc/pfxhttp/")
		viper.AddConfigPath("/etc/pfxhttp/")
		viper.AddConfigPath("$HOME/.pfxhttp")
		viper.AddConfigPath(".")
	}

	// Attempt to read configuration
	err = viper.ReadInConfig()
	if err != nil {
		slog.Info("No configuration file found")
	}

	// Enable reading environment variables
	viper.AutomaticEnv()
	viper.SetEnvPrefix("PFXHTTP")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// Parse the configuration into the struct
	err = cfg.HandleConfig()

	return cfg, err
}
