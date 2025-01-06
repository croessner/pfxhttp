package main

import (
	"time"

	"github.com/spf13/viper"
)

type Config struct {
	Server     Server             `mapstructure:"server"`
	SocketMaps map[string]Request `mapstructure:"socket_maps"`
}

type Server struct {
	Listen              Listen     `mapstructure:"listen"`
	HTTPClient          HTTPClient `mapstructure:"http_client"`
	TLS                 TLS        `mapstructure:"tls"`
	SockmapMaxReplySize int        `mapstructure:"socketmap_max_reply_size"`
}

type Listen struct {
	Type    string `mapstructure:"type"`
	Address string `mapstructure:"address"`
	Port    int    `mapstructure:"port"`
	Mode    string `mapstructure:"mode"`
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

	viper.SetConfigName("pfxhttp")

	viper.SetConfigType("yaml")

	viper.AddConfigPath("/usr/local/etc/pfxhttp/")
	viper.AddConfigPath("/etc/pfxhttp/")
	viper.AddConfigPath("$HOME/.pfxhttp")
	viper.AddConfigPath(".")

	err = viper.ReadInConfig()
	if err != nil {
		return nil, err
	}

	err = cfg.HandleConfig()

	return cfg, err
}
