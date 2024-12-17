package main

import "github.com/spf13/viper"

type Config struct {
	Server     Server             `mapstructure:"server"`
	SocketMaps map[string]Request `mapstructure:"socket_maps"`
}

type Server struct {
	Listen Listen `mapstructure:"listen"`
	TLS    TLS    `mapstructure:"tls"`
}

type Listen struct {
	Type    string `mapstructure:"type"`
	Address string `mapstructure:"address"`
	Port    int    `mapstructure:"port"`
}

type TLS struct {
	Enabled    bool   `mapstructure:"enabled"`
	Cert       string `mapstructure:"cert"`
	Key        string `mapstructure:"key"`
	SkipVerify bool   `mapstructure:"skip_verify"`
}

type Request struct {
	Target     string `mapstructure:"target"`
	Payload    string `mapstructure:"payload"`
	StatusCode int    `mapstructure:"status_code"`
	ValueField string `mapstructure:"value_field"`
}

func (cfg *Config) HandleConfig() error {
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
