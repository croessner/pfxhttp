package main

import (
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/go-playground/validator/v10"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

type Config struct {
	Server         Server             `mapstructure:"server" validate:"required"`
	SocketMaps     map[string]Request `mapstructure:"socket_maps" validate:"omitempty,dive"`
	PolicyServices map[string]Request `mapstructure:"policy_services" validate:"omitempty,dive"`
}

type Server struct {
	Listen              []Listen   `mapstructure:"listen" validate:"required,min=1,dive"`
	Logging             Logging    `mapstructure:"logging" validate:"omitempty"`
	HTTPClient          HTTPClient `mapstructure:"http_client" validate:"omitempty"`
	TLS                 TLS        `mapstructure:"tls" validate:"omitempty"`
	SockmapMaxReplySize int        `mapstructure:"socketmap_max_reply_size" validate:"omitempty,min=1,max=1000000000"`
	JWTDBPath           string     `mapstructure:"jwt_db_path" validate:"omitempty,filepath"`
}

type Listen struct {
	Kind    string `mapstructure:"kind" validate:"required,oneof=socket_map policy_service"`
	Name    string `mapstructure:"name" validate:"omitempty,alphanumunicode|alphanum_underscore,excludesall= "`
	Type    string `mapstructure:"type" validate:"required,oneof=tcp tcp6 unix"`
	Address string `mapstructure:"address" validate:"required,ip_addr|filepath"`
	Port    int    `mapstructure:"port" validate:"omitempty,min=1,max=65535"`
	Mode    string `mapstructure:"mode" validate:"omitempty,octal_mode"`
}

type Logging struct {
	JSON  bool   `mapstructure:"json"`
	Level string `mapstructure:"level" validate:"omitempty,oneof=none debug info error"`
}

type HTTPClient struct {
	MaxConnsPerHost     int           `mapstructure:"max_connections_per_host" validate:"omitempty,min=1,max=16384"`
	MaxIdleConns        int           `mapstructure:"max_idle_connections" validate:"omitempty,min=0,max=16384"`
	MaxIdleConnsPerHost int           `mapstructure:"max_idle_connections_per_host" validate:"omitempty,min=0,max=16384"`
	IdleConnTimeout     time.Duration `mapstructure:"idle_connection_timeout" validate:"omitempty,min=1ms,max=1h"`
	Proxy               string        `mapstructure:"proxy" validate:"omitempty,http_url"`
}

type TLS struct {
	Enabled    bool   `mapstructure:"enabled"`
	Cert       string `mapstructure:"cert" validate:"omitempty,file"`
	Key        string `mapstructure:"key" validate:"omitempty,file"`
	SkipVerify bool   `mapstructure:"http_client_skip_verify"`
}

type JWTAuth struct {
	Enabled       bool              `mapstructure:"enabled"`
	TokenEndpoint string            `mapstructure:"token_endpoint" validate:"required_if=Enabled true,http_url"`
	Credentials   map[string]string `mapstructure:"credentials" validate:"required_if=Enabled true"`
	ContentType   string            `mapstructure:"content_type" validate:"omitempty,oneof=application/x-www-form-urlencoded application/json"`
}

type Request struct {
	Target        string   `mapstructure:"target" validate:"required,http_url"`
	CustomHeaders []string `mapstructure:"custom_headers" validate:"omitempty,dive,printascii"`
	Payload       string   `mapstructure:"payload" validate:"omitempty,ascii"`
	StatusCode    int      `mapstructure:"status_code" validate:"omitempty,min=100,max=599"`
	ValueField    string   `mapstructure:"value_field" validate:"omitempty,printascii"`
	ErrorField    string   `mapstructure:"error_field" validate:"omitempty,printascii"`
	NoErrorValue  string   `mapstructure:"no_error_value" validate:"omitempty,printascii"`
	JWTAuth       JWTAuth  `mapstructure:"jwt_auth" validate:"omitempty"`
}

func (cfg *Config) HandleConfig() error {
	var validationErrors validator.ValidationErrors

	err := viper.Unmarshal(cfg)
	if err != nil {
		return err
	}

	validate := validator.New(validator.WithRequiredStructEnabled())

	_ = validate.RegisterValidation("octal_mode", isValidOctalMode)
	_ = validate.RegisterValidation("alphanum_underscore", isAlphanumUnderscore)

	err = validate.Struct(cfg)
	if err == nil {
		return nil
	}

	if errors.As(err, &validationErrors) {
		return prettyFormatValidationErrors(validationErrors)
	}

	return err
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

func isValidOctalMode(fl validator.FieldLevel) bool {
	mode := fl.Field().String()

	if !strings.HasPrefix(mode, "0") {
		return false
	}

	_, err := strconv.ParseUint(mode, 8, 32)

	return err == nil
}

func isAlphanumUnderscore(fl validator.FieldLevel) bool {
	value := fl.Field().String()

	for _, r := range value {
		if !unicode.IsLetter(r) && !unicode.IsNumber(r) && r != '_' {
			return false
		}
	}

	return true
}

func toSnakeCase(fieldName string) string {
	var result strings.Builder

	previousWasUpper := false

	for i, r := range fieldName {
		if unicode.IsUpper(r) {
			if i > 0 && !previousWasUpper {
				result.WriteByte('_')
			}

			previousWasUpper = true
		} else {
			previousWasUpper = false
		}

		result.WriteRune(unicode.ToLower(r))
	}

	return result.String()
}

func prettyFormatValidationErrors(validationErrors validator.ValidationErrors) error {
	var errorMessages []string

	for _, fieldErr := range validationErrors {
		message := fmt.Sprintf(
			"field '%s' (struct field: '%s') failed on the '%s' validation rule",
			toSnakeCase(fieldErr.Field()),
			fieldErr.StructField(),
			fieldErr.Tag(),
		)

		if fieldErr.Param() != "" {
			message = fmt.Sprintf("%s. Rule parameter: %s", message, fieldErr.Param())
		}

		errorMessages = append(errorMessages, message)
	}

	return errors.New("validation errors: " + strings.Join(errorMessages, "; "))
}
