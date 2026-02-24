package main

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
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
	DovecotSASL    map[string]Request `mapstructure:"dovecot_sasl" validate:"omitempty,dive"`
}

type Server struct {
	Listen              []Listen            `mapstructure:"listen" validate:"required,min=1,dive"`
	RunAsUser           string              `mapstructure:"run_as_user" validate:"omitempty"`
	RunAsGroup          string              `mapstructure:"run_as_group" validate:"omitempty"`
	Logging             Logging             `mapstructure:"logging" validate:"omitempty"`
	HTTPClient          HTTPClient          `mapstructure:"http_client" validate:"omitempty"`
	TLS                 TLS                 `mapstructure:"tls" validate:"omitempty"`
	SockmapMaxReplySize int                 `mapstructure:"socketmap_max_reply_size" validate:"omitempty,min=1,max=1000000000"`
	ResponseCache       ResponseCacheConfig `mapstructure:"response_cache" validate:"omitempty"`
	WorkerPool          WorkerPoolConfig    `mapstructure:"worker_pool" validate:"omitempty"`
}

type Listen struct {
	Kind       string           `mapstructure:"kind" validate:"required,oneof=socket_map policy_service dovecot_sasl"`
	Name       string           `mapstructure:"name" validate:"omitempty,alphanumunicode|alphanum_underscore,excludesall= "`
	Type       string           `mapstructure:"type" validate:"required,oneof=tcp tcp6 unix"`
	Address    string           `mapstructure:"address" validate:"required"`
	Port       int              `mapstructure:"port" validate:"omitempty,min=1,max=65535"`
	Mode       string           `mapstructure:"mode" validate:"omitempty,octal_mode"`
	User       string           `mapstructure:"user" validate:"omitempty"`
	Group      string           `mapstructure:"group" validate:"omitempty"`
	WorkerPool WorkerPoolConfig `mapstructure:"worker_pool" validate:"omitempty"`
}

type WorkerPoolConfig struct {
	MaxWorkers int `mapstructure:"max_workers" validate:"omitempty,min=1"`
	MaxQueue   int `mapstructure:"max_queue" validate:"omitempty,min=1"`
}

type Logging struct {
	JSON  bool   `mapstructure:"json"`
	Level string `mapstructure:"level" validate:"omitempty,oneof=none debug info error"`
}

type ResponseCacheConfig struct {
	Enabled bool          `mapstructure:"enabled"`
	TTL     time.Duration `mapstructure:"ttl" validate:"omitempty,min=1s,max=168h"`
}

type HTTPClient struct {
	MaxConnsPerHost     int           `mapstructure:"max_connections_per_host" validate:"omitempty,min=1,max=16384"`
	MaxIdleConns        int           `mapstructure:"max_idle_connections" validate:"omitempty,min=0,max=16384"`
	MaxIdleConnsPerHost int           `mapstructure:"max_idle_connections_per_host" validate:"omitempty,min=0,max=16384"`
	IdleConnTimeout     time.Duration `mapstructure:"idle_connection_timeout" validate:"omitempty,min=1ms,max=1h"`
	Timeout             time.Duration `mapstructure:"timeout" validate:"omitempty,min=1s,max=1h"`
	Proxy               string        `mapstructure:"proxy" validate:"omitempty,http_url"`
}

type TLS struct {
	Enabled    bool   `mapstructure:"enabled"`
	Cert       string `mapstructure:"cert" validate:"omitempty,file"`
	Key        string `mapstructure:"key" validate:"omitempty,file"`
	RootCA     string `mapstructure:"root_ca" validate:"omitempty,file"`
	SkipVerify bool   `mapstructure:"skip_verify"`
}

type BackendOIDCAuth struct {
	Enabled          bool     `mapstructure:"enabled"`
	ConfigurationURI string   `mapstructure:"configuration_uri" validate:"required_if=Enabled true,http_url"`
	ClientID         string   `mapstructure:"client_id" validate:"required_if=Enabled true"`
	ClientSecret     string   `mapstructure:"client_secret"`
	PrivateKeyFile   string   `mapstructure:"private_key_file" validate:"omitempty,file"`
	Scopes           []string `mapstructure:"scopes"`
	// AuthMethod controls how the client authenticates to token endpoints.
	// Values: auto, client_secret_basic, client_secret_post, private_key_jwt, none
	AuthMethod string `mapstructure:"auth_method" validate:"omitempty,oneof=auto client_secret_basic client_secret_post private_key_jwt none"`
}

type SASLOIDCAuth struct {
	Enabled          bool     `mapstructure:"enabled"`
	ConfigurationURI string   `mapstructure:"configuration_uri" validate:"required_if=Enabled true,http_url"`
	ClientID         string   `mapstructure:"client_id" validate:"required_if=Enabled true"`
	ClientSecret     string   `mapstructure:"client_secret"`
	Scopes           []string `mapstructure:"scopes"`
	// AuthMethod controls how the client authenticates to token/introspection endpoints.
	// Values: auto, client_secret_basic, client_secret_post, none
	AuthMethod string `mapstructure:"auth_method" validate:"omitempty,oneof=auto client_secret_basic client_secret_post none"`
	// Validation controls how incoming OAuth tokens are validated for SASL.
	// Values: introspection, jwks, auto
	Validation   string        `mapstructure:"validation" validate:"omitempty,oneof=introspection jwks auto"`
	JWKSCacheTTL time.Duration `mapstructure:"jwks_cache_ttl" validate:"omitempty,min=1m,max=168h"`
}

type Request struct {
	Target                  string          `mapstructure:"target" validate:"required,http_url"`
	CustomHeaders           []string        `mapstructure:"custom_headers" validate:"omitempty,dive,printascii"`
	Payload                 string          `mapstructure:"payload" validate:"omitempty,ascii"`
	StatusCode              int             `mapstructure:"status_code" validate:"omitempty,min=100,max=599"`
	ValueField              string          `mapstructure:"value_field" validate:"omitempty,printascii"`
	ErrorField              string          `mapstructure:"error_field" validate:"omitempty,printascii"`
	NoErrorValue            string          `mapstructure:"no_error_value" validate:"omitempty,printascii"`
	BackendOIDCAuth         BackendOIDCAuth `mapstructure:"backend_oidc_auth" validate:"omitempty"`
	SASLOIDCAuth            SASLOIDCAuth    `mapstructure:"sasl_oidc_auth" validate:"omitempty"`
	DefaultLocalPort        string          `mapstructure:"default_local_port" validate:"omitempty,numeric"`
	HTTPRequestCompression  bool            `mapstructure:"http_request_compression"`
	HTTPResponseCompression bool            `mapstructure:"http_response_compression"`
}

func (cfg *Config) HandleConfig() error {

	err := viper.Unmarshal(cfg)
	if err != nil {
		return err
	}

	// Apply defaults for worker pool if not configured
	numCPU := runtime.GOMAXPROCS(0)
	if cfg.Server.WorkerPool.MaxWorkers == 0 {
		cfg.Server.WorkerPool.MaxWorkers = numCPU * 2
	}
	if cfg.Server.WorkerPool.MaxQueue == 0 {
		cfg.Server.WorkerPool.MaxQueue = cfg.Server.WorkerPool.MaxWorkers * 10
	}

	for i := range cfg.Server.Listen {
		if cfg.Server.Listen[i].WorkerPool.MaxWorkers == 0 {
			// If per-listener pool is not configured, we don't automatically
			// set it here because we want it to fall back to the global pool.
			// But if it IS partially configured (e.g. only MaxWorkers), we should
			// provide a default for MaxQueue.
		} else if cfg.Server.Listen[i].WorkerPool.MaxQueue == 0 {
			cfg.Server.Listen[i].WorkerPool.MaxQueue = cfg.Server.Listen[i].WorkerPool.MaxWorkers * 10
		}
	}

	// Provide sensible defaults for Backend OIDC across all request maps
	setBackendOIDCDefaults := func(r *Request) {
		if !r.BackendOIDCAuth.Enabled {
			return
		}
		// auth_method defaulting
		if r.BackendOIDCAuth.AuthMethod == "" || r.BackendOIDCAuth.AuthMethod == "auto" {
			if r.BackendOIDCAuth.PrivateKeyFile != "" {
				r.BackendOIDCAuth.AuthMethod = "private_key_jwt"
			} else if r.BackendOIDCAuth.ClientSecret != "" {
				r.BackendOIDCAuth.AuthMethod = "client_secret_basic"
			} else {
				r.BackendOIDCAuth.AuthMethod = "none"
			}
		}
	}

	// Provide sensible defaults for SASL OIDC across all request maps
	setSASLOIDCDefaults := func(r *Request) {
		if !r.SASLOIDCAuth.Enabled {
			return
		}
		// auth_method defaulting
		if r.SASLOIDCAuth.AuthMethod == "" || r.SASLOIDCAuth.AuthMethod == "auto" {
			if r.SASLOIDCAuth.ClientSecret != "" {
				r.SASLOIDCAuth.AuthMethod = "client_secret_basic"
			} else {
				r.SASLOIDCAuth.AuthMethod = "none"
			}
		}
		// validation defaulting
		if r.SASLOIDCAuth.Validation == "" {
			r.SASLOIDCAuth.Validation = "introspection"
		}
		// JWKS cache TTL default
		if r.SASLOIDCAuth.JWKSCacheTTL == 0 {
			r.SASLOIDCAuth.JWKSCacheTTL = 5 * time.Minute
		}
	}

	for k := range cfg.SocketMaps {
		v := cfg.SocketMaps[k]
		setBackendOIDCDefaults(&v)
		setSASLOIDCDefaults(&v)
		cfg.SocketMaps[k] = v
	}
	for k := range cfg.PolicyServices {
		v := cfg.PolicyServices[k]
		setBackendOIDCDefaults(&v)
		setSASLOIDCDefaults(&v)
		cfg.PolicyServices[k] = v
	}
	for k := range cfg.DovecotSASL {
		v := cfg.DovecotSASL[k]
		setBackendOIDCDefaults(&v)
		setSASLOIDCDefaults(&v)
		cfg.DovecotSASL[k] = v
	}

	validate := validator.New(validator.WithRequiredStructEnabled())

	_ = validate.RegisterValidation("octal_mode", isValidOctalMode)
	_ = validate.RegisterValidation("alphanum_underscore", isAlphanumUnderscore)

	err = validate.Struct(cfg)
	if err == nil {
		return nil
	}

	if ve, ok := errors.AsType[validator.ValidationErrors](err); ok {
		return prettyFormatValidationErrors(ve)
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
		// Viper will automatically look for pfxhttp.yaml, pfxhttp.yml, etc.
		// unless SetConfigType is explicitly set.

		viper.AddConfigPath("/usr/local/etc/pfxhttp")
		viper.AddConfigPath("/etc/pfxhttp")
		if home, err := os.UserHomeDir(); err == nil {
			viper.AddConfigPath(filepath.Join(home, ".pfxhttp"))
		}
		viper.AddConfigPath(".")
	}

	// Attempt to read configuration
	err = viper.ReadInConfig()
	if err != nil {
		slog.Warn("Configuration file not found, using defaults", "error", err)
	} else {
		slog.Info("Using configuration file", "file", viper.ConfigFileUsed())
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
