package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"maps"
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
	Chroot              string              `mapstructure:"chroot" validate:"omitempty,dir"`
	Logging             Logging             `mapstructure:"logging" validate:"omitempty"`
	HTTPClient          HTTPClient          `mapstructure:"http_client" validate:"omitempty"`
	TLS                 TLS                 `mapstructure:"tls" validate:"omitempty"`
	SockmapMaxReplySize int                 `mapstructure:"socketmap_max_reply_size" validate:"omitempty,min=1,max=1000000000"`
	ResponseCache       ResponseCacheConfig `mapstructure:"response_cache" validate:"omitempty"`
	WorkerPool          WorkerPoolConfig    `mapstructure:"worker_pool" validate:"omitempty"`
	Observability       ObservabilityConfig `mapstructure:"observability" validate:"omitempty"`
}

type Listen struct {
	Kind    string `mapstructure:"kind" validate:"required,oneof=socket_map policy_service dovecot_sasl"`
	Name    string `mapstructure:"name" validate:"omitempty,alphanumunicode|alphanum_underscore,excludesall= "`
	Type    string `mapstructure:"type" validate:"required,oneof=tcp tcp6 unix"`
	Address string `mapstructure:"address" validate:"required"`
	Port    int    `mapstructure:"port" validate:"omitempty,min=1,max=65535"`
	Mode    string `mapstructure:"mode" validate:"omitempty,octal_mode"`
	User    string `mapstructure:"user" validate:"omitempty"`
	Group   string `mapstructure:"group" validate:"omitempty"`
	// SystemdSocketName selects a systemd FileDescriptorName to consume instead of creating a native listener.
	SystemdSocketName string           `mapstructure:"systemd_socket_name" validate:"omitempty,printascii"`
	WorkerPool        WorkerPoolConfig `mapstructure:"worker_pool" validate:"omitempty"`
}

type WorkerPoolConfig struct {
	MaxWorkers int `mapstructure:"max_workers" validate:"omitempty,min=1"`
	MaxQueue   int `mapstructure:"max_queue" validate:"omitempty,min=1"`
}

type Logging struct {
	JSON       bool   `mapstructure:"json"`
	Level      string `mapstructure:"level" validate:"omitempty,oneof=none debug info error"`
	UseSystemd bool   `mapstructure:"use_systemd"`
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
	// AccountClaim specifies which claim (JWT) or introspection response field
	// should be used as the account/username. If empty, the default resolution
	// chain (sub → preferred_username → username) is used.
	AccountClaim string `mapstructure:"account_claim" validate:"omitempty,printascii"`
}

// reservedConfigKey is the key name reserved for section-level defaults.
const reservedConfigKey = "defaults"

const (
	// listenKindSocketMap identifies Postfix socket map listener entries.
	listenKindSocketMap = "socket_map"
	// listenKindPolicyService identifies Postfix policy service listener entries.
	listenKindPolicyService = "policy_service"
	// listenKindDovecotSASL identifies Dovecot SASL listener entries.
	listenKindDovecotSASL = "dovecot_sasl"
)

const (
	// listenTypeTCP identifies IPv4 or dual-stack TCP listener entries.
	listenTypeTCP = "tcp"
	// listenTypeTCP6 identifies IPv6 TCP listener entries.
	listenTypeTCP6 = "tcp6"
	// listenTypeUnix identifies Unix domain socket listener entries.
	listenTypeUnix = "unix"
)

// Transport names accepted on dovecot_sasl entries.
const (
	transportJSON = "json"
	transportGRPC = "grpc"
)

// GRPCRequest holds gRPC-specific transport settings used when
// dovecot_sasl.<name>.transport is set to "grpc". Caller authorization
// (Basic/Bearer) is derived from the surrounding Request (http_auth_basic /
// backend_oidc_auth); arbitrary request metadata lives here.
type GRPCRequest struct {
	Address  string              `mapstructure:"address" validate:"omitempty,hostname_port"`
	Timeout  time.Duration       `mapstructure:"timeout" validate:"omitempty,min=1ms,max=1h"`
	Metadata map[string][]string `mapstructure:"metadata" validate:"omitempty"`
	TLS      GRPCTLS             `mapstructure:"tls" validate:"omitempty"`
}

// GRPCTLS configures the TLS connection for the gRPC client. RootCA pins the
// trust anchors; ClientCert/ClientKey enable mTLS; ServerName overrides the
// SNI/SAN used during the handshake. MinVersion selects the lowest accepted
// TLS protocol version (1.2 or 1.3). The hard floor is 1.2 — anything older
// is forbidden by validation regardless of YAML input. Boolean fields are
// pointers so defaults merging can distinguish "unset" from explicit false.
type GRPCTLS struct {
	Enabled    *bool  `mapstructure:"enabled"`
	RootCA     string `mapstructure:"root_ca" validate:"omitempty,file"`
	ClientCert string `mapstructure:"client_cert" validate:"omitempty,file"`
	ClientKey  string `mapstructure:"client_key" validate:"omitempty,file"`
	ServerName string `mapstructure:"server_name" validate:"omitempty"`
	MinVersion string `mapstructure:"min_tls_version" validate:"omitempty,oneof=1.2 1.3"`
	SkipVerify *bool  `mapstructure:"skip_verify"`
}

type Request struct {
	Target                  string          `mapstructure:"target" validate:"omitempty,http_url"`
	HTTPAuthBasic           string          `mapstructure:"http_auth_basic" validate:"omitempty"`
	CustomHeaders           []string        `mapstructure:"custom_headers" validate:"omitempty,dive,printascii"`
	Payload                 string          `mapstructure:"payload" validate:"omitempty,ascii"`
	StatusCode              int             `mapstructure:"status_code" validate:"omitempty,min=100,max=599"`
	ValueField              string          `mapstructure:"value_field" validate:"omitempty,printascii"`
	ErrorField              string          `mapstructure:"error_field" validate:"omitempty,printascii"`
	NoErrorValue            string          `mapstructure:"no_error_value" validate:"omitempty,printascii"`
	BackendOIDCAuth         BackendOIDCAuth `mapstructure:"backend_oidc_auth" validate:"omitempty"`
	SASLOIDCAuth            SASLOIDCAuth    `mapstructure:"sasl_oidc_auth" validate:"omitempty"`
	DefaultLocalPort        string          `mapstructure:"default_local_port" validate:"omitempty,numeric"`
	Transport               string          `mapstructure:"transport" validate:"omitempty,oneof=json grpc"`
	GRPC                    GRPCRequest     `mapstructure:"grpc" validate:"omitempty"`
	HTTPRequestCompression  bool            `mapstructure:"http_request_compression"`
	HTTPResponseCompression bool            `mapstructure:"http_response_compression"`
}

// mergeRequest merges defaults into a specific entry.
// Explicit (non-zero) values in entry take precedence over defaults.
// CustomHeaders are merged additively (defaults first, then entry-specific).
func mergeRequest(defaults, entry Request) Request {
	if entry.Target == "" {
		entry.Target = defaults.Target
	}

	if entry.HTTPAuthBasic == "" {
		entry.HTTPAuthBasic = defaults.HTTPAuthBasic
	}

	// Additive merge for custom_headers: defaults headers first, then entry-specific
	if len(defaults.CustomHeaders) > 0 {
		merged := make([]string, 0, len(defaults.CustomHeaders)+len(entry.CustomHeaders))
		merged = append(merged, defaults.CustomHeaders...)
		merged = append(merged, entry.CustomHeaders...)
		entry.CustomHeaders = merged
	}

	if entry.Payload == "" {
		entry.Payload = defaults.Payload
	}

	if entry.StatusCode == 0 {
		entry.StatusCode = defaults.StatusCode
	}

	if entry.ValueField == "" {
		entry.ValueField = defaults.ValueField
	}

	if entry.ErrorField == "" {
		entry.ErrorField = defaults.ErrorField
	}

	if entry.NoErrorValue == "" {
		entry.NoErrorValue = defaults.NoErrorValue
	}

	if !entry.HTTPRequestCompression {
		entry.HTTPRequestCompression = defaults.HTTPRequestCompression
	}

	if !entry.HTTPResponseCompression {
		entry.HTTPResponseCompression = defaults.HTTPResponseCompression
	}

	if !entry.BackendOIDCAuth.Enabled && defaults.BackendOIDCAuth.Enabled {
		entry.BackendOIDCAuth = defaults.BackendOIDCAuth
	}

	if !entry.SASLOIDCAuth.Enabled && defaults.SASLOIDCAuth.Enabled {
		entry.SASLOIDCAuth = defaults.SASLOIDCAuth
	}

	if entry.DefaultLocalPort == "" {
		entry.DefaultLocalPort = defaults.DefaultLocalPort
	}

	if entry.Transport == "" {
		entry.Transport = defaults.Transport
	}

	mergeGRPC(&entry.GRPC, defaults.GRPC)

	return entry
}

// mergeGRPC fills empty fields of entry with values from defaults so the
// section-level "defaults" block can supply common gRPC settings.
func mergeGRPC(entry *GRPCRequest, defaults GRPCRequest) {
	if entry.Address == "" {
		entry.Address = defaults.Address
	}

	if entry.Timeout == 0 {
		entry.Timeout = defaults.Timeout
	}

	entry.Metadata = mergeStringSliceMap(defaults.Metadata, entry.Metadata)

	if entry.TLS.Enabled == nil && defaults.TLS.Enabled != nil {
		entry.TLS.Enabled = new(*defaults.TLS.Enabled)
	}

	if entry.TLS.RootCA == "" {
		entry.TLS.RootCA = defaults.TLS.RootCA
	}

	if entry.TLS.ClientCert == "" {
		entry.TLS.ClientCert = defaults.TLS.ClientCert
	}

	if entry.TLS.ClientKey == "" {
		entry.TLS.ClientKey = defaults.TLS.ClientKey
	}

	if entry.TLS.ServerName == "" {
		entry.TLS.ServerName = defaults.TLS.ServerName
	}

	if entry.TLS.MinVersion == "" {
		entry.TLS.MinVersion = defaults.TLS.MinVersion
	}

	if entry.TLS.SkipVerify == nil && defaults.TLS.SkipVerify != nil {
		entry.TLS.SkipVerify = new(*defaults.TLS.SkipVerify)
	}
}

// mergeStringSliceMap merges default keyed string-slice values with entry
// values, replacing whole keys when an entry defines the same key.
func mergeStringSliceMap(defaults, entry map[string][]string) map[string][]string {
	if len(defaults) == 0 {
		return cloneStringSliceMap(entry)
	}

	merged := cloneStringSliceMap(defaults)
	for key, values := range entry {
		merged[key] = slicesClone(values)
	}

	return merged
}

// cloneStringSliceMap returns a deep copy of a map whose values are string
// slices so later normalization cannot mutate the original config data.
func cloneStringSliceMap(in map[string][]string) map[string][]string {
	if len(in) == 0 {
		return nil
	}

	out := make(map[string][]string, len(in))
	for key, values := range in {
		out[key] = slicesClone(values)
	}

	return out
}

// slicesClone returns a copy of the provided string slice, preserving nil as
// nil so unset values remain distinguishable from empty-but-set values.
func slicesClone(in []string) []string {
	if in == nil {
		return nil
	}

	out := make([]string, len(in))
	copy(out, in)

	return out
}

func boolValue(value *bool) bool {
	return value != nil && *value
}

// resolveDefaults extracts the optional "defaults" key from a section map,
// merges its values into all other entries, and returns a flat map without
// the "defaults" key.
func resolveDefaults(raw map[string]Request) map[string]Request {
	if raw == nil {
		return nil
	}

	defaults, hasDefaults := raw[reservedConfigKey]

	result := make(map[string]Request, len(raw))

	for name, entry := range maps.All(raw) {
		if name == reservedConfigKey {
			continue
		}

		if hasDefaults {
			entry = mergeRequest(defaults, entry)
		}

		result[name] = entry
	}

	return result
}

// validateTargets checks that all entries in a section map have a non-empty target URL.
func validateTargets(section map[string]Request, sectionName string) error {
	for name, entry := range maps.All(section) {
		if entry.Target == "" {
			return fmt.Errorf("entry '%s' in '%s' is missing a required 'target' URL", name, sectionName)
		}
	}

	return nil
}

// validateDovecotSASLEndpoints checks transport-specific endpoint requirements
// for dovecot_sasl entries. For HTTP transport (default) the entry must have
// a 'target' URL. For gRPC transport the entry must have a 'grpc.address'.
func validateDovecotSASLEndpoints(section map[string]Request) error {
	for name, entry := range maps.All(section) {
		switch entry.Transport {
		case transportGRPC:
			if entry.GRPC.Address == "" {
				return fmt.Errorf("entry '%s' in 'dovecot_sasl' uses transport 'grpc' and is missing a required 'grpc.address'", name)
			}
			if len(entry.CustomHeaders) > 0 {
				return fmt.Errorf("entry '%s' in 'dovecot_sasl' uses transport 'grpc' but custom_headers are HTTP-only; use grpc.metadata", name)
			}
		case transportJSON, "":
			if entry.Target == "" {
				return fmt.Errorf("entry '%s' in 'dovecot_sasl' is missing a required 'target' URL", name)
			}
			if len(entry.GRPC.Metadata) > 0 {
				return fmt.Errorf("entry '%s' in 'dovecot_sasl' configures grpc.metadata but does not use transport 'grpc'", name)
			}
		default:
			return fmt.Errorf("entry '%s' in 'dovecot_sasl' has unsupported transport %q", name, entry.Transport)
		}
	}

	return nil
}

// validateAuthSourceConflicts rejects entries that configure both static Basic
// caller auth and backend OIDC caller auth, because both would write the same
// Authorization channel.
func validateAuthSourceConflicts(cfg *Config) error {
	check := func(sectionName string, section map[string]Request) error {
		for name, entry := range maps.All(section) {
			if entry.HTTPAuthBasic != "" && entry.BackendOIDCAuth.Enabled {
				return fmt.Errorf("entry '%s' in '%s' configures both 'http_auth_basic' and 'backend_oidc_auth'", name, sectionName)
			}
		}

		return nil
	}

	if err := check("socket_maps", cfg.SocketMaps); err != nil {
		return err
	}
	if err := check("policy_services", cfg.PolicyServices); err != nil {
		return err
	}
	if err := check("dovecot_sasl", cfg.DovecotSASL); err != nil {
		return err
	}

	return nil
}

// normalizeDovecotSASLGRPCMetadata normalizes gRPC metadata for every
// dovecot_sasl entry and writes the canonical form back into the section map.
func normalizeDovecotSASLGRPCMetadata(section map[string]Request) error {
	for name, entry := range maps.All(section) {
		if len(entry.GRPC.Metadata) == 0 {
			continue
		}

		normalized, err := normalizeGRPCMetadata(entry.GRPC.Metadata)
		if err != nil {
			return fmt.Errorf("entry '%s' in 'dovecot_sasl' has invalid grpc.metadata: %w", name, err)
		}

		entry.GRPC.Metadata = normalized
		section[name] = entry
	}

	return nil
}

// normalizeGRPCMetadata validates static outgoing gRPC metadata and returns a
// canonical lowercase-key map suitable for metadata.AppendToOutgoingContext.
func normalizeGRPCMetadata(raw map[string][]string) (map[string][]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}

	normalized := make(map[string][]string, len(raw))
	for rawKey, values := range raw {
		key := strings.ToLower(strings.TrimSpace(rawKey))
		if key == "" {
			return nil, fmt.Errorf("metadata key must not be empty")
		}
		if key == "authorization" {
			return nil, fmt.Errorf("metadata key %q is reserved for http_auth_basic/backend_oidc_auth", key)
		}
		if strings.HasPrefix(key, "grpc-") {
			return nil, fmt.Errorf("metadata key %q uses the reserved grpc- prefix", key)
		}
		if strings.HasSuffix(key, "-bin") {
			return nil, fmt.Errorf("binary metadata key %q is not supported", key)
		}
		for _, r := range key {
			if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.') {
				return nil, fmt.Errorf("metadata key %q contains invalid character %q", rawKey, r)
			}
		}
		if _, exists := normalized[key]; exists {
			return nil, fmt.Errorf("metadata key %q is duplicated after normalization", key)
		}
		if len(values) == 0 {
			return nil, fmt.Errorf("metadata key %q must define at least one value", key)
		}

		copied := make([]string, 0, len(values))
		for _, value := range values {
			if value == "" {
				return nil, fmt.Errorf("metadata key %q contains an empty value", key)
			}
			if !isPrintableASCII(value) {
				return nil, fmt.Errorf("metadata key %q contains a non-printable or non-ASCII value", key)
			}

			copied = append(copied, value)
		}

		normalized[key] = copied
	}

	return normalized, nil
}

// isPrintableASCII reports whether value can be sent as non-binary gRPC
// metadata without using the reserved "-bin" binary metadata form.
func isPrintableASCII(value string) bool {
	for _, r := range value {
		if r < 0x20 || r > 0x7e {
			return false
		}
	}

	return true
}

// validateSystemdSocketNames rejects names that cannot be safely matched through LISTEN_FDNAMES.
func validateSystemdSocketNames(listeners []Listen) error {
	for _, listen := range listeners {
		name := listen.SystemdSocketName
		if name == "" {
			continue
		}

		if strings.TrimSpace(name) != name {
			return fmt.Errorf("listener %s has invalid systemd_socket_name %q: value must not contain leading or trailing whitespace", listenKey(listen), name)
		}

		if strings.Contains(name, ":") {
			return fmt.Errorf("listener %s has invalid systemd_socket_name %q: value must not contain ':'", listenKey(listen), name)
		}
	}

	return nil
}

// validateNoReservedKeys checks that no listener references the reserved "defaults" key.
func validateNoReservedKeys(cfg *Config) error {
	for _, listen := range cfg.Server.Listen {
		if listen.Name == reservedConfigKey {
			return fmt.Errorf("listener name '%s' is reserved and cannot be used", reservedConfigKey)
		}
	}

	return nil
}

// resolveHTTPAuthBasic converts the http_auth_basic field into a Base64-encoded
// Authorization header and prepends it to CustomHeaders.
func resolveHTTPAuthBasic(section map[string]Request) {
	for name, entry := range maps.All(section) {
		if entry.HTTPAuthBasic != "" {
			entry.CustomHeaders = append([]string{basicAuthorizationHeader(entry.HTTPAuthBasic)}, entry.CustomHeaders...)
			entry.HTTPAuthBasic = ""
			section[name] = entry
		}
	}
}

// resolveDovecotSASLHTTPBasicAuth converts http_auth_basic into an HTTP header
// only for JSON-backed SASL entries; gRPC entries keep it for metadata auth.
func resolveDovecotSASLHTTPBasicAuth(section map[string]Request) {
	for name, entry := range maps.All(section) {
		if entry.Transport == transportGRPC || entry.HTTPAuthBasic == "" {
			continue
		}

		entry.CustomHeaders = append([]string{basicAuthorizationHeader(entry.HTTPAuthBasic)}, entry.CustomHeaders...)
		entry.HTTPAuthBasic = ""
		section[name] = entry
	}
}

// basicAuthorizationHeader renders credentials as a full HTTP Authorization
// header entry for custom_headers.
func basicAuthorizationHeader(credentials string) string {
	return "Authorization: " + basicAuthorizationValue(credentials)
}

// basicAuthorizationValue renders credentials as the value portion used by
// HTTP Authorization and gRPC authorization metadata.
func basicAuthorizationValue(credentials string) string {
	encoded := base64.StdEncoding.EncodeToString([]byte(credentials))

	return "Basic " + encoded
}

// splitBasicAuthCredentials validates and separates the user:password form used for Basic auth.
func splitBasicAuthCredentials(credentials string) (string, string, error) {
	username, password, ok := strings.Cut(credentials, ":")
	if !ok || username == "" || password == "" {
		return "", "", errors.New("must use non-empty user:password credentials")
	}

	return username, password, nil
}

func (cfg *Config) HandleConfig() error {

	err := viper.Unmarshal(cfg)
	if err != nil {
		return err
	}

	if err := validateSystemdSocketNames(cfg.Server.Listen); err != nil {
		return err
	}

	// Validate reserved keywords before resolving defaults
	if err := validateNoReservedKeys(cfg); err != nil {
		return err
	}

	// Resolve defaults for each section
	cfg.SocketMaps = resolveDefaults(cfg.SocketMaps)
	cfg.PolicyServices = resolveDefaults(cfg.PolicyServices)
	cfg.DovecotSASL = resolveDefaults(cfg.DovecotSASL)

	if err := validateAuthSourceConflicts(cfg); err != nil {
		return err
	}

	if err := normalizeDovecotSASLGRPCMetadata(cfg.DovecotSASL); err != nil {
		return err
	}

	// Resolve http_auth_basic into Authorization headers for HTTP transports.
	resolveHTTPAuthBasic(cfg.SocketMaps)
	resolveHTTPAuthBasic(cfg.PolicyServices)
	resolveDovecotSASLHTTPBasicAuth(cfg.DovecotSASL)

	// Validate that all entries have a target after defaults merge
	if err := validateTargets(cfg.SocketMaps, "socket_maps"); err != nil {
		return err
	}

	if err := validateTargets(cfg.PolicyServices, "policy_services"); err != nil {
		return err
	}

	if err := validateDovecotSASLEndpoints(cfg.DovecotSASL); err != nil {
		return err
	}

	cfg.Server.Observability = normalizeObservabilityConfig(cfg.Server.Observability, version)
	if err := validateObservabilityConfig(cfg.Server.Observability); err != nil {
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

// ReloadConfig re-reads the configuration file and returns a new Config instance.
func ReloadConfig() (*Config, error) {
	cfg := &Config{}

	if err := viper.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("error re-reading config: %w", err)
	}

	if err := cfg.HandleConfig(); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return cfg, nil
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

// validateObservabilityConfig enforces cross-field constraints that struct tags cannot express.
func validateObservabilityConfig(cfg ObservabilityConfig) error {
	if cfg.PrometheusEnabled {
		if cfg.PrometheusAddress == "" {
			return errors.New("observability prometheus_address must not be empty when prometheus_enabled is true")
		}

		if cfg.PrometheusPort < 1 || cfg.PrometheusPort > 65535 {
			return errors.New("observability prometheus_port must be between 1 and 65535")
		}

		if !strings.HasPrefix(cfg.PrometheusPath, "/") {
			return errors.New("observability prometheus_path must start with '/'")
		}

		if cfg.PrometheusHTTPAuthBasic != "" {
			if _, _, err := splitBasicAuthCredentials(cfg.PrometheusHTTPAuthBasic); err != nil {
				return fmt.Errorf("observability prometheus_http_auth_basic %w", err)
			}
		}

		if cfg.PrometheusTLS.Enabled {
			if cfg.PrometheusTLS.Cert == "" || cfg.PrometheusTLS.Key == "" {
				return errors.New("observability prometheus_tls requires cert and key when enabled")
			}

			if _, err := resolveTLSMinVersion(cfg.PrometheusTLS.MinVersion); err != nil {
				return fmt.Errorf("observability prometheus_tls: %w", err)
			}
		}
	}

	if ratio := defaultedOTelSampleRatio(cfg); ratio < 0 || ratio > 1 {
		return errors.New("observability otel_sample_ratio must be between 0.0 and 1.0")
	}

	if !cfg.OTelEnabled {
		return nil
	}

	if !cfg.OTelTracesEnabled && !cfg.OTelMetricsEnabled {
		return errors.New("observability otel_enabled requires otel_traces_enabled or otel_metrics_enabled")
	}

	if cfg.OTLPEndpoint == "" {
		return errors.New("observability otel_exporter_otlp_endpoint is required when otel_enabled is true")
	}

	return nil
}
