# Pfxhttp – HTTP Proxy for Postfix

Pfxhttp is a lightweight HTTP proxy designed to integrate Postfix with external HTTP APIs for **socket maps** and **policy services**. This enables dynamic and flexible email workflows by connecting Postfix to modern APIs.

# Table of contents

<!-- TOC -->
* [Pfxhttp – HTTP Proxy for Postfix](#pfxhttp--http-proxy-for-postfix)
* [Table of contents](#table-of-contents)
  * [Overview](#overview)
  * [Getting Started](#getting-started)
    * [Installation](#installation)
      * [Prerequisites](#prerequisites)
    * [Running as a System Service](#running-as-a-system-service)
    * [Command-line Options](#command-line-options)
  * [Configuration](#configuration)
    * [HTTP Client User-Agent](#http-client-user-agent)
    * [Server Settings](#server-settings)
    * [Response Cache](#response-cache)
    * [Worker Pool](#worker-pool)
    * [OIDC Authentication](#oidc-authentication)
    * [HTTP Request/Response Compression](#http-requestresponse-compression)
    * [Integrating with Postfix](#integrating-with-postfix)
      * [Socket Maps](#socket-maps)
      * [Policy Services](#policy-services)
      * [Dovecot SASL](#dovecot-sasl)
  * [Logging and Troubleshooting](#logging-and-troubleshooting)
  * [Contributing](#contributing)
  * [References](#references)
    * [Advanced OIDC options](#advanced-oidc-options)
<!-- TOC -->


## Overview

Pfxhttp allows you to:

- **Perform dynamic lookups** via socket maps, such as resolving virtual mailboxes or domains.
- **Implement custom mail policy checks** through HTTP-based policy services.

The application is configured using a YAML file, specifying HTTP endpoints, the format of requests, and field mappings. It supports key Postfix features like query lookups and policy service hooks.

## Getting Started

### Installation

Pfxhttp is written in **Go**. It can be compiled with the following commands:

```bash
make
make install
```

#### Prerequisites

- Go 1.26 or later

### Running as a System Service

Pfxhttp is typically run as a **systemd** service. Below is an example unit file:

```ini
[Unit]
Description=PfxHTTP Postfix-to-HTTP server
After=network.target

[Service]
Type=simple
Restart=always
User=pfxhttp
Group=pfxhttp
EnvironmentFile=-/etc/default/pfxhttp
ExecStart=/usr/local/sbin/pfxhttp
StandardOutput=journal
StandardError=journal
SyslogIdentifier=pfxhttp
MemoryMax=50M
CPUQuota=10%

CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_CHOWN
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
NoNewPrivileges=true
ReadOnlyPaths=/etc
ProtectKernelModules=true
MemoryDenyWriteExecute=true
ProtectControlGroups=true
ProtectKernelLogs=true
ProtectClock=true
RestrictSUIDSGID=true
ProtectProc=invisible
LimitNOFILE=1024
#RestrictAddressFamilies=AF_INET AF_INET6

[Install]
WantedBy=multi-user.target
```

You must create a user pfxhttp and a group pfxhttp before using this unit file!

To install and start the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable pfxhttp
sudo systemctl start pfxhttp
```

### Command-line Options

Pfxhttp provides the following command-line flags:

- **--config**: Specifies the path to the configuration file. Overrides the default configuration file location.
  ```bash
  ./pfxhttp --config=/path/to/config.yml
  ```

- **--format**: Sets the logging format. Available options are `yaml`, `toml` or `json`.
  ```bash
  ./pfxhttp --format=json
  ```

> Use these flags as needed to customize the behavior of the application during runtime.

---

## Configuration

### HTTP Client User-Agent

All outbound HTTP requests use a default `User-Agent` header of `PostfixToHTTP/` followed by the build version (Git tag). If the `User-Agent` header is already set via custom headers in a request configuration, it will not be overridden.

Pfxhttp is configured through a YAML file named `pfxhttp.yml` (or a custom file specified with the `--config` and `--format` flags). The following are the main sections:

### Server Settings

The `server` section contains global options, including:

- **Listeners**: Define socket map and policy service listeners for Postfix integration.
- **Logging**: Enable JSON-formatted logs and set verbosity (`debug`, `info`, or `error`).
- **HTTP Client Options**: Configure connection limits, timeouts, and optional TLS settings.
- **OIDC Authentication**: Configure OIDC authentication (Client Credentials Flow) for HTTP requests with automatic token management.
- **Response Cache**: Optional in-memory cache to serve responses when the backend is unavailable.
- **Worker Pool**: Controlled performance by limiting the number of concurrent connections and providing back-pressure via a job queue.

Below is a detailed example configuration for `pfxhttp.yml`:

```yaml
server:
  listen:
    - kind: "socket_map"
      name: "demo_map"
      type: "tcp"
      address: "[::]"
      port: 23450

    - kind: "policy_service"
      name: "example_policy"
      type: "tcp"
      address: "[::]"
      port: 23451

    - kind: "dovecot_sasl"
      name: "dovecot_sasl"
      type: "tcp"
      address: "0.0.0.0"
      port: 23453

  logging:
    json: true
    level: info

  tls:
    enabled: true
    skip_verify: true
    root_ca: "/etc/ssl/certs/ca-certificates.crt"

  http_client:
    timeout: 30s
    max_connections_per_host: 100
    max_idle_connections: 20
    max_idle_connections_per_host: 20
    idle_connection_timeout: 90s
    proxy: "http://proxy.example.com:8080"

  # Optional response cache to serve data during backend outages
  response_cache:
    enabled: true
    ttl: 5m  # cache lifetime per entry

socket_maps:
  demo_map:
    target: "https://127.0.0.1:9443/api/v1/custom/map"
    custom_headers:
      - "Authorization: Bearer <token>"
    payload: >
      {
        "key": "{{ .Key }}"
      }
    status_code: 200
    value_field: "data.result"
    error_field: "error"
    no_error_value: "not-found"

  oidc_demo_map:
    target: "https://127.0.0.1:9443/api/v1/custom/map"
    backend_oidc_auth:
      enabled: true
      configuration_uri: "https://example.com/.well-known/openid-configuration"
      client_id: "foobar"
      client_secret: "secret"
    payload: >
      {
        "key": "{{ .Key }}"
      }
    status_code: 200
    value_field: "data.result"
    error_field: "error"
    no_error_value: "not-found"

policy_services:
  example_policy:
    target: "https://127.0.0.1:9443/api/v1/custom/policy"
    custom_headers:
      - "Authorization: Bearer <token>"
    payload: "{{ .Key }}"
    status_code: 200
    value_field: "policy.result"
    error_field: "policy.error"
    no_error_value: "OK"

  oidc_example_policy:
    target: "https://127.0.0.1:9443/api/v1/custom/policy"
    backend_oidc_auth:
      enabled: true
      configuration_uri: "https://example.com/.well-known/openid-configuration"
      client_id: "foobar"
      client_secret: "secret"
    payload: "{{ .Key }}"
    status_code: 200
    value_field: "policy.result"
    error_field: "policy.error"
    no_error_value: "OK"

dovecot_sasl:
  dovecot_sasl:
    target: https://127.0.0.1:9443/api/v1/auth/json
    # Bearer to backend (Nauthilus) via Client-Credentials-Flow (optional)
    backend_oidc_auth:
      enabled: true
      configuration_uri: https://127.0.0.1:9443/.well-known/openid-configuration
      client_id: pfxhttp
      client_secret: backend-secret
    # Validation of incoming XOAUTH2/OAUTHBEARER tokens
    sasl_oidc_auth:
      enabled: true
      configuration_uri: https://127.0.0.1:9443/.well-known/openid-configuration
      client_id: roundcube
      client_secret: introspection-secret
      scopes:
        - "introspect"
      validation: introspection
    # Note: For dovecot_sasl, the payload is generated internally according to Nauthilus
    # /api/v1/auth/json; a payload entry has no effect here.
    status_code: 200
    # Username is returned via HTTP response header "Auth-User" by the backend.
    # Errors are signaled via HTTP status and the "Auth-Status" header.

```

**Important**: Postfix has a hardcoded socket map reply size limit of **100,000 bytes** (Postfix 3.9.1 or older).

### Response Cache

Pfxhttp includes an optional in-memory response cache. It always forwards responses from your backend, but if the backend becomes unavailable, it can serve a previously cached response for a configurable time (TTL).

Behavior:
- On backend failure: if a valid cache entry exists for the same map/policy name and key, it is returned.
- Cache population:
  - Socket maps: cache only definitive successes (status "OK").
  - Policy services: cache only definitive actions (anything other than empty).
- Expiration: entries expire after the TTL.

Configuration (server section):
```yaml
server:
  response_cache:
    enabled: true
    ttl: 5m
```

Notes:
- TTL must be between 1s and 168h (7 days).
- Cache is in-memory and per-process; it is cleared on restart.
- Keys are derived from the tuple (name, key). For policy services, the key is the JSON of the policy payload.

### Worker Pool

Pfxhttp uses a worker pool to manage concurrent connections efficiently. This prevents the server from spawning an unlimited number of goroutines, which could lead to resource exhaustion under high load. You can configure a global worker pool for all listeners or a dedicated pool per listener.

Configuration (server section for global pool):
```yaml
server:
  worker_pool:
    max_workers: 10   # Number of concurrent workers
    max_queue: 100    # Maximum number of connections waiting in the queue
```

Configuration (listen section for per-listener pool):
```yaml
server:
  listen:
    - kind: "socket_map"
      name: "demo_map"
      type: "tcp"
      address: "[::]"
      port: 23450
      worker_pool:
        max_workers: 5
        max_queue: 20
```

Behavior:
- **Max Workers**: Defines how many connections are processed simultaneously.
- **Max Queue**: Defines how many connections can be queued before the server starts applying back-pressure (blocking the `accept` call).
- **Back-Pressure**: When the queue is full, the server will wait until a worker becomes available before accepting more connections. This naturally slows down the sender (Postfix).
- **Precedence**: A worker pool defined in the `listen` section takes precedence over the global `worker_pool` in the `server` section.
- **Defaults**: If no `worker_pool` is configured in the `server` section, Pfxhttp automatically initializes a global worker pool with `max_workers` set to `2 * GOMAXPROCS` and `max_queue` set to `10 * max_workers`.

### OIDC Authentication

Pfxhttp supports OIDC Client Credentials Flow for HTTP requests to the target endpoints. This allows you to securely authenticate with APIs that require OIDC tokens.

The OIDC authentication feature includes:

- Automatic discovery of OIDC endpoints via the OpenID configuration URI
- Automatic token fetching using the `client_credentials` grant type
- Support for `client_secret` (Basic Authentication)
- Support for `private_key_jwt` (RSA, ECDSA, or Ed25519)
- Automatic token caching and refresh before expiration

To configure OIDC authentication for a socket map or policy service:

```yaml
socket_maps:
  example:
    target: "https://api.example.com/endpoint"
    backend_oidc_auth:
      enabled: true
      configuration_uri: "https://auth.example.com/.well-known/openid-configuration"
      client_id: "your-client-id"
      # Use either client_secret:
      client_secret: "your-client-secret"
      # OR private_key_file for private_key_jwt:
      # private_key_file: "/path/to/private-key.pem"
      # Optional: list of scopes
      scopes:
        - "api.read"
        - "api.write"
```

The OIDC access token will be automatically fetched and included in the `Authorization` header as a `Bearer` token for all requests to the target endpoint.

---

### HTTP Request/Response Compression

Pfxhttp allows you to control HTTP compression per target (socket map or policy service). This is useful when your backend supports gzip and you want to reduce bandwidth or comply with specific API requirements. Nauthilus backends support gzip exclusively.

- http_request_compression: When true, Pfxhttp gzips the request body and sets Content-Encoding: gzip. Disabled by default.
- http_response_compression: When true, Pfxhttp advertises Accept-Encoding: gzip and will transparently decompress gzip responses if the server replies with Content-Encoding: gzip. Disabled by default.

Notes:
- Compression settings are defined per target, not globally.
- The HTTP client's automatic gzip handling is disabled to ensure per-target control.
- Only gzip is supported currently.

Example:

socket_maps:
  demo:
    target: https://127.0.0.1:9443/api/v1/custom/postfix/socket_map
    http_request_compression: true
    http_response_compression: true
    payload: >
      {
        "key": "{{ .Key }}"
      }
    status_code: 200
    value_field: "demo_value"

policy_services:
  policy:
    target: https://127.0.0.1:9443/api/v1/custom/postfix/policy_service
    http_request_compression: false
    http_response_compression: true
    payload: "{{ .Key }}"
    status_code: 200
    value_field: "result"

### Integrating with Postfix

#### Socket Maps

To configure Postfix to use a socket map, simply add it to your `main.cf`:

```plaintext
# main.cf
virtual_mailbox_domains = socketmap:tcp:127.0.0.1:23450:demo_map
```

Here, Postfix connects to the TCP socket map listener defined in `pfxhttp.yml` for `demo_map`.

#### Policy Services

To use a policy service, include it in your recipient restrictions list in `main.cf`:

```plaintext
# main.cf
smtpd_recipient_restrictions =
    permit_mynetworks,
    reject_unauth_destination,
    check_policy_service inet:127.0.0.1:23451
```

This setup enables Postfix to query the policy service defined in `pfxhttp.yml` for `example_policy`.

#### Dovecot SASL

Pfxhttp can act as a Dovecot-compatible SASL server for Postfix. When Postfix does not provide a `local_port`, administrators may configure a fallback in the corresponding `dovecot_sasl` target via `default_local_port`.

Example configuration:

```yaml
dovecot_sasl:
  login_smtp:
    target: "https://nauthilus.example.org/api/v1/sasl/auth"
    # Optional fallback when Postfix does not provide the local port
    default_local_port: "587"
    # Optional: enable OIDC-based token validation for XOAUTH2/OAUTHBEARER
    sasl_oidc_auth:
      enabled: true
      configuration_uri: "https://auth.example.org/.well-known/openid-configuration"
```

Behavior:
- If Dovecot provides `local_port`, it is forwarded.
- Else, if `default_local_port` is set, it is sent as `local_port` to the backend.
- Applies to both password-based and OAuth-based SASL flows.

---

## Logging and Troubleshooting

Logs are output to the console by default and should be captured by the service manager (e.g., **systemd**). Log verbosity is configurable in the `pfxhttp.yml` file.

If Pfxhttp fails to start, verify the following:

- Ensure the configuration file (`/etc/pfxhttp/pfxhttp.yml`) is valid and complete.
- Ensure the service is running with the appropriate permissions for the configured resources.

---

## Contributing

Contributions are welcome! Feel free to submit pull requests or issues to improve the project. The project is distributed under the **MIT License**.

---

## References

- [Postfix Documentation](http://www.postfix.org/)
- [Nauthilus](https://github.com/croessner/nauthilus)
- Manpages:
 - `pfxhttp(8)`: Overview and service management
 - `pfxhttp.yml(5)`: Detailed configuration guide


### Advanced OIDC options

The following optional fields fine-tune OIDC behavior. Defaults are chosen for maximum interoperability and security.

- `auth_method`: How the client authenticates to the token and introspection endpoints. Values:
  - `auto` (defaulting is resolved during config load)
  - `client_secret_basic` (default)
  - `client_secret_post`
  - `private_key_jwt`
  - `none`

  If `auth_method` is omitted or set to `auto`, the following preference is applied:
  - Use `private_key_jwt` when `private_key_file` is set
  - Else use `client_secret_basic` when `client_secret` is set
  - Else fall back to `none` (send only `client_id`)

- `sasl_oidc_auth.scopes`: Optional list of scopes to send as a space-separated `scope` parameter to the introspection endpoint. Only needed if your provider requires it for introspection access.

- `sasl_oidc_auth.validation`: How SASL OAuth tokens are validated.
  - `introspection` (default): Always call the provider’s introspection endpoint (RFC 7662). Supports opaque tokens and immediate revocation checks.
  - `jwks`: Validate tokens locally using the provider’s `jwks_uri`. Lowest latency for JWTs, but revocations may take effect only after key/claim changes.
  - `auto`: Try JWKS first for JWTs; fall back to introspection for opaque tokens or transient JWKS issues.

- `sasl_oidc_auth.jwks_cache_ttl`: Duration for caching the JWKS document. Default: `5m`.

Example with advanced settings:

```yaml
socket_maps:
  example:
    target: "https://api.example.com/endpoint"
    backend_oidc_auth:
      enabled: true
      configuration_uri: "https://auth.example.com/.well-known/openid-configuration"
      client_id: "your-client-id"
      client_secret: "your-client-secret"
      # Use POST body instead of Basic Auth:
      auth_method: client_secret_post
    # SASL token validation strategy (for dovecot_sasl only):
    sasl_oidc_auth:
      enabled: true
      configuration_uri: "https://auth.example.com/.well-known/openid-configuration"
      client_id: "roundcube"
      client_secret: "introspection-secret"
      validation: auto  # or: introspection | jwks
      jwks_cache_ttl: 5m
```

Notes:
- HTTP requests to the token and introspection endpoints now include `Accept: application/json`.
- Request bodies are built once and never rewritten after `http.NewRequest`, ensuring correct `Content-Length` handling.
- For target requests with `backend_oidc_auth`, any pre-existing `Authorization` header (e.g., set via `custom_headers`) is explicitly removed and replaced with `Authorization: Bearer <token>`.
- For introspection requests with `sasl_oidc_auth`, any `Authorization` header is explicitly cleared before applying the selected client authentication (`client_secret_basic` or `client_secret_post`).
- JWKS-based validation supports RSA, EC (P-256/384/521), and Ed25519 keys from the provider’s `jwks_uri`.
