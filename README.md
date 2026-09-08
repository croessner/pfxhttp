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
      * [Optional systemd socket activation](#optional-systemd-socket-activation)
    * [Command-line Options](#command-line-options)
  * [Configuration](#configuration)
    * [HTTP Client User-Agent](#http-client-user-agent)
    * [Server Settings](#server-settings)
    * [Section Defaults](#section-defaults)
    * [HTTP Basic Authentication](#http-basic-authentication)
    * [Response Cache](#response-cache)
    * [Connection, Request and Protocol Limits](#connection-request-and-protocol-limits)
    * [Observability](#observability)
    * [Privilege Dropping & Chroot](#privilege-dropping--chroot)
      * [Privilege Dropping](#privilege-dropping)
      * [Chroot](#chroot)
        * [Limitations and prerequisites](#limitations-and-prerequisites)
    * [OIDC Authentication](#oidc-authentication)
    * [HTTP Request/Response Compression](#http-requestresponse-compression)
    * [Integrating with Postfix](#integrating-with-postfix)
      * [Socket Maps](#socket-maps)
      * [Policy Services](#policy-services)
      * [Dovecot SASL](#dovecot-sasl)
        * [gRPC Transport (alternative to JSON)](#grpc-transport-alternative-to-json)
  * [Logging and Troubleshooting](#logging-and-troubleshooting)
    * [Session Tracking](#session-tracking)
    * [Systemd Integration](#systemd-integration)
  * [Contributing](#contributing)
  * [References](#references)
    * [Advanced OIDC options](#advanced-oidc-options)
<!-- TOC -->


## Overview

Pfxhttp allows you to:

- **Perform dynamic lookups** via socket maps, such as resolving virtual mailboxes or domains.
- **Implement custom mail policy checks** through HTTP-based policy services.
- **Export optional observability** through Prometheus metrics and OpenTelemetry OTLP HTTP traces/metrics.

The application is configured using a YAML file, specifying HTTP endpoints, the format of requests, and field mappings. It supports key Postfix features like query lookups and policy service hooks.

## Getting Started

### Installation

Pfxhttp is written in **Go**. It can be compiled with the following commands:

```bash
make
make install
```

Release builds also publish Linux `.deb` and `.rpm` packages. The packages use
distribution-owned paths and include:

- `/usr/sbin/pfxhttp`
- `/etc/pfxhttp/pfxhttp.yml`
- `/etc/pfxhttp/pfxhttp.env`
- `/usr/lib/systemd/system/pfxhttp.service`
- `/usr/lib/systemd/system/pfxhttp-policy.socket`
- `/usr/lib/systemd/system/pfxhttp@.socket`
- `/usr/share/man/man5/pfxhttp.yml.5.gz`
- `/usr/share/man/man8/pfxhttp.8.gz`
- `/usr/share/doc/pfxhttp/README.md`
- `/usr/share/doc/pfxhttp/LICENSE`
- `/usr/share/doc/pfxhttp/pfxhttp.yml.demo`

Package installation creates the `pfxhttp` system user and group when missing,
reloads the systemd manager, and leaves service enablement to the operator. The
packaged service reads optional overrides from `/etc/pfxhttp/pfxhttp.env`. The
packaged default configuration matches `pfxhttp-policy.socket`: it consumes the
systemd descriptor named `policy` for
`/var/spool/postfix/private/pfxhttp-policy`, avoids demo credentials, and stores
`/etc/pfxhttp/pfxhttp.yml` as a conffile with `root:pfxhttp` ownership and
`0640` permissions so SIGHUP reloads remain readable after privilege drop. To
run `pfxhttp.service` without socket activation, edit the listener to remove
`systemd_socket_name` and configure a native TCP or Unix endpoint first.

#### Prerequisites

- Go 1.26.8 for development, CI, and release builds (module language baseline: Go 1.26).

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
EnvironmentFile=-/etc/pfxhttp/pfxhttp.env
ExecStart=/usr/local/sbin/pfxhttp
StandardOutput=journal
StandardError=journal
SyslogIdentifier=pfxhttp
MemoryMax=50M
CPUQuota=10%

CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_CHOWN CAP_SYS_CHROOT
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

#### Optional systemd socket activation

Pfxhttp can also consume sockets created by systemd. This mode is optional and
per listener: if `systemd_socket_name` is omitted, the listener uses the native
`net.Listen` path exactly as before. If `systemd_socket_name` is set, pfxhttp
expects systemd to provide a matching `FileDescriptorName` via `LISTEN_FDS`.

Use `Accept=no` in the `.socket` unit. Systemd owns the listen socket, but
pfxhttp still accepts connections itself and continues to use the configured
worker pools.

Example socket unit for one Postfix policy-service socket:

```ini
[Unit]
Description=PfxHTTP policy service socket

[Socket]
ListenStream=/var/spool/postfix/private/pfxhttp-policy
FileDescriptorName=policy
Accept=no
SocketMode=0660
SocketUser=postfix
SocketGroup=postfix
Service=pfxhttp.service

[Install]
WantedBy=sockets.target
```

For several listeners that follow the same naming scheme, the repository also
ships a template unit as `contrib/systemd/pfxhttp@.socket`. The instance name is
used both as the systemd `FileDescriptorName` and as the socket path suffix:

```ini
[Socket]
ListenStream=/var/spool/postfix/private/pfxhttp-%i
FileDescriptorName=%i
Accept=no
Service=pfxhttp.service
```

For example, enabling `pfxhttp@policy.socket` creates
`/var/spool/postfix/private/pfxhttp-policy` and passes it to `pfxhttp.service`
as `FileDescriptorName=policy`. Multiple template instances can point to the
same `pfxhttp.service`; systemd passes all sockets for that service to the
process when it starts. Use explicit `.socket` units instead if a listener needs
a path or descriptor name that does not fit the template. Enable either the
template instance or a concrete `.socket` unit for a listener, not both.
The packaged default configuration matches the concrete
`pfxhttp-policy.socket` unit.

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now pfxhttp-policy.socket
sudo systemctl restart pfxhttp.service
```

Matching listener configuration:

```yaml
server:
  listen:
    - kind: "policy_service"
      name: "policy"
      type: "unix"
      address: "/var/spool/postfix/private/pfxhttp-policy"
      systemd_socket_name: "policy"
```

For backend-only configuration changes, `SIGHUP` reloads continue to work. If a
reload would add, remove, or change a systemd-activated listener, pfxhttp keeps
the current configuration and logs that a service restart is required. With the
`.socket` unit active, `systemctl restart pfxhttp.service` keeps the listen
socket available while the process is replaced.

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
- **Privilege Dropping**: Run as a specific user/group after binding listeners (`run_as_user`, `run_as_group`).
- **Chroot**: Optionally isolate the process in a chroot jail (`chroot`).
- **Logging**: Enable JSON-formatted logs and set verbosity (`debug`, `info`, or `error`).
- **HTTP Client Options**: Configure connection limits, timeouts, and optional TLS settings.
- **OIDC Authentication**: Configure OIDC authentication (Client Credentials Flow) for HTTP requests with automatic token management.
- **Response Cache**: Optional in-memory cache to serve responses when the backend is unavailable.
- **Listener-owned limits**: Bound admitted connections, backend work, queueing, framing memory and protocol deadlines independently for every listener.
- **Systemd Socket Activation**: Optionally bind a listener to a named systemd `FileDescriptorName` via `systemd_socket_name`.
- **Observability**: Optional Prometheus endpoint and OpenTelemetry OTLP HTTP export for listener, request, HTTP backend, gRPC backend, and OIDC activity.

Below is a detailed example configuration for `pfxhttp.yml`:

```yaml
server:
  run_as_user: "pfxhttp"
  run_as_group: "pfxhttp"
  # chroot: "/var/lib/pfxhttp"

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
      # systemd_socket_name: "example_policy"

    - kind: "dovecot_sasl"
      name: "dovecot_sasl"
      type: "tcp"
      address: "127.0.0.1"
      port: 23453

  logging:
    json: true
    level: info
    use_systemd: false

  tls:
    enabled: true
    skip_verify: false
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

  observability:
    prometheus_enabled: false
    prometheus_address: "127.0.0.1"
    prometheus_port: 9464
    prometheus_path: "/metrics"
    prometheus_runtime_metrics: false
    # prometheus_http_auth_basic: "<username>:<password>"
    prometheus_tls:
      enabled: false
      # cert: "/etc/pfxhttp/metrics.crt"
      # key: "/etc/pfxhttp/metrics.key"
      min_tls_version: "1.2"
    otel_enabled: false
    otel_traces_enabled: false
    otel_metrics_enabled: false
    otel_service_name: "pfxhttp"
    # otel_service_version defaults to the binary version.
    # otel_exporter_otlp_endpoint: "http://127.0.0.1:4318"
    # otel_exporter_otlp_headers:
    #   authorization: "Bearer token"
    otel_exporter_otlp_insecure: false
    otel_sample_ratio: 1.0

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
      client_secret: "<set-in-deployment>"
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
      client_secret: "<set-in-deployment>"
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
      client_secret: "<set-in-deployment>"
    # Validation of incoming XOAUTH2/OAUTHBEARER tokens
    sasl_oidc_auth:
      enabled: true
      configuration_uri: https://127.0.0.1:9443/.well-known/openid-configuration
      client_id: roundcube
      client_secret: "<set-in-deployment>"
      # OR private_key_file for private_key_jwt:
      # private_key_file: /etc/pfxhttp/introspection-client.pem
      # auth_method: private_key_jwt
      scopes:
        - "introspect"
      validation: introspection
    mechanisms:
      - PLAIN
      - XOAUTH2
      - OAUTHBEARER
    # Note: For dovecot_sasl, the payload is generated internally according to Nauthilus
    # /api/v1/auth/json; a payload entry has no effect here.
    status_code: 200
    # Username is returned via HTTP response header "Auth-User" by the backend.
    # Errors are signaled via HTTP status and the "Auth-Status" header.

```

**Important**: Postfix has a hardcoded socket map reply size limit of **100,000 bytes** (Postfix 3.9.1 or older).

### Section Defaults

Each section (`socket_maps`, `policy_services`, `dovecot_sasl`) supports an optional `defaults` block. Values defined in `defaults` are automatically inherited by all entries in that section. Explicit values in an entry override the inherited defaults.

- **Additive merge for `custom_headers`**: Headers from `defaults` are prepended to entry-specific headers (not replaced). `custom_headers` are HTTP-only and are rejected for `transport: grpc` entries.
- **Keyed merge for `grpc.metadata`**: Metadata from `defaults` is inherited by gRPC entries; entry-specific keys override default keys.
- The `defaults` key is **reserved** and cannot be used as a listener name.
- `defaults` is optional — existing configurations without it continue to work unchanged.

Example with defaults:
```yaml
socket_maps:
  defaults:
    target: "https://api.example.com/postfix/map"
    http_auth_basic: "<username>:<password>"
    http_response_compression: true
    payload: >
      {
        "key": "{{ .Key }}"
      }
    status_code: 200
    value_field: "result"
    error_field: "error"

  relay_domains:
    custom_headers:
      - "X-Pfx-Name: relay_domains"

  relay_recipient_maps:
    custom_headers:
      - "X-Pfx-Name: relay_recipient_maps"

  transport_maps:
    custom_headers:
      - "X-Pfx-Name: transport_maps"
```

Each entry inherits `target`, `http_auth_basic`, `payload`, `status_code`, etc. from `defaults` and only needs to specify what differs.

### HTTP Basic Authentication

Instead of manually adding an `Authorization: Basic ...` header, you can use the `http_auth_basic` field:

```yaml
http_auth_basic: "<username>:<password>"
```

The value is automatically Base64-encoded and set as an `Authorization: Basic <base64>` header for HTTP transports. For `dovecot_sasl` gRPC entries, the same value is sent as `authorization: Basic <base64>` gRPC metadata. This field can be used both in `defaults` and in individual entries.

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

### Connection, Request and Protocol Limits

Connections and backend requests are deliberately separate resources. Every listener owns its own connection supervisor and request limiter, even when it inherits server defaults. Long-lived Postfix policy or SASL connections therefore cannot consume another listener's backend request capacity.

```yaml
server:
  limits:
    max_connections: 1024
    max_inflight_requests: 32
    max_queued_requests: 320
    request_queue_timeout: 2s
    request_timeout: 4s
    backend_timeout: 1s
    response_write_reserve: 500ms
  protocol_limits:
    socket_map:
      idle_timeout: 15s
      partial_request_timeout: 10s
      write_timeout: 10s
      max_request_bytes: 1048576
      max_length_digits: 10
    policy_service:
      idle_timeout: 0s
      partial_request_timeout: 10s
      write_timeout: 10s
      max_request_bytes: 1048576
      max_line_bytes: 65536
      max_attributes: 256
    dovecot_sasl:
      idle_timeout: 0s
      partial_request_timeout: 30s
      write_timeout: 10s
      max_line_bytes: 16384
  listen:
    - kind: socket_map
      name: demo
      type: tcp
      address: 127.0.0.1
      port: 23450
      limits:
        max_connections: 256
        max_inflight_requests: 16
        max_queued_requests: 0
```

Missing listener values inherit the corresponding normalized server value. Missing server values use the defaults above, except `max_inflight_requests`, which defaults to `2 * GOMAXPROCS` (at least one), and `max_queued_requests`, which defaults to ten times that value. A configured `max_queued_requests: 0` disables queueing; it does not mean unlimited. For each protocol, an omitted `idle_timeout` inherits, while an explicit `0s` disables the server-side idle close. All other numeric or duration zero values mean “not set” and are replaced by defaults; there is no unlimited connection, in-flight, frame-size or write-timeout value.

Connection, in-flight, queued-request and attribute counts are capped at 1,048,576. Queue, request, backend, idle, partial-frame and write timeouts are capped at one hour; `response_write_reserve` is capped at one minute. SocketMap and policy requests are capped at 67,108,864 bytes, SocketMap length prefixes at 10 digits, policy lines at 16,777,216 bytes, and Dovecot SASL lines at 1,048,576 bytes. Positive timeouts have a one-millisecond minimum except `request_timeout`, whose minimum is one second. Cross-field budget validation may make an individual field's maximum unusable with another maximum, such as a one-hour backend budget inside a one-hour total request budget.

`max_connections` bounds admitted client connections. `max_inflight_requests` bounds requests currently using backend/cache execution. `max_queued_requests` bounds complete, decoded requests waiting for an execution permit. Queue saturation never permits mail silently: SocketMap returns a valid `TEMP` reply, policy service returns `action=defer_if_permit ...`, and Dovecot SASL returns a temporary authentication failure where protocol state permits it or closes the connection.

The request deadline is one total budget shared by queueing, every HTTP or gRPC backend attempt/retry, and the response reserve. Configuration is rejected unless:

```text
request_timeout > request_queue_timeout + backend_timeout + response_write_reserve
```

The queue term is zero when queueing is disabled. The backend context is capped by both `backend_timeout` and the remaining request deadline before `response_write_reserve`; retries do not receive a fresh full budget. `server.http_client.timeout` and per-entry `grpc.timeout` are additional upper bounds, not budgets that extend the surrounding request.

Inventory the effective caller settings before choosing values. Postfix SocketMap normally has 100-second connect/send/receive/active limits and closes an idle connection after about 10 seconds. Policy clients intentionally reuse connections; upstream defaults include 300 seconds idle, 1000 seconds TTL, 100 seconds per operation, two attempts, and a one-second retry delay, with endpoint-specific overrides available. A deployment using a five-second policy timeout must keep framing remainder plus the complete Pfxhttp request budget below those five seconds; increasing the Postfix timeout alone does not repair an oversized backend budget. See the official [SocketMap table](https://www.postfix.org/socketmap_table.5.html), [policy delegation guide](https://www.postfix.org/SMTPD_POLICY_README.html), [postconf reference](https://www.postfix.org/postconf.5.html), and [postmap reference](https://www.postfix.org/postmap.1.html).

Size `max_connections` from the relevant Postfix process limits, persistent Dovecot SASL connections, planned restart overlap and burst headroom. Size `max_inflight_requests` from measured backend capacity, then choose a small bounded queue that can drain inside `request_queue_timeout`. Unix-domain Dovecot SASL sockets are preferred; TCP carries the auth protocol without transport encryption and must be confined to a trusted private path as described in the official [Postfix SASL guide](https://www.postfix.org/SASL_README.html).

The legacy `worker_pool` block is deprecated. When it is present, Pfxhttp logs a startup warning and maps `max_workers` conservatively to request concurrency, `max_queue` to request queue depth, and their sum to connection admission only for new fields that were not explicitly configured. This compatibility mapping does not preserve the old connection-as-worker execution model. Migrate by recording the effective warning values, adding explicit `limits` values per listener, validating normal Postfix reuse, and then removing `worker_pool`.

SIGHUP validates the complete new file before applying backend mappings, HTTP/TLS/cache/logging settings and native-listener changes. Changing a native listener's limit or relevant protocol block restarts only that listener. Native listener replacement is not rollback-atomic: if rebinding the changed endpoint fails after validation, that listener remains unavailable and the operator must correct the configuration and reload or restart. Adding, removing or changing a systemd-activated listener requires a service restart while its `.socket` unit remains active. Changes to `run_as_user`, `run_as_group`, `chroot` or observability endpoint lifecycle are restart-only; a reload containing any such change is rejected before runtime changes and the current configuration remains active.

### Observability

Observability is disabled by default. When enabled, Pfxhttp records bounded listener connection and drain outcomes, idle versus partial framing state, request admission and queue state, complete protocol-level requests, outgoing HTTP backend requests, outgoing gRPC `Authenticate` calls, and OIDC discovery/token/JWKS/introspection traffic. Request contexts are delegated through these paths so outbound HTTP headers and gRPC metadata receive the active W3C trace context.

Application spans start only after a complete protocol frame has been read. Idle connections and incomplete frames therefore do not create request spans. Socket-map and policy-service requests expose decode, request-queue, backend, response-encode, and response-write child spans in execution order. Dovecot SASL requests expose request-queue, mechanism-step, backend-auth, response-write, and continuation-wait spans so multi-step SASL exchanges show the time spent waiting for the next continuation without overlapping backend work. Raw requests, credentials, continuation IDs, backend payloads, and backend denial reasons are not recorded in spans or logs.

gRPC-backed SASL traces also split the pre-call preparation into `gRPC connection`, `gRPC metadata`, and `gRPC request build` spans. When OIDC caller authentication is enabled, token cache lookups, cache-lock waits, discovery, token fetches, client assertions, and JWKS validation are traced as child spans without recording secrets or token values.

Application request metrics keep the request-side name in the `name` label and add the configured listener name in the `listener` label. This lets dashboards show ingress latency per listener while still preserving map/backend-specific views for the outbound side.

The Prometheus and OpenTelemetry metric sets include `pfxhttp_listener_connection_state` (`idle` and `partial`), `pfxhttp_listener_drains`, `pfxhttp_listener_request_state` (`inflight` and `queued`), `pfxhttp_listener_request_admissions`, `pfxhttp_listener_request_queue_wait`, and `pfxhttp_listener_protocol_failures`. Their labels use configured listener or backend names and bounded outcome values; unknown client-supplied SocketMap names collapse to `unknown`. These process metrics explain capacity and framing behavior, but they are not a substitute for an end-to-end Postfix or Dovecot protocol probe when deciding service health.

Prometheus uses a dedicated HTTP endpoint:

```yaml
server:
  observability:
    prometheus_enabled: true
    prometheus_address: "127.0.0.1"
    prometheus_port: 9464
    prometheus_path: "/metrics"
    prometheus_runtime_metrics: false
    prometheus_http_auth_basic: "<username>:<password>"
    prometheus_tls:
      enabled: true
      cert: "/etc/pfxhttp/metrics.crt"
      key: "/etc/pfxhttp/metrics.key"
      min_tls_version: "1.2"
```

`prometheus_http_auth_basic` protects the scrape endpoint with incoming HTTP Basic auth and must use `user:password` form. `prometheus_tls` enables HTTPS for the dedicated Prometheus endpoint; it requires a certificate and key when enabled and accepts `min_tls_version` values `1.2` or `1.3`. These settings apply only to the metrics HTTP server. The top-level `server.tls` section remains the outbound backend HTTP client TLS configuration.

Scrape example:

```bash
curl --cacert /etc/pfxhttp/metrics.crt -u "$PFXHTTP_METRICS_BASIC_AUTH" https://127.0.0.1:9464/metrics
```

OpenTelemetry uses OTLP over HTTP. `otel_enabled` is the master switch; traces and metrics remain separate opt-in controls:

```yaml
server:
  observability:
    otel_enabled: true
    otel_traces_enabled: true
    otel_metrics_enabled: true
    otel_service_name: "pfxhttp"
    otel_exporter_otlp_endpoint: "http://127.0.0.1:4318"
    otel_exporter_otlp_insecure: true
    otel_sample_ratio: 1.0
```

Configuration keys:

| Key                           | Default       | Description                                                  |
|-------------------------------|---------------|--------------------------------------------------------------|
| `prometheus_enabled`          | `false`       | Starts the Prometheus HTTP endpoint.                         |
| `prometheus_address`          | `127.0.0.1`   | Bind address for the metrics endpoint.                       |
| `prometheus_port`             | `9464`        | Bind port for the metrics endpoint.                          |
| `prometheus_path`             | `/metrics`    | HTTP path for Prometheus scraping.                           |
| `prometheus_runtime_metrics`  | `false`       | Adds Go runtime and process collectors.                      |
| `prometheus_http_auth_basic`  | empty         | Protects the scrape endpoint with Basic auth `user:password`. |
| `prometheus_tls.enabled`      | `false`       | Serves the Prometheus endpoint over HTTPS.                   |
| `prometheus_tls.cert`         | empty         | PEM certificate file for the HTTPS scrape endpoint.          |
| `prometheus_tls.key`          | empty         | PEM private key file for the HTTPS scrape endpoint.          |
| `prometheus_tls.min_tls_version` | `1.2`      | Lowest accepted TLS version: `1.2` or `1.3`.                 |
| `otel_enabled`                | `false`       | Enables OpenTelemetry export.                                |
| `otel_traces_enabled`         | `false`       | Exports traces when OTel is enabled.                         |
| `otel_metrics_enabled`        | `false`       | Exports OTel metrics when OTel is enabled.                   |
| `otel_service_name`           | `pfxhttp`     | Sets the `service.name` resource attribute.                  |
| `otel_service_version`        | build version | Sets the `service.version` resource attribute.               |
| `otel_exporter_otlp_endpoint` | empty         | OTLP HTTP collector endpoint; required when OTel is enabled. |
| `otel_exporter_otlp_headers`  | empty         | Map of headers for the OTLP HTTP exporter.                   |
| `otel_exporter_otlp_insecure` | `false`       | Uses insecure transport for OTLP HTTP.                       |
| `otel_sample_ratio`           | `1.0`         | Parent-based trace sampling ratio from `0.0` to `1.0`.       |

If `otel_enabled` is true, at least one of `otel_traces_enabled` or `otel_metrics_enabled` must also be true, and `otel_exporter_otlp_endpoint` must be set. Observability is initialized at process startup; change Prometheus bind settings or OTLP exporter settings with a service restart, not SIGHUP reload.

### Privilege Dropping & Chroot

Pfxhttp can drop root privileges after startup and optionally run inside a chroot jail for additional isolation.

#### Privilege Dropping

When started as root, Pfxhttp can drop to a non-root user and group after binding all listeners:

```yaml
server:
  run_as_user: "pfxhttp"
  run_as_group: "pfxhttp"
```

The user and group must exist on the system. Supplementary groups are cleared before switching.

#### Chroot

Pfxhttp supports an optional `chroot` setting that changes the process root directory after binding listeners but before dropping privileges:

```yaml
server:
  run_as_user: "pfxhttp"
  run_as_group: "pfxhttp"
  chroot: "/var/lib/pfxhttp"
```

The startup order is:

1. **Resolve credentials** — look up user/group in `/etc/passwd` and `/etc/group`
2. **Bind listeners** — bind to privileged ports or Unix sockets
3. **Chroot** — change root directory
4. **Drop privileges** — switch to the resolved UID/GID

##### Limitations and prerequisites

Running inside a chroot jail imposes several constraints that must be understood before enabling this feature:

**Configuration file**
The configuration file (`pfxhttp.yml`) is read **before** the chroot takes effect. The path given via `--config` (or the default search paths) must refer to the real filesystem, not to a path inside the chroot. After chroot, the configuration file does not need to be present inside the jail. However, a SIGHUP reload will re-read the configuration file — since the process is now inside the chroot, the file must also be accessible at its configured path relative to the new root (e.g., `/var/lib/pfxhttp/etc/pfxhttp/pfxhttp.yml`).

**Port binding and TCP listeners**
All TCP listeners are bound **before** the chroot and privilege drop. Privileged ports (< 1024) therefore work at initial startup, because the process still has root privileges at that point. No special preparation inside the chroot is needed for TCP listeners. After a SIGHUP reload, however, the process runs as an unprivileged user. Binding new or changed TCP listeners to privileged ports (< 1024) will fail. Only unprivileged ports (≥ 1024) can be used for listeners added or changed via reload.

**Unix sockets**
Unix socket listeners are created **before** the chroot. The socket paths in the configuration refer to the real filesystem. After chroot, the process can still accept connections on these existing sockets because the file descriptors remain open. Postfix (or any other client) connects to the socket path on the real filesystem — no change is needed on the client side.

After a SIGHUP reload, any new or changed Unix socket listener paths are resolved relative to the chroot root. For example, a configured path `/run/pfxhttp/new.sock` becomes `/var/lib/pfxhttp/run/pfxhttp/new.sock` on the real filesystem. The corresponding directories must exist inside the chroot and be writable by the unprivileged user.

When `systemd_socket_name` is configured, systemd creates the socket before
pfxhttp starts. The socket path, mode, user, and group should be managed in the
`.socket` unit; pfxhttp only consumes the already-open file descriptor.

**DNS resolution**
The Go runtime requires certain files for name resolution. The chroot directory **must** contain:

- `etc/resolv.conf`
- `etc/hosts`
- `etc/nsswitch.conf`

If any of these files are missing, Pfxhttp will refuse to start and log an error listing the missing files. Without these files, HTTP requests to hostnames (e.g., OIDC discovery endpoints) will fail silently or return errors.

**TLS certificates**
When using TLS with a custom `root_ca`, the CA certificate file is loaded **before** the chroot. The path in the configuration refers to the real filesystem. However, if the HTTP client is re-initialized during a SIGHUP reload, the `root_ca` path must be accessible inside the chroot (e.g., `/var/lib/pfxhttp/etc/ssl/certs/ca-bundle.crt`). It is therefore recommended to always place the CA file inside the chroot.

Similarly, if `cert` and `key` are configured for client TLS certificates, these files should also be present inside the chroot for reload compatibility.

**OIDC private key files**
If `private_key_file` is configured for `private_key_jwt` authentication, the key file is read when token or introspection requests are prepared (not at startup). After chroot, the path must be accessible inside the jail.

**Example chroot directory layout**

```
/var/lib/pfxhttp/
├── etc/
│   ├── hosts
│   ├── nsswitch.conf
│   ├── resolv.conf
│   ├── ssl/
│   │   └── certs/
│   │       └── ca-bundle.crt
│   └── pfxhttp/
│       └── pfxhttp.yml          # only needed if SIGHUP reload is used
```

> **Note:** When using chroot, the systemd unit file must run the service as root (remove `User=` and `Group=` directives) and include `CAP_SYS_CHROOT` in `CapabilityBoundingSet`. Use `run_as_user` and `run_as_group` in the configuration file instead.

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
      client_secret: "<set-in-deployment>"
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
virtual_mailbox_domains = socketmap:inet:127.0.0.1:23450:demo_map
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

#### Docker interoperability proof

`make test-postfix-interop` runs the production PfxHTTP binary with real
`postmap`, SMTP policy, and Postfix-to-PfxHTTP Dovecot SASL clients on an
isolated Docker network. It does not start or reconfigure Postfix or Dovecot on
the host. See [the Docker Postfix interoperability lane](test/e2e/postfix/README.md)
for image prerequisites, assertions, stable blocker behavior, and cleanup.

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
    # Optional exact list of advertised mechanisms. If omitted, pfxhttp
    # advertises PLAIN and LOGIN, plus XOAUTH2/OAUTHBEARER when
    # sasl_oidc_auth.enabled is true.
    mechanisms:
      - PLAIN
      - XOAUTH2
      - OAUTHBEARER
```

Behavior:
- If Dovecot provides `local_port`, it is forwarded.
- Else, if `default_local_port` is set, it is sent as `local_port` to the backend.
- Applies to both password-based and OAuth-based SASL flows.
- `mechanisms` is transport-independent. When set, it is the exact allowlist
  advertised to Postfix; unknown values are rejected, duplicates are rejected,
  and `XOAUTH2` / `OAUTHBEARER` require `sasl_oidc_auth.enabled: true`.

##### SASL EXTERNAL

`EXTERNAL` enables certificate-backed authentication through the trusted
Postfix TLS terminator. It is never enabled by default; add it explicitly to
`mechanisms`. For each `AUTH EXTERNAL`, Postfix must provide these singular
Dovecot auth-request fields:

- `ssl_client_verify=SUCCESS`
- `ssl_client_san_email=<one rfc822Name SAN identity>`
- `ssl_client_fingerprint=<SHA-256, SHA-384, or SHA-512 fingerprint>`

Pfxhttp rejects missing, duplicate, malformed, ambiguous, or unverified fields
before making a passwordless backend request. The SAN identity is resolved
with Nauthilus `AuthService.LookupIdentity` for `transport: grpc`, or by posting
the existing JSON auth request without a password and with `mode=no-auth` for
`transport: json`. The canonical backend account is returned to Postfix in the
Dovecot `OK user=...` response.

Pfxhttp emits that canonical account verbatim only when it is non-empty, valid
UTF-8, free of leading or trailing whitespace and protocol control characters,
and the complete `OK` response fits the effective line limit of the accepting
Dovecot listener. Invalid
backend values fail temporarily instead of being normalized or written to the
auth socket. For HTTP identity lookups, `401` and `403` are temporary caller
failures only when Nauthilus supplies no `Auth-Status`; with `Auth-Status` they
are permanent domain/identity failures. `408`, `425`, `429`, and `5xx` remain
temporary, while a successful Nauthilus response without `Auth-User` is an
identity-not-found failure.

RFC 4422 authorization identities are empty or must exactly equal the
certificate identity by default. Delegation is opt-in and succeeds only when a
second identity lookup resolves to the same canonical account:

```yaml
dovecot_sasl:
  smtp_auth:
    mechanisms:
      - PLAIN
      - EXTERNAL
    external_auth:
      allow_authorization_id: false
```

The Dovecot auth socket carries certificate-derived authentication facts and
must remain on a trusted private path. Pfxhttp does not validate an X.509 chain
itself; `SUCCESS` must be emitted only after the TLS terminator has completed
certificate-chain validation and extracted exactly one leaf `rfc822Name`.
OIDC-protected gRPC callers also need the Nauthilus
`nauthilus:lookup_identity` scope in addition to any scopes used by password
authentication.

##### gRPC Transport (alternative to JSON)

For password-based SASL mechanisms (PLAIN/LOGIN), `dovecot_sasl` entries can
optionally call the Nauthilus **gRPC AuthService** instead of posting JSON to
the HTTP endpoint. The gRPC service shares the same authentication contract
(`Authenticate` RPC in `nauthilus.auth.v1`), so caller credentials, OIDC
backend authentication and TLS settings keep their semantics across both
transports.

Certificate-based `EXTERNAL` uses `LookupIdentity` on the configured transport.
Token-based mechanisms (XOAUTH2 / OAUTHBEARER) always validate via the OIDC
introspection / JWKS endpoints over HTTP, regardless of `transport`.

```yaml
dovecot_sasl:
  smtp_auth:
    transport: grpc
    mechanisms:
      - PLAIN
    # backend_oidc_auth applies to gRPC just like HTTP and produces the
    # `authorization: Bearer <token>` metadata for outgoing RPCs.
    backend_oidc_auth:
      enabled: true
      configuration_uri: "https://idp.example.org/.well-known/openid-configuration"
      client_id: "pfxhttp"
      private_key_file: "/etc/pfxhttp/private.pem"
      auth_method: "private_key_jwt"
    grpc:
      address: "nauthilus.example.org:9444"
      timeout: 5s
      metadata:
        accept-language:
          - "de"
      tls:
        enabled: true
        root_ca: "/etc/pfxhttp/nauthilus-ca.pem"
        # Optional mTLS:
        client_cert: "/etc/pfxhttp/client.pem"
        client_key: "/etc/pfxhttp/client.key"
        # server_name overrides the SNI/SAN used during the TLS handshake.
        server_name: "nauthilus.example.org"
        # min_tls_version is "1.2" (default) or "1.3". Anything below 1.2
        # is rejected at config-load time.
        min_tls_version: "1.3"
        # skip_verify disables certificate verification — only for testing.
        skip_verify: false
```

Notes:

- `transport` defaults to `json`. When set to `grpc`, the `target` HTTP URL
  is no longer required; instead `grpc.address` (`host:port`) becomes
  mandatory.
- The gRPC `Authenticate` request forwards the same core SASL context as the
  JSON transport and additionally maps every parsed field that exists in the
  AuthService contract when Postfix/Dovecot supplies it: `external_session_id`
  (or `session`), `user_agent`, `ssl_session_id`, `ssl_client_verify`,
  `ssl_client_dn`, `ssl_client_cn`, `ssl_issuer`, `ssl_client_notbefore`,
  `ssl_client_notafter`, `ssl_subject_dn`, `ssl_issuer_dn`,
  `ssl_client_subject_dn`, `ssl_client_issuer_dn`, `ssl_serial`,
  `ssl_fingerprint`, `oidc_cid`, and `auth_login_attempt`. Direct contract
  names such as `client_ip`, `local_ip`, `client_port`, `local_port`,
  `client_hostname`, `protocol`, `method`, `ssl`, and `ssl_protocol` are also
  accepted; classic Dovecot names such as `rip`, `lip`, and `local_name`
  remain supported. Fields without an AuthService equivalent, such as
  `ssl_cipher_bits`, `ssl_pxt_id`, `nologin`, and `no_penalty`, are not sent
  over gRPC.
- If Postfix/Dovecot does not provide `external_session_id` or `session`,
  pfxhttp sends its own Dovecot-SASL connection session ID as
  `external_session_id` so backend logs still have a stable correlation value.
- Caller authorization is derived from existing fields:
  - `backend_oidc_auth.enabled: true` → the OIDC manager fetches a token via
    Client Credentials / `private_key_jwt` and the result is sent as
    `authorization: Bearer <token>` metadata.
  - Otherwise `http_auth_basic: "<username>:<password>"` is encoded and sent as
    `authorization: Basic <base64>` metadata.
- Additional gRPC request metadata is configured explicitly under
  `grpc.metadata`. Keys are normalized to lowercase. The `authorization` key,
  `grpc-` prefix and binary `-bin` metadata are reserved; use
  `http_auth_basic` or `backend_oidc_auth` for caller authorization.
- `custom_headers` are HTTP-only. Entries using `transport: grpc` must use
  `grpc.metadata` instead.
- gRPC receive-buffer compaction limits the memory overhead of fragmented HTTP/2
  DATA frames. Keep the upstream default enabled; do not set
  `GRPC_GO_EXPERIMENTAL_ENABLE_RECEIVE_BUFFER_COMPACTION=false` in deployments.
- The shared connection pool maintains one long-lived `*grpc.ClientConn` per
  `dovecot_sasl` entry. Multiple SASL sessions multiplex over the same HTTP/2
  connection. Existing Dovecot connections use the reloaded backend settings
  for the next authentication request. SIGHUP-based reloads automatically:
  - rebuild a connection when the gRPC settings of an entry change,
  - close connections for entries that were removed or switched back to
    the JSON transport,
  - leave unchanged entries' connections in place to avoid disruption.
- gRPC errors are mapped conservatively: caller-credential rejection,
  backend unavailability and timeouts surface as **temporary** failures so
  Postfix retries instead of immediately blacklisting the user.

---

## Logging and Troubleshooting

Logs are output to the console by default and should be captured by the service manager (e.g., **systemd**). Log verbosity is configurable in the `pfxhttp.yml` file.

Available logging options:

- **json**: If `true`, log output is formatted as JSON. Default: `false`.
- **level**: Log verbosity. Options: `none`, `debug`, `info`, `error`. Default: `info`.
- **use_systemd**: If `true`, timestamps are omitted from log lines. This is useful when running under systemd, which adds its own timestamps. Default: `false`.

```yaml
server:
  logging:
    json: false
    level: info
    use_systemd: true
```

### Session Tracking

Pfxhttp assigns a unique **session ID** to every incoming connection. This session ID is logged with every message related to that connection, making it easy to trace all activity belonging to a single client connection.

Within a connection, each individual request (e.g., a socket map lookup, a policy check, or a SASL AUTH/CONT command) receives a unique **sub_session ID**. This allows fine-grained tracing of individual requests within a long-lived connection.

The session IDs are 16-character random hex strings generated using `crypto/rand`.

Log fields:

- `session`: Identifies the connection. Stays the same for all log lines of a given connection.
- `sub_session`: Identifies a single request within a connection.

Example log output:

```
level=INFO msg="New connection established" session=a1b2c3d4e5f67890 client=127.0.0.1:12345
level=DEBUG msg="Received request" session=a1b2c3d4e5f67890 sub_session=9f8e7d6c5b4a3210 client=127.0.0.1:12345
level=DEBUG msg="Response sent" session=a1b2c3d4e5f67890 sub_session=9f8e7d6c5b4a3210 client=127.0.0.1:12345
level=INFO msg="Connection closed" session=a1b2c3d4e5f67890 client=127.0.0.1:12345
```

### Systemd Integration

When running under systemd, the journal already adds timestamps to every log line. To avoid duplicate timestamps, set `use_systemd: true` in the logging configuration:

```yaml
server:
  logging:
    level: info
    use_systemd: true
```

This removes the `time` field from log output. All other fields (level, message, session, sub_session, etc.) remain unchanged.

If Pfxhttp fails to start, verify the following:

- Ensure the configuration file (`/etc/pfxhttp/pfxhttp.yml`) is valid and complete.
- Ensure the service is running with the appropriate permissions for the configured resources.

---

## Contributing

Contributions are welcome! Feel free to submit pull requests or issues to improve the project. The project is distributed under the **MIT License**.

Before committing code changes, run the local quality gate:

```bash
make guardrails
```

This requires `golangci-lint` v2.12.1 or a compatible v2 release on `PATH`.

Dependency updates should be followed by `go mod tidy` and `go mod vendor` so the vendored build remains reproducible.

Release tags must use `vMAJOR.MINOR.PATCH`. Prerelease tags such as
`v1.2.3-alpha.2` or `v1.2.3-rc.4` are supported and are published as GitHub
prereleases. Docker prereleases only receive the exact version tag; stable
release tags also update `latest`, `vMAJOR`, and `vMAJOR.MINOR`.
Linux package prereleases use Debian/RPM-compatible `~` package versions.
Release package jobs build both formats through `scripts/build-linux-package.sh`
and validate the final package contents with `scripts/verify-linux-package.sh`
before upload.

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

- `private_key_file`: PEM-encoded RSA, ECDSA, or Ed25519 private key used by `private_key_jwt`.
  For `backend_oidc_auth`, the client assertion audience is the discovered `token_endpoint`.
  For `sasl_oidc_auth` introspection, the audience is the discovered `introspection_endpoint`.

- `sasl_oidc_auth.scopes`: Optional list of scopes to send as a space-separated `scope` parameter to the introspection endpoint. Only needed if your provider requires it for introspection access.

- `sasl_oidc_auth.validation`: How SASL OAuth tokens are validated.
  - `introspection` (default): Always call the provider’s introspection endpoint (RFC 7662). Supports opaque tokens and immediate revocation checks.
  - `jwks`: Validate tokens locally using the provider’s `jwks_uri`. Lowest latency for JWTs, but revocations may take effect only after key/claim changes.
  - `auto`: Try JWKS first for JWTs; fall back to introspection for opaque tokens or transient JWKS issues.

- `sasl_oidc_auth.jwks_cache_ttl`: Duration for caching the JWKS document. Default: `5m`.

- `sasl_oidc_auth.account_claim`: Specifies which claim (for JWT/JWKS validation) or which field in the introspection response should be used as the account/username. If omitted, the default resolution chain is used:
  - **JWKS**: `sub` → `preferred_username` → `username`
  - **Introspection**: `sub` → `username`

Example with advanced settings:

```yaml
socket_maps:
  example:
    target: "https://api.example.com/endpoint"
    backend_oidc_auth:
      enabled: true
      configuration_uri: "https://auth.example.com/.well-known/openid-configuration"
      client_id: "your-client-id"
      client_secret: "<set-in-deployment>"
      # Use POST body instead of Basic Auth:
      auth_method: client_secret_post
    # SASL token validation strategy (for dovecot_sasl only):
    sasl_oidc_auth:
      enabled: true
      configuration_uri: "https://auth.example.com/.well-known/openid-configuration"
      client_id: "roundcube"
      client_secret: "<set-in-deployment>"
      # OR private_key_file: "/etc/pfxhttp/introspection-client.pem"
      # auth_method: private_key_jwt
      validation: auto  # or: introspection | jwks
      jwks_cache_ttl: 5m
      # Use a custom claim/field as the account name:
      account_claim: "dovecot_account"
```

Notes:
- HTTP requests to the token and introspection endpoints now include `Accept: application/json`.
- Request bodies are built once and never rewritten after `http.NewRequest`, ensuring correct `Content-Length` handling.
- For target requests with `backend_oidc_auth`, any pre-existing `Authorization` header (e.g., set via `custom_headers`) is explicitly removed and replaced with `Authorization: Bearer <token>`.
- For introspection requests with `sasl_oidc_auth`, any `Authorization` header is explicitly cleared before applying the selected client authentication (`client_secret_basic`, `client_secret_post`, or `private_key_jwt`).
- JWKS-based validation supports RSA, EC (P-256/384/521), and Ed25519 keys from the provider’s `jwks_uri`.
