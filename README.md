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
    * [Server Settings](#server-settings)
    * [Response Cache](#response-cache)
    * [OIDC Authentication](#oidc-authentication)
    * [HTTP Request/Response Compression](#http-requestresponse-compression)
    * [Integrating with Postfix](#integrating-with-postfix)
      * [Socket Maps](#socket-maps)
      * [Policy Services](#policy-services)
  * [Logging and Troubleshooting](#logging-and-troubleshooting)
  * [Contributing](#contributing)
  * [References](#references)
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

Pfxhttp is configured through a YAML file named `pfxhttp.yml` (or a custom file specified with the `--config` and `--format` flags). The following are the main sections:

### Server Settings

The `server` section contains global options, including:

- **Listeners**: Define socket map and policy service listeners for Postfix integration.
- **Logging**: Enable JSON-formatted logs and set verbosity (`debug`, `info`, or `error`).
- **HTTP Client Options**: Configure connection limits, timeouts, and optional TLS settings.
- **OIDC Authentication**: Configure OIDC authentication (Client Credentials Flow) for HTTP requests with automatic token management.
- **Response Cache**: Optional in-memory cache to serve responses when the backend is unavailable.

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

  logging:
    json: true
    level: info

  tls:
    enabled: true
    http_client_skip_verify: true

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
    oidc_auth:
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
    oidc_auth:
      enabled: true
      configuration_uri: "https://example.com/.well-known/openid-configuration"
      client_id: "foobar"
      client_secret: "secret"
    payload: "{{ .Key }}"
    status_code: 200
    value_field: "policy.result"
    error_field: "policy.error"
    no_error_value: "OK"
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
    oidc_auth:
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
