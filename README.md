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
      * [Customizing the Build](#customizing-the-build)
        * [Build Tags](#build-tags)
      * [Verifying Your Configuration](#verifying-your-configuration)
    * [Running as a System Service](#running-as-a-system-service)
    * [Command-line Options](#command-line-options)
  * [Configuration](#configuration)
    * [Server Settings](#server-settings)
    * [Response Cache](#response-cache)
    * [JWT Authentication](#jwt-authentication)
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

- Go 1.24 or later
- For JWT support only:
  - SQLite development libraries (libsqlite3-dev on Debian/Ubuntu, sqlite-devel on RHEL/CentOS)
  - GCC or another C compiler for CGO

#### Customizing the Build

When building with JWT support, you may need to customize the SQLite library and include paths:

```bash
# For custom SQLite installation paths (only needed for JWT support)
make TAGS=jwt SQLITE_LIB_PATH=/path/to/sqlite/lib SQLITE_INCLUDE_PATH=/path/to/sqlite/include

# On macOS with Homebrew (only needed for JWT support)
make TAGS=jwt SQLITE_LIB_PATH=/usr/local/opt/sqlite/lib SQLITE_INCLUDE_PATH=/usr/local/opt/sqlite/include
```

You can also set these as environment variables when building with JWT support:

```bash
export CGO_LDFLAGS="-L/path/to/sqlite/lib -lsqlite3"
export CGO_CFLAGS="-I/path/to/sqlite/include"
make TAGS=jwt
```

##### Build Tags

Pfxhttp supports optional features through build tags:

- **jwt**: Enables JWT authentication support (requires SQLite)

To build with JWT support:
```bash
make TAGS=jwt
```

To build without JWT support (no SQLite dependency):
```bash
make
```

#### Verifying Your Configuration

If you're building with JWT support, you can check your SQLite configuration with:

```bash
make sqlite-config
```

And run the tests to ensure everything is working correctly:

```bash
# Run all tests
make test

# For JWT builds only: Run the customsql package tests (SQLite-specific)
# This is recommended for testing the SQLite functionality when using JWT
make test-customsql
```

> **Note:** When testing JWT functionality with SQLite, always use the `test-customsql` target rather than trying to test individual files, as this ensures all dependencies are properly included.

By default, Pfxhttp and its associated man pages are installed in `/usr/local`.

The configuration is located in one of the following directories, based on priority:

1. `/usr/local/etc/pfxhttp/`
2. `/etc/pfxhttp/`
3. `$HOME/.pfxhttp/`
4. Current directory (`.`)

The expected configuration file name is `pfxhttp.yml`.

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
- **JWT Authentication**: Configure JWT authentication for HTTP requests with automatic token management.
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

  # Path to SQLite database for JWT token storage
  jwt_db_path: "/var/lib/pfxhttp/jwt.db"

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

  jwt_demo_map:
    target: "https://127.0.0.1:9443/api/v1/custom/map"
    jwt_auth:
      enabled: true
      token_endpoint: "https://example.com/api/token"
      credentials:
        username: "foobar"
        password: "secret"
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

  jwt_example_policy:
    target: "https://127.0.0.1:9443/api/v1/custom/policy"
    jwt_auth:
      enabled: true
      token_endpoint: "https://example.com/api/token"
      credentials:
        username: "foobar"
        password: "secret"
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

### JWT Authentication

Pfxhttp supports JWT authentication for HTTP requests to the target endpoints. This allows you to securely authenticate with APIs that require JWT tokens. 

> **Note:** JWT support is optional and requires building Pfxhttp with the `jwt` build tag (`make TAGS=jwt`). This feature depends on SQLite for token storage.

The JWT authentication feature includes:

- Automatic token fetching from a token endpoint
- Token storage in a SQLite database
- Automatic token refresh when tokens expire

To configure JWT authentication:

1. Make sure you've built Pfxhttp with JWT support:
   ```bash
   make TAGS=jwt
   ```

2. Set the `jwt_db_path` in the server section to specify where tokens will be stored:
   ```yaml
   server:
     jwt_db_path: "/var/lib/pfxhttp/jwt.db"
   ```

3. Configure JWT authentication for each socket map or policy service that requires it:
   ```yaml
   socket_maps:
     example:
       target: "https://api.example.com/endpoint"
       jwt_auth:
         enabled: true
         token_endpoint: "https://api.example.com/token"
         credentials:
           some_username_identifier: "your_username"
           some_password_identifier: "your_password"
         content_type: "application/json"  # Optional: "application/x-www-form-urlencoded" (default) or "application/json"
   ```

The JWT token will be automatically fetched from the token endpoint and included in the Authorization header as a Bearer token for all requests to the target endpoint.

If you build Pfxhttp without the `jwt` build tag, the JWT configuration in the YAML file will be ignored, and no JWT authentication will be performed.

---

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
