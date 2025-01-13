# Pfxhttp – HTTP Proxy for Postfix

Pfxhttp is a lightweight HTTP proxy designed to integrate Postfix with external HTTP APIs for **socket maps** and **policy services**. This enables dynamic and flexible email workflows by connecting Postfix to modern APIs.

# Table of contents

<!-- TOC -->
* [Pfxhttp – HTTP Proxy for Postfix](#pfxhttp--http-proxy-for-postfix)
* [Table of contents](#table-of-contents)
  * [Overview](#overview)
  * [Getting Started](#getting-started)
    * [Installation](#installation)
    * [Running as a System Service](#running-as-a-system-service)
    * [Command-line Options](#command-line-options)
  * [Configuration](#configuration)
    * [Server Settings](#server-settings)
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

Pfxhttp is written in **Go** and can be compiled with the following commands:

```bash
make
make install
```

By default, Pfxhttp and its associated man pages are installed in `/usr/local`.

The configuration is located in one of the following directories, based on priority:

1. `/usr/local/etc/pfxhttp/`
2. `/etc/pfxhttp/`
3. `$HOME/.pfxhttp/`
4. Current directory (`.`)

The expected configuration file name is `pfxhttp.yml`.

> **Note:** This first implementation was tested using Go version **1.23**.

### Running as a System Service

Pfxhttp is typically run as a **systemd** service. Below is an example unit file:

```ini
[Unit]
Description=Postfix HTTP Proxy (pfxhttp)
After=network.target

[Service]
ExecStart=/usr/local/bin/pfxhttp
Restart=always
User=postfix
Group=postfix

[Install]
WantedBy=multi-user.target
```

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
```

**Important**: Postfix has a hardcoded socket map reply size limit of **100,000 bytes** (Postfix 3.9.1 or older).

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