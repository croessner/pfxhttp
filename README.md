# Postfix to HTTP

This program serves as a kind of bridge between Postfix and HTTP. The Postfix socketmaps can be used to delegate table requests to HTTP servers.

The current implementation assumes JSON requests and responses to the HTTP server. The POST method is used for this.

The mapping between Postfix and HTTP takes place in a configuration file. Socketmaps send a **name** field in the request, which must be defined in the configuration
 and refers to an HTTP server. At the same time, a key to be searched for is transmitted, which must be referenced in a payload template.
The payload itself is JSON. When a request is made, the key in the template is replaced by the search key from Postfix and sent to the HTTP server. This
processes the request and sends back JSON.

**pfxhttp** also supports policy services. Please look at the configuration example to get detailed information about the usage.

## Installation

The program is written in Go and is compiled as follows:

```shell
make
```

> Note
> 
> This first implementation was tested with Go version 1.23

The configuration is located in one of the following directories:

1. /usr/local/etc/pfxhttp/
2. /etc/pfxhttp/
3. $HOME/.pfxhttp
4. .

The configuration file must have the name pfxhttp.yml.

## Configuration

```yml
---
# pfxhttp config file

server:

  listen:
    # List of "socket_map" and "policy_service" listeners.

    - kind: "socket_map"
      
      # An optional name for this listener.
      name: ""
      
      # 'tcp', 'tcp6' or 'unix'
      # By using 'unix' the paramter 'mode' must also be specified
      type: "tcp"
       
      # An IPv4 or IPv6 address (also 0.0.0.0 or [::]). For "unix" this is a path.
      address: "[::]"
       
      # TCP port, if any.
      port: 23450
       
      # Optional unix socket mode
      mode: "0666"

    - kind: "policy_service"

      # The 'name' field is required, if 'kind' is "policy_service". It is an indicator under the 'policy_services'
      # section to find a matching configuration for this policy.
      name: "default"

      # 'tcp', 'tcp6' or 'unix'
      # By using 'unix' the paramter 'mode' must also be specified
      type: "tcp"

      # An IPv4 or IPv6 address (also 0.0.0.0 or [::]). For "unix" this is a path.
      address: "[::]"

      # TCP port, if any.
      port: 23451

      # Optional unix socket mode
      mode: "0666"

  logging:
    # Optional flag to get logging JSON formatted
    json: true
    
    # Optional log level. Supported: debug, info, error. Unknown values result in info level.
    level: info
    
  http_client:
    # These values tune the HTTP client inside pfxhttp. The names should be self-explaining. If unsure leave them unconfigured.
    max_connections_per_host: 10
    max_idle_connections: 4
    max_idle_connections_per_host: 1
    idle_connection_timeout: 10

  tls:
    # Use TLS for connections to the HTTP servers. This is a global setting for all servers.
    enabled: true
    
    # For testing purposes only. This will ignore certificate validation.
    http_client_skip_verify: true

    # Optional: A client certificate and key
    #cert:
    #key:
  
  # Default Postfix limit  
  #socketmap_max_reply_size: 100000
  
socket_maps:

  # Blocks with socket map definitions. Each identifier should match a socketmap name.
  demo:
    # URL of this specific map
    target: https://127.0.0.1:9443/api/v1/custom/demo
    
    # Optional HTTP request headers. For Basic auth and others...
    custom_headers:
      # User 'test', password 'test'
      - "Authorization: Basic dGVzdDp0ZXN0"
    
    # The payload is a valid JSON string that encapsulates a Go template variable named .Key. This variable
    # is replaced with the key from the Postfix request.
    payload: >
      {
        "key": "{{ .Key }}"
      }
    # This is the expected return HTTP status code.
    status_code: 200
    
    # The JSON result must have this field to retrieve the value, which is then sent back to Postfix.
    value_field: "demo_value"

    # The JSON result may contain an optional error message. This is the name of the field in the response.
    error_field: "error"

    # If error_field is set, this field can always be returned. The optional no_error_value parameter then defines a 
    # value identical to a success message.
    no_error_value: "none"

policy_services:

  # Blocks with policy service definitions. Each identifier should match a policy service name from the 'listen' section.
  default:
    # URL of this specific map
    target: https://127.0.0.1:9443/api/v1/custom/anotherdemo
  
    # Optional HTTP request headers. For Basic auth and others...
    custom_headers:
     # User 'test', password 'test'
     - "Authorization: Basic dGVzdDp0ZXN0"
  
    # The payload is a valid JSON string that encapsulates a Go template variable named .Key. This variable
    # is replaced with the key from the Postfix request, which is the JSON-formatted string of the Postfix policy request.
    payload: "{{ .Key }}"
    
    # This is the expected return HTTP status code.
    status_code: 200
  
    # The JSON result must have this field to retrieve the value, which is then sent back to Postfix.
    value_field: "demo_value"
  
    # The JSON result may contain an optional error message. This is the name of the field in the response.
    error_field: "error"
  
    # If error_field is set, this field can always be returned. The optional no_error_value parameter then defines a 
    # value identical to a success message.
    no_error_value: "none"
 ```

As of writing this document, Postfix has a hard coded socket map reply size of 100000 (Postfix version <= 3.9.1).

> Mote
>
> You can use Nauthilus for example, to implement several socket map hooks. See https://github.com/croessner/nauthilus

## Contribute

Feel free to improve it.

MIT license