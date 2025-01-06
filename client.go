package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"strings"
	"text/template"
	"time"
)

var httpClient *http.Client

// InitializeHttpClient configures and initializes the global HTTP client based on the provided configuration.
func InitializeHttpClient(cfg *Config) {
	var proxyFunc func(*http.Request) (*url.URL, error)

	if cfg.Server.HTTPClient.Proxy != "" {
		proxyURL, err := url.Parse(cfg.Server.HTTPClient.Proxy)
		if err != nil {
			proxyFunc = http.ProxyFromEnvironment
		} else {
			proxyFunc = http.ProxyURL(proxyURL)
		}
	} else {
		proxyFunc = http.ProxyFromEnvironment
	}

	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 10 * time.Second,
	}

	transport := &http.Transport{
		DialContext:         dialer.DialContext,
		TLSHandshakeTimeout: 10 * time.Second,
		Proxy:               proxyFunc,
		MaxConnsPerHost:     cfg.Server.HTTPClient.MaxConnsPerHost,
		MaxIdleConns:        cfg.Server.HTTPClient.MaxIdleConns,
		MaxIdleConnsPerHost: cfg.Server.HTTPClient.MaxIdleConnsPerHost,
		IdleConnTimeout:     cfg.Server.HTTPClient.IdleConnTimeout,
	}

	if cfg.Server.TLS.Enabled {
		tlsConfig := &tls.Config{
			MinVersion: tls.VersionTLS12,
		}

		if cfg.Server.TLS.SkipVerify {
			tlsConfig.InsecureSkipVerify = true
		}

		if cfg.Server.TLS.Cert != "" && cfg.Server.TLS.Key != "" {
			tlsConfig.Certificates = make([]tls.Certificate, 1)
			tlsConfig.Certificates[0], _ = tls.LoadX509KeyPair(cfg.Server.TLS.Cert, cfg.Server.TLS.Key)
		}

		transport.TLSClientConfig = tlsConfig
	}

	httpClient = &http.Client{
		Timeout:   60 * time.Second,
		Transport: transport,
	}

	httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
}

// GenericClient is an interface for managing the lifecycle of communication processes between senders and receivers.
type GenericClient interface {
	// SetReceiver sets the Receiver that will handle incoming NetString data for the implementing GenericClient.
	SetReceiver(Receiver)

	// GetSender retrieves the Sender used for handling outgoing data in the implementing GenericClient.
	GetSender() Sender

	// RenderTemplate processes the provided template string,
	// substituting placeholders with context data, and returns the result.
	RenderTemplate(string) (string, error)

	// SendAndReceive initiates the request-response process
	// by sending data with the Sender and receiving a response with the Receiver.
	SendAndReceive() error
}

// BridgeClient represents a client capable of handling data flow between a receiver and sender within a configurable setup.
// It uses a configuration object to manage operations and leverages Receiver and Sender interfaces to facilitate communication.
// Receives data via a Receiver, processes it using defined logic, and sends results through a Sender.
type BridgeClient struct {
	config   *Config
	receiver Receiver
	sender   Sender
}

// SetReceiver assigns the specified Receiver to the BridgeClient for handling incoming data operations.
func (c *BridgeClient) SetReceiver(receiver Receiver) {
	c.receiver = receiver
}

// GetSender retrieves the Sender instance currently associated with the BridgeClient.
func (c *BridgeClient) GetSender() Sender {
	return c.sender
}

// RenderTemplate parses and renders the provided template string using data from the receiver's key.
func (c *BridgeClient) RenderTemplate(tmpl string) (string, error) {
	var rendered bytes.Buffer

	parsedTemplate, err := template.New("template").Parse(tmpl)
	if err != nil {
		return "", err
	}

	templateData := struct {
		Key string
	}{
		Key: c.receiver.GetKey(),
	}

	if err = parsedTemplate.Execute(&rendered, templateData); err != nil {
		return "", err
	}

	return rendered.String(), nil
}

// SendAndReceive handles the data flow by sending a POST request with rendered payload and processes the response.
// It retrieves the target and payload template from the configuration, renders the template, and sends the request.
// Custom headers can be included if specified in the settings. Timeout and other errors update the sender's status.
// Validates the response against expected status and value fields, updating the sender's status accordingly.
// Returns an error if request creation, template rendering, or response handling fails.
func (c *BridgeClient) SendAndReceive() error {
	c.sender = NewPostfixSender()

	settings, ok := c.config.SocketMaps[c.receiver.GetName()]
	if !ok {
		return errors.New("receiver settings not found in socket maps")
	}

	if settings.Target == "" {
		return errors.New("target URL is not specified in the settings")
	}

	renderedPayload, err := c.RenderTemplate(settings.Payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", settings.Target, bytes.NewBuffer([]byte(renderedPayload)))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")

	if len(settings.CustomHeaders) != 0 {
		for _, header := range settings.CustomHeaders {
			headerKey, headerValue := splitHeader(header)
			if headerKey != "" && headerValue != "" {
				req.Header.Set(headerKey, headerValue)
			}
		}
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		if errors.Is(err, http.ErrHandlerTimeout) {
			c.sender.SetStatus("TIMEOUT")
			c.sender.SetData("request timed out")

			return nil
		} else {
			c.sender.SetStatus("TEMP")
			c.sender.SetData(err.Error())

			return nil
		}
	}

	return c.handleResponse(resp, settings)
}

var _ GenericClient = (*BridgeClient)(nil)

// splitHeader splits a header string into a key and value pair, separating by the first colon.
// Returns empty strings if the input is improperly formatted.
func splitHeader(header string) (headerKey string, headerValue string) {
	headerParts := strings.SplitN(header, ":", 2)

	if len(headerParts) != 2 {
		return "", ""
	}

	headerKey = strings.TrimSpace(headerParts[0])
	headerValue = strings.TrimSpace(headerParts[1])

	return headerKey, headerValue
}

// handleResponse processes the HTTP response and updates the sender's status and data based on the response content.
func (c *BridgeClient) handleResponse(resp *http.Response, request Request) error {
	var responseData map[string]any

	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return errors.New("failed to read response body: " + err.Error())
	}

	if err = json.Unmarshal(bodyBytes, &responseData); err != nil {
		return errors.New("failed to unmarshal JSON: " + err.Error())
	}

	if request.ErrorField != "" {
		if rawValue, found := getNestedValue(responseData, request.ErrorField, 0); found {
			value := convertResponse(rawValue, 0)
			if value != "" && request.NoErrorValue != "" && value != request.NoErrorValue {
				c.sender.SetStatus("PERM")
				c.sender.SetData(fmt.Sprintf("unexpected error received: %s", value))

				return nil
			}
		}
	}

	if resp.StatusCode != request.StatusCode {
		c.sender.SetStatus("PERM")
		c.sender.SetData("unexpected status code received: " + resp.Status)

		return nil
	}

	if rawValue, found := getNestedValue(responseData, request.ValueField, 0); !found {
		c.sender.SetStatus("NOTFOUND")
		c.sender.SetData("")
	} else {
		value := convertResponse(rawValue, 0)
		if value == "" {
			c.sender.SetStatus("PERM")
			c.sender.SetData(fmt.Sprintf("unexpected value received: type=%T value=%v", rawValue, rawValue))

			return nil
		}

		if len(value) > c.config.Server.SockmapMaxReplySize {
			c.sender.SetStatus("PERM")
			c.sender.SetData(fmt.Sprintf("value too long: %d", len(value)))
		}

		c.sender.SetStatus("OK")
		c.sender.SetData(value)
	}

	return nil
}

// getNestedValue recursively searches for a key in a nested map and returns the value and a boolean indicating success.
// responseData is the map[string]any to search within.
// key is the string to search for.
// level is the current recursion depth, used to prevent infinite recursion.
// Returns the value associated with the key and a boolean indicating whether the key was found.
func getNestedValue(responseData map[string]any, key string, level uint) (any, bool) {
	if level == math.MaxUint16 {
		return nil, false
	}

	for k1, v1 := range responseData {
		if k1 == key {
			return v1, true
		}

		if v2, ok := v1.(map[string]any); ok {
			if value, ok := getNestedValue(v2, key, level+1); ok {
				return value, true
			}
		}
	}

	return nil, false
}

// convertResponse converts a rawValue of any type to a string based on its type, respecting a maximum recursion level.
func convertResponse(rawValue any, level uint16) string {
	if level == math.MaxUint16 {
		return ""
	}

	switch value := rawValue.(type) {
	case bool:
		return fmt.Sprintf("%t", value)
	case float64:
		return fmt.Sprintf("%f", value)
	case string:
		return value
	case []string:
		return strings.Join(value, ",")
	case []any:
		var values []string

		for _, v := range value {
			values = append(values, convertResponse(v, level+1))
		}

		return strings.Join(values, ",")
	default:
		return ""
	}
}

// NewBridgeClient creates and returns a new instance of BridgeClient configured using the provided Config object.
func NewBridgeClient(cfg *Config) GenericClient {
	return &BridgeClient{config: cfg}
}
