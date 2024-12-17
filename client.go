package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"text/template"
	"time"
)

var httpClient *http.Client

func InitializeHttpClient(cfg *Config) {
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 10 * time.Second,
	}

	transport := &http.Transport{
		DialContext:         dialer.DialContext,
		TLSHandshakeTimeout: 10 * time.Second,
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
		Timeout:   30 * time.Second,
		Transport: transport,
	}

	httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
}

type Client struct {
	config   *Config
	receiver *PostfixReceiver
	sender   *PostfixSender
}

func (c *Client) SetReceiver(receiver *PostfixReceiver) {
	c.receiver = receiver
}

func (c *Client) GetSender() *PostfixSender {
	return c.sender
}

func (c *Client) RenderTemplate(tmpl string) (string, error) {
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

func (c *Client) SendAndReceive() error {
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

	resp, err := httpClient.Do(req)
	if err != nil {
		if errors.Is(err, http.ErrHandlerTimeout) {
			c.sender.SetStatus("TIMEOUT")
			c.sender.SetData("request timed out")

			return nil
		} else {
			return err
		}
	}

	return c.handleResponse(resp, settings)
}

func (c *Client) handleResponse(resp *http.Response, request Request) error {
	var responseData map[string]any

	c.sender = NewPostfixSender()

	if resp.StatusCode != request.StatusCode {
		c.sender.SetStatus("PERM")
		c.sender.SetData("unexpected status code received: " + resp.Status)

		return nil
	}

	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return errors.New("failed to read response body: " + err.Error())
	}

	if err := json.Unmarshal(bodyBytes, &responseData); err != nil {
		return errors.New("failed to unmarshal JSON: " + err.Error())
	}

	if rawValue, ok := responseData[request.ValueField]; !ok {
		c.sender.SetStatus("NOTFOUND")
		c.sender.SetData("")
	} else {
		if value, ok := rawValue.(string); !ok {
			c.sender.SetStatus("OK")
			c.sender.SetData(value)
		} else {
			c.sender.SetStatus("PERM")
			c.sender.SetData(fmt.Sprintf("unexpected value received: %v", value))
		}
	}

	return nil
}

func NewClient(cfg *Config) *Client {
	return &Client{config: cfg}
}
