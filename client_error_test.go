package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

type deadlineErrorReader struct{}

func (deadlineErrorReader) Read([]byte) (int, error) {
	return 0, context.DeadlineExceeded
}

func TestMapResponseRejectsValueAboveConfiguredReplyLimit(t *testing.T) {
	t.Parallel()

	client := &MapClient{
		config: &Config{Server: Server{SockmapMaxReplySize: 3}},
		sender: NewPostfixSender(),
	}
	response := &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Body:       io.NopCloser(strings.NewReader(`{"value":"four"}`)),
	}
	request := Request{StatusCode: http.StatusOK, ValueField: testValueField}

	if err := client.handleResponse(response, request); err != nil {
		t.Fatalf("handleResponse() error = %v", err)
	}

	if got := client.sender.String(); got != "PERM value too long: 4" {
		t.Fatalf("SocketMap response = %q, want bounded PERM reply", got)
	}
}

func TestHTTPResponseBodyErrorsPreserveDeadlineCause(t *testing.T) {
	t.Parallel()

	request := Request{}
	clients := []struct {
		name   string
		handle func(*http.Response, Request) error
	}{
		{name: "socket map", handle: (&MapClient{}).handleResponse},
		{name: testSocketName, handle: (&PolicyClient{}).handleResponse},
	}

	for _, client := range clients {
		t.Run(client.name, func(t *testing.T) {
			t.Parallel()

			response := &http.Response{Body: io.NopCloser(deadlineErrorReader{})}

			err := client.handle(response, request)
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("response error = %v, want wrapped context deadline", err)
			}
		})
	}
}
