package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

type echoPayload struct {
	Key string `json:"key"`
}

type testReceiver struct{ name, key string }

func (r *testReceiver) String() string                { return r.name + " " + r.key }
func (r *testReceiver) ReadNetString(_ NetData) error { return nil }
func (r *testReceiver) ReadPolcy(_ Policy) error      { return nil }
func (r *testReceiver) GetName() string               { return r.name }
func (r *testReceiver) GetKey() string                { return r.key }

type responsePayload struct {
	Result string `json:"result,omitempty"`
	Demo   string `json:"demo_value,omitempty"`
}

func startTestServer(t *testing.T, expectCompressed bool, respondCompressed bool, handler func(w http.ResponseWriter, r *http.Request, body []byte)) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var reader io.Reader = r.Body

		if expectCompressed {
			if r.Header.Get("Content-Encoding") != "gzip" {
				t.Fatalf("expected Content-Encoding gzip, got %q", r.Header.Get("Content-Encoding"))
			}

			zr, err := gzip.NewReader(r.Body)
			if err != nil {
				t.Fatalf("gzip.NewReader failed: %v", err)
			}

			defer func(zr *gzip.Reader) {
				_ = zr.Close()
			}(zr)

			reader = zr
		}

		body, err := io.ReadAll(reader)
		if err != nil {
			t.Fatalf("reading request body failed: %v", err)
		}

		if respondCompressed {
			w.Header().Set("Content-Encoding", "gzip")

			var buf bytes.Buffer

			zw := gzip.NewWriter(&buf)
			// create a small json response mirroring a field
			resp := responsePayload{Result: "action=OK description=hello", Demo: "world"}
			j, _ := json.Marshal(resp)
			_, _ = zw.Write(j)
			_ = zw.Close()

			w.WriteHeader(http.StatusOK)

			_, _ = w.Write(buf.Bytes())

			return
		}

		w.WriteHeader(http.StatusOK)

		handler(w, r, body)
	}))
}

func TestMapClient_RequestAndResponseCompression(t *testing.T) {
	// Server expects gzipped request and sends gzipped response
	ts := startTestServer(t, true, true, func(w http.ResponseWriter, r *http.Request, body []byte) {
		// echo plain json response in non-compressed branch (unused here)
		w.Header().Set("Content-Type", "application/json")

		_, _ = w.Write([]byte(`{"demo_value":"ok"}`))
	})

	defer ts.Close()

	cfg := &Config{
		Server: Server{HTTPClient: HTTPClient{}},
		SocketMaps: map[string]Request{
			"demo": {
				Target:                  ts.URL,
				Payload:                 `{"key": "{{ .Key }}"}`,
				StatusCode:              200,
				ValueField:              "demo_value",
				HTTPRequestCompression:  true,
				HTTPResponseCompression: true,
			},
		},
	}

	InitializeHttpClient(cfg)

	client := NewMapClient(context.Background(), cfg)
	client.SetReceiver(&testReceiver{name: "demo", key: "abc"})

	if err := client.SendAndReceive(); err != nil {
		t.Fatalf("SendAndReceive error: %v", err)
	}

	sender := client.GetSender().(*PostfixSender)
	if sender.status != "OK" || sender.data == "" {
		t.Fatalf("unexpected sender result: %s %s", sender.status, sender.data)
	}
}

func TestPolicyClient_RequestCompression_ResponsePlain(t *testing.T) {
	// Server expects gzipped request and returns plain json
	ts := startTestServer(t, true, false, func(w http.ResponseWriter, r *http.Request, body []byte) {
		// assert JSON content is correct after decompression
		var ep echoPayload

		if err := json.Unmarshal(body, &ep); err != nil {
			t.Fatalf("bad json in request: %v", err)
		}

		if ep.Key == "" {
			t.Fatalf("expected key in request payload")
		}

		w.Header().Set("Content-Type", "application/json")

		_, _ = w.Write([]byte(`{"result":"action=OK description=ok"}`))
	})

	defer ts.Close()

	cfg := &Config{
		Server: Server{HTTPClient: HTTPClient{}},
		PolicyServices: map[string]Request{
			"policy": {
				Target:                 ts.URL,
				Payload:                `{"key":"{{ .Key }}"}`,
				StatusCode:             200,
				ValueField:             "result",
				HTTPRequestCompression: true,
			},
		},
	}

	InitializeHttpClient(cfg)

	client := NewPolicyClient(context.Background(), cfg)
	client.SetReceiver(&testReceiver{name: "policy", key: "abc"})

	if err := client.SendAndReceive(); err != nil {
		t.Fatalf("SendAndReceive error: %v", err)
	}

	sender := client.GetSender().(*PostfixSender)
	if sender.status != "action=OK" {
		t.Fatalf("unexpected policy status: %s", sender.status)
	}
}
