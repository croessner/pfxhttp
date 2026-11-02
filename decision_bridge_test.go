package main

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestDecisionReply rejects missing, incoherent and side-effectful generic replies.
func TestDecisionReply(t *testing.T) {
	for _, tc := range []struct{ body, want string }{
		{`{"request_id":"test","decision_id":"decision","effect":"permit","status":{"code":"permit","retryable":false,"message":""}}`, "DUNNO"},
		{`{"request_id":"test","decision_id":"decision","effect":"deny","status":{"code":"policy_denied","retryable":false,"message":""}}`, postfixActionReject},
		{`{"request_id":"other","decision_id":"decision","effect":"permit","status":{"code":"permit","retryable":false,"message":""}}`, decisionTemporaryAction},
		{`{"request_id":"test","decision_id":"decision","effect":"permit","status":{"code":"provider_unavailable","retryable":true,"message":""}}`, decisionTemporaryAction},
		{`{"request_id":"test","decision_id":"decision","effect":"permit","obligations":[{}],"status":{"code":"permit","retryable":false,"message":""}}`, decisionTemporaryAction},
		{`{"effect":"permit"}`, decisionTemporaryAction},
	} {
		action := decisionReply(strings.NewReader(tc.body), "test")
		if action != tc.want {
			t.Errorf("got %q want %q", action, tc.want)
		}
	}
}

// TestDecisionClientsRoundTrip covers both ingress clients, gzip and stale-cache bypass.
func TestDecisionClientsRoundTrip(t *testing.T) {
	for _, component := range []string{componentSocketMap, componentPolicyService} {
		for _, compressed := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/gzip=%v", component, compressed), func(t *testing.T) { testDecisionClient(t, component, compressed) })
		}
	}
}

// testDecisionClient verifies typed requests and transport failure behavior against a local backend.
func testDecisionClient(t *testing.T, component string, compressed bool) {
	t.Helper()

	backend := decisionFixtureBackend(t, component, compressed)
	defer backend.Close()

	receiver := decisionFixtureReceiver(t, component)
	settings := Request{Target: backend.URL, HTTPResponseCompression: compressed, Decision: &DecisionBridge{Enabled: true, ObservationScope: fixtureObservationScope}}
	deps := &Deps{Config: &Config{SocketMaps: map[string]Request{fixtureDecisionName: settings}, PolicyServices: map[string]Request{fixtureDecisionName: settings}}, HTTPClient: backend.Client(), RespCache: NewInMemoryResponseCache(time.Minute)}

	var client GenericClient
	if component == componentSocketMap {
		client = NewMapClient(deps, slog.Default())
	} else {
		client = NewPolicyClient(deps, slog.Default())
	}

	client.SetReceiver(receiver)

	if err := client.SendAndReceive(); err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(client.GetSender().String(), decisionNeutralAction) {
		t.Fatal(client.GetSender().String())
	}

	deps.RespCache.Set(receiver.GetName(), receiver.GetKey(), CachedResponse{Status: string(DovecotCmdOK), Data: decisionNeutralAction})
	backend.Close()

	if err := client.SendAndReceive(); err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(client.GetSender().String(), decisionTemporaryAction) {
		t.Fatalf("stale decision reused: %s", client.GetSender().String())
	}
}

// decisionFixtureReceiver supplies realistic envelope context only to the policy transport.
func decisionFixtureReceiver(t *testing.T, component string) Receiver {
	t.Helper()

	if component == componentSocketMap {
		receiver := NewPostfixMapReceiver()
		if err := receiver.ReadNetString(NewNetStringFromString(fixtureDecisionName + " " + fixtureSenderAddress)); err != nil {
			t.Fatal(err)
		}

		return receiver
	}

	receiver := NewPostfixPolicyReceiver(fixtureDecisionName)

	policy := NewPostfixPolicy()
	for key, value := range map[string]string{"request": "smtpd_access_policy", "sender": fixtureSenderAddress, "client_address": "192.0.2.1", "protocol_state": "END-OF-MESSAGE", "instance": "fixture-session", "queue_id": "QUEUE"} {
		policy.SetData(key, value)
	}

	if err := receiver.ReadPolcy(policy); err != nil {
		t.Fatal(err)
	}

	return receiver
}

// decisionFixtureBackend validates typed payloads and returns optional gzip decisions.
func decisionFixtureBackend(t *testing.T, component string, compressed bool) *httptest.Server {
	t.Helper()

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request map[string]any
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
			w.WriteHeader(500)

			return
		}

		id, _ := request["request_id"].(string)
		if request["version"] != "1" || id == "" {
			t.Error("invalid generic request")
		}

		resource := request["resource"].(map[string]any)[decisionAttributes].(map[string]any)
		if resource["mail.sender_domain"].(map[string]any)[decisionStringKind] != "example.com" {
			t.Error("incorrect domain translation")
		}

		if component == componentPolicyService {
			if _, ok := resource["mail.observation_id"]; !ok {
				t.Error("missing observation identity")
			}

			if _, ok := request["environment"]; !ok {
				t.Error("missing SMTP peer context")
			}
		} else if _, ok := request["environment"]; ok {
			t.Error("invented socketmap context")
		}

		body := fmt.Sprintf(`{"request_id":%q,"decision_id":"fixture","effect":"permit","status":{"code":"permit","message":"","retryable":false}}`, id)

		var output io.Writer = w
		if compressed {
			w.Header().Set("Content-Encoding", "gzip")

			z := gzip.NewWriter(w)
			defer func() { _ = z.Close() }()

			output = z
		}

		if _, err := io.WriteString(output, body); err != nil {
			t.Error(err)
		}
	}))

	return backend
}

const fixtureDecisionName = "domain_age"

const fixtureSenderAddress = "user@example.com"

// TestDecisionDefaultsOwnTheirConfiguration inherits complete decision settings without sharing mutation.
func TestDecisionDefaultsOwnTheirConfiguration(t *testing.T) {
	defaults := Request{Decision: &DecisionBridge{Enabled: true, Namespace: "mail", Action: "observe-sender-domain", ObservationScope: fixtureObservationScope}}

	merged := mergeRequest(defaults, Request{})
	if merged.Decision == nil || *merged.Decision != *defaults.Decision {
		t.Fatal("decision defaults lost")
	}

	merged.Decision.Action = "assess-sender-domain"
	if merged.Decision.Action == defaults.Decision.Action {
		t.Fatal("default configuration was shared")
	}

	disabled := mergeRequest(defaults, Request{Decision: &DecisionBridge{Enabled: false}})
	if disabled.Decision.Enabled {
		t.Fatal("explicit disable was ignored")
	}
}

const fixtureObservationScope = "mx.example"

// TestDecisionDomainAcceptsQuotedEnvelopeSenders preserves valid quoted SMTP local parts.
func TestDecisionDomainAcceptsQuotedEnvelopeSenders(t *testing.T) {
	for _, sender := range []string{`"Jane Doe"@example.com`, `"user@relay"@example.com`} {
		receiver := NewPostfixPolicyReceiver(fixtureDecisionName)
		policy := NewPostfixPolicy()
		policy.SetData("request", "smtpd_access_policy")
		policy.SetData("sender", sender)

		if err := receiver.ReadPolcy(policy); err != nil {
			t.Fatal(err)
		}

		domain, valid := decisionDomain(receiver, componentPolicyService)
		if !valid || domain != "example.com" {
			t.Fatalf("quoted envelope %q rejected: %q %v", sender, domain, valid)
		}
	}
}
