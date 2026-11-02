package main

import (
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
)

const decisionTemporaryAction = "DEFER_IF_PERMIT"

// DecisionBridge selects the generic Nauthilus protocol independently of legacy templates.
type DecisionBridge struct {
	Enabled          bool   `mapstructure:"enabled"`
	ObservationScope string `mapstructure:"observation_scope"`
	Namespace        string `mapstructure:"namespace"`
	Action           string `mapstructure:"action"`
}

// decisionReply validates correlated, side-effect-free decisions before mapping delivery actions.
func decisionReply(reader io.Reader, requestID string) string {
	var response decisionResponse

	body, err := io.ReadAll(io.LimitReader(reader, 65537))
	if err != nil || len(body) > 65536 || json.Unmarshal(body, &response) != nil || !response.valid(requestID) {
		return decisionTemporaryAction
	}

	return response.action()
}

// decisionDomain extracts only the envelope domain; it never claims header or authenticated identity.
func decisionDomain(receiver Receiver, component string) (string, bool) {
	sender, valid := decisionSender(receiver, component)
	if !valid {
		return "", false
	}

	if sender == "" || sender == "<>" {
		return "", true
	}

	if strings.ContainsAny(sender, "\x00\r\n \t<>") {
		return "", false
	}

	if strings.Contains(sender, "@") {
		local, domain, ok := strings.Cut(sender, "@")
		if !validMailboxParts(local, domain, ok) {
			return "", false
		}

		sender = domain
	} else if component == componentPolicyService {
		return "", false
	}

	if sender == "" || len(sender) > 253 || strings.ContainsAny(sender, "/:[]\\") {
		return "", false
	}

	return sender, true
}

// sendDecision shares translation across Postfix transports and never consults the stale-response cache.
func sendDecision(ctx context.Context, client *http.Client, receiver Receiver, sender Sender, settings Request, component string, oidc *OIDCManager, logger *slog.Logger) error {
	setDecisionAction(sender, component, decisionTemporaryAction)

	domain, valid := decisionDomain(receiver, component)
	if !valid {
		return nil
	}

	if domain == "" {
		setDecisionAction(sender, component, decisionNeutralAction)
		return nil
	}

	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return nil
	}

	id := hex.EncodeToString(random)

	namespace, action := settings.Decision.Namespace, settings.Decision.Action
	if namespace == "" {
		namespace = "mail"
	}

	if action == "" {
		action = "assess-sender-domain"
	}

	payload := map[string]any{"version": "1", "request_id": id, "target": map[string]string{"namespace": namespace, "action": action}, "resource": map[string]any{"type": "mail-domain", decisionAttributes: map[string]any{"mail.sender_domain": map[string]string{decisionStringKind: domain}}}}
	if !addDecisionAttributes(payload, receiver, component, settings.Decision.ObservationScope) {
		return nil
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	request, err := buildOutboundJSONRequest(ctx, component, receiver.GetName(), settings, string(body))
	if err != nil {
		return nil
	}

	if _, _, err = addOIDCAuth(request, receiver.GetName(), settings.BackendOIDCAuth, oidc, logger); err != nil {
		return nil
	}

	boundedClient := *client
	boundedClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	response, err := boundedClient.Do(request)
	if err != nil {
		return nil
	}

	setDecisionAction(sender, component, readDecisionResponse(response, id))

	return nil
}

// setDecisionAction encodes an allowlisted SMTP access action in each transport's framing.
func setDecisionAction(sender Sender, component, action string) {
	message := ""
	if action == postfixActionReject {
		message = "5.7.1 Sender domain rejected by policy"
	}

	if action == decisionTemporaryAction {
		message = "4.7.1 Sender domain assessment unavailable"
	}

	if component == componentSocketMap {
		sender.SetStatus("OK")
		sender.SetData(strings.TrimSpace(action + " " + message))

		return
	}

	sender.SetStatus(action)
	sender.SetData(message)
}

// addDecisionAttributes forwards explicitly typed SMTP facts without inventing socketmap context.
func addDecisionAttributes(payload map[string]any, receiver Receiver, component, scope string) bool {
	if component != componentPolicyService {
		return true
	}

	var attributes map[string]string
	if json.Unmarshal([]byte(receiver.GetKey()), &attributes) != nil {
		return false
	}

	environment := map[string]any{}

	if address := attributes["client_address"]; address != "" {
		ip, err := netip.ParseAddr(address)
		if err != nil {
			return false
		}

		environment["mail.client_ip"] = map[string]string{decisionStringKind: ip.Unmap().String()}
	}

	for _, key := range []string{"protocol_state", "instance"} {
		if value := attributes[key]; value != "" {
			environment["mail."+key] = map[string]string{decisionStringKind: value}
		}
	}

	if len(environment) > 0 {
		payload["environment"] = map[string]any{decisionAttributes: environment}
	}

	if scope != "" && attributes["protocol_state"] == "END-OF-MESSAGE" && attributes["queue_id"] != "" && attributes["instance"] != "" {
		digest := sha256.Sum256([]byte(scope + "\x00" + attributes["instance"] + "\x00" + attributes["queue_id"]))
		resource := payload["resource"].(map[string]any)[decisionAttributes].(map[string]any)
		resource["mail.observation_id"] = map[string]string{decisionStringKind: hex.EncodeToString(digest[:])}
	}

	return true
}

// decisionResponse preserves mandatory status-member presence in generic replies.
type decisionResponse struct {
	RequestID  string `json:"request_id"`
	DecisionID string `json:"decision_id"`
	Effect     string `json:"effect"`
	Status     struct {
		Code      string  `json:"code"`
		Retryable *bool   `json:"retryable"`
		Message   *string `json:"message"`
	} `json:"status"`
	Obligations []json.RawMessage `json:"obligations"`
}

// valid rejects uncorrelated, incomplete or unhandled-effect responses.
func (response decisionResponse) valid(requestID string) bool {
	return response.RequestID == requestID && response.DecisionID != "" && len(response.Obligations) == 0 && response.Status.Retryable != nil && response.Status.Message != nil && !*response.Status.Retryable
}

// decisionSender extracts a present policy sender or the literal socketmap key.
func decisionSender(receiver Receiver, component string) (string, bool) {
	sender := receiver.GetKey()

	if component == componentPolicyService {
		var attributes map[string]string
		if json.Unmarshal([]byte(sender), &attributes) != nil || attributes["request"] != "smtpd_access_policy" {
			return "", false
		}

		var exists bool

		sender, exists = attributes["sender"]
		if !exists {
			return "", false
		}
	}

	return sender, true
}

// readDecisionResponse bounds decompressed data and treats protocol failures as temporary errors.
func readDecisionResponse(response *http.Response, id string) string {
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != http.StatusOK {
		return decisionTemporaryAction
	}

	var reader io.Reader = response.Body
	if strings.EqualFold(response.Header.Get("Content-Encoding"), "gzip") {
		compressed, err := gzip.NewReader(response.Body)
		if err != nil {
			return decisionTemporaryAction
		}
		defer func() { _ = compressed.Close() }()

		reader = compressed
	}

	return decisionReply(reader, id)
}

const decisionEffectPermit = "permit"

const decisionNeutralAction = "DUNNO"

const decisionNotApplicable = "not_applicable"

const decisionAttributes = "attributes"

const decisionStringKind = "string"

// action accepts only coherent effect and status pairs.
func (response decisionResponse) action() string {
	switch response.Effect {
	case decisionEffectPermit:
		if response.Status.Code == decisionEffectPermit {
			return decisionNeutralAction
		}
	case decisionNotApplicable:
		if response.Status.Code == decisionNotApplicable || response.Status.Code == "no_applicable_rule" {
			return decisionNeutralAction
		}
	case "deny":
		if response.Status.Code == "policy_denied" || response.Status.Code == "no_match_deny" {
			return postfixActionReject
		}
	}

	return decisionTemporaryAction
}

// validMailboxParts rejects ambiguous multi-address socketmap or envelope keys.
func validMailboxParts(local, domain string, found bool) bool {
	return found && local != "" && !strings.Contains(domain, "@")
}
