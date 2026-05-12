package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Dovecot SASL Protocol Implementation
//
// This file implements the Dovecot authentication protocol as used by Postfix
// when configured with smtpd_sasl_type = dovecot. The protocol is a line-based
// text protocol communicated over a Unix domain socket.
//
// Protocol Overview:
//
// The Dovecot auth protocol consists of multiple phases:
//
// 1. Handshake Phase:
//    - Server sends: VERSION <major> <minor>
//    - Server sends: MECH <mechanism> [plain] [anonymous]
//    - Server sends: SPID <pid>
//    - Server sends: CUID <id>
//    - Server sends: COOKIE <cookie>
//    - Server sends: DONE
//    - Client sends: VERSION <major> <minor>
//    - Client sends: CPID <pid>
//
// 2. Authentication Phase:
//    - Client sends: AUTH <id> <mechanism> service=<service> [resp=<base64>] [lip=<local-ip>] [rip=<remote-ip>] [lport=<port>] [rport=<port>] [local_name=<name>] [user=<name>] [secured] [nologin] [no-penalty] [ssl=<protocol>] [ssl_cipher=<name>] [ssl_cipher_bits=<bits>] [ssl_pxt_id=<id>] [client_id=<id>]
//    - Server responds with one of:
//      - OK <id> [user=<username>]
//      - FAIL <id> [reason=<reason>] [user=<username>] [temp]
//      - CONT <id> <base64-data>
//
// 3. Continuation (for multi-step mechanisms like LOGIN):
//    - Client sends: CONT <id> <base64-data>
//    - Server responds with OK, FAIL, or another CONT
//
// Protocol Version: 1.2
//
// References:
//   - Postfix SASL README (smtpd_sasl_type = dovecot)
//   - Postfix source: src/xsasl/xsasl_dovecot.c (implementation of the client side)
//   - Dovecot source: src/auth/auth-request.c, src/auth/auth-worker-client.c (implementation of the server side)
//   - Dovecot protocol documentation: https://github.com/dovecot/core/blob/main/doc/wiki/Design.AuthProtocol.txt (as the web doc is unstable)

const (
	// DovecotProtoVersionMajor is the major protocol version supported.
	DovecotProtoVersionMajor = 1

	// DovecotProtoVersionMinor is the minor protocol version supported.
	DovecotProtoVersionMinor = 2
)

// DovecotCommand represents the type of a Dovecot auth protocol command.
type DovecotCommand string

const (
	// Handshake commands
	DovecotCmdVersion DovecotCommand = "VERSION"
	DovecotCmdMech    DovecotCommand = "MECH"
	DovecotCmdSPID    DovecotCommand = "SPID"
	DovecotCmdCUID    DovecotCommand = "CUID"
	DovecotCmdCookie  DovecotCommand = "COOKIE"
	DovecotCmdDone    DovecotCommand = "DONE"
	DovecotCmdCPID    DovecotCommand = "CPID"

	// Authentication commands
	DovecotCmdAuth DovecotCommand = "AUTH"
	DovecotCmdCont DovecotCommand = "CONT"

	// Response commands
	DovecotCmdOK   DovecotCommand = "OK"
	DovecotCmdFail DovecotCommand = "FAIL"
)

// DovecotMechanism represents a SASL mechanism with its properties.
type DovecotMechanism struct {
	// Name is the SASL mechanism name (e.g., "PLAIN", "LOGIN").
	Name string

	// PlainText indicates if the mechanism transmits credentials in plain text.
	PlainText bool

	// Anonymous indicates if the mechanism supports anonymous authentication.
	Anonymous bool

	// Dictionary indicates if the mechanism is subject to passive dictionary attacks.
	Dictionary bool

	// Active indicates if the mechanism is subject to active attacks.
	Active bool

	// ForwardSecrecy indicates if the mechanism supports forward secrecy.
	ForwardSecrecy bool

	// MutualAuth indicates if the mechanism supports mutual authentication.
	MutualAuth bool
}

// DovecotAuthRequest represents a parsed AUTH command from a client.
type DovecotAuthRequest struct {
	// ID is the unique request identifier assigned by the client.
	ID string

	// Mechanism is the SASL mechanism name requested (e.g., "PLAIN", "LOGIN").
	Mechanism string

	// Service is the service name (e.g., "smtp", "imap").
	Service string

	// InitialResponse is the base64-decoded initial response (from resp= parameter).
	InitialResponse []byte

	// LocalIP is the local IP address of the connection.
	LocalIP string

	// RemoteIP is the remote IP address of the client.
	RemoteIP string

	// LocalPort is the local port of the connection.
	LocalPort string

	// RemotePort is the remote port of the client.
	RemotePort string

	// LocalName is the local hostname.
	LocalName string

	// ClientHostname is the remote/client hostname when provided explicitly.
	ClientHostname string

	// User is the username.
	User string

	// ExternalSessionID is an optional caller-provided session/correlation ID.
	ExternalSessionID string

	// UserAgent identifies the upstream client if provided.
	UserAgent string

	// Secured indicates if the connection is secured (TLS).
	Secured bool

	// SSL is the backend SSL indicator value when provided directly.
	SSL string

	// NoLogin indicates the nologin flag was set. This is used by Dovecot's auth
	// clients (like Postfix) to check if a user exists and is eligible for login
	// without actually performing a login or updating last login timestamps.
	NoLogin bool

	// NoPenalty indicates the no-penalty flag was set. This tells the auth server
	// to skip any penalty logic (like artificial delays or IP blocking) that
	// would normally be applied on authentication failure.
	NoPenalty bool

	// SSLProtocol is the SSL protocol name (e.g., TLSv1.3).
	SSLProtocol string

	// SSLCipher is the SSL cipher name.
	SSLCipher string

	// SSLCipherBits is the number of bits used in the SSL cipher.
	SSLCipherBits string

	// SSLPXTID is the SSL proxy client ID.
	SSLPXTID string

	// SSLSessionID is the TLS session ID when provided by the client.
	SSLSessionID string

	// SSLClientVerify is the TLS client certificate verification result.
	SSLClientVerify string

	// SSLClientDN is the TLS client certificate DN.
	SSLClientDN string

	// SSLClientCN is the TLS client certificate common name.
	SSLClientCN string

	// SSLIssuer is the TLS certificate issuer.
	SSLIssuer string

	// SSLClientNotBefore is the client certificate not-before timestamp.
	SSLClientNotBefore string

	// SSLClientNotAfter is the client certificate not-after timestamp.
	SSLClientNotAfter string

	// SSLSubjectDN is the TLS certificate subject DN.
	SSLSubjectDN string

	// SSLIssuerDN is the TLS certificate issuer DN.
	SSLIssuerDN string

	// SSLClientSubjectDN is the client certificate subject DN.
	SSLClientSubjectDN string

	// SSLClientIssuerDN is the client certificate issuer DN.
	SSLClientIssuerDN string

	// SSLSerial is the TLS certificate serial number.
	SSLSerial string

	// SSLFingerprint is the TLS certificate fingerprint.
	SSLFingerprint string

	// ClientID is the client ID.
	ClientID string

	// OIDCCID is the OIDC client ID/correlation value when provided.
	OIDCCID string

	// AuthLoginAttempt counts the current login attempt when provided.
	AuthLoginAttempt uint32
}

// ensureDovecotAuthExternalSessionID keeps caller-provided correlation IDs
// authoritative and uses the local pfxhttp connection session only as a fallback.
func ensureDovecotAuthExternalSessionID(req *DovecotAuthRequest, fallbackSessionID string) {
	if req == nil || req.ExternalSessionID != "" || fallbackSessionID == "" {
		return
	}

	req.ExternalSessionID = fallbackSessionID
}

// DovecotContRequest represents a parsed CONT command from a client.
type DovecotContRequest struct {
	// ID is the request identifier matching the original AUTH request.
	ID string

	// Data is the base64-decoded continuation data.
	Data []byte
}

// DovecotHandshake holds the parameters for the server handshake.
type DovecotHandshake struct {
	// Mechanisms is the list of supported SASL mechanisms.
	Mechanisms []DovecotMechanism

	// SPID is the server process ID.
	SPID string

	// CUID is the connection unique ID.
	CUID string

	// Cookie is the authentication cookie.
	Cookie string
}

// DovecotDecoder decodes Dovecot auth protocol messages from line-based input.
//
// The decoder is responsible for parsing incoming protocol lines into structured
// Go types. It handles both handshake commands (VERSION, CPID) and authentication
// commands (AUTH, CONT).
//
// Usage:
//
//	decoder := &DovecotDecoder{}
//	cmd, args := decoder.ParseLine("AUTH\t1\tPLAIN\tservice=smtp\tresp=dGVzdA==")
//	if cmd == DovecotCmdAuth {
//	    authReq, err := decoder.DecodeAuthRequest(args)
//	    // handle authReq
//	}
type DovecotDecoder struct{}

// ParseLine splits a protocol line into the command and its arguments.
// The Dovecot protocol uses tab-separated fields.
// Returns the command type and the remaining argument string.
func (d *DovecotDecoder) ParseLine(line string) (DovecotCommand, string) {
	line = strings.TrimSpace(line)
	if line == "" {
		return "", ""
	}

	parts := strings.SplitN(line, "\t", 2)
	cmd := DovecotCommand(strings.ToUpper(parts[0]))

	if len(parts) > 1 {
		return cmd, parts[1]
	}

	return cmd, ""
}

// DecodeVersion parses a VERSION command arguments string.
// Expected format: "<major>\t<minor>"
// Returns major version, minor version, and any error.
func (d *DovecotDecoder) DecodeVersion(args string) (int, int, error) {
	parts := strings.SplitN(args, "\t", 2)
	if len(parts) != 2 {
		return 0, 0, errors.New("invalid VERSION format: expected major and minor")
	}

	var major, minor int

	_, err := fmt.Sscanf(parts[0], "%d", &major)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid major version: %w", err)
	}

	_, err = fmt.Sscanf(parts[1], "%d", &minor)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid minor version: %w", err)
	}

	return major, minor, nil
}

// DecodeCPID parses a CPID command arguments string.
// Expected format: "<pid>"
// Returns the client process ID string.
func (d *DovecotDecoder) DecodeCPID(args string) (string, error) {
	pid := strings.TrimSpace(args)
	if pid == "" {
		return "", errors.New("empty CPID")
	}

	return pid, nil
}

// DecodeAuthRequest parses an AUTH command arguments string into a DovecotAuthRequest.
// Expected format: "<id>\t<mechanism>\t[param=value\t...]"
// Parameters include Dovecot/Postfix names such as service=, user=, resp=,
// lip=, rip=, lport=, rport=, local_name=, secured, nologin, no-penalty,
// ssl=, ssl_cipher=, ssl_cipher_bits=, ssl_pxt_id=, client_id=, and direct
// Nauthilus AuthService names such as client_ip=, local_ip=,
// external_session_id=, user_agent=, ssl_session_id=, ssl_client_verify=,
// ssl_client_dn=, oidc_cid=, and auth_login_attempt=.
//
// Postfix Source Reference (xsasl_dovecot.c):
// - xsasl_dovecot_server_first() and xsasl_dovecot_server_next() construct this command.
// - Parameters are added based on the connection state (e.g., vstream_getpeername, etc.).
func (d *DovecotDecoder) DecodeAuthRequest(args string) (*DovecotAuthRequest, error) {
	parts := strings.Split(args, "\t")
	if len(parts) < 2 {
		return nil, errors.New("AUTH requires at least id and mechanism")
	}

	req := &DovecotAuthRequest{
		ID:        parts[0],
		Mechanism: strings.ToUpper(parts[1]),
	}

	for _, param := range parts[2:] {
		key, value, hasValue := strings.Cut(param, "=")
		switch key {
		case "service":
			req.Service = value
		case "protocol":
			req.Service = value
		case "method":
			req.Mechanism = strings.ToUpper(value)
		case "resp":
			if hasValue {
				decoded, err := base64.StdEncoding.DecodeString(value)
				if err != nil {
					return nil, fmt.Errorf("invalid base64 in resp: %w", err)
				}

				req.InitialResponse = decoded
			}
		case "lip":
			req.LocalIP = value
		case "local_ip":
			req.LocalIP = value
		case "rip":
			req.RemoteIP = value
		case "client_ip":
			req.RemoteIP = value
		case "lport":
			req.LocalPort = value
		case "local_port":
			req.LocalPort = value
		case "rport":
			req.RemotePort = value
		case "client_port":
			req.RemotePort = value
		case "local_name":
			req.LocalName = value
		case "client_hostname":
			req.ClientHostname = value
		case "user":
			req.User = value
		case "external_session_id", "session":
			req.ExternalSessionID = value
		case "user_agent":
			req.UserAgent = value
		case "secured":
			req.Secured = true
		case "nologin":
			req.NoLogin = true
		case "no-penalty":
			req.NoPenalty = true
		case "ssl":
			if isTLSProtocolName(value) {
				req.SSLProtocol = value
			} else {
				req.SSL = value
			}
		case "ssl_session_id":
			req.SSLSessionID = value
		case "ssl_client_verify":
			req.SSLClientVerify = value
		case "ssl_client_dn":
			req.SSLClientDN = value
		case "ssl_client_cn":
			req.SSLClientCN = value
		case "ssl_issuer":
			req.SSLIssuer = value
		case "ssl_client_notbefore":
			req.SSLClientNotBefore = value
		case "ssl_client_notafter":
			req.SSLClientNotAfter = value
		case "ssl_subject_dn":
			req.SSLSubjectDN = value
		case "ssl_issuer_dn":
			req.SSLIssuerDN = value
		case "ssl_client_subject_dn":
			req.SSLClientSubjectDN = value
		case "ssl_client_issuer_dn":
			req.SSLClientIssuerDN = value
		case "ssl_cipher":
			req.SSLCipher = value
		case "ssl_cipher_bits":
			req.SSLCipherBits = value
		case "ssl_pxt_id":
			req.SSLPXTID = value
		case "ssl_protocol":
			req.SSLProtocol = value
		case "ssl_serial":
			req.SSLSerial = value
		case "ssl_fingerprint":
			req.SSLFingerprint = value
		case "client_id":
			req.ClientID = value
		case "oidc_cid":
			req.OIDCCID = value
		case "auth_login_attempt":
			if value == "" {
				continue
			}

			attempt, err := strconv.ParseUint(value, 10, 32)
			if err != nil {
				return nil, fmt.Errorf("invalid auth_login_attempt: %w", err)
			}

			req.AuthLoginAttempt = uint32(attempt)
		}
	}

	return req, nil
}

func isTLSProtocolName(value string) bool {
	v := strings.ToUpper(value)

	return strings.HasPrefix(v, "TLS") || strings.HasPrefix(v, "SSL")
}

// DecodeContRequest parses a CONT command arguments string into a DovecotContRequest.
// Expected format: "<id>\t<base64-data>"
//
// Postfix Source Reference (xsasl_dovecot.c):
// - xsasl_dovecot_server_next() handles multi-step authentication by sending CONT.
func (d *DovecotDecoder) DecodeContRequest(args string) (*DovecotContRequest, error) {
	parts := strings.SplitN(args, "\t", 2)
	if len(parts) < 2 {
		return nil, errors.New("CONT requires id and data")
	}

	decoded, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid base64 in CONT data: %w", err)
	}

	return &DovecotContRequest{
		ID:   parts[0],
		Data: decoded,
	}, nil
}

// DovecotEncoder encodes Dovecot auth protocol messages into line-based output.
//
// The encoder produces protocol-compliant lines for both server handshake
// messages and authentication responses. All lines are terminated with a
// newline character.
//
// Usage:
//
//	encoder := &DovecotEncoder{}
//	lines := encoder.EncodeHandshake(handshake)
//	for _, line := range lines {
//	    conn.Write([]byte(line))
//	}
type DovecotEncoder struct{}

// EncodeHandshake generates the complete server handshake sequence.
// The handshake includes VERSION, MECH (for each mechanism), SPID, CUID, COOKIE, and DONE lines.
// Returns a slice of protocol lines ready to be written to the connection.
//
// Postfix Source Reference (xsasl_dovecot.c):
//   - xsasl_dovecot_init() and xsasl_dovecot_server_create() expect this handshake
//     to negotiate supported mechanisms and protocol version.
func (e *DovecotEncoder) EncodeHandshake(hs *DovecotHandshake) []string {
	lines := make([]string, 0, len(hs.Mechanisms)+5)

	lines = append(lines, fmt.Sprintf("%s\t%d\t%d\n", DovecotCmdVersion, DovecotProtoVersionMajor, DovecotProtoVersionMinor))

	for _, mech := range hs.Mechanisms {
		mechLine := string(DovecotCmdMech) + "\t" + mech.Name
		if mech.PlainText {
			mechLine += "\tplaintext"
		}
		if mech.Anonymous {
			mechLine += "\tanonymous"
		}
		if mech.Dictionary {
			mechLine += "\tdictionary"
		}
		if mech.Active {
			mechLine += "\tactive"
		}
		if mech.ForwardSecrecy {
			mechLine += "\tforward-secrecy"
		}
		if mech.MutualAuth {
			mechLine += "\tmutual-auth"
		}

		lines = append(lines, mechLine+"\n")
	}

	lines = append(lines,
		fmt.Sprintf("%s\t%s\n", DovecotCmdSPID, hs.SPID),
		fmt.Sprintf("%s\t%s\n", DovecotCmdCUID, hs.CUID),
		fmt.Sprintf("%s\t%s\n", DovecotCmdCookie, hs.Cookie),
		string(DovecotCmdDone)+"\n",
	)

	return lines
}

// EncodeOK encodes a successful authentication response.
// Format: "OK\t<id>\tuser=<username>\n"
//
// Postfix Source Reference (xsasl_dovecot.c):
// - xsasl_dovecot_parse_reply() parses this response to finalize authentication.
func (e *DovecotEncoder) EncodeOK(id string, username string) string {
	if username != "" {
		return fmt.Sprintf("%s\t%s\tuser=%s\n", DovecotCmdOK, id, username)
	}

	return fmt.Sprintf("%s\t%s\n", DovecotCmdOK, id)
}

// EncodeFail encodes a failed authentication response.
// Format: "FAIL\t<id>\t[reason=<reason>]\t[user=<username>]\t[temp]\n"
// If temp is true, the failure is marked as temporary, signaling the client may retry.
//
// Postfix Source Reference (xsasl_dovecot.c):
// - xsasl_dovecot_parse_reply() handles "FAIL" and maps "temp" to XSASL_AUTH_STAT_TEMP.
func (e *DovecotEncoder) EncodeFail(id string, reason string, username string, temp bool) string {
	line := string(DovecotCmdFail) + "\t" + id

	if reason != "" {
		line += "\treason=" + reason
	}

	if username != "" {
		line += "\tuser=" + username
	}

	if temp {
		line += "\ttemp"
	}

	return line + "\n"
}

// EncodeCont encodes a continuation challenge for multi-step authentication.
// The data is base64-encoded before being included in the protocol line.
// Format: "CONT\t<id>\t<base64-data>\n"
//
// Postfix Source Reference (xsasl_dovecot.c):
// - xsasl_dovecot_parse_reply() handles "CONT" for mechanisms like LOGIN.
func (e *DovecotEncoder) EncodeCont(id string, data []byte) string {
	encoded := base64.StdEncoding.EncodeToString(data)

	return fmt.Sprintf("%s\t%s\t%s\n", DovecotCmdCont, id, encoded)
}
