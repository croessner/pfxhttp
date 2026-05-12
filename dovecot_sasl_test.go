package main

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestDovecotDecoderParseLine(t *testing.T) {
	decoder := &DovecotDecoder{}

	tests := []struct {
		name     string
		input    string
		wantCmd  DovecotCommand
		wantArgs string
	}{
		{
			name:     "VERSION command",
			input:    "VERSION\t1\t2\n",
			wantCmd:  DovecotCmdVersion,
			wantArgs: "1\t2",
		},
		{
			name:     "CPID command",
			input:    "CPID\t12345\n",
			wantCmd:  DovecotCmdCPID,
			wantArgs: "12345",
		},
		{
			name:     "AUTH command with params",
			input:    "AUTH\t1\tPLAIN\tservice=smtp\tresp=dGVzdA==\n",
			wantCmd:  DovecotCmdAuth,
			wantArgs: "1\tPLAIN\tservice=smtp\tresp=dGVzdA==",
		},
		{
			name:     "CONT command",
			input:    "CONT\t1\tdGVzdA==\n",
			wantCmd:  DovecotCmdCont,
			wantArgs: "1\tdGVzdA==",
		},
		{
			name:     "DONE command no args",
			input:    "DONE\n",
			wantCmd:  DovecotCmdDone,
			wantArgs: "",
		},
		{
			name:     "Case insensitive command",
			input:    "auth\t1\tPLAIN\n",
			wantCmd:  DovecotCmdAuth,
			wantArgs: "1\tPLAIN",
		},
		{
			name:     "Windows line ending",
			input:    "VERSION\t1\t2\r\n",
			wantCmd:  DovecotCmdVersion,
			wantArgs: "1\t2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd, args := decoder.ParseLine(tt.input)
			if cmd != tt.wantCmd {
				t.Errorf("ParseLine() cmd = %v, want %v", cmd, tt.wantCmd)
			}
			if args != tt.wantArgs {
				t.Errorf("ParseLine() args = %v, want %v", args, tt.wantArgs)
			}
		})
	}
}

func TestDovecotDecoderDecodeVersion(t *testing.T) {
	decoder := &DovecotDecoder{}

	tests := []struct {
		name      string
		args      string
		wantMajor int
		wantMinor int
		wantErr   bool
	}{
		{
			name:      "Valid version",
			args:      "1\t2",
			wantMajor: 1,
			wantMinor: 2,
			wantErr:   false,
		},
		{
			name:    "Missing minor",
			args:    "1",
			wantErr: true,
		},
		{
			name:    "Invalid major",
			args:    "abc\t2",
			wantErr: true,
		},
		{
			name:    "Invalid minor",
			args:    "1\txyz",
			wantErr: true,
		},
		{
			name:    "Empty",
			args:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			major, minor, err := decoder.DecodeVersion(tt.args)
			if (err != nil) != tt.wantErr {
				t.Errorf("DecodeVersion() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if major != tt.wantMajor {
					t.Errorf("DecodeVersion() major = %v, want %v", major, tt.wantMajor)
				}
				if minor != tt.wantMinor {
					t.Errorf("DecodeVersion() minor = %v, want %v", minor, tt.wantMinor)
				}
			}
		})
	}
}

func TestDovecotDecoderDecodeCPID(t *testing.T) {
	decoder := &DovecotDecoder{}

	tests := []struct {
		name    string
		args    string
		want    string
		wantErr bool
	}{
		{name: "Valid PID", args: "12345", want: "12345", wantErr: false},
		{name: "PID with whitespace", args: "  999  ", want: "999", wantErr: false},
		{name: "Empty PID", args: "", wantErr: true},
		{name: "Whitespace only", args: "   ", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decoder.DecodeCPID(tt.args)
			if (err != nil) != tt.wantErr {
				t.Errorf("DecodeCPID() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("DecodeCPID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDovecotDecoderDecodeAuthRequest(t *testing.T) {
	decoder := &DovecotDecoder{}

	// Build a base64-encoded PLAIN response: \x00user\x00pass
	plainResp := base64.StdEncoding.EncodeToString([]byte("\x00testuser\x00testpass"))

	tests := []struct {
		name    string
		args    string
		want    *DovecotAuthRequest
		wantErr bool
	}{
		{
			name: "Full AUTH request with SSL fields",
			args: "1\tPLAIN\tservice=smtp\tresp=" + plainResp + "\tlip=127.0.0.1\trip=192.168.1.1\tlport=25\trport=54321\tsecured\tlocal_name=mail.example.com\tuser=test@example.com\tno-penalty\tssl=TLSv1.3\tssl_cipher=TLS_AES_256_GCM_SHA384\tssl_cipher_bits=256\tssl_pxt_id=proxy1\tclient_id=client123",
			want: &DovecotAuthRequest{
				ID:              "1",
				Mechanism:       "PLAIN",
				Service:         "smtp",
				InitialResponse: []byte("\x00testuser\x00testpass"),
				LocalIP:         "127.0.0.1",
				RemoteIP:        "192.168.1.1",
				LocalPort:       "25",
				RemotePort:      "54321",
				Secured:         true,
				LocalName:       "mail.example.com",
				User:            "test@example.com",
				NoPenalty:       true,
				SSLProtocol:     "TLSv1.3",
				SSLCipher:       "TLS_AES_256_GCM_SHA384",
				SSLCipherBits:   "256",
				SSLPXTID:        "proxy1",
				ClientID:        "client123",
			},
			wantErr: false,
		},
		{
			name: "Minimal AUTH request",
			args: "42\tLOGIN",
			want: &DovecotAuthRequest{
				ID:        "42",
				Mechanism: "LOGIN",
			},
			wantErr: false,
		},
		{
			name: "AUTH with nologin",
			args: "1\tPLAIN\tnologin",
			want: &DovecotAuthRequest{
				ID:        "1",
				Mechanism: "PLAIN",
				NoLogin:   true,
			},
			wantErr: false,
		},
		{
			name:    "Too few fields",
			args:    "1",
			wantErr: true,
		},
		{
			name:    "Invalid base64 in resp",
			args:    "1\tPLAIN\tresp=!!!invalid!!!",
			wantErr: true,
		},
		{
			name: "Mechanism is uppercased",
			args: "1\tplain\tservice=smtp",
			want: &DovecotAuthRequest{
				ID:        "1",
				Mechanism: "PLAIN",
				Service:   "smtp",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decoder.DecodeAuthRequest(tt.args)
			if (err != nil) != tt.wantErr {
				t.Errorf("DecodeAuthRequest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if got.ID != tt.want.ID {
					t.Errorf("ID = %v, want %v", got.ID, tt.want.ID)
				}
				if got.Mechanism != tt.want.Mechanism {
					t.Errorf("Mechanism = %v, want %v", got.Mechanism, tt.want.Mechanism)
				}
				if got.Service != tt.want.Service {
					t.Errorf("Service = %v, want %v", got.Service, tt.want.Service)
				}
				if string(got.InitialResponse) != string(tt.want.InitialResponse) {
					t.Errorf("InitialResponse = %v, want %v", got.InitialResponse, tt.want.InitialResponse)
				}
				if got.LocalIP != tt.want.LocalIP {
					t.Errorf("LocalIP = %v, want %v", got.LocalIP, tt.want.LocalIP)
				}
				if got.RemoteIP != tt.want.RemoteIP {
					t.Errorf("RemoteIP = %v, want %v", got.RemoteIP, tt.want.RemoteIP)
				}
				if got.Secured != tt.want.Secured {
					t.Errorf("Secured = %v, want %v", got.Secured, tt.want.Secured)
				}
				if got.NoLogin != tt.want.NoLogin {
					t.Errorf("NoLogin = %v, want %v", got.NoLogin, tt.want.NoLogin)
				}
				if got.NoPenalty != tt.want.NoPenalty {
					t.Errorf("NoPenalty = %v, want %v", got.NoPenalty, tt.want.NoPenalty)
				}
				if got.LocalName != tt.want.LocalName {
					t.Errorf("LocalName = %v, want %v", got.LocalName, tt.want.LocalName)
				}
				if got.User != tt.want.User {
					t.Errorf("User = %v, want %v", got.User, tt.want.User)
				}
				if got.SSLProtocol != tt.want.SSLProtocol {
					t.Errorf("SSLProtocol = %v, want %v", got.SSLProtocol, tt.want.SSLProtocol)
				}
				if got.SSLCipher != tt.want.SSLCipher {
					t.Errorf("SSLCipher = %v, want %v", got.SSLCipher, tt.want.SSLCipher)
				}
				if got.SSLCipherBits != tt.want.SSLCipherBits {
					t.Errorf("SSLCipherBits = %v, want %v", got.SSLCipherBits, tt.want.SSLCipherBits)
				}
				if got.SSLPXTID != tt.want.SSLPXTID {
					t.Errorf("SSLPXTID = %v, want %v", got.SSLPXTID, tt.want.SSLPXTID)
				}
				if got.ClientID != tt.want.ClientID {
					t.Errorf("ClientID = %v, want %v", got.ClientID, tt.want.ClientID)
				}
			}
		})
	}
}

func TestDovecotDecoderDecodeAuthRequestGRPCFields(t *testing.T) {
	decoder := &DovecotDecoder{}

	got, err := decoder.DecodeAuthRequest(
		"1\tplain\tprotocol=smtp\tmethod=login\tlocal_ip=127.0.0.1\tclient_ip=192.0.2.10\tlocal_port=587\tclient_port=43124" +
			"\tclient_hostname=client.example.org\tsession=session-1\tuser_agent=Postfix/3.11\tssl=on" +
			"\tssl_session_id=tls-session\tssl_client_verify=SUCCESS\tssl_client_dn=CN=client,O=Example" +
			"\tssl_client_cn=client\tssl_issuer=Example CA\tssl_client_notbefore=20260502000000Z" +
			"\tssl_client_notafter=20270502000000Z\tssl_subject_dn=CN=server,O=Example" +
			"\tssl_issuer_dn=CN=Example CA,O=Example\tssl_client_subject_dn=CN=client,O=Example" +
			"\tssl_client_issuer_dn=CN=Example Client CA,O=Example\tssl_protocol=TLSv1.3" +
			"\tssl_cipher=TLS_AES_256_GCM_SHA384\tssl_serial=01:02:03\tssl_fingerprint=AA:BB:CC" +
			"\tclient_id=client-x\toidc_cid=oidc-client\tauth_login_attempt=3",
	)
	if err != nil {
		t.Fatalf("DecodeAuthRequest: %v", err)
	}

	if got.Mechanism != "LOGIN" || got.Service != "smtp" {
		t.Fatalf("mechanism/service mismatch: %+v", got)
	}

	if got.LocalIP != "127.0.0.1" || got.RemoteIP != "192.0.2.10" ||
		got.LocalPort != "587" || got.RemotePort != "43124" {
		t.Fatalf("address fields mismatch: %+v", got)
	}

	if got.ClientHostname != "client.example.org" ||
		got.ExternalSessionID != "session-1" ||
		got.UserAgent != "Postfix/3.11" {
		t.Fatalf("identity fields mismatch: %+v", got)
	}

	if got.SSL != "on" || got.SSLSessionID != "tls-session" || got.SSLClientVerify != "SUCCESS" {
		t.Fatalf("ssl state mismatch: %+v", got)
	}

	if got.SSLClientDN != "CN=client,O=Example" ||
		got.SSLClientCN != "client" ||
		got.SSLIssuer != "Example CA" ||
		got.SSLClientNotBefore != "20260502000000Z" ||
		got.SSLClientNotAfter != "20270502000000Z" {
		t.Fatalf("ssl client fields mismatch: %+v", got)
	}

	if got.SSLSubjectDN != "CN=server,O=Example" ||
		got.SSLIssuerDN != "CN=Example CA,O=Example" ||
		got.SSLClientSubjectDN != "CN=client,O=Example" ||
		got.SSLClientIssuerDN != "CN=Example Client CA,O=Example" {
		t.Fatalf("ssl DN fields mismatch: %+v", got)
	}

	if got.SSLProtocol != "TLSv1.3" ||
		got.SSLCipher != "TLS_AES_256_GCM_SHA384" ||
		got.SSLSerial != "01:02:03" ||
		got.SSLFingerprint != "AA:BB:CC" {
		t.Fatalf("ssl protocol/material mismatch: %+v", got)
	}

	if got.ClientID != "client-x" || got.OIDCCID != "oidc-client" || got.AuthLoginAttempt != 3 {
		t.Fatalf("client/oidc fields mismatch: %+v", got)
	}
}

func TestDovecotDecoderDecodeContRequest(t *testing.T) {
	decoder := &DovecotDecoder{}

	tests := []struct {
		name    string
		args    string
		wantID  string
		wantErr bool
	}{
		{
			name:    "Valid CONT",
			args:    "1\t" + base64.StdEncoding.EncodeToString([]byte("testdata")),
			wantID:  "1",
			wantErr: false,
		},
		{
			name:    "Missing data",
			args:    "1",
			wantErr: true,
		},
		{
			name:    "Invalid base64",
			args:    "1\t!!!invalid!!!",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decoder.DecodeContRequest(tt.args)
			if (err != nil) != tt.wantErr {
				t.Errorf("DecodeContRequest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if got.ID != tt.wantID {
					t.Errorf("ID = %v, want %v", got.ID, tt.wantID)
				}
				if string(got.Data) != "testdata" {
					t.Errorf("Data = %v, want %v", string(got.Data), "testdata")
				}
			}
		})
	}
}

func TestEnsureDovecotAuthExternalSessionID(t *testing.T) {
	const callerSessionID = "from-client"

	t.Run("keeps caller value", func(t *testing.T) {
		req := &DovecotAuthRequest{ExternalSessionID: callerSessionID}

		ensureDovecotAuthExternalSessionID(req, "from-pfxhttp")

		if req.ExternalSessionID != callerSessionID {
			t.Fatalf("ExternalSessionID = %q, want caller value", req.ExternalSessionID)
		}
	})

	t.Run("uses fallback", func(t *testing.T) {
		req := &DovecotAuthRequest{}

		ensureDovecotAuthExternalSessionID(req, "from-pfxhttp")

		if req.ExternalSessionID != "from-pfxhttp" {
			t.Fatalf("ExternalSessionID = %q, want fallback", req.ExternalSessionID)
		}
	})

	t.Run("ignores empty fallback", func(t *testing.T) {
		req := &DovecotAuthRequest{}

		ensureDovecotAuthExternalSessionID(req, "")

		if req.ExternalSessionID != "" {
			t.Fatalf("ExternalSessionID = %q, want empty", req.ExternalSessionID)
		}
	})
}

func TestDovecotEncoderEncodeHandshake(t *testing.T) {
	encoder := &DovecotEncoder{}

	hs := &DovecotHandshake{
		Mechanisms: []DovecotMechanism{
			{Name: "PLAIN", PlainText: true, Dictionary: true, Active: true},
			{Name: "LOGIN", PlainText: true, Dictionary: true, Active: true},
			{Name: "XOAUTH2", ForwardSecrecy: true},
		},
		SPID:   "1234",
		CUID:   "1",
		Cookie: "abcdef0123456789",
	}

	lines := encoder.EncodeHandshake(hs)

	if len(lines) != 8 {
		t.Fatalf("Expected 8 handshake lines, got %d", len(lines))
	}

	if lines[0] != "VERSION\t1\t2\n" {
		t.Errorf("Line 0 = %q, want VERSION line", lines[0])
	}

	if !strings.Contains(lines[1], "MECH\tPLAIN\tplaintext\tdictionary\tactive") {
		t.Errorf("Line 1 = %q, want PLAIN mechanism with flags", lines[1])
	}

	if !strings.Contains(lines[2], "MECH\tLOGIN\tplaintext\tdictionary\tactive") {
		t.Errorf("Line 2 = %q, want LOGIN mechanism with flags", lines[2])
	}

	if lines[3] != "MECH\tXOAUTH2\tforward-secrecy\n" {
		t.Errorf("Line 3 = %q, want XOAUTH2 mechanism with forward-secrecy", lines[3])
	}

	if lines[4] != "SPID\t1234\n" {
		t.Errorf("Line 4 = %q, want SPID", lines[4])
	}

	if lines[5] != "CUID\t1\n" {
		t.Errorf("Line 5 = %q, want CUID", lines[5])
	}

	if lines[6] != "COOKIE\tabcdef0123456789\n" {
		t.Errorf("Line 6 = %q, want COOKIE", lines[6])
	}

	if lines[7] != "DONE\n" {
		t.Errorf("Line 7 = %q, want DONE", lines[7])
	}
}

func TestDovecotEncoderEncodeOK(t *testing.T) {
	encoder := &DovecotEncoder{}

	tests := []struct {
		name     string
		id       string
		username string
		want     string
	}{
		{
			name:     "With username",
			id:       "1",
			username: "user@example.com",
			want:     "OK\t1\tuser=user@example.com\n",
		},
		{
			name:     "Without username",
			id:       "42",
			username: "",
			want:     "OK\t42\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := encoder.EncodeOK(tt.id, tt.username)
			if got != tt.want {
				t.Errorf("EncodeOK() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDovecotEncoderEncodeFail(t *testing.T) {
	encoder := &DovecotEncoder{}

	tests := []struct {
		name     string
		id       string
		reason   string
		username string
		temp     bool
		want     string
	}{
		{
			name:     "Simple failure",
			id:       "1",
			reason:   "bad password",
			username: "",
			temp:     false,
			want:     "FAIL\t1\treason=bad password\n",
		},
		{
			name:     "Temporary failure with user",
			id:       "2",
			reason:   "backend down",
			username: "user@test.com",
			temp:     true,
			want:     "FAIL\t2\treason=backend down\tuser=user@test.com\ttemp\n",
		},
		{
			name:     "No reason no user",
			id:       "3",
			reason:   "",
			username: "",
			temp:     false,
			want:     "FAIL\t3\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := encoder.EncodeFail(tt.id, tt.reason, tt.username, tt.temp)
			if got != tt.want {
				t.Errorf("EncodeFail() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDovecotEncoderEncodeCont(t *testing.T) {
	encoder := &DovecotEncoder{}

	data := []byte("Username:")
	got := encoder.EncodeCont("1", data)

	expected := "CONT\t1\t" + base64.StdEncoding.EncodeToString(data) + "\n"
	if got != expected {
		t.Errorf("EncodeCont() = %q, want %q", got, expected)
	}
}

func TestDovecotEncoderEncodeContEmptyData(t *testing.T) {
	encoder := &DovecotEncoder{}

	got := encoder.EncodeCont("5", []byte{})
	expected := "CONT\t5\t\n"
	if got != expected {
		t.Errorf("EncodeCont() empty = %q, want %q", got, expected)
	}
}

func TestDovecotRoundTrip(t *testing.T) {
	// Test that encoding and decoding a handshake produces consistent results
	encoder := &DovecotEncoder{}
	decoder := &DovecotDecoder{}

	hs := &DovecotHandshake{
		Mechanisms: []DovecotMechanism{
			{Name: "PLAIN", PlainText: true},
		},
		SPID:   "999",
		CUID:   "42",
		Cookie: "deadbeef",
	}

	lines := encoder.EncodeHandshake(hs)

	// Parse VERSION line
	cmd, args := decoder.ParseLine(lines[0])
	if cmd != DovecotCmdVersion {
		t.Errorf("Expected VERSION, got %v", cmd)
	}
	major, minor, err := decoder.DecodeVersion(args)
	if err != nil {
		t.Fatalf("DecodeVersion error: %v", err)
	}
	if major != DovecotProtoVersionMajor || minor != DovecotProtoVersionMinor {
		t.Errorf("Version = %d.%d, want %d.%d", major, minor, DovecotProtoVersionMajor, DovecotProtoVersionMinor)
	}

	// Parse MECH line
	cmd, _ = decoder.ParseLine(lines[1])
	if cmd != DovecotCmdMech {
		t.Errorf("Expected MECH, got %v", cmd)
	}

	// Parse DONE line
	cmd, _ = decoder.ParseLine(lines[len(lines)-1])
	if cmd != DovecotCmdDone {
		t.Errorf("Expected DONE, got %v", cmd)
	}
}
