package main

import (
	"encoding/json"
	"errors"
	"regexp"
	"strings"
)

// Receiver defines an interface for handling NetString data by reading it and retrieving associated properties.
type Receiver interface {
	// String returns a string representation of the implementing type.
	String() string

	// ReadNetString processes a NetData instance and populates the implementing type's data structure.
	ReadNetString(netString NetData) error

	// ReadPolcy processes the provided Policy instance and applies the Receiver's specific logic; returns an error if unsuccessful.
	ReadPolcy(policy Policy) error

	// GetName returns the name associated with the implementing Receiver.
	GetName() string

	// GetKey returns the key associated with the implementing Receiver.
	GetKey() string
}

// PostfixMapReceiver represents a receiver in a communication system, storing a name and key for message processing.
type PostfixMapReceiver struct {
	name string
	key  string
}

// String returns a string representation of the PostfixMapReceiver, combining its name and key separated by a space.
func (r *PostfixMapReceiver) String() string {
	return r.name + " " + r.key
}

// GetName retrieves the name of the PostfixMapReceiver instance.
func (r *PostfixMapReceiver) GetName() string {
	return r.name
}

// GetKey retrieves the key value from the PostfixMapReceiver instance.
func (r *PostfixMapReceiver) GetKey() string {
	return r.key
}

// ReadNetString parses the provided NetString into the PostfixMapReceiver's name and key, returning an error if invalid.
func (r *PostfixMapReceiver) ReadNetString(netString NetData) error {
	data := netString.String()
	pattern := regexp.MustCompile(`^(\S+)\s(\S+)$`)

	matches := pattern.FindStringSubmatch(data)
	if len(matches) != 3 {
		return errors.New("invalid netstring")
	}

	r.name = matches[1]
	r.key = strings.ReplaceAll(matches[2], "\"<>\"", "<>")

	return nil
}

func (r *PostfixMapReceiver) ReadPolcy(_ Policy) error {
	return nil
}

var _ Receiver = (*PostfixMapReceiver)(nil)

// NewPostfixMapReceiver creates and returns a new instance of PostfixMapReceiver which implements the Receiver interface.
func NewPostfixMapReceiver() Receiver {
	return &PostfixMapReceiver{}
}

type PostfixPolicyReceiver struct {
	name string
	data Policy
}

func (r *PostfixPolicyReceiver) String() string {
	return r.name + ": " + r.data.String()
}

func (r *PostfixPolicyReceiver) GetName() string {
	return r.name
}

func (r *PostfixPolicyReceiver) GetKey() string {
	return r.data.String()
}

func (r *PostfixPolicyReceiver) ReadNetString(_ NetData) error {
	return nil
}

func (r *PostfixPolicyReceiver) ReadPolcy(policy Policy) error {
	r.data = policy

	return nil
}

var _ Receiver = (*PostfixPolicyReceiver)(nil)

func NewPostfixPolicyReceiver(name string) Receiver {
	return &PostfixPolicyReceiver{name: name}
}

// Sender defines an interface for setting status and data for an implementation.
type Sender interface {
	// String returns a string representation of the implementing type.
	String() string

	// SetStatus sets the status value for the implementing type to the specified string.
	SetStatus(status string)

	// SetData sets the data value for the implementing type to the specified string.
	SetData(data string)
}

// PostfixSender represents a sender in the communication process, holding status and data attributes.
type PostfixSender struct {
	status string
	data   string
}

// String returns the concatenated string of the status and data fields of the PostfixSender instance, separated by a space.
func (s *PostfixSender) String() string {
	return s.status + " " + s.data
}

// SetStatus updates the status of the PostfixSender instance with the provided status string.
func (s *PostfixSender) SetStatus(status string) {
	s.status = status
}

// SetData updates the data field of the PostfixSender instance with the provided data string.
func (s *PostfixSender) SetData(data string) {
	s.data = data
}

var _ Sender = (*PostfixSender)(nil)

// NewPostfixSender creates and returns a new instance of PostfixSender implementing the Sender interface.
func NewPostfixSender() Sender {
	return &PostfixSender{}
}

// Policy defines an interface for managing key-value data with methods to set, get, and stringify the data.
type Policy interface {
	// String returns the string representation of the implemented Policy, typically combining key-value pairs into a single string.
	String() string

	// SetData sets the given key-value pair into the policy's data storage, overwriting the value if the key already exists.
	SetData(key, value string)

	// GetData retrieves all the key-value pairs stored in the policy's data as a map of strings.
	GetData() map[string]string
}

// PostfixPolicy represents a structure to hold SMTPD access policy data as key-value pairs.
type PostfixPolicy struct {
	/*
		https://www.postfix.org/SMTPD_POLICY_README.html

		request=smtpd_access_policy
		protocol_state=RCPT
		protocol_name=SMTP
		helo_name=some.domain.tld
		queue_id=8045F2AB23
		sender=foo@bar.tld
		recipient=bar@foo.tld
		recipient_count=0
		client_address=1.2.3.4
		client_name=another.domain.tld
		reverse_client_name=another.domain.tld
		instance=123.456.7
		sasl_method=plain
		sasl_username=you
		sasl_sender=
		size=12345
		ccert_subject=solaris9.porcupine.org
		ccert_issuer=Wietse+20Venema
		ccert_fingerprint=C2:9D:F4:87:71:73:73:D9:18:E7:C2:F3:C1:DA:6E:04
		encryption_protocol=TLSv1/SSLv3
		encryption_cipher=DHE-RSA-AES256-SHA
		encryption_keysize=256
		etrn_domain=
		stress=
		ccert_pubkey_fingerprint=68:B3:29:DA:98:93:E3:40:99:C7:D8:AD:5C:B9:C9:40
		client_port=1234
		policy_context=submission
		server_address=10.3.2.1
		server_port=54321
		compatibility_level=major.minor.patch
		mail_version=3.8.0}
	*/

	data map[string]string
}

// String converts the PostfixPolicy data map into a JSON string. Returns an empty string if the receiver is nil or on error.
func (p *PostfixPolicy) String() string {
	jsonData, err := json.Marshal(p.data)
	if err != nil {
		return ""
	}

	return string(jsonData)
}

// SetData sets a key-value pair in the PostfixPolicy data map.
func (p *PostfixPolicy) SetData(key, value string) {
	p.data[key] = value
}

// GetData retrieves the entire key-value map stored in the PostfixPolicy. Returns nil if the receiver is nil.
func (p *PostfixPolicy) GetData() map[string]string {
	return p.data
}

// NewPostfixPolicy creates and returns a new instance of PostfixPolicy implementing the Policy interface with an empty data map.
func NewPostfixPolicy() Policy {
	return &PostfixPolicy{
		data: make(map[string]string),
	}
}

var _ Policy = (*PostfixPolicy)(nil)
