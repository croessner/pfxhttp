package main

import (
	"errors"
	"regexp"
)

// Receiver defines an interface for handling NetString data by reading it and retrieving associated properties.
type Receiver interface {
	// ReadNetString processes a NetString instance and populates the implementing type's data structure.
	ReadNetString(netString *NetString) error

	// GetName returns the name associated with the implementing Receiver.
	GetName() string

	// GetKey returns the key associated with the implementing Receiver.
	GetKey() string
}

// PostfixReceiver represents a receiver in a communication system, storing a name and key for message processing.
type PostfixReceiver struct {
	name string
	key  string
}

// String returns a string representation of the PostfixReceiver, combining its name and key separated by a space.
func (r *PostfixReceiver) String() string {
	return r.name + " " + r.key
}

// GetName retrieves the name of the PostfixReceiver instance.
func (r *PostfixReceiver) GetName() string {
	return r.name
}

// GetKey retrieves the key value from the PostfixReceiver instance.
func (r *PostfixReceiver) GetKey() string {
	return r.key
}

// ReadNetString parses the provided NetString into the PostfixReceiver's name and key, returning an error if invalid.
func (r *PostfixReceiver) ReadNetString(netString *NetString) error {
	data := netString.String()
	pattern := regexp.MustCompile(`^(\S+)\s(\S+)$`)

	matches := pattern.FindStringSubmatch(data)
	if len(matches) != 3 {
		return errors.New("invalid netstring")
	}

	r.name = matches[1]
	r.key = matches[2]

	return nil
}

var _ Receiver = (*PostfixReceiver)(nil)

// NewPostfixReceiver creates and returns a new instance of PostfixReceiver which implements the Receiver interface.
func NewPostfixReceiver() Receiver {
	return &PostfixReceiver{}
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
