package main

import (
	"errors"
	"regexp"
)

type PostfixReceiver struct {
	name string
	key  string
}

func (r *PostfixReceiver) String() string {
	return r.name + " " + r.key
}

func (r *PostfixReceiver) GetName() string {
	return r.name
}
func (r *PostfixReceiver) GetKey() string {
	return r.key
}

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

func NewPostfixReceiver() *PostfixReceiver {
	return &PostfixReceiver{}
}

type PostfixSender struct {
	status string
	data   string
}

func (s *PostfixSender) String() string {
	return s.status + " " + s.data
}

func (s *PostfixSender) SetStatus(status string) {
	s.status = status
}

func (s *PostfixSender) SetData(data string) {
	s.data = data
}

func NewPostfixSender() *PostfixSender {
	return &PostfixSender{}
}
