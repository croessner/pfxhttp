package main

type NetString struct {
	length uint16
	data   []byte
}

func (ns *NetString) String() string {
	return string(ns.data)
}

func (ns *NetString) Length() uint16 {
	return ns.length
}

func (ns *NetString) Data() []byte {
	return ns.data
}

func (ns *NetString) SetData(data []byte) {
	ns.data = data
}

func (ns *NetString) SetLength(length uint16) {
	ns.length = length
}

func NewNetString(data []byte) *NetString {
	return &NetString{
		length: uint16(len(data)),
		data:   data,
	}
}

func NewNetStringFromString(data string) *NetString {
	return &NetString{
		length: uint16(len(data)),
		data:   []byte(data),
	}
}
