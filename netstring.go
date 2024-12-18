package main

// NetData represents an interface for network data with methods to retrieve its string representation,
// length, and raw bytes.
type NetData interface {
	// String returns the string representation of the data contained in the implementing type.
	String() string

	// Length returns the length of the data as a 16-bit unsigned integer.
	Length() uint16

	// Data retrieves the raw byte slice representing the network data.
	Data() []byte
}

// NetString represents a data structure composed of a length-prefixed byte slice for network communication.
// The length field, stored as a uint16, designates the size of the byte slice data.
// This type is used to serialize and deserialize structured data in a network-friendly format.
type NetString struct {
	length uint16
	data   []byte
}

// String returns the string representation of the NetString's data field, converting it from a byte slice to a string.
func (ns *NetString) String() string {
	return string(ns.data)
}

// Length returns the length of the NetString's data as a uint16 value.
func (ns *NetString) Length() uint16 {
	return ns.length
}

// Data returns the byte slice data stored in the NetString.
func (ns *NetString) Data() []byte {
	return ns.data
}

var _ NetData = (*NetString)(nil)

// NewNetString creates and initializes a new NetString instance with the provided byte slice data.
// The length of the data is automatically computed and stored in the length field.
func NewNetString(data []byte) *NetString {
	return &NetString{
		length: uint16(len(data)),
		data:   data,
	}
}

// NewNetStringFromString creates a new NetString instance from the given string data,
// setting its length and byte slice data.
func NewNetStringFromString(data string) NetData {
	return &NetString{
		length: uint16(len(data)),
		data:   []byte(data),
	}
}
