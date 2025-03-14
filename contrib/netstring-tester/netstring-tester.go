package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

func main() {
	fmt.Println("Netstring client")

	// Parse command-line flags
	address := flag.String("address", "", "The socket address (e.g., ':8080' for TCP or '/tmp/socket' for UNIX)")
	protocol := flag.String("protocol", "tcp", "The protocol to use: tcp, tcp6, or unix")
	key := flag.String("key", "", "The 'key' part of the Netstring payload")
	value := flag.String("value", "", "The 'value' part of the Netstring payload")

	flag.Parse()

	if *address == "" || *protocol == "" || *key == "" || *value == "" {
		fmt.Println("Usage: -address <socket-address> -protocol <tcp|tcp6|unix> -key <key> -value <value>")

		os.Exit(1)
	}

	// Create connection
	conn, err := net.Dial(*protocol, *address)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Failed to connect: %s\n", err)

		os.Exit(1)
	}

	defer func(conn net.Conn) {
		_ = conn.Close()
	}(conn)

	fmt.Println("Connected successfully!")

	// Prepare Netstring
	payload := fmt.Sprintf("%s %s", *key, *value)
	netString := fmt.Sprintf("%d:%s,", len(payload), payload)

	// Send Netstring
	_, err = conn.Write([]byte(netString))
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Failed to send Netstring: %s\n", err)

		os.Exit(1)
	}

	fmt.Println("Netstring sent successfully!")

	// Read response
	reader := bufio.NewReader(conn)

	// Read the length part of the Netstring (up to ":")
	lengthPart, err := reader.ReadString(':')
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error while reading response length: %s\n", err)

		os.Exit(1)
	}

	// Parse the length as an integer
	lengthStr := strings.TrimSuffix(lengthPart, ":")
	payloadLength, err := strconv.Atoi(lengthStr)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Invalid length format: %s\n", lengthStr)

		os.Exit(1)
	}

	// Read the specified number of bytes (the payload)
	payloadBytes := make([]byte, payloadLength)
	_, err = reader.Read(payloadBytes)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error while reading response payload: %s\n", err)

		os.Exit(1)
	}

	// Read the trailing comma (to complete the Netstring)
	trailingChar, err := reader.ReadByte()
	if err != nil || trailingChar != ',' {
		_, _ = fmt.Fprintf(os.Stderr, "Error while reading final comma or invalid Netstring format\n")

		os.Exit(1)
	}

	// Print the received payload
	fmt.Printf("Received response payload: %s\n", string(payloadBytes))

	os.Exit(0)
}
