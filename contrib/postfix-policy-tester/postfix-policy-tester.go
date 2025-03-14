package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
)

func main() {
	fmt.Println("Postfix Policy Client")

	// Parse command-line flags
	address := flag.String("address", "", "The socket address (e.g., ':8080' for TCP or '/tmp/socket' for UNIX)")
	protocol := flag.String("protocol", "tcp", "The protocol to use: tcp, tcp6, or unix")

	flag.Parse()

	if *address == "" || *protocol == "" {
		fmt.Println("Usage: -address <socket-address> -protocol <tcp|tcp6|unix>")

		os.Exit(1)
	}

	// Establish a connection to the policy server
	conn, err := net.Dial(*protocol, *address)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Failed to connect: %s\n", err)

		os.Exit(1)
	}

	defer func(conn net.Conn) {
		_ = conn.Close()
	}(conn)

	fmt.Println("Connected successfully!")

	// Collect policy data fields from the user
	policyData := askPolicyFields()

	// Send the collected policy data to the server
	sendPolicyRequest(conn, policyData)

	// Read and display the response from the server
	readPolicyResponse(conn)
}

// Ask for user input with a prompt and return the entered string
func askInput(prompt string) string {
	fmt.Print(prompt + " ")
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()

	return strings.TrimSpace(scanner.Text())
}

// Gather all required Postfix Policy fields from the user one by one
func askPolicyFields() []string {
	var data []string

	fmt.Println("Please provide the Postfix policy request details.")

	// Define fields in the order we want
	fieldOrder := []string{
		"request",
		"protocol_state",
		"protocol_name",
		"queue_id",
		"sender",
		"size",
		"recipient",
		"client_address",
		"client_name",
		"reverse_client_name",
		"instance",
		"sasl_method",
		"sasl_username",
		"sasl_sender",
		"stress",
		"ccert_subject",
		"ccert_issuer",
		"ccert_fingerprint",
	}

	// Define fields to be collected (field name and its description)
	fieldDescriptions := map[string]string{
		"request":             "Request type (usually: smtpd_access_policy):",
		"protocol_state":      "Protocol state (e.g., RCPT):",
		"protocol_name":       "Protocol name (e.g., ESMTP):",
		"queue_id":            "Queue ID (in format e.g., ABC123DEF456):",
		"sender":              "Sender email address (e.g., user@example.com):",
		"size":                "Message size (in bytes):",
		"recipient":           "Recipient email address (e.g., recipient@example.com):",
		"client_address":      "Client IP address (e.g., 192.168.0.1):",
		"client_name":         "Client hostname (e.g., mail.example.com):",
		"reverse_client_name": "Reverse client hostname (e.g., example.com):",
		"instance":            "Instance name or ID of the postfix daemon:",
		"sasl_method":         "SASL authentication method (if any):",
		"sasl_username":       "SASL authenticated username (if any):",
		"sasl_sender":         "SASL sender address (if any):",
		"stress":              "Stress factor (optional):",
		"ccert_subject":       "Certificate subject (if applicable):",
		"ccert_issuer":        "Certificate issuer (if applicable):",
		"ccert_fingerprint":   "Certificate fingerprint (if applicable):",
	}

	// Loop through each defined field and ask the user for input
	for _, field := range fieldOrder {
		prompt := fieldDescriptions[field]

		value := askInput(prompt)
		if value != "" {
			// Add key=value pair to the data if it's not empty
			data = append(data, fmt.Sprintf("%s=%s", field, value))
		}
	}

	// Return the collected policy fields
	return data
}

// Sends the Postfix Policy request to the server line by line
func sendPolicyRequest(conn net.Conn, policyData []string) {
	writer := bufio.NewWriter(conn)

	// Write each line of data to the socket
	for _, line := range policyData {
		_, err := writer.WriteString(line + "\n")
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Error sending request: %s\n", err)

			os.Exit(1)
		}
	}

	// Write a blank line to indicate the end of the request
	_, err := writer.WriteString("\n")
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error sending termination line: %s\n", err)

		os.Exit(1)
	}

	// Flush the buffer to ensure data is sent to the server
	err = writer.Flush()
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error flushing buffer: %s\n", err)

		os.Exit(1)
	}

	fmt.Println("Policy request sent.")
}

// Reads and displays the server's response line by line until an empty line
func readPolicyResponse(conn net.Conn) {
	reader := bufio.NewReader(conn)

	fmt.Println("\nServer response:")

	for {
		// Read each line of the server response
		line, err := reader.ReadString('\n')
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Error reading server response: %s\n", err)

			os.Exit(1)
		}

		// Stop reading if a blank line is encountered
		if strings.TrimSpace(line) == "" {
			break
		}

		// Print the response line
		fmt.Println(line)
	}

	fmt.Println("Response processing completed.")
}
