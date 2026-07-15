// Package main provides the Docker-only Postfix interoperability fixture and probes.
package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	authv1 "PostfixToHTTP/proto/auth/v1"

	"google.golang.org/grpc"
)

const (
	backendHTTPAddress = ":8080"
	backendGRPCAddress = ":8081"
	metricsURL         = "http://pfxhttp:9464/metrics"
	statsURL           = "http://backend:8080/stats"
	postfixSMTPAddress = "postfix:25"
	overloadSMTP       = "postfix:2526"
	grpcSMTP           = "postfix:2527"
	socketMapSMTP      = "postfix:2528"
	socketMapAddress   = "pfxhttp:23450"
	policyAddress      = "pfxhttp:23451"
	dovecotAddress     = "pfxhttp:23453"
	probeTimeout       = 8 * time.Second
	backendErrorField  = "error"
	backendNoError     = "none"
	backendResultField = "result"
	backendValueField  = "value"
	mappedValue        = "mapped"
	policyDunno        = "DUNNO"
	socketMapComponent = "component=\"socket_map\""
)

var probeHTTPClient = &http.Client{Timeout: 2 * time.Second}

type backendStats struct {
	SlowStarted  atomic.Int64
	SlowCanceled atomic.Int64
	GRPCStarted  atomic.Int64
	GRPCCanceled atomic.Int64
}

type statsSnapshot struct {
	SlowStarted  int64 `json:"slow_started"`
	SlowCanceled int64 `json:"slow_canceled"`
	GRPCStarted  int64 `json:"grpc_started"`
	GRPCCanceled int64 `json:"grpc_canceled"`
}

func (s *backendStats) snapshot() statsSnapshot {
	return statsSnapshot{
		SlowStarted:  s.SlowStarted.Load(),
		SlowCanceled: s.SlowCanceled.Load(),
		GRPCStarted:  s.GRPCStarted.Load(),
		GRPCCanceled: s.GRPCCanceled.Load(),
	}
}

type grpcAuthBackend struct {
	authv1.UnimplementedAuthServiceServer
	stats *backendStats
}

func (b *grpcAuthBackend) Authenticate(ctx context.Context, request *authv1.AuthRequest) (*authv1.AuthResponse, error) {
	b.stats.GRPCStarted.Add(1)

	if request.GetUsername() == "budget-user" {
		select {
		case <-ctx.Done():
			b.stats.GRPCCanceled.Add(1)

			return nil, ctx.Err()
		case <-time.After(30 * time.Second):
		}
	}

	return &authv1.AuthResponse{
		Ok:           true,
		Decision:     authv1.AuthDecision_AUTH_DECISION_OK,
		AccountField: "e2e-account",
	}, nil
}

func main() {
	if len(os.Args) < 2 {
		fatalf("mode is required")
	}

	var err error

	switch os.Args[1] {
	case "backend":
		err = runBackend()
	case "probe":
		err = runProbe(os.Args[2:])
	default:
		err = fmt.Errorf("unknown mode %q", os.Args[1])
	}

	if err != nil {
		fatalf("%v", err)
	}
}

func fatalf(format string, arguments ...any) {
	_, _ = fmt.Fprintf(os.Stderr, "E2E failure: "+format+"\n", arguments...)

	os.Exit(1)
}

func runBackend() error {
	stats := &backendStats{}
	httpServer := &http.Server{
		Addr:              backendHTTPAddress,
		Handler:           backendHandler(stats),
		ReadHeaderTimeout: 2 * time.Second,
	}

	grpcListener, err := net.Listen("tcp", backendGRPCAddress)
	if err != nil {
		return err
	}

	grpcServer := grpc.NewServer()
	authv1.RegisterAuthServiceServer(grpcServer, &grpcAuthBackend{stats: stats})

	errorsChannel := make(chan error, 2)

	go func() { errorsChannel <- httpServer.ListenAndServe() }()
	go func() { errorsChannel <- grpcServer.Serve(grpcListener) }()

	return <-errorsChannel
}

func backendHandler(stats *backendStats) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/map", func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(writer, map[string]string{backendValueField: mappedValue, backendErrorField: backendNoError})
	})
	mux.HandleFunc("/access", func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(writer, map[string]string{backendValueField: policyDunno, backendErrorField: backendNoError})
	})
	mux.HandleFunc("/policy", func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(writer, map[string]string{backendResultField: policyDunno, backendErrorField: backendNoError})
	})
	mux.HandleFunc("/auth", func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Auth-User", "e2e-account")
		writeJSON(writer, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("/slow-policy", func(writer http.ResponseWriter, request *http.Request) {
		stats.SlowStarted.Add(1)
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusOK)

		if flusher, ok := writer.(http.Flusher); ok {
			flusher.Flush()
		}

		select {
		case <-request.Context().Done():
			stats.SlowCanceled.Add(1)

			return
		case <-time.After(30 * time.Second):
			writeJSON(writer, map[string]string{backendResultField: policyDunno, backendErrorField: backendNoError})
		}
	})
	mux.HandleFunc("/stats", func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(writer, stats.snapshot())
	})

	return mux
}

func writeJSON(writer http.ResponseWriter, value any) {
	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(value)
}

func runProbe(arguments []string) error {
	if len(arguments) != 1 {
		return errors.New("probe subcommand is required")
	}

	switch arguments[0] {
	case "wait":
		return waitForServices()
	case "policy-reuse":
		return provePolicyReuse()
	case "smtp-auth":
		return proveSMTPAuth(postfixSMTPAddress, "e2e-user", true)
	case "smtp-auth-eventually":
		return proveSMTPAuthEventually()
	case "mixed":
		return proveMixedLoad()
	case "socketmap-reuse-idle":
		return provePostfixSocketMapReuseAndIdle()
	case "overload-budget":
		return proveOverloadAndHTTPBudget()
	case "grpc-budget":
		return proveGRPCBudget()
	case "lifecycle":
		return proveLifecycleDrain()
	default:
		return fmt.Errorf("unknown probe %q", arguments[0])
	}
}

func waitForServices() error {
	deadline := time.Now().Add(30 * time.Second)
	addresses := []string{
		socketMapAddress, policyAddress, dovecotAddress, postfixSMTPAddress, socketMapSMTP, "pfxhttp:23458", "backend:8080",
	}

	for time.Now().Before(deadline) {
		allReady := true

		for _, address := range addresses {
			connection, err := net.DialTimeout("tcp", address, 250*time.Millisecond)
			if err != nil {
				allReady = false

				break
			}

			_ = connection.Close()
		}

		if allReady {
			fmt.Println("service readiness: PASS")

			return nil
		}

		time.Sleep(100 * time.Millisecond)
	}

	return errors.New("services did not become ready within 30s")
}

type smtpClient struct {
	connection net.Conn
	reader     *bufio.Reader
}

func dialSMTP(address string) (*smtpClient, error) {
	connection, err := net.DialTimeout("tcp", address, probeTimeout)
	if err != nil {
		return nil, err
	}

	client := &smtpClient{connection: connection, reader: bufio.NewReader(connection)}

	_ = connection.SetDeadline(time.Now().Add(probeTimeout))
	if code, _, err := client.readReply(); err != nil || code != 220 {
		_ = connection.Close()

		return nil, fmt.Errorf("SMTP greeting code=%d: %w", code, err)
	}

	return client, nil
}

func (c *smtpClient) close() {
	_ = c.connection.Close()
}

func (c *smtpClient) command(command string) (int, string, error) {
	if err := c.connection.SetDeadline(time.Now().Add(probeTimeout)); err != nil {
		return 0, "", err
	}

	if _, err := io.WriteString(c.connection, command+"\r\n"); err != nil {
		return 0, "", err
	}

	return c.readReply()
}

func (c *smtpClient) readReply() (int, string, error) {
	var lines []string

	for {
		line, err := c.reader.ReadString('\n')
		if err != nil {
			return 0, strings.Join(lines, ""), err
		}

		lines = append(lines, line)
		if len(line) < 4 {
			return 0, strings.Join(lines, ""), errors.New("short SMTP reply")
		}

		code, err := strconv.Atoi(line[:3])
		if err != nil {
			return 0, strings.Join(lines, ""), err
		}

		if line[3] == ' ' {
			return code, strings.Join(lines, ""), nil
		}
	}
}

func prepareSMTPMail(address string) (*smtpClient, error) {
	client, err := dialSMTP(address)
	if err != nil {
		return nil, err
	}

	if code, _, err := client.command("EHLO probe.example.test"); err != nil || code != 250 {
		client.close()

		return nil, fmt.Errorf("EHLO code=%d: %w", code, err)
	}

	if code, _, err := client.command("MAIL FROM:<sender@probe.invalid>"); err != nil || code != 250 {
		client.close()

		return nil, fmt.Errorf("MAIL code=%d: %w", code, err)
	}

	return client, nil
}

func provePolicyReuse() error {
	before, err := fetchMetrics()
	if err != nil {
		return err
	}

	client, err := prepareSMTPMail(postfixSMTPAddress)
	if err != nil {
		return err
	}
	defer client.close()

	for range 2 {
		code, _, commandErr := client.command("RCPT TO:<recipient@example.test>")
		if commandErr != nil || code != 250 {
			return fmt.Errorf("policy RCPT code=%d: %w", code, commandErr)
		}
	}

	after, err := waitForMetrics(func(metrics string) bool {
		return metricValue(metrics, "pfxhttp_application_requests_total", "component=\"policy_service\"", "listener=\"policy\"")-
			metricValue(before, "pfxhttp_application_requests_total", "component=\"policy_service\"", "listener=\"policy\"") >= 2
	})
	if err != nil {
		return err
	}

	acceptDelta := metricValue(after, "pfxhttp_listener_connections_total", "component=\"policy_service\"", "name=\"policy\"", "event=\"accept\"") -
		metricValue(before, "pfxhttp_listener_connections_total", "component=\"policy_service\"", "name=\"policy\"", "event=\"accept\"")

	requestDelta := metricValue(after, "pfxhttp_application_requests_total", "component=\"policy_service\"", "listener=\"policy\"") -
		metricValue(before, "pfxhttp_application_requests_total", "component=\"policy_service\"", "listener=\"policy\"")
	if acceptDelta != 1 || requestDelta < 2 {
		return fmt.Errorf("policy reuse evidence accept_delta=%.0f request_delta=%.0f", acceptDelta, requestDelta)
	}

	fmt.Println("Postfix policy connection reuse: PASS")

	return nil
}

func fetchMetrics() (string, error) {
	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, metricsURL, nil)
	if err != nil {
		return "", err
	}

	response, err := probeHTTPClient.Do(request)
	if err != nil {
		return "", err
	}
	defer func() { _ = response.Body.Close() }()

	data, err := io.ReadAll(response.Body)

	return string(data), err
}

func metricValue(metrics, name string, labels ...string) float64 {
	for line := range strings.SplitSeq(metrics, "\n") {
		if !strings.HasPrefix(line, name+"{") {
			continue
		}

		matches := true
		for _, label := range labels {
			matches = matches && strings.Contains(line, label)
		}

		if !matches {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) == 2 {
			value, _ := strconv.ParseFloat(fields[1], 64)

			return value
		}
	}

	return 0
}

func proveSMTPAuth(address, username string, expectSuccess bool) error { //nolint:gocyclo // One SMTP transcript.
	client, err := dialSMTP(address)
	if err != nil {
		return err
	}
	defer client.close()

	code, capabilities, err := client.command("EHLO probe.example.test")
	if err != nil || code != 250 || !strings.Contains(capabilities, "AUTH") {
		return fmt.Errorf("SMTP AUTH capability code=%d present=%t: %w", code, strings.Contains(capabilities, "AUTH"), err)
	}

	password := os.Getenv("PFXHTTP_E2E_AUTH_SECRET")
	if password == "" {
		return errors.New("PFXHTTP_E2E_AUTH_SECRET is required")
	}

	encoded := base64.StdEncoding.EncodeToString([]byte("\x00" + username + "\x00" + password))

	code, _, err = client.command("AUTH PLAIN " + encoded)
	if err != nil {
		return err
	}

	if expectSuccess && code != 235 {
		return fmt.Errorf("SMTP AUTH code=%d, want 235", code)
	}

	if !expectSuccess && (code < 400 || code >= 600) {
		return fmt.Errorf("SMTP AUTH code=%d, want fail-closed failure", code)
	}

	if expectSuccess {
		fmt.Println("Postfix Dovecot SASL path: PASS")
	}

	return nil
}

func proveSMTPAuthEventually() error {
	deadline := time.Now().Add(15 * time.Second)

	var lastError error

	for time.Now().Before(deadline) {
		lastError = proveSMTPAuth(postfixSMTPAddress, "e2e-user", true)
		if lastError == nil {
			return nil
		}

		time.Sleep(200 * time.Millisecond)
	}

	return fmt.Errorf("postfix SMTP AUTH did not recover after restart: %w", lastError)
}

func proveMixedLoad() error {
	connections, err := openPersistentProtocolConnections()
	if err != nil {
		return err
	}
	defer closeConnections(connections)

	// The public SocketMap client normally closes after roughly ten idle seconds.
	<-time.After(11 * time.Second)

	var waitGroup sync.WaitGroup

	errorChannel := make(chan error, 24)

	for range 20 {
		waitGroup.Go(func() {
			errorChannel <- socketMapLookup()
		})
	}

	waitGroup.Wait()
	close(errorChannel)

	for err := range errorChannel {
		if err != nil {
			return err
		}
	}

	client, err := prepareSMTPMail(postfixSMTPAddress)
	if err != nil {
		return err
	}
	defer client.close()

	if code, _, err := client.command("RCPT TO:<recipient@example.test>"); err != nil || code != 250 {
		return fmt.Errorf("mixed policy RCPT code=%d: %w", code, err)
	}

	fmt.Println("mixed persistent protocol load and idle cycle: PASS")

	return nil
}

func openPersistentProtocolConnections() ([]net.Conn, error) {
	idleMap, err := net.DialTimeout("tcp", socketMapAddress, probeTimeout)
	if err != nil {
		return nil, err
	}

	policy, err := net.DialTimeout("tcp", policyAddress, probeTimeout)
	if err != nil {
		_ = idleMap.Close()

		return nil, err
	}

	if err = writePolicyRequest(policy); err != nil {
		closeConnections([]net.Conn{idleMap, policy})

		return nil, err
	}

	dovecot, err := openDovecotConnection()
	if err != nil {
		closeConnections([]net.Conn{idleMap, policy})

		return nil, err
	}

	return []net.Conn{idleMap, policy, dovecot}, nil
}

func writePolicyRequest(connection net.Conn) error {
	_ = connection.SetDeadline(time.Now().Add(probeTimeout))
	if _, err := io.WriteString(connection, "request=smtpd_access_policy\nprotocol_state=RCPT\n\n"); err != nil {
		return err
	}

	reader := bufio.NewReader(connection)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return err
		}

		if line == "\n" {
			return nil
		}
	}
}

func openDovecotConnection() (net.Conn, error) {
	connection, err := net.DialTimeout("tcp", dovecotAddress, probeTimeout)
	if err != nil {
		return nil, err
	}

	_ = connection.SetDeadline(time.Now().Add(probeTimeout))

	reader := bufio.NewReader(connection)
	for {
		line, readErr := reader.ReadString('\n')
		if readErr != nil {
			_ = connection.Close()

			return nil, readErr
		}

		if strings.HasPrefix(line, "DONE") {
			break
		}
	}

	if _, err = io.WriteString(connection, "VERSION\t1\t2\nCPID\t4242\n"); err != nil {
		_ = connection.Close()

		return nil, err
	}

	_ = connection.SetDeadline(time.Time{})

	return connection, nil
}

func socketMapLookup() error {
	connection, err := net.DialTimeout("tcp", socketMapAddress, probeTimeout)
	if err != nil {
		return err
	}
	defer func() { _ = connection.Close() }()

	payload := "map synthetic-key"
	request := fmt.Sprintf("%d:%s,", len(payload), payload)

	_ = connection.SetDeadline(time.Now().Add(probeTimeout))
	if _, err = io.WriteString(connection, request); err != nil {
		return err
	}

	response, err := bufio.NewReader(connection).ReadString(',')
	if err != nil || !strings.Contains(response, "OK mapped") {
		return fmt.Errorf("socket map response invalid: %w", err)
	}

	return nil
}

func proveOverloadAndHTTPBudget() error {
	before, err := fetchStats()
	if err != nil {
		return err
	}

	first, err := prepareSMTPMail(overloadSMTP)
	if err != nil {
		return err
	}
	defer first.close()

	firstResult := make(chan smtpResult, 1)
	go timedRCPT(first, firstResult)

	if _, err = waitForMetrics(func(metrics string) bool {
		return metricValue(
			metrics,
			"pfxhttp_listener_request_state",
			"component=\"policy_service\"",
			"name=\"overload\"",
			"state=\"inflight\"",
		) >= 1
	}); err != nil {
		return fmt.Errorf("overload request did not become inflight: %w", err)
	}

	second, err := prepareSMTPMail(overloadSMTP)
	if err != nil {
		return err
	}
	defer second.close()

	secondResult := make(chan smtpResult, 1)
	go timedRCPT(second, secondResult)

	secondOutcome := <-secondResult
	firstOutcome := <-firstResult

	if err = validateTemporarySMTPResult(secondOutcome, 1500*time.Millisecond); err != nil {
		return fmt.Errorf("overload response: %w", err)
	}

	if err = validateTemporarySMTPResult(firstOutcome, 5*time.Second); err != nil {
		return fmt.Errorf("budget response: %w", err)
	}

	if err = waitForStat(func(snapshot statsSnapshot) bool { return snapshot.SlowCanceled > before.SlowCanceled }); err != nil {
		return err
	}

	fmt.Println("Postfix-visible overload and five-second HTTP budget: PASS")

	return nil
}

type smtpResult struct {
	code    int
	reply   string
	elapsed time.Duration
	err     error
}

func timedRCPT(client *smtpClient, result chan<- smtpResult) {
	start := time.Now()

	code, reply, err := client.command("RCPT TO:<recipient@example.test>")
	result <- smtpResult{code: code, reply: reply, elapsed: time.Since(start), err: err}
}

func validateTemporarySMTPResult(result smtpResult, maximum time.Duration) error {
	if result.err != nil {
		return result.err
	}

	if result.code < 400 || result.code >= 500 {
		return fmt.Errorf("SMTP code=%d, want temporary failure", result.code)
	}

	if result.elapsed >= maximum {
		return fmt.Errorf("elapsed=%s, want <%s", result.elapsed, maximum)
	}

	if !strings.Contains(result.reply, "Service temporarily unavailable") {
		return errors.New("SMTP reply did not contain PfxHTTP's temporary policy action")
	}

	return nil
}

func fetchStats() (statsSnapshot, error) {
	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, statsURL, nil)
	if err != nil {
		return statsSnapshot{}, err
	}

	response, err := probeHTTPClient.Do(request)
	if err != nil {
		return statsSnapshot{}, err
	}
	defer func() { _ = response.Body.Close() }()

	var snapshot statsSnapshot

	err = json.NewDecoder(response.Body).Decode(&snapshot)

	return snapshot, err
}

func waitForMetrics(predicate func(string) bool) (string, error) {
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		metrics, err := fetchMetrics()
		if err == nil && predicate(metrics) {
			return metrics, nil
		}

		time.Sleep(20 * time.Millisecond)
	}

	return "", errors.New("metrics did not reach expected state")
}

func provePostfixSocketMapReuseAndIdle() error { //nolint:funlen,gocyclo // One public SMTP/SocketMap lifecycle transcript.
	before, err := fetchMetrics()
	if err != nil {
		return err
	}

	client, err := prepareSMTPMail(socketMapSMTP)
	if err != nil {
		return err
	}
	defer client.close()

	for index := range 2 {
		code, _, commandErr := client.command(fmt.Sprintf("RCPT TO:<access-%d@example.test>", index))
		if commandErr != nil || code != 250 {
			return fmt.Errorf("SocketMap access RCPT code=%d: %w", code, commandErr)
		}
	}

	if _, err = waitForMetrics(func(metrics string) bool {
		return accessMapMetricDelta(metrics, before, "pfxhttp_application_requests_total", "") >= 2 &&
			accessMapMetricDelta(metrics, before, "pfxhttp_listener_connections_total", "accept") == 1
	}); err != nil {
		return fmt.Errorf("postfix socket map reuse: %w", err)
	}

	// Observe beyond Postfix's normal ten-second SocketMap idle window while a
	// fresh valid lookup on the independent public map remains non-starved.
	time.Sleep(5 * time.Second)

	if err = socketMapLookup(); err != nil {
		return err
	}

	time.Sleep(7 * time.Second)

	code, _, err := client.command("RCPT TO:<access-after-idle@example.test>")
	if err != nil || code != 250 {
		return fmt.Errorf("SocketMap access after idle code=%d: %w", code, err)
	}

	if _, err = waitForMetrics(func(metrics string) bool {
		return accessMapMetricDelta(metrics, before, "pfxhttp_application_requests_total", "") >= 3 &&
			accessMapMetricDelta(metrics, before, "pfxhttp_listener_connections_total", "accept") >= 2 &&
			accessMapMetricDelta(metrics, before, "pfxhttp_listener_connections_total", "close") >= 1
	}); err != nil {
		return fmt.Errorf("postfix socket map idle recycle: %w", err)
	}

	fmt.Println("Postfix SocketMap reuse, idle recycle, and fresh lookup: PASS")

	return nil
}

func accessMapMetricDelta(metrics, before, metric, event string) float64 {
	labels := []string{socketMapComponent, "name=\"access\""}
	if event == "" {
		labels = append(labels, "listener=\"access\"")
	} else {
		labels = append(labels, "event=\""+event+"\"")
	}

	return metricValue(metrics, metric, labels...) - metricValue(before, metric, labels...)
}

func waitForStat(predicate func(statsSnapshot) bool) error {
	deadline := time.Now().Add(5 * time.Second)

	var (
		last      statsSnapshot
		lastError error
	)

	for time.Now().Before(deadline) {
		snapshot, err := fetchStats()
		last = snapshot
		lastError = err

		if err == nil && predicate(snapshot) {
			return nil
		}

		time.Sleep(20 * time.Millisecond)
	}

	return fmt.Errorf(
		"backend statistic did not reach expected state: slow_started=%d slow_canceled=%d grpc_started=%d grpc_canceled=%d read_error=%v",
		last.SlowStarted, last.SlowCanceled, last.GRPCStarted, last.GRPCCanceled, lastError,
	)
}

func proveGRPCBudget() error {
	before, err := fetchStats()
	if err != nil {
		return err
	}

	start := time.Now()

	if err = proveSMTPAuth(grpcSMTP, "budget-user", false); err != nil {
		return err
	}

	elapsed := time.Since(start)
	if elapsed >= 5*time.Second {
		return fmt.Errorf("gRPC SMTP AUTH elapsed=%s, want <5s", elapsed)
	}

	if err = waitForStat(func(snapshot statsSnapshot) bool { return snapshot.GRPCCanceled > before.GRPCCanceled }); err != nil {
		return err
	}

	after, err := fetchStats()
	if err != nil {
		return err
	}

	if after.GRPCStarted-before.GRPCStarted != 1 {
		return fmt.Errorf("gRPC attempts=%d, want exactly one shared-budget attempt", after.GRPCStarted-before.GRPCStarted)
	}

	fmt.Println("30-second gRPC timeout constrained to one SMTP AUTH budget: PASS")

	return nil
}

func proveLifecycleDrain() error {
	connections, err := openPersistentProtocolConnections()
	if err != nil {
		return err
	}
	defer closeConnections(connections)

	if err = os.WriteFile("/runtime/ready", []byte("ready\n"), 0o600); err != nil {
		return err
	}

	deadline := time.Now().Add(15 * time.Second)
	for _, connection := range connections {
		_ = connection.SetReadDeadline(deadline)
		if _, err = bufio.NewReader(connection).ReadByte(); err == nil {
			return errors.New("persistent connection remained readable after shutdown")
		}

		if networkError, ok := err.(net.Error); ok && networkError.Timeout() {
			return errors.New("persistent connection was not drained before timeout")
		}
	}

	if err = os.WriteFile("/runtime/drained", []byte("drained\n"), 0o600); err != nil {
		return err
	}

	fmt.Println("graceful mixed-connection drain: PASS")

	return nil
}

func closeConnections(connections []net.Conn) {
	for _, connection := range connections {
		_ = connection.Close()
	}
}
