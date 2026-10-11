# Docker Postfix interoperability lane

This lane runs the production PfxHTTP binary, a local HTTP/gRPC fixture, and
real Postfix clients on one isolated Docker network. It never starts or
reconfigures Postfix or Dovecot on the host. A separate Dovecot container is not
used because Postfix talks directly to PfxHTTP's Dovecot-compatible auth
protocol; inserting Dovecot would bypass the boundary being tested.

Install the required images before entering an offline or restricted test
environment:

```sh
docker pull golang:1.26.9-alpine3.24
docker pull alpine:3.23
docker pull chrroessner/postfix:latest
```

Then run the durable public target from the repository root:

```sh
make test-postfix-interop
```

Set `PFXHTTP_E2E_POSTFIX_IMAGE` to test another locally available Postfix image.
The lane prints the exact Postfix version and image reference. It proves:

- real `postmap -q` lookup plus a persistent Postfix `smtpd` SocketMap client;
- two SMTP access lookups on one SocketMap connection, the normal
  greater-than-ten-second idle window, a deterministic 11-second listener
  recycle followed by a reconnect from the same Postfix process, and a
  non-starved fresh lookup during that idle interval;
- two policy requests in one real SMTP session and one reused PfxHTTP policy
  connection;
- real Postfix SMTP AUTH through PfxHTTP's Dovecot protocol;
- concurrent persistent policy/SASL/SocketMap clients and fresh map load;
- bounded Postfix-visible policy overload, HTTP cancellation, and a 30-second
  gRPC timeout constrained by one sub-five-second fail-closed SMTP AUTH budget
  (Postfix 3.11 reports the Dovecot `temp` failure as SMTP `535`);
- graceful mixed-connection shutdown, restart, raw readiness, and a bounded
  public SMTP AUTH reconnect/reprobe window;
- absence of generated credentials and fixed client identity markers from the
  captured PfxHTTP and backend logs. Postfix logs are neither printed nor kept
  as artifacts;

The harness generates its credential marker at runtime, stores logs only in a
mode-0700 test-owned temporary directory, and removes that directory and its
unique Compose project on exit. It never prunes global Docker state.

Missing Docker, Compose, daemon access, a required local image, Postfix
`socketmap`, or Postfix `dovecot` SASL support makes the direct
`bash test/e2e/postfix/scripts/run.sh` invocation exit with code `77` and a
stable message beginning with `PFXHTTP_POSTFIX_E2E_BLOCKED:`. GNU Make reports
recipe failure with its own non-zero exit code (commonly `2`) while preserving
that blocker line. Such a result is blocked, never passed. Test or
interoperability failures make the direct script exit with code `1` and begin
with `PFXHTTP_POSTFIX_E2E_FAILED:`.
