# PostfixToHTTP Development Guidelines

This repository is a Go 1.26 project. Keep `go.mod`, Docker builds, CI, and
operator-facing documentation aligned with Go 1.26 whenever toolchain details
change.

## Required Workflow

- Use the Makefile targets instead of ad hoc command variants whenever possible.
- Run `make guardrails` before every commit or pull request.
- Run tests with `GOEXPERIMENT=runtimesecret`; the Makefile exports this for
  `make test`, `make race`, and `make guardrails`.
- Run lint through `make lint`; `make guardrails` includes `golangci-lint`.
- Keep the vendored module tree in sync. After dependency updates, run
  `go mod tidy` and `go mod vendor`.
- Add focused regression tests for bug fixes before changing production code
  when a reproducer is practical.
- Write code comments and technical documentation in English.

## Quality Gates

`make guardrails` runs the local quality gate:

- `make fix`
- `make vet`
- `make lint`
- `make test`
- `make race`
- `make build-check`
