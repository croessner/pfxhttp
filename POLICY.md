# Engineering Policy

These rules are mandatory for coding changes in this repository.

## Must Rules

- MUST: Keep the project on Go 1.26 across module metadata, CI, Docker builds,
  and documentation.
- MUST: Run `make guardrails` before committing or opening a pull request.
- MUST: Keep `.golangci.yml` aligned with the repository guardrail policy and
  run `golangci-lint` through `make lint` or `make guardrails`.
- MUST: Keep `vendor/` synchronized after dependency changes.
- MUST: Run Go tests with `GOEXPERIMENT=runtimesecret`; prefer the Makefile
  targets so this is set consistently.
- MUST: Add focused regression coverage for bug fixes when a reproducer is
  practical.
- MUST: Write code comments and technical documentation in English.
- MUST: Write commit messages as `Prefix: Concise headline`, using only the
  approved prefixes `Add`, `Change`, `Fix`, `Remove`, `Refactor`, `Test`,
  `Docs`, `Build`, `Ci`, `Vendor`, `Security`, and `Chore`.
- MUST: Use the commit subject as a headline for what was fundamentally done,
  then use the body as a short bullet list of the essential implementation,
  validation, operator-facing, packaging, or dependency details.
- MUST: Split unrelated work into separate commits when no single approved
  prefix and headline describes the change cleanly.

## Definition Of Done

- [ ] Dependency changes were followed by `go mod tidy` and `go mod vendor`.
- [ ] `make guardrails` passes locally.
- [ ] `golangci-lint` findings are fixed or intentionally documented.
- [ ] New or changed code has focused test coverage where appropriate.
- [ ] Comments and technical docs introduced by the change are English-only.
- [ ] Commit messages use the approved prefix, headline, and bullet-list body
      format.
