#!/usr/bin/env bash

set -euo pipefail

repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$repo_root"

fail() {
	printf 'check-release-hardening: %s\n' "$*" >&2
	exit 1
}

require_file() {
	[[ -f "$1" ]] || fail "missing required file: $1"
}

require_contains() {
	grep -Eq "$2" "$1" || fail "$3"
}

release_workflows=(
	.github/workflows/build-stable.yaml
	.github/workflows/docker-stable.yaml
	.github/workflows/docker-stable-build.yaml
	.github/workflows/docker-build-push.yaml
)

require_file scripts/sbom.sh
require_file scripts/docker-base-digests.sh
require_file Dockerfile
require_file Makefile

for workflow in "${release_workflows[@]}"; do
	require_file "$workflow"

	while IFS= read -r action; do
		[[ "$action" == ./* ]] && continue
		[[ "$action" =~ @[0-9a-f]{40}$ ]] || fail "$workflow contains an unpinned action: $action"
	done < <(sed -nE 's/^[[:space:]]*uses:[[:space:]]*[>~-]?[[:space:]]*([^[:space:]#]+).*/\1/p' "$workflow")
done

if grep -R -n -E '(curl|wget)[^|]*\|[[:space:]]*(sh|bash)\b' \
	--exclude=check-release-hardening.sh scripts .github/workflows; then
	fail "remote installer bytes must not be piped directly into a shell"
fi

require_contains scripts/sbom.sh 'checksums\.txt' \
	"scripts/sbom.sh must verify Syft release checksums"
require_contains scripts/sbom.sh '(sha256sum|shasum -a 256)' \
	"scripts/sbom.sh must use a SHA-256 verifier"
require_contains .github/workflows/build-stable.yaml '^[[:space:]]{2}govulncheck:' \
	"release artifact workflow must define a govulncheck job"
require_contains .github/workflows/build-stable.yaml '^[[:space:]]{6}- govulncheck$' \
	"release publication must depend on govulncheck"
require_contains .github/workflows/build-stable.yaml 'chown -R "\$\{HOST_UID\}:\$\{HOST_GID\}" dist$' \
	"package build container must return the complete dist tree to the runner user"
require_contains .github/workflows/docker-stable.yaml '^[[:space:]]{4}needs: govulncheck$' \
	"Docker publication must depend on govulncheck"
require_contains .github/workflows/docker-stable-build.yaml 'GO_IMAGE=\$\{golang_image\}@\$\{golang_digest\}' \
	"stable Docker build must pin the Go builder by digest"
require_contains .github/workflows/docker-stable-build.yaml 'RUNTIME_IMAGE=\$\{runtime_image\}@\$\{runtime_digest\}' \
	"stable Docker build must pin the runtime image by digest"
require_contains .github/workflows/docker-build-push.yaml '^[[:space:]]+sbom:[[:space:]]+\$\{\{ inputs\.sbom \}\}$' \
	"reusable Docker build must pass through SBOM generation"
require_contains Dockerfile '^ARG GO_IMAGE=golang:1\.26\.5-alpine3\.24$' \
	"Dockerfile must default to the release Go toolchain"
require_contains Makefile '^GOVULNCHECK_GOFLAGS \?= -mod=vendor$' \
	"govulncheck must default to vendored dependencies"

if command -v actionlint >/dev/null 2>&1; then
	actionlint "${release_workflows[@]}"
fi

printf 'check-release-hardening: release workflow contract is valid\n'
