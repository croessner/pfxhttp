#!/usr/bin/env bash

set -euo pipefail

runtime_image="${RUNTIME_IMAGE:-alpine:3.24}"
golang_image="${GO_IMAGE:-golang:1.26.8-alpine3.24}"

hash_cmd() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum
		return
	fi

	if command -v shasum >/dev/null 2>&1; then
		shasum -a 256
		return
	fi

	printf 'No SHA-256 tool found (sha256sum/shasum).\n' >&2
	exit 1
}

manifest_digest() {
	local image="$1"
	local digest

	digest="$(
		docker buildx imagetools inspect "$image" --raw \
			| hash_cmd \
			| awk '{print $1}'
	)"

	printf 'sha256:%s\n' "$digest"
}

printf 'runtime_image=%s\n' "$runtime_image"
printf 'runtime_digest=%s\n' "$(manifest_digest "$runtime_image")"
printf 'golang_image=%s\n' "$golang_image"
printf 'golang_digest=%s\n' "$(manifest_digest "$golang_image")"
