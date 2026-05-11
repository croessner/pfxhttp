#!/usr/bin/env bash
set -euo pipefail

script="${1:-scripts/release-semver-metadata.sh}"

metadata_value() {
  local tag="$1"
  local key="$2"

  "${script}" "${tag}" | awk -F= -v wanted="${key}" '$1 == wanted { print $2 }'
}

assert_value() {
  local tag="$1"
  local key="$2"
  local expected="$3"
  local actual

  actual="$(metadata_value "${tag}" "${key}")"
  if [[ "${actual}" != "${expected}" ]]; then
    echo "Expected ${key} for ${tag} to be '${expected}', got '${actual}'." >&2
    exit 1
  fi
}

assert_invalid() {
  local tag="$1"

  if "${script}" "${tag}" >/dev/null 2>&1; then
    echo "Expected ${tag} to be rejected." >&2
    exit 1
  fi
}

assert_value "v1.2.3" "version" "1.2.3"
assert_value "v1.2.3" "base_version" "1.2.3"
assert_value "v1.2.3" "package_version" "1.2.3"
assert_value "v1.2.3" "prerelease" "false"
assert_value "v1.2.3" "tag_major" "v1"
assert_value "v1.2.3" "tag_minor" "v1.2"
assert_value "v1.2.3" "tag_patch" "v1.2.3"

assert_value "v1.2.3-alpha.2" "version" "1.2.3-alpha.2"
assert_value "v1.2.3-alpha.2" "base_version" "1.2.3"
assert_value "v1.2.3-alpha.2" "package_version" "1.2.3~alpha.2"
assert_value "v1.2.3-alpha.2" "prerelease" "true"
assert_value "v1.2.3-alpha.2" "tag_patch" "v1.2.3"

assert_value "v1.2.3-rc.4" "version" "1.2.3-rc.4"
assert_value "v1.2.3-rc.4" "package_version" "1.2.3~rc.4"
assert_value "v1.2.3-rc.4" "prerelease" "true"

assert_invalid "1.2.3"
assert_invalid "v1.2"
assert_invalid "v1.2.3-"
assert_invalid "v01.2.3"
