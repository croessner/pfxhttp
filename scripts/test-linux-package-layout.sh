#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT

fake_binary="${tmp}/pfxhttp"
stage_root="${tmp}/stage"

printf '#!/bin/sh\nexit 0\n' > "${fake_binary}"
chmod 0755 "${fake_binary}"

"${repo_root}/scripts/build-linux-package.sh" \
  --stage-only \
  --binary "${fake_binary}" \
  --stage-root "${stage_root}"

expected_files="$(
  cat <<'FILES'
etc/pfxhttp/pfxhttp.env
etc/pfxhttp/pfxhttp.yml
usr/lib/systemd/system/pfxhttp-policy.socket
usr/lib/systemd/system/pfxhttp.service
usr/lib/systemd/system/pfxhttp@.socket
usr/sbin/pfxhttp
usr/share/doc/pfxhttp/LICENSE
usr/share/doc/pfxhttp/README.md
usr/share/doc/pfxhttp/pfxhttp.yml.demo
usr/share/man/man5/pfxhttp.yml.5.gz
usr/share/man/man8/pfxhttp.8.gz
FILES
)"

actual_files="$(cd "${stage_root}" && find . -type f -print | sed 's#^\./##' | sort)"
if [[ "${actual_files}" != "${expected_files}" ]]; then
  diff -u <(printf '%s\n' "${expected_files}") <(printf '%s\n' "${actual_files}") >&2 || true
  echo "Package staging file list does not match expected content." >&2
  exit 1
fi

if find "${stage_root}" -path "${stage_root}/usr/local" -print -quit | grep -q .; then
  echo "Package staging must not install files under /usr/local." >&2
  exit 1
fi

if ! grep -q '/usr/sbin/pfxhttp --config /etc/pfxhttp/pfxhttp.yml' \
  "${stage_root}/usr/lib/systemd/system/pfxhttp.service"; then
  echo "Packaged systemd service does not point at /usr/sbin/pfxhttp." >&2
  exit 1
fi

if ! grep -q 'EnvironmentFile=-/etc/pfxhttp/pfxhttp.env' \
  "${stage_root}/usr/lib/systemd/system/pfxhttp.service"; then
  echo "Packaged systemd service does not use the packaged environment file." >&2
  exit 1
fi

policy_socket="${stage_root}/usr/lib/systemd/system/pfxhttp-policy.socket"
if ! grep -q 'ListenStream=/var/spool/postfix/private/pfxhttp-policy' "${policy_socket}" ||
  ! grep -q 'FileDescriptorName=policy' "${policy_socket}" ||
  ! grep -q 'Accept=no' "${policy_socket}" ||
  ! grep -q 'Service=pfxhttp.service' "${policy_socket}"; then
  echo "Concrete policy socket unit does not match the packaged policy listener." >&2
  exit 1
fi

template_socket="${stage_root}/usr/lib/systemd/system/pfxhttp@.socket"
if ! grep -q 'ListenStream=/var/spool/postfix/private/pfxhttp-%i' "${template_socket}" ||
  ! grep -q 'FileDescriptorName=%i' "${template_socket}" ||
  ! grep -q 'Accept=no' "${template_socket}" ||
  ! grep -q 'Service=pfxhttp.service' "${template_socket}"; then
  echo "Template socket unit does not map the instance name to the socket descriptor." >&2
  exit 1
fi

package_config="${stage_root}/etc/pfxhttp/pfxhttp.yml"
if ! grep -q 'kind: "policy_service"' "${package_config}" ||
  ! grep -q 'name: "policy"' "${package_config}" ||
  ! grep -q 'type: "unix"' "${package_config}" ||
  ! grep -q 'address: "/var/spool/postfix/private/pfxhttp-policy"' "${package_config}" ||
  ! grep -q 'systemd_socket_name: "policy"' "${package_config}"; then
  echo "Packaged default config does not match pfxhttp-policy.socket." >&2
  exit 1
fi

if grep -Eq '0\.0\.0\.0|skip_verify: true|Authorization: Basic|admin-password|client_secret:' "${package_config}"; then
  echo "Packaged default config contains unsafe demo-facing values." >&2
  exit 1
fi

file_mode() {
  if stat -c '%a' "$1" >/dev/null 2>&1; then
    stat -c '%a' "$1"
  else
    stat -f '%Lp' "$1"
  fi
}

assert_mode() {
  local path="$1"
  local expected="$2"
  local actual

  actual="$(file_mode "${stage_root}/${path}")"
  if [[ "${actual}" != "${expected}" ]]; then
    echo "Expected ${path} mode ${expected}, got ${actual}." >&2
    exit 1
  fi
}

assert_mode "usr/sbin/pfxhttp" "755"
assert_mode "etc/pfxhttp/pfxhttp.yml" "640"
assert_mode "etc/pfxhttp/pfxhttp.env" "640"
