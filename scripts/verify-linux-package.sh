#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/verify-linux-package.sh PACKAGE...

Verify built pfxhttp DEB/RPM package content and packaged defaults.
USAGE
}

if [[ $# -eq 0 ]]; then
  usage >&2
  exit 1
fi

tmp_root="$(mktemp -d)"
trap 'rm -rf "${tmp_root}"' EXIT

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

normalize_paths() {
  sed -e 's#^\./##' -e 's#^/##' | LC_ALL=C sort
}

absolute_path() {
  case "$1" in
    /*) printf '%s\n' "$1" ;;
    *) printf '%s/%s\n' "${PWD}" "$1" ;;
  esac
}

verify_tree() {
  local root="$1"
  local actual_files package_config policy_socket template_socket

  actual_files="$(cd "${root}" && find . -type f -print | normalize_paths)"
  if [[ "${actual_files}" != "${expected_files}" ]]; then
    diff -u <(printf '%s\n' "${expected_files}") <(printf '%s\n' "${actual_files}") >&2 || true
    echo "Package file list does not match expected content." >&2
    exit 1
  fi

  if find "${root}" -path "${root}/usr/local" -print -quit | grep -q .; then
    echo "Package must not install files under /usr/local." >&2
    exit 1
  fi

  if ! grep -q '/usr/sbin/pfxhttp --config /etc/pfxhttp/pfxhttp.yml' \
    "${root}/usr/lib/systemd/system/pfxhttp.service"; then
    echo "Packaged service does not use /usr/sbin/pfxhttp." >&2
    exit 1
  fi

  if ! grep -q 'EnvironmentFile=-/etc/pfxhttp/pfxhttp.env' \
    "${root}/usr/lib/systemd/system/pfxhttp.service"; then
    echo "Packaged service does not use the packaged environment file." >&2
    exit 1
  fi

  policy_socket="${root}/usr/lib/systemd/system/pfxhttp-policy.socket"
  if ! grep -q 'ListenStream=/var/spool/postfix/private/pfxhttp-policy' "${policy_socket}" ||
    ! grep -q 'FileDescriptorName=policy' "${policy_socket}" ||
    ! grep -q 'Accept=no' "${policy_socket}" ||
    ! grep -q 'Service=pfxhttp.service' "${policy_socket}"; then
    echo "Concrete policy socket unit does not match the packaged policy listener." >&2
    exit 1
  fi

  template_socket="${root}/usr/lib/systemd/system/pfxhttp@.socket"
  if ! grep -q 'ListenStream=/var/spool/postfix/private/pfxhttp-%i' "${template_socket}" ||
    ! grep -q 'FileDescriptorName=%i' "${template_socket}" ||
    ! grep -q 'Accept=no' "${template_socket}" ||
    ! grep -q 'Service=pfxhttp.service' "${template_socket}"; then
    echo "Template socket unit does not map the instance name to the socket descriptor." >&2
    exit 1
  fi

  package_config="${root}/etc/pfxhttp/pfxhttp.yml"
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
}

verify_deb() {
  local pkg
  local tmp

  pkg="$(absolute_path "$1")"

  command -v dpkg-deb >/dev/null 2>&1 || {
    echo "dpkg-deb is required to verify ${pkg}" >&2
    exit 1
  }

  tmp="$(mktemp -d "${tmp_root}/deb.XXXXXX")"
  dpkg-deb -x "${pkg}" "${tmp}"
  verify_tree "${tmp}"

  if ! dpkg-deb -f "${pkg}" Package Version Architecture >/dev/null; then
    echo "Could not read DEB metadata from ${pkg}." >&2
    exit 1
  fi
}

verify_rpm() {
  local pkg
  local tmp

  pkg="$(absolute_path "$1")"

  command -v rpm >/dev/null 2>&1 || {
    echo "rpm is required to verify ${pkg}" >&2
    exit 1
  }
  command -v rpm2cpio >/dev/null 2>&1 || {
    echo "rpm2cpio is required to verify ${pkg}" >&2
    exit 1
  }
  command -v cpio >/dev/null 2>&1 || {
    echo "cpio is required to verify ${pkg}" >&2
    exit 1
  }

  tmp="$(mktemp -d "${tmp_root}/rpm.XXXXXX")"
  (cd "${tmp}" && rpm2cpio "${pkg}" | cpio -idm --quiet)
  verify_tree "${tmp}"

  if ! rpm -qip "${pkg}" >/dev/null; then
    echo "Could not read RPM metadata from ${pkg}." >&2
    exit 1
  fi

  if rpm -qp --requires "${pkg}" | grep -q 'group(pfxhttp)'; then
    echo "RPM package must not depend on a pre-existing pfxhttp group." >&2
    exit 1
  fi
}

for pkg in "$@"; do
  case "${pkg}" in
    *.deb) verify_deb "${pkg}" ;;
    *.rpm) verify_rpm "${pkg}" ;;
    *)
      echo "Unsupported package extension: ${pkg}" >&2
      exit 1
      ;;
  esac
done
