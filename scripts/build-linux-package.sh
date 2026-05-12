#!/usr/bin/env bash
set -euo pipefail

APP_NAME="pfxhttp"
DESCRIPTION="Postfix to HTTP wrapper"
MAINTAINER="Christian Roessner <christian@roessner.email>"
SERVICE_USER="pfxhttp"
SERVICE_GROUP="pfxhttp"

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
  cat <<'USAGE'
Usage: scripts/build-linux-package.sh --type deb|rpm --arch ARCH --version VERSION --binary PATH [--out-dir DIR]
       scripts/build-linux-package.sh --stage-only --binary PATH --stage-root DIR

Build a Linux package from an already-built pfxhttp binary.

ARCH accepts amd64/x86_64 or arm64/aarch64. DEB and RPM package paths are
staged with distro-owned paths under /usr, not /usr/local.
USAGE
}

package_type=""
arch=""
version=""
binary="${repo_root}/${APP_NAME}"
out_dir="${repo_root}/dist/packages"
stage_only=false
stage_root=""
cleanup_tmp=""

cleanup() {
  if [[ -n "${cleanup_tmp}" ]]; then
    rm -rf "${cleanup_tmp}"
  fi
}

trap cleanup EXIT

while [[ $# -gt 0 ]]; do
  case "$1" in
    --type)
      package_type="$2"
      shift 2
      ;;
    --arch)
      arch="$2"
      shift 2
      ;;
    --version)
      version="$2"
      shift 2
      ;;
    --binary)
      binary="$2"
      shift 2
      ;;
    --out-dir)
      out_dir="$2"
      shift 2
      ;;
    --stage-only)
      stage_only=true
      shift
      ;;
    --stage-root)
      stage_root="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

normalize_deb_arch() {
  case "$1" in
    amd64|x86_64) echo "amd64" ;;
    arm64|aarch64) echo "arm64" ;;
    *) echo "Unsupported DEB architecture: $1" >&2; return 1 ;;
  esac
}

normalize_rpm_arch() {
  case "$1" in
    amd64|x86_64) echo "x86_64" ;;
    arm64|aarch64) echo "aarch64" ;;
    *) echo "Unsupported RPM architecture: $1" >&2; return 1 ;;
  esac
}

install_service_file() {
  local root="$1"
  local target="${root}/usr/lib/systemd/system/${APP_NAME}.service"

  sed \
    -e 's#/usr/local/sbin/pfxhttp#/usr/sbin/pfxhttp#g' \
    "${repo_root}/contrib/systemd/${APP_NAME}.service" > "${target}"
  chmod 0644 "${target}"
}

stage_common_tree() {
  local root="$1"

  if [[ ! -f "${binary}" ]]; then
    echo "Binary not found: ${binary}" >&2
    exit 1
  fi

  rm -rf "${root}"
  install -d -m 0755 \
    "${root}/etc/${APP_NAME}" \
    "${root}/usr/lib/systemd/system" \
    "${root}/usr/sbin" \
    "${root}/usr/share/doc/${APP_NAME}" \
    "${root}/usr/share/man/man5" \
    "${root}/usr/share/man/man8"

  install -m 0755 "${binary}" "${root}/usr/sbin/${APP_NAME}"
  install -m 0640 "${repo_root}/packaging/${APP_NAME}.yml" "${root}/etc/${APP_NAME}/${APP_NAME}.yml"
  install -m 0640 "${repo_root}/packaging/${APP_NAME}.env" "${root}/etc/${APP_NAME}/${APP_NAME}.env"

  install_service_file "${root}"
  install -m 0644 "${repo_root}/contrib/systemd/${APP_NAME}-policy.socket" "${root}/usr/lib/systemd/system/"
  install -m 0644 "${repo_root}/contrib/systemd/${APP_NAME}@.socket" "${root}/usr/lib/systemd/system/"

  gzip -n -9 -c "${repo_root}/man/man5/${APP_NAME}.yml.5" > "${root}/usr/share/man/man5/${APP_NAME}.yml.5.gz"
  gzip -n -9 -c "${repo_root}/man/man8/${APP_NAME}.8" > "${root}/usr/share/man/man8/${APP_NAME}.8.gz"
  chmod 0644 "${root}/usr/share/man/man5/${APP_NAME}.yml.5.gz" "${root}/usr/share/man/man8/${APP_NAME}.8.gz"

  install -m 0644 "${repo_root}/README.md" "${root}/usr/share/doc/${APP_NAME}/"
  install -m 0644 "${repo_root}/LICENSE" "${root}/usr/share/doc/${APP_NAME}/"
  install -m 0644 "${repo_root}/${APP_NAME}.yml" "${root}/usr/share/doc/${APP_NAME}/${APP_NAME}.yml.demo"
}

write_deb_scripts() {
  local debian_dir="$1"

  cat > "${debian_dir}/postinst" <<'EOF'
#!/bin/sh
set -e

if ! getent group pfxhttp >/dev/null 2>&1; then
  addgroup --system pfxhttp >/dev/null 2>&1 || groupadd --system pfxhttp
fi

if ! getent passwd pfxhttp >/dev/null 2>&1; then
  nologin="/usr/sbin/nologin"
  if [ ! -x "${nologin}" ]; then
    nologin="/sbin/nologin"
  fi

  adduser --system --ingroup pfxhttp --no-create-home --home /nonexistent \
    --shell "${nologin}" --disabled-login --disabled-password pfxhttp >/dev/null 2>&1 ||
    useradd --system --gid pfxhttp --home-dir /nonexistent --no-create-home \
      --shell "${nologin}" pfxhttp
fi

if getent group pfxhttp >/dev/null 2>&1; then
  chgrp pfxhttp /etc/pfxhttp/pfxhttp.yml /etc/pfxhttp/pfxhttp.env 2>/dev/null || true
  chmod 0640 /etc/pfxhttp/pfxhttp.yml /etc/pfxhttp/pfxhttp.env 2>/dev/null || true
fi

if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload >/dev/null 2>&1 || true
fi

exit 0
EOF

  cat > "${debian_dir}/postrm" <<'EOF'
#!/bin/sh
set -e

if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload >/dev/null 2>&1 || true
fi

exit 0
EOF

  chmod 0755 "${debian_dir}/postinst" "${debian_dir}/postrm"
}

build_deb() {
  local deb_arch
  deb_arch="$(normalize_deb_arch "${arch}")"

  command -v dpkg-deb >/dev/null 2>&1 || {
    echo "dpkg-deb is required to build DEB packages" >&2
    exit 1
  }

  local tmp pkg debian_dir package_file installed_size
  tmp="$(mktemp -d)"
  cleanup_tmp="${tmp}"
  pkg="${tmp}/${APP_NAME}"
  debian_dir="${pkg}/DEBIAN"

  stage_common_tree "${pkg}"
  install -d -m 0755 "${debian_dir}"

  installed_size="$(du -sk "${pkg}" | awk '{print $1}')"
  cat > "${debian_dir}/control" <<EOF
Package: ${APP_NAME}
Version: ${version}
Section: mail
Priority: optional
Architecture: ${deb_arch}
Maintainer: ${MAINTAINER}
Installed-Size: ${installed_size}
Depends: ca-certificates
Description: ${DESCRIPTION}
 pfxhttp exposes Postfix socket map, policy service, and Dovecot SASL
 integration over HTTP or gRPC backends.
EOF

  cat > "${debian_dir}/conffiles" <<EOF
/etc/${APP_NAME}/${APP_NAME}.yml
/etc/${APP_NAME}/${APP_NAME}.env
EOF
  write_deb_scripts "${debian_dir}"

  install -d -m 0755 "${out_dir}"
  package_file="${out_dir}/${APP_NAME}_${version}_${deb_arch}.deb"
  dpkg-deb -Zgzip --root-owner-group --build "${pkg}" "${package_file}"
}

write_rpm_spec() {
  local spec_file="$1"
  local rpm_arch="$2"
  local source_name="$3"

  cat > "${spec_file}" <<EOF
%global debug_package %{nil}
%global __os_install_post %{nil}

Name: ${APP_NAME}
Version: ${version}
Release: 1%{?dist}
Summary: ${DESCRIPTION}
License: MIT
URL: https://github.com/croessner/pfxhttp
BuildArch: ${rpm_arch}
Source0: ${source_name}
Requires: ca-certificates
Requires(pre): shadow-utils
Requires(post): systemd
Requires(postun): systemd

%description
pfxhttp exposes Postfix socket map, policy service, and Dovecot SASL
integration over HTTP or gRPC backends.

%prep
%setup -q -n ${APP_NAME}-${version}

%build

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}
cp -a . %{buildroot}/

%pre
if ! getent group ${SERVICE_GROUP} >/dev/null 2>&1; then
  groupadd -r ${SERVICE_GROUP}
fi

if ! getent passwd ${SERVICE_USER} >/dev/null 2>&1; then
  nologin="/sbin/nologin"
  if [ -x /usr/sbin/nologin ]; then
    nologin="/usr/sbin/nologin"
  fi

  useradd -r -g ${SERVICE_GROUP} -d /nonexistent -s "\${nologin}" \
    -c "pfxhttp service user" ${SERVICE_USER}
fi

%post
if getent group ${SERVICE_GROUP} >/dev/null 2>&1; then
  chgrp ${SERVICE_GROUP} /etc/${APP_NAME}/${APP_NAME}.yml /etc/${APP_NAME}/${APP_NAME}.env 2>/dev/null || true
  chmod 0640 /etc/${APP_NAME}/${APP_NAME}.yml /etc/${APP_NAME}/${APP_NAME}.env 2>/dev/null || true
fi

if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload >/dev/null 2>&1 || true
fi

%postun
if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload >/dev/null 2>&1 || true
fi

%files
%defattr(-,root,root,-)
%dir /etc/${APP_NAME}
%config(noreplace) %attr(0640,root,root) /etc/${APP_NAME}/${APP_NAME}.yml
%config(noreplace) %attr(0640,root,root) /etc/${APP_NAME}/${APP_NAME}.env
/usr/sbin/${APP_NAME}
/usr/lib/systemd/system/${APP_NAME}.service
/usr/lib/systemd/system/${APP_NAME}-policy.socket
/usr/lib/systemd/system/${APP_NAME}@.socket
%doc /usr/share/doc/${APP_NAME}/README.md
%doc /usr/share/doc/${APP_NAME}/${APP_NAME}.yml.demo
%license /usr/share/doc/${APP_NAME}/LICENSE
/usr/share/man/man5/${APP_NAME}.yml.5.gz
/usr/share/man/man8/${APP_NAME}.8.gz

%changelog
* Tue May 12 2026 ${MAINTAINER} - ${version}-1
- Package ${APP_NAME} ${version}
EOF
}

build_rpm() {
  local rpm_arch
  rpm_arch="$(normalize_rpm_arch "${arch}")"

  command -v rpmbuild >/dev/null 2>&1 || {
    echo "rpmbuild is required to build RPM packages" >&2
    exit 1
  }

  local tmp pkg srcdir source_name spec_file
  tmp="$(mktemp -d)"
  cleanup_tmp="${tmp}"
  pkg="${tmp}/pkgroot"
  srcdir="${tmp}/${APP_NAME}-${version}"
  source_name="${APP_NAME}-${version}.tar.gz"

  stage_common_tree "${pkg}"
  mkdir -p "${srcdir}" "${tmp}/rpmbuild/BUILD" "${tmp}/rpmbuild/RPMS" \
    "${tmp}/rpmbuild/SOURCES" "${tmp}/rpmbuild/SPECS" "${tmp}/rpmbuild/SRPMS"
  cp -a "${pkg}/." "${srcdir}/"
  tar -C "${tmp}" -czf "${tmp}/rpmbuild/SOURCES/${source_name}" "${APP_NAME}-${version}"

  spec_file="${tmp}/rpmbuild/SPECS/${APP_NAME}.spec"
  write_rpm_spec "${spec_file}" "${rpm_arch}" "${source_name}"

  rpmbuild \
    --define "_topdir ${tmp}/rpmbuild" \
    --target "${rpm_arch}" \
    -bb "${spec_file}"

  install -d -m 0755 "${out_dir}"
  find "${tmp}/rpmbuild/RPMS" -type f -name '*.rpm' -exec cp {} "${out_dir}/" \;
}

if [[ "${stage_only}" == "true" ]]; then
  if [[ -z "${stage_root}" ]]; then
    echo "--stage-root is required with --stage-only" >&2
    usage >&2
    exit 1
  fi

  stage_common_tree "${stage_root}"
  exit 0
fi

if [[ -z "${package_type}" || -z "${arch}" || -z "${version}" ]]; then
  usage >&2
  exit 1
fi

case "${package_type}" in
  deb) build_deb ;;
  rpm) build_rpm ;;
  *)
    echo "Unsupported package type: ${package_type}" >&2
    usage >&2
    exit 1
    ;;
esac
