#!/usr/bin/env bash

set -euo pipefail

root_dir="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
default_output_prefix="pfxhttp"

output_dir="${OUTPUT_DIR:-${root_dir}/sbom}"
output_prefix="${OUTPUT_PREFIX:-$default_output_prefix}"
output_prefix_set=false
source_dir="${SOURCE_DIR:-$root_dir}"
skip_source=false
file_target=""
syft_version="${SYFT_VERSION:-v1.16.0}"
syft_bin="${SYFT_BIN:-${root_dir}/bin/syft}"

sha256_check() {
	local checksum_file="$1"

	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum -c "$checksum_file"
		return
	fi

	if command -v shasum >/dev/null 2>&1; then
		shasum -a 256 -c "$checksum_file"
		return
	fi

	printf 'No SHA-256 verifier found (sha256sum/shasum).\n' >&2
	exit 1
}

syft_platform() {
	local os arch

	os="$(uname -s)"
	arch="$(uname -m)"

	case "$os" in
	Linux) os="linux" ;;
	Darwin) os="darwin" ;;
	*)
		printf 'Unsupported OS for automatic Syft installation: %s\n' "$os" >&2
		exit 1
		;;
	esac

	case "$arch" in
	x86_64 | amd64) arch="amd64" ;;
	arm64 | aarch64) arch="arm64" ;;
	*)
		printf 'Unsupported architecture for automatic Syft installation: %s\n' "$arch" >&2
		exit 1
		;;
	esac

	printf '%s_%s\n' "$os" "$arch"
}

pretty_print_json() {
	local target="$1"
	local tmp="${target}.tmp"

	if command -v jq >/dev/null 2>&1; then
		jq . "$target" >"$tmp"
	elif command -v python3 >/dev/null 2>&1; then
		python3 -m json.tool "$target" >"$tmp"
	elif command -v python >/dev/null 2>&1; then
		python -m json.tool "$target" >"$tmp"
	else
		printf 'No JSON formatter found for %s.\n' "$target" >&2
		exit 1
	fi

	mv "$tmp" "$target"
}

usage() {
	cat <<'USAGE'
Usage: scripts/sbom.sh [options]

Options:
  --output-dir <path>       Output directory for SBOM files.
  --output-prefix <name>    File name prefix for SBOM files.
  --source-dir <path>       Directory to scan.
  --skip-source             Skip the source directory SBOM.
  --file <path>             Generate an SBOM for one package or archive.
  --syft-version <version>  Syft version to install if it is unavailable.
  --syft-bin <path>         Path to the Syft binary.
  -h, --help                Show this help.
USAGE
}

ensure_syft() {
	if [[ -x "$syft_bin" ]]; then
		return
	fi

	command -v curl >/dev/null 2>&1 || {
		printf 'curl is required to install Syft.\n' >&2
		exit 1
	}
	mkdir -p "$(dirname -- "$syft_bin")"

	local version_no_v platform archive_name release_base tmp_dir checksum_line

	version_no_v="${syft_version#v}"
	platform="$(syft_platform)"
	archive_name="syft_${version_no_v}_${platform}.tar.gz"
	release_base="https://github.com/anchore/syft/releases/download/${syft_version}"
	tmp_dir="$(mktemp -d)"
	trap 'rm -rf "$tmp_dir"' RETURN

	curl -sSfL "${release_base}/${archive_name}" -o "${tmp_dir}/${archive_name}"
	curl -sSfL "${release_base}/syft_${version_no_v}_checksums.txt" -o "${tmp_dir}/checksums.txt"

	checksum_line="$(awk -v archive="$archive_name" '$2 == archive { print; found = 1 } END { exit found ? 0 : 1 }' "${tmp_dir}/checksums.txt")" || {
		printf 'No checksum entry found for %s.\n' "$archive_name" >&2
		exit 1
	}
	printf '%s\n' "$checksum_line" >"${tmp_dir}/selected-checksum.txt"

	(
		cd "$tmp_dir"
		sha256_check selected-checksum.txt
		tar -xzf "$archive_name" syft
		install -m 0755 syft "$syft_bin"
	)

	[[ -x "$syft_bin" ]] || {
		printf 'Syft installation failed.\n' >&2
		exit 1
	}
}

while [[ $# -gt 0 ]]; do
	case "$1" in
	--output-dir)
		output_dir="$2"
		shift 2
		;;
	--output-prefix)
		output_prefix="$2"
		output_prefix_set=true
		shift 2
		;;
	--source-dir)
		source_dir="$2"
		shift 2
		;;
	--skip-source)
		skip_source=true
		shift
		;;
	--file)
		file_target="$2"
		shift 2
		;;
	--syft-version)
		syft_version="$2"
		shift 2
		;;
	--syft-bin)
		syft_bin="$2"
		shift 2
		;;
	-h | --help)
		usage
		exit 0
		;;
	*)
		printf 'Unknown argument: %s\n' "$1" >&2
		usage >&2
		exit 1
		;;
	esac
done

if [[ -n "$file_target" && "$output_prefix_set" == false && "$output_prefix" == "$default_output_prefix" ]]; then
	output_prefix="$(basename -- "$file_target")"
fi

ensure_syft
mkdir -p "$output_dir"

if [[ "$skip_source" == false ]]; then
	[[ -d "$source_dir" ]] || {
		printf 'Source directory not found: %s\n' "$source_dir" >&2
		exit 1
	}
	"$syft_bin" "dir:${source_dir}" -o "spdx-json=${output_dir}/${output_prefix}-source.spdx.json"
	pretty_print_json "${output_dir}/${output_prefix}-source.spdx.json"
fi

if [[ -n "$file_target" ]]; then
	[[ -f "$file_target" ]] || {
		printf 'File not found: %s\n' "$file_target" >&2
		exit 1
	}
	"$syft_bin" "file:${file_target}" -o "spdx-json=${output_dir}/${output_prefix}.spdx.json"
	pretty_print_json "${output_dir}/${output_prefix}.spdx.json"
fi
