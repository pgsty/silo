#!/usr/bin/env bash

set -euo pipefail

if [ "$#" -ne 1 ]; then
	echo "usage: $0 TARGET" >&2
	exit 2
fi

target=$1
target_dir=$(dirname "${target}")
if [ ! -d "${target_dir}" ]; then
	echo "target directory does not exist: ${target_dir}" >&2
	exit 1
fi

sha256_file() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | awk '{print $1}'
	else
		shasum -a 256 "$1" | awk '{print $1}'
	fi
}

if [ -n "${MCLI_BIN:-}" ]; then
	if [ ! -f "${MCLI_BIN}" ]; then
		echo "MCLI_BIN is not a regular file: ${MCLI_BIN}" >&2
		exit 1
	fi
	if ! printf '%s\n' "${MCLI_SHA256:-}" | grep -Eq '^[0-9a-fA-F]{64}$'; then
		echo "MCLI_SHA256 must contain the expected SHA-256 for MCLI_BIN" >&2
		exit 1
	fi
	actual=$(sha256_file "${MCLI_BIN}")
	if [ "${actual}" != "${MCLI_SHA256,,}" ]; then
		echo "MCLI_BIN checksum mismatch: expected ${MCLI_SHA256,,}, got ${actual}" >&2
		exit 1
	fi
	install -m 0755 "${MCLI_BIN}" "${target}"
	exit 0
fi

release=${MCLI_RELEASE:-RELEASE.2026-09-13T00-00-00Z}
version_hyphen=${release#RELEASE.}
package_version=$(printf '%s\n' "${version_hyphen}" | sed -E 's/^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2})-([0-9]{2})-([0-9]{2})Z$/\1\2\3\4\5\6.0.0/')
if [ "${package_version}" = "${version_hyphen}" ]; then
	echo "invalid MCLI_RELEASE: ${release}" >&2
	exit 1
fi

case $(uname -s) in
	Linux) os=linux ;;
	Darwin) os=darwin ;;
	*) echo "unsupported mcli host OS: $(uname -s)" >&2; exit 1 ;;
esac
case $(uname -m) in
	x86_64 | amd64) arch=amd64 ;;
	aarch64 | arm64) arch=arm64 ;;
	*) echo "unsupported mcli host architecture: $(uname -m)" >&2; exit 1 ;;
esac

archive="mcli_${package_version}_${os}_${arch}.tar.gz"
checksums="mcli_${package_version}_checksums.txt"
base_url="https://github.com/pgsty/mc/releases/download/${release}"
tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/silo-mcli.XXXXXX")
trap 'rm -rf "${tmp_dir}"' EXIT

curl --fail --location --retry 3 --silent --show-error \
	"${base_url}/${checksums}" --output "${tmp_dir}/${checksums}"
curl --fail --location --retry 3 --silent --show-error \
	"${base_url}/${archive}" --output "${tmp_dir}/${archive}"

expected=$(awk -v asset="${archive}" '
	{
		name=$2
		sub(/^\*/, "", name)
		if (name == asset && length($1) == 64 && $1 ~ /^[0-9a-fA-F]+$/) print tolower($1)
	}
' "${tmp_dir}/${checksums}")
if ! printf '%s\n' "${expected}" | grep -Eq '^[0-9a-f]{64}$'; then
	echo "checksum manifest does not contain exactly one valid entry for ${archive}" >&2
	exit 1
fi
actual=$(sha256_file "${tmp_dir}/${archive}")
if [ "${actual}" != "${expected}" ]; then
	echo "downloaded ${archive} checksum mismatch" >&2
	exit 1
fi

tar -xzf "${tmp_dir}/${archive}" -C "${tmp_dir}" mcli
install -m 0755 "${tmp_dir}/mcli" "${target}"
