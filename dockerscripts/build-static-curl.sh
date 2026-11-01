#!/bin/sh
set -eu

# Build both release architectures from the same verified upstream source.
# The previous binary supplier stopped publishing current ARM64 builds.
CURL_VERSION=8.23.0
CURL_SHA256=8dadd7d2536a314f982ad05a651b713f426bf7d02cc2c76cffb9796f2218e6c5

case ${TARGETARCH:?TARGETARCH is required} in
amd64) expected_arch=x86_64 ;;
arm64) expected_arch=aarch64 ;;
*) echo "Unsupported cURL architecture: ${TARGETARCH}" >&2; exit 1 ;;
esac
[ "$(apk --print-arch)" = "$expected_arch" ] || {
    echo "cURL must be built natively for ${TARGETARCH}" >&2
    exit 1
}

# Keep security fixes in statically linked libraries, including distro backports.
apk add --no-cache --upgrade build-base curl ca-certificates \
    'musl-dev>=1.2.6-r3' 'openssl-libs-static>=3.5.9-r0' \
    'nghttp2-static>=1.70.0-r0' libpsl-static libidn2-static \
    libunistring-static 'zlib-static>=1.3.2-r1' 'brotli-static>=1.2.1-r0' \
    zstd-static 'libssh2-static>=1.11.1-r4'

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
curl --fail --location --silent --show-error --retry 3 \
    --connect-timeout 15 --max-time 180 \
    "https://curl.se/download/curl-${CURL_VERSION}.tar.xz" -o "$work/curl.tar.xz"
printf '%s  %s\n' "$CURL_SHA256" "$work/curl.tar.xz" | sha256sum -c -
tar -xJf "$work/curl.tar.xz" -C "$work"
cd "$work/curl-${CURL_VERSION}"
PKG_CONFIG="pkg-config --static" LDFLAGS="-static" ./configure \
    --disable-shared --enable-static --with-openssl --with-libssh2 \
    --with-nghttp2 --with-brotli --with-zstd --with-libidn2 --with-libpsl \
    --with-ca-bundle=/etc/ssl/certs/ca-certificates.crt --without-ca-path \
    --disable-ldap --disable-ldaps
# libtool's -static only embeds libcurl; -all-static also embeds its dependencies.
make -j"${CURL_BUILD_JOBS:-4}" LDFLAGS="-all-static"
strip src/curl
if readelf -l src/curl | grep -q INTERP || readelf -d src/curl | grep -q NEEDED; then
    echo "cURL still requires a dynamic loader or shared libraries" >&2
    exit 1
fi
src/curl --version
mkdir -p /go/bin /go/share/curl
cp src/curl /go/bin/curl
cp COPYING /go/share/curl/COPYING
apk info -v | sort > /go/share/curl/build-packages.txt
