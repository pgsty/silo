#!/bin/sh
set -eu

# Build both release architectures from the same verified upstream source.
# The previous binary supplier stopped publishing current ARM64 builds.
CURL_VERSION=8.22.0
CURL_SHA256=f7ef3ae8a22e521f289803fe93543eb64c329b58aa73a9e224dfd915a2a5f4f7

case ${TARGETARCH:?TARGETARCH is required} in
amd64) expected_arch=x86_64 ;;
arm64) expected_arch=aarch64 ;;
*) echo "Unsupported cURL architecture: ${TARGETARCH}" >&2; exit 1 ;;
esac
[ "$(apk --print-arch)" = "$expected_arch" ] || {
    echo "cURL must be built natively for ${TARGETARCH}" >&2
    exit 1
}

apk add --no-cache --upgrade build-base curl ca-certificates \
    openssl-libs-static nghttp2-static libpsl-static libidn2-static \
    libunistring-static zlib-static brotli-static zstd-static libssh2-static

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
