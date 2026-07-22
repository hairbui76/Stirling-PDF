#!/usr/bin/env bash
set -euo pipefail

pdfium_revision=7543
os=$(uname -s)
architecture=$(uname -m)

case "$os" in
  Linux)
    if ldd --version 2>&1 | grep -qi musl; then
      platform=linux-musl
    else
      platform=linux
    fi
    library_relative=lib/libpdfium.so
    library_name=libpdfium.so
    ;;
  Darwin)
    platform=mac
    library_relative=lib/libpdfium.dylib
    library_name=libpdfium.dylib
    ;;
  *)
    echo "Unsupported operating system for PDFium: $os" >&2
    exit 1
    ;;
esac

case "$architecture" in
  x86_64|amd64) architecture=x64 ;;
  aarch64|arm64) architecture=arm64 ;;
  armv7l|armv7) architecture=arm ;;
  i386|i686) architecture=x86 ;;
  *)
    echo "Unsupported architecture for PDFium: $architecture" >&2
    exit 1
    ;;
esac

asset="pdfium-${platform}-${architecture}.tgz"
case "$asset" in
  pdfium-linux-x64.tgz) expected_sha256=9329a3c4b19b3c8d0a93af5440f44be84e4bd879a204e47b1a7a160e96809da4 ;;
  pdfium-linux-arm64.tgz) expected_sha256=4965a4c0b64c45b5edefa1072e2b483bf90b4d25d7deec44f104dcbdecf05c3e ;;
  pdfium-linux-arm.tgz) expected_sha256=820e695b152f5cfe3a794a7abf08cc17a2d4d4f8f52919d9946346cbf5a90572 ;;
  pdfium-linux-x86.tgz) expected_sha256=3495232b5c9ab4f7c1350652663149df1a5ba79b652f2d15bc13c01d5d95db1e ;;
  pdfium-linux-musl-x64.tgz) expected_sha256=f76bc640fac021d949ab59468880d7c62e7a103fb0dcfb42228818858824aa06 ;;
  pdfium-linux-musl-arm64.tgz) expected_sha256=28a0ccc52cea06e55091623c7abcef2079309642a87684552f88b9f018afcc82 ;;
  pdfium-mac-x64.tgz) expected_sha256=2510460ac106f14b884598a0da3f53a99e23d79512acf027c5e101c2bb2f26cb ;;
  pdfium-mac-arm64.tgz) expected_sha256=41c269723b4711793de70ff34e65c00fa79907d6c023741837579e906b846faa ;;
  *)
    echo "No pinned PDFium artifact for $os/$architecture ($asset)" >&2
    exit 1
    ;;
esac

workspace=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cache_root="$workspace/.pdfium"
archive_directory="$cache_root/archives"
archive="$archive_directory/$asset"
asset_stem=${asset%.tgz}
extracted="$cache_root/$pdfium_revision/$asset_stem"
extracted_library="$extracted/$library_relative"
current="$cache_root/current"
current_library="$current/$library_name"

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    echo "A SHA-256 utility (sha256sum or shasum) is required" >&2
    return 1
  fi
}

mkdir -p "$archive_directory" "$extracted" "$current"
actual_sha256=''
if [[ -f "$archive" ]]; then
  actual_sha256=$(sha256_file "$archive")
fi
if [[ "$actual_sha256" != "$expected_sha256" ]]; then
  rm -f "$archive"
  curl --fail --location --retry 3 \
    "https://github.com/bblanchon/pdfium-binaries/releases/download/chromium/$pdfium_revision/$asset" \
    --output "$archive"
  actual_sha256=$(sha256_file "$archive")
  if [[ "$actual_sha256" != "$expected_sha256" ]]; then
    rm -f "$archive"
    echo "Checksum mismatch for $asset: expected $expected_sha256, received $actual_sha256" >&2
    exit 1
  fi
fi

if [[ ! -f "$extracted_library" ]]; then
  tar -xzf "$archive" -C "$extracted"
fi
if [[ ! -f "$extracted_library" ]]; then
  echo "The PDFium archive did not contain $extracted_library" >&2
  exit 1
fi

cp -f "$extracted_library" "$current_library"
cp -f "$extracted/LICENSE" "$current/LICENSE"
if [[ -d "$extracted/licenses" ]]; then
  mkdir -p "$current/licenses"
  cp -R "$extracted/licenses/." "$current/licenses/"
fi

printf '%s\n' "$current_library"
