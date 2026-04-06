#!/usr/bin/env bash
# Install prebuilt libaleo_bridge for the current platform.
# Usage: ./install.sh [version]
#   version: git tag (default: latest)
#
# The library is installed to /usr/local/lib (or $INSTALL_DIR if set).

set -euo pipefail

REPO="debendraoli/go-provable-sdk"
VERSION="${1:-latest}"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/lib}"

detect_target() {
    local os arch
    os="$(uname -s)"
    arch="$(uname -m)"

    case "$os" in
        Linux)  os="unknown-linux-gnu" ;;
        Darwin) os="apple-darwin" ;;
        *)      echo "Unsupported OS: $os" >&2; exit 1 ;;
    esac

    case "$arch" in
        x86_64|amd64)  arch="x86_64" ;;
        arm64|aarch64) arch="aarch64" ;;
        *)             echo "Unsupported arch: $arch" >&2; exit 1 ;;
    esac

    echo "${arch}-${os}"
}

TARGET="$(detect_target)"
echo "Detected platform: $TARGET"

if [ "$VERSION" = "latest" ]; then
    DOWNLOAD_URL="https://github.com/$REPO/releases/latest/download/provable-sdk-${TARGET}.tar.gz"
else
    DOWNLOAD_URL="https://github.com/$REPO/releases/download/${VERSION}/provable-sdk-${TARGET}.tar.gz"
fi

echo "Downloading $DOWNLOAD_URL ..."
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

curl -fsSL "$DOWNLOAD_URL" -o "$TMP/archive.tar.gz"
tar xzf "$TMP/archive.tar.gz" -C "$TMP"

echo "Installing to $INSTALL_DIR ..."
if [ -w "$INSTALL_DIR" ]; then
    cp "$TMP"/libaleo_bridge.* "$INSTALL_DIR/"
else
    sudo cp "$TMP"/libaleo_bridge.* "$INSTALL_DIR/"
fi

# Update linker cache on Linux
if [ "$(uname -s)" = "Linux" ] && command -v ldconfig >/dev/null 2>&1; then
    sudo ldconfig
fi

echo "Done. libaleo_bridge installed to $INSTALL_DIR"
echo ""
echo "You can now use the SDK:"
echo "  go get github.com/$REPO"
