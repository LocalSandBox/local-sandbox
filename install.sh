#!/bin/sh
set -eu

REPO="LocalSandBox/local-sandbox"
INSTALL_DIR="$HOME/.local/bin"

##### Platform checks

OS="$(uname -s)"
ARCH="$(uname -m)"

if [ "$OS" != "Darwin" ]; then
    echo "Error: this installer currently ships macOS CLI release artifacts only. Detected: $OS" >&2
    echo "Windows 11 x64 backend and Node package support exist, but Windows CLI release/install artifacts are not shipped yet." >&2
    exit 1
fi

case "$OS:$ARCH" in
    Darwin:arm64)
        CLI_SUFFIX="darwin-aarch64"
        ;;
    Darwin:x86_64)
        CLI_SUFFIX="darwin-x86_64"
        ;;
    *)
        echo "Error: lsb does not support this platform yet. Detected: $OS/$ARCH" >&2
        exit 1
        ;;
esac

##### Fetch latest release tag

echo "Fetching latest release..."
TAG=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p')

if [ -z "$TAG" ]; then
    echo "Error: could not determine latest release." >&2
    exit 1
fi

VERSION="${TAG#v}"
echo "Latest version: $VERSION"

##### Download and extract

TARBALL="lsb-v${VERSION}-${CLI_SUFFIX}.tar.gz"
URL="https://github.com/${REPO}/releases/download/${TAG}/${TARBALL}"

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

echo "Downloading ${TARBALL}..."
curl -fsSL "$URL" -o "$TMPDIR/$TARBALL"

mkdir -p "$INSTALL_DIR"
tar -xzf "$TMPDIR/$TARBALL" -C "$INSTALL_DIR"
chmod +x "$INSTALL_DIR/lsb"
xattr -d com.apple.quarantine "$INSTALL_DIR/lsb" 2>/dev/null || true

echo ""
echo "Installed lsb $VERSION to $INSTALL_DIR/lsb"

##### PATH check

case ":$PATH:" in
    *":$INSTALL_DIR:"*) ;;
    *)
        echo ""
        echo "Add $INSTALL_DIR to your PATH:"
        echo ""
        echo "  export PATH=\"$INSTALL_DIR:\$PATH\""
        echo ""
        echo "Add the line above to your ~/.zshrc to make it permanent."
        ;;
esac
