#!/bin/sh
set -eu

REPO="superhq-ai/shuru"
INSTALL_DIR="$HOME/.local/bin"

##### Platform checks

OS="$(uname -s)"
ARCH="$(uname -m)"

if [ "$OS" != "Darwin" ]; then
    echo "Error: shuru only supports macOS. Detected: $OS" >&2
    exit 1
fi

case "$OS:$ARCH" in
    Darwin:arm64)
        CLI_SUFFIX="darwin-aarch64"
        ;;
    Darwin:x86_64)
        echo "Error: shuru does not support Intel macOS yet. Detected: $ARCH" >&2
        exit 1
        ;;
    *)
        echo "Error: shuru does not support this platform yet. Detected: $OS/$ARCH" >&2
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

TARBALL="shuru-v${VERSION}-${CLI_SUFFIX}.tar.gz"
URL="https://github.com/${REPO}/releases/download/${TAG}/${TARBALL}"

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

echo "Downloading ${TARBALL}..."
curl -fsSL "$URL" -o "$TMPDIR/$TARBALL"

mkdir -p "$INSTALL_DIR"
tar -xzf "$TMPDIR/$TARBALL" -C "$INSTALL_DIR"
chmod +x "$INSTALL_DIR/shuru"
xattr -d com.apple.quarantine "$INSTALL_DIR/shuru" 2>/dev/null || true

echo ""
echo "Installed shuru $VERSION to $INSTALL_DIR/shuru"

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
