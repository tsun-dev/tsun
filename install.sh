#!/bin/bash
# tsun installer script
# Usage: curl -sSL https://raw.githubusercontent.com/cWashington91/tsun/main/install.sh | bash

set -e

# Detect OS and architecture
OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
    Linux*)
        case "$ARCH" in
            x86_64)  PLATFORM="linux-x86_64" ;;
            aarch64) PLATFORM="linux-aarch64" ;;
            *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
        esac
        ;;
    Darwin*)
        case "$ARCH" in
            x86_64)  PLATFORM="macos-x86_64" ;;
            arm64)   PLATFORM="macos-aarch64" ;;
            *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
        esac
        ;;
    *)
        echo "Unsupported operating system: $OS"
        exit 1
        ;;
esac

echo "Detected platform: $PLATFORM"
echo "Installing tsun..."

# Download and extract
DOWNLOAD_URL="https://github.com/cWashington91/tsun/releases/latest/download/tsun-${PLATFORM}.tar.gz"

echo "Downloading from: $DOWNLOAD_URL"
curl -sSL "$DOWNLOAD_URL" | tar xz

# Install to /usr/local/bin or ~/bin
INSTALL_DIR="/usr/local/bin"
if [ ! -w "$INSTALL_DIR" ]; then
    INSTALL_DIR="$HOME/bin"
    mkdir -p "$INSTALL_DIR"
fi

mv tsun "$INSTALL_DIR/"
chmod +x "$INSTALL_DIR/tsun"

echo ""
echo "✓ tsun installed to $INSTALL_DIR/tsun"
echo ""

# Check if directory is in PATH
if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
    echo "⚠ Warning: $INSTALL_DIR is not in your PATH"
    echo "Add this to your shell profile (~/.bashrc or ~/.zshrc):"
    echo "  export PATH=\"$INSTALL_DIR:\$PATH\""
    echo ""
fi

# Verify installation
if command -v tsun &> /dev/null; then
    echo "Installation verified:"
    tsun --version
else
    echo "⚠ tsun installed but not in PATH. Run: $INSTALL_DIR/tsun --version"
fi

echo ""
echo "Get started:"
echo "  tsun scan --target http://testphp.vulnweb.com --engine mock"
echo ""
echo "Docs: https://github.com/cWashington91/tsun"
