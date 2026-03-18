#!/bin/bash
set -euo pipefail

# PortPulse Installer
# Usage: curl -sSf https://raw.githubusercontent.com/the-shadow-0/PortPulse/main/scripts/install.sh | sh

REPO="the-shadow-0/PortPulse"
BINARY="portpulse"
INSTALL_DIR="${HOME}/.local/bin"

echo "⚡ PortPulse Installer"
echo "═══════════════════════"
echo ""

# Detect architecture
ARCH=$(uname -m)
case "$ARCH" in
    x86_64)  TARGET="x86_64-unknown-linux-gnu" ;;
    aarch64) TARGET="aarch64-unknown-linux-gnu" ;;
    *)
        echo "❌ Unsupported architecture: $ARCH"
        echo "   Please build from source: cargo install --path crates/cli"
        exit 1
        ;;
esac

echo "  Architecture: $ARCH ($TARGET)"

# Check for Rust/cargo
if command -v cargo &> /dev/null; then
    echo "  Cargo found: $(cargo --version)"
    echo ""
    echo "  Installing from source (recommended)..."
    echo ""
    
    TMPDIR=$(mktemp -d)
    trap "rm -rf $TMPDIR" EXIT
    
    git clone "https://github.com/${REPO}.git" "$TMPDIR/portpulse" --depth 1
    cd "$TMPDIR/portpulse"
    cargo install --path crates/cli
    
    echo ""
    echo "✅ PortPulse installed successfully!"
    echo ""
    echo "  Usage:"
    echo "    sudo portpulse live          # Launch dashboard (with eBPF)"
    echo "    portpulse live --no-ebpf     # Launch dashboard (fallback)"
    echo "    portpulse --help             # Show all commands"
else
    echo "  Cargo not found."
    echo ""
    echo "  To install PortPulse, you need Rust:"
    echo "    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
    echo ""
    echo "  Then run this script again."
    exit 1
fi
