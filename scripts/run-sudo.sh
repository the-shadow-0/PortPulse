#!/bin/bash
# Run PortPulse with sudo while preserving the user's Rust toolchain.
# Usage: ./scripts/run-sudo.sh [portpulse args...]
#
# Why this script exists:
# When you run `sudo cargo run`, sudo uses root's PATH which may have
# a different (or no) Rust toolchain, causing Cargo.lock version mismatches.
# This script passes the user's cargo/rustc paths to sudo explicitly.

set -euo pipefail

CARGO_BIN=$(which cargo)
RUSTC_BIN=$(which rustc)
RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}"
CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"

echo "⚡ PortPulse — Running with elevated privileges"
echo "  Cargo: $CARGO_BIN"
echo "  Rustc: $RUSTC_BIN"
echo ""

# Method 1: If binary is already built, just run it directly
if [ -f "target/debug/portpulse" ]; then
    echo "  Using pre-built binary: target/debug/portpulse"
    sudo ./target/debug/portpulse "$@"
elif [ -f "target/release/portpulse" ]; then
    echo "  Using pre-built binary: target/release/portpulse"
    sudo ./target/release/portpulse "$@"
else
    # Method 2: Build first (as user), then run with sudo
    echo "  Building first..."
    cargo build --bin portpulse
    echo "  Running with sudo..."
    sudo ./target/debug/portpulse "$@"
fi
