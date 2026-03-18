.PHONY: build release install test lint fmt clean check

# Default target
all: check build

# Build debug binary
build:
	cargo build --workspace

# Build release binary (optimized, stripped)
release:
	cargo build --workspace --release

# Install the binary
install:
	cargo install --path crates/cli

# Run all tests
test:
	cargo test --workspace

# Run clippy linter
lint:
	cargo clippy --workspace -- -D warnings

# Format code
fmt:
	cargo fmt --all

# Check formatting
fmt-check:
	cargo fmt --all -- --check

# Run all checks (format + lint + test)
check: fmt-check lint test

# Clean build artifacts
clean:
	cargo clean

# Build static binary (for distribution)
static:
	RUSTFLAGS='-C target-feature=+crt-static' cargo build --release --target x86_64-unknown-linux-gnu

# Run with sudo (for eBPF probes)
run:
	sudo cargo run --bin portpulse -- live

# Run in fallback mode (no root required)
run-fallback:
	cargo run --bin portpulse -- live --no-ebpf

# Show help
help:
	@echo "PortPulse Build Targets:"
	@echo "  make build       — Build debug binary"
	@echo "  make release     — Build release binary"
	@echo "  make install     — Install binary to ~/.cargo/bin"
	@echo "  make test        — Run all tests"
	@echo "  make lint        — Run clippy"
	@echo "  make fmt         — Format code"
	@echo "  make check       — Format + lint + test"
	@echo "  make clean       — Clean build artifacts"
	@echo "  make static      — Build static binary"
	@echo "  make run         — Run with sudo (eBPF)"
	@echo "  make run-fallback— Run without eBPF"
