# Contributing to PortPulse

Thank you for your interest in contributing to PortPulse! 🎉

## Getting Started

### Prerequisites
- Rust 1.75+ (`rustup install stable`)
- Linux (eBPF features require kernel 5.4+)
- `cargo`, `clippy`, `rustfmt`

### Building from Source
```bash
git clone https://github.com/the-shadow-0/PortPulse.git
cd portpulse
cargo build --workspace
cargo test --workspace
```

### Running
```bash
# With eBPF (requires root)
sudo cargo run --bin portpulse -- live

# Without eBPF (fallback mode)
cargo run --bin portpulse -- live --no-ebpf

# Run tests
cargo test --workspace

# Run linter
cargo clippy --workspace -- -D warnings

# Format code
cargo fmt --all
```

## How to Contribute

### Reporting Bugs
1. Check existing issues first
2. Include: OS, kernel version, Rust version
3. Provide reproduction steps
4. Include relevant PortPulse output

### Suggesting Features
1. Open a discussion first
2. Describe the use case
3. Propose an implementation approach

### Pull Requests
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Write tests for new functionality
4. Ensure `cargo test --workspace` passes
5. Ensure `cargo clippy --workspace -- -D warnings` passes
6. Ensure `cargo fmt --all -- --check` passes
7. Submit a PR with a clear description

## Architecture Overview

PortPulse is organized as a Cargo workspace with 4 crates:

| Crate | Purpose |
|---|---|
| `portpulse-core` | Data models, event pipeline, aggregator, classifier, policy engine, export |
| `portpulse-ebpf` | eBPF probe definitions, loader, event reader, /proc fallback |
| `portpulse-tui` | Ratatui terminal UI, widgets, theme, animated graph |
| `portpulse` (cli) | Binary entry point, clap arguments, subcommand handlers |

### Data Flow
```
Kernel / /proc → Event Source → EventBus → Aggregator → Classifier → TUI
```

## Good First Issues

Here are some great starter tasks:

- **Add port descriptions**: Expand the `explain` command's port database
- **IPv6 graph support**: Add IPv6 address handling to the connection graph
- **Sortable columns**: Implement click-to-sort in the connections table
- **Color themes**: Add light/solarized/dracula themes
- **More tests**: Increase test coverage for the classifier and policy engine
- **Documentation**: Improve inline code documentation

## Plugin System (Future)

PortPulse is designed for extensibility. Future plugin ideas:

- **Exporters**: Prometheus, Elasticsearch, InfluxDB
- **Enrichers**: GeoIP, WHOIS, threat feeds
- **Alerters**: Slack, Discord, PagerDuty
- **Resolvers**: Custom DNS resolution
- **Analyzers**: Custom risk scoring modules

## Code Style

- Follow standard Rust conventions
- Use `tracing` for logging (not `println!` in library code)
- Document public APIs with `///` doc comments
- Keep functions focused and under 50 lines where possible
- Write tests for all public APIs

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
