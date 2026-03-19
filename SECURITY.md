# 🔐 Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 0.1.x   | ✅ Current release |

---

## 🛡️ PortPulse Security Model

PortPulse is a **local-first, read-only** network observability tool. Understanding its security boundaries is critical.

### What PortPulse Does

| Behavior | Details |
|----------|---------|
| **Reads** network metadata | PIDs, IPs, ports, process names, DNS domains |
| **Reads** `/proc` filesystem | Process info, socket inodes, cgroups |
| **Attaches** eBPF kprobes | Read-only kernel observation (when running as root) |
| **Generates** nftables rules | Printed to stdout for **manual review** — never auto-applied |
| **Exports** data to files | JSON/CSV written to user-specified paths |

### What PortPulse Does **NOT** Do

| Behavior | Guarantee |
|----------|-----------|
| ❌ Capture packet payloads | Only metadata (IPs, ports, PIDs) — never packet contents |
| ❌ Modify kernel state | eBPF kprobes are strictly observational |
| ❌ Send data over the network | Zero telemetry, zero analytics, zero phone-home |
| ❌ Auto-apply firewall rules | `quarantine` command only **prints** rules for review |
| ❌ Store persistent data | No databases, no log files unless explicitly exported |
| ❌ Require internet access | Fully offline operation — no external dependencies at runtime |

---

## 🔑 Privilege Requirements

### With eBPF (Full Mode)
```bash
sudo portpulse live
```
Requires one of:
- **Root access** (UID 0)
- **`CAP_BPF` + `CAP_PERFMON`** capabilities (Linux 5.8+)

### Without eBPF (Fallback Mode)
```bash
portpulse live --no-ebpf
```
- No root required
- Reduced visibility (polling `/proc/net/*` instead of real-time eBPF events)
- No DNS query capture in fallback mode
- Short-lived connections may be missed

### Capability-Based Access (Recommended for Production)
```bash
# Set capabilities instead of running as root
sudo setcap cap_bpf,cap_perfmon=ep ./target/release/portpulse

# Run without sudo
portpulse live
```

---

## 🐛 Reporting a Vulnerability

We take security seriously. If you discover a vulnerability in PortPulse, **please report it responsibly**.

### 🚨 Do NOT

- Open a public GitHub issue for security vulnerabilities
- Post vulnerability details on social media or forums
- Exploit the vulnerability beyond what's necessary to demonstrate it

### ✅ Do

1. **Email**: Send a detailed report to **security@portpulse.dev** (or open a [GitHub Security Advisory](https://github.com/the-shadow-0/PortPulse/security/advisories/new))
2. **Include**:
   - Description of the vulnerability
   - Steps to reproduce
   - Affected versions
   - Potential impact assessment
   - Suggested fix (if you have one)
3. **Wait**: We will acknowledge your report within **48 hours**
4. **Coordinate**: We'll work with you on a fix and coordinate disclosure

### 🏆 Recognition

We believe in recognizing security researchers. If you report a valid vulnerability:
- You'll be credited in the security advisory (unless you prefer anonymity)
- You'll be added to our Security Hall of Fame in this file
- We'll coordinate public disclosure timing with you

---

## 🔒 eBPF Security Considerations

### BPF Verifier
All eBPF programs loaded by PortPulse must pass the Linux kernel's **BPF verifier**, which enforces:

| Check | Purpose |
|-------|---------|
| Bounded loops | Prevents infinite execution in kernel context |
| Valid memory access | No out-of-bounds reads or writes |
| Instruction count limit | Finite execution time (prevents kernel hangs) |
| Type safety | Ensures correct argument types for helper functions |
| Stack depth limit | Maximum 512 bytes of stack per eBPF program |

### Automatic Cleanup
- eBPF programs are **reference-counted** by the kernel
- When PortPulse exits (normally or crashes), all probes are automatically detached
- No kernel modifications persist after PortPulse stops

### Perf Buffer Safety
- Events are delivered via a **bounded ring buffer**
- If the buffer fills up, events are **dropped** (not queued)
- The kernel is never blocked waiting for userspace

---

## 📋 Dependency Security

### Audit
```bash
# Run cargo-audit to check for known vulnerabilities
cargo install cargo-audit
cargo audit
```

### Key Dependencies

| Crate | Purpose | Security Notes |
|-------|---------|----------------|
| `tokio` | Async runtime | Widely audited, RUSTSEC tracked |
| `serde` | Serialization | No unsafe code in core |
| `clap` | CLI parsing | No network access |
| `ratatui` | TUI framework | Terminal-only, no network |
| `crossterm` | Terminal control | Terminal-only, no network |
| `chrono` | Time handling | No unsafe in default features |
| `uuid` | Unique IDs | Cryptographically random (v4) |

### Supply Chain
- `Cargo.lock` is committed for **reproducible builds**
- No build scripts download external resources
- No procedural macros execute arbitrary code at compile time

---

## 🏅 Security Hall of Fame

*No vulnerabilities reported yet. Be the first responsible disclosure!*

---

## 📄 Updates

This security policy is reviewed and updated with each release. Last updated: **v0.1.0**.
