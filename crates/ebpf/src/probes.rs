use serde::{Deserialize, Serialize};

/// eBPF probe definitions for PortPulse.
///
/// # Probes Overview
///
/// PortPulse uses three categories of eBPF probes:
///
/// ## 1. TCP Connection Tracking
/// - **kprobe/tcp_v4_connect** — Fires when a process initiates a TCP connection.
///   Captures: PID, source addr:port, destination addr:port.
/// - **kretprobe/tcp_v4_connect** — Return probe to confirm successful connection.
/// - **kprobe/inet_csk_accept** — Fires when a TCP connection is accepted (server-side).
///   Captures: PID, source addr:port, destination addr:port.
/// - **tracepoint/tcp/tcp_set_state** — Tracks TCP state transitions.
///   Captures: oldstate → newstate, socket info.
///
/// ## 2. UDP Tracking  
/// - **kprobe/udp_sendmsg** — Fires when UDP data is sent.
///   Captures: PID, destination addr:port, message length.
/// - **kprobe/udp_recvmsg** — Fires when UDP data is received.
///
/// ## 3. DNS Capture
/// - **kprobe/udp_sendmsg** (port 53 filter) — Captures DNS queries by
///   filtering UDP messages destined to port 53.
/// - **tracepoint/net/net_dev_xmit** — Alternative for packet-level DNS capture.
///
/// # Safety Considerations
///
/// - All probes use BPF_PROG_TYPE_KPROBE or BPF_PROG_TYPE_TRACEPOINT
/// - eBPF verifier ensures memory safety and bounded execution
/// - No kernel modifications: all probes are read-only observers
/// - Automatic cleanup on program exit (eBPF programs are reference-counted)
/// - Perf buffer is used for kernel→userspace event delivery (bounded, non-blocking)

/// Definition of a probe to attach
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeDefinition {
    /// Probe name for identification
    pub name: String,
    /// Type of probe
    pub probe_type: ProbeType,
    /// Kernel function or tracepoint to attach to
    pub attach_point: String,
    /// Whether this probe is required (vs. optional/best-effort)
    pub required: bool,
    /// Description of what this probe captures
    pub description: String,
}

/// Type of eBPF probe
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProbeType {
    Kprobe,
    Kretprobe,
    Tracepoint,
    RawTracepoint,
}

/// Shared event structure passed from eBPF to userspace via perf buffer
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct RawSocketEvent {
    /// Event type discriminator
    pub event_type: u32,
    /// Process ID
    pub pid: u32,
    /// Thread group ID
    pub tgid: u32,
    /// Source IPv4 address (network byte order)
    pub src_addr: u32,
    /// Destination IPv4 address (network byte order)
    pub dst_addr: u32,
    /// Source port
    pub src_port: u16,
    /// Destination port
    pub dst_port: u16,
    /// Bytes transferred (for send/recv)
    pub bytes: u64,
    /// Timestamp (nanoseconds since boot)
    pub timestamp_ns: u64,
}

/// Event type constants matching eBPF program definitions
pub mod event_types {
    pub const TCP_CONNECT: u32 = 1;
    pub const TCP_ACCEPT: u32 = 2;
    pub const TCP_CLOSE: u32 = 3;
    pub const UDP_SEND: u32 = 4;
    pub const UDP_RECV: u32 = 5;
    pub const DNS_QUERY: u32 = 6;
}

/// Get all probe definitions for PortPulse
pub fn default_probes() -> Vec<ProbeDefinition> {
    vec![
        ProbeDefinition {
            name: "tcp_connect".into(),
            probe_type: ProbeType::Kprobe,
            attach_point: "tcp_v4_connect".into(),
            required: true,
            description: "Track outbound TCP connections".into(),
        },
        ProbeDefinition {
            name: "tcp_connect_ret".into(),
            probe_type: ProbeType::Kretprobe,
            attach_point: "tcp_v4_connect".into(),
            required: false,
            description: "Confirm TCP connection success/failure".into(),
        },
        ProbeDefinition {
            name: "tcp_accept".into(),
            probe_type: ProbeType::Kprobe,
            attach_point: "inet_csk_accept".into(),
            required: true,
            description: "Track inbound TCP connections".into(),
        },
        ProbeDefinition {
            name: "tcp_state".into(),
            probe_type: ProbeType::Tracepoint,
            attach_point: "tcp/tcp_set_state".into(),
            required: false,
            description: "Track TCP state transitions".into(),
        },
        ProbeDefinition {
            name: "udp_send".into(),
            probe_type: ProbeType::Kprobe,
            attach_point: "udp_sendmsg".into(),
            required: true,
            description: "Track UDP sends including DNS queries".into(),
        },
        ProbeDefinition {
            name: "udp_recv".into(),
            probe_type: ProbeType::Kprobe,
            attach_point: "udp_recvmsg".into(),
            required: false,
            description: "Track UDP receives including DNS responses".into(),
        },
    ]
}
