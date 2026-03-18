use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::IpAddr;
use uuid::Uuid;

// ─── Protocol ────────────────────────────────────────────────────────

/// Network protocol type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Unknown,
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Protocol::Tcp => write!(f, "TCP"),
            Protocol::Udp => write!(f, "UDP"),
            Protocol::Icmp => write!(f, "ICMP"),
            Protocol::Unknown => write!(f, "???"),
        }
    }
}

// ─── Connection State ────────────────────────────────────────────────

/// TCP connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ConnectionState {
    Established,
    SynSent,
    SynRecv,
    FinWait1,
    FinWait2,
    TimeWait,
    Close,
    CloseWait,
    LastAck,
    Listen,
    Closing,
    Unknown,
}

impl fmt::Display for ConnectionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConnectionState::Established => write!(f, "ESTABLISHED"),
            ConnectionState::SynSent => write!(f, "SYN_SENT"),
            ConnectionState::SynRecv => write!(f, "SYN_RECV"),
            ConnectionState::FinWait1 => write!(f, "FIN_WAIT1"),
            ConnectionState::FinWait2 => write!(f, "FIN_WAIT2"),
            ConnectionState::TimeWait => write!(f, "TIME_WAIT"),
            ConnectionState::Close => write!(f, "CLOSE"),
            ConnectionState::CloseWait => write!(f, "CLOSE_WAIT"),
            ConnectionState::LastAck => write!(f, "LAST_ACK"),
            ConnectionState::Listen => write!(f, "LISTEN"),
            ConnectionState::Closing => write!(f, "CLOSING"),
            ConnectionState::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

impl ConnectionState {
    /// Parse the numeric state from /proc/net/tcp
    pub fn from_proc_state(state: u8) -> Self {
        match state {
            0x01 => ConnectionState::Established,
            0x02 => ConnectionState::SynSent,
            0x03 => ConnectionState::SynRecv,
            0x04 => ConnectionState::FinWait1,
            0x05 => ConnectionState::FinWait2,
            0x06 => ConnectionState::TimeWait,
            0x07 => ConnectionState::Close,
            0x08 => ConnectionState::CloseWait,
            0x09 => ConnectionState::LastAck,
            0x0A => ConnectionState::Listen,
            0x0B => ConnectionState::Closing,
            _ => ConnectionState::Unknown,
        }
    }
}

// ─── Risk Level ──────────────────────────────────────────────────────

/// Risk severity level for connections
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RiskLevel {
    Safe,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RiskLevel::Safe => write!(f, "✓ SAFE"),
            RiskLevel::Low => write!(f, "◐ LOW"),
            RiskLevel::Medium => write!(f, "▲ MEDIUM"),
            RiskLevel::High => write!(f, "⚠ HIGH"),
            RiskLevel::Critical => write!(f, "🔴 CRITICAL"),
        }
    }
}

impl RiskLevel {
    /// Convert a score between 0.0 and 1.0 to a risk level
    pub fn from_score(score: f64) -> Self {
        match score {
            s if s < 0.1 => RiskLevel::Safe,
            s if s < 0.3 => RiskLevel::Low,
            s if s < 0.6 => RiskLevel::Medium,
            s if s < 0.85 => RiskLevel::High,
            _ => RiskLevel::Critical,
        }
    }
}

// ─── Risk Score ──────────────────────────────────────────────────────

/// Computed risk score with explanation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskScore {
    /// Numeric score between 0.0 (safe) and 1.0 (critical)
    pub score: f64,
    /// Human-readable severity level
    pub level: RiskLevel,
    /// Reasons contributing to the risk score
    pub reasons: Vec<String>,
}

impl RiskScore {
    pub fn safe() -> Self {
        Self {
            score: 0.0,
            level: RiskLevel::Safe,
            reasons: vec![],
        }
    }

    pub fn new(score: f64, reasons: Vec<String>) -> Self {
        let clamped = score.clamp(0.0, 1.0);
        Self {
            score: clamped,
            level: RiskLevel::from_score(clamped),
            reasons,
        }
    }
}

// ─── Process Info ────────────────────────────────────────────────────

/// Information about a Linux process
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    /// Process ID
    pub pid: u32,
    /// Parent process ID
    pub ppid: u32,
    /// Process name (comm)
    pub name: String,
    /// Full command line
    pub cmdline: String,
    /// User who owns the process
    pub user: String,
    /// User ID
    pub uid: u32,
    /// Container ID (if running in a container)
    pub container_id: Option<String>,
    /// cgroup path
    pub cgroup: Option<String>,
    /// When the process was first seen
    pub first_seen: DateTime<Utc>,
}

impl ProcessInfo {
    pub fn unknown(pid: u32) -> Self {
        Self {
            pid,
            ppid: 0,
            name: format!("<pid:{}>", pid),
            cmdline: String::new(),
            user: String::from("unknown"),
            uid: 0,
            container_id: None,
            cgroup: None,
            first_seen: Utc::now(),
        }
    }
}

// ─── Connection ──────────────────────────────────────────────────────

/// A tracked network connection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Connection {
    /// Unique connection identifier
    pub id: Uuid,
    /// Protocol (TCP, UDP, etc.)
    pub protocol: Protocol,
    /// Connection state
    pub state: ConnectionState,
    /// Local IP address
    pub local_addr: IpAddr,
    /// Local port
    pub local_port: u16,
    /// Remote IP address
    pub remote_addr: IpAddr,
    /// Remote port
    pub remote_port: u16,
    /// Resolved remote hostname (if known)
    pub remote_hostname: Option<String>,
    /// Process information
    pub process: ProcessInfo,
    /// Risk assessment
    pub risk: RiskScore,
    /// Connection established timestamp
    pub started_at: DateTime<Utc>,
    /// Last activity timestamp
    pub last_seen: DateTime<Utc>,
    /// Bytes sent
    pub bytes_sent: u64,
    /// Bytes received
    pub bytes_recv: u64,
}

// ─── DNS Query ───────────────────────────────────────────────────────

/// A captured DNS query
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsQuery {
    /// Unique query ID
    pub id: Uuid,
    /// Domain being resolved
    pub domain: String,
    /// Query type (A, AAAA, CNAME, etc.)
    pub query_type: DnsQueryType,
    /// Resolved IP addresses
    pub resolved_ips: Vec<IpAddr>,
    /// Process that made the query
    pub process: Option<ProcessInfo>,
    /// When the query was made
    pub timestamp: DateTime<Utc>,
    /// Response time in milliseconds
    pub response_time_ms: Option<u64>,
    /// Risk assessment
    pub risk: RiskScore,
}

/// DNS query type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DnsQueryType {
    A,
    AAAA,
    CNAME,
    MX,
    TXT,
    NS,
    PTR,
    SRV,
    SOA,
    Unknown,
}

impl fmt::Display for DnsQueryType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DnsQueryType::A => write!(f, "A"),
            DnsQueryType::AAAA => write!(f, "AAAA"),
            DnsQueryType::CNAME => write!(f, "CNAME"),
            DnsQueryType::MX => write!(f, "MX"),
            DnsQueryType::TXT => write!(f, "TXT"),
            DnsQueryType::NS => write!(f, "NS"),
            DnsQueryType::PTR => write!(f, "PTR"),
            DnsQueryType::SRV => write!(f, "SRV"),
            DnsQueryType::SOA => write!(f, "SOA"),
            DnsQueryType::Unknown => write!(f, "???"),
        }
    }
}

// ─── Network Event (for timeline) ───────────────────────────────────

/// A discrete network event for timeline tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkEvent {
    /// Unique event ID
    pub id: Uuid,
    /// Event type
    pub event_type: NetworkEventType,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    /// Associated PID
    pub pid: Option<u32>,
    /// Human-readable description
    pub description: String,
    /// Risk level for this event
    pub risk: RiskLevel,
}

/// Types of network events
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NetworkEventType {
    ConnectionOpened,
    ConnectionClosed,
    DnsQuery,
    DnsResponse,
    SuspiciousActivity,
    PolicyViolation,
    ProcessStarted,
    ProcessExited,
    PortListening,
}

impl fmt::Display for NetworkEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetworkEventType::ConnectionOpened => write!(f, "CONN_OPEN"),
            NetworkEventType::ConnectionClosed => write!(f, "CONN_CLOSE"),
            NetworkEventType::DnsQuery => write!(f, "DNS_QUERY"),
            NetworkEventType::DnsResponse => write!(f, "DNS_RESP"),
            NetworkEventType::SuspiciousActivity => write!(f, "SUSPICIOUS"),
            NetworkEventType::PolicyViolation => write!(f, "POLICY_VIOL"),
            NetworkEventType::ProcessStarted => write!(f, "PROC_START"),
            NetworkEventType::ProcessExited => write!(f, "PROC_EXIT"),
            NetworkEventType::PortListening => write!(f, "PORT_LISTEN"),
        }
    }
}

// ─── Policy ──────────────────────────────────────────────────────────

/// A policy rule for the policy engine
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    /// Rule name
    pub name: String,
    /// Rule description
    pub description: String,
    /// Rule type
    pub rule_type: PolicyRuleType,
    /// Whether the rule is enabled
    pub enabled: bool,
}

/// Types of policy rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PolicyRuleType {
    /// Block connections to specific domains
    BlockDomain { domains: Vec<String> },
    /// Block connections on specific ports
    BlockPort { ports: Vec<u16> },
    /// Block specific IP ranges
    BlockIpRange { cidrs: Vec<String> },
    /// Alert on process making network calls
    AlertOnProcess { process_names: Vec<String> },
    /// Custom risk threshold alert
    RiskThreshold { min_score: f64 },
}
