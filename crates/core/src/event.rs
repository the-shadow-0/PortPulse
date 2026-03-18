use crate::models::{Connection, DnsQuery, NetworkEvent};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use tokio::sync::broadcast;
use uuid::Uuid;

// ─── Event Types ─────────────────────────────────────────────────────

/// Raw events from the kernel / eBPF probes or proc scanner
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Event {
    /// A new TCP connection was established
    TcpConnect {
        id: Uuid,
        pid: u32,
        src_addr: IpAddr,
        src_port: u16,
        dst_addr: IpAddr,
        dst_port: u16,
        timestamp: DateTime<Utc>,
    },

    /// A TCP connection was accepted (server-side)
    TcpAccept {
        id: Uuid,
        pid: u32,
        src_addr: IpAddr,
        src_port: u16,
        dst_addr: IpAddr,
        dst_port: u16,
        timestamp: DateTime<Utc>,
    },

    /// A UDP message was sent
    UdpSend {
        id: Uuid,
        pid: u32,
        src_addr: IpAddr,
        src_port: u16,
        dst_addr: IpAddr,
        dst_port: u16,
        bytes: u64,
        timestamp: DateTime<Utc>,
    },

    /// A TCP connection was closed
    TcpClose {
        pid: u32,
        src_addr: IpAddr,
        src_port: u16,
        dst_addr: IpAddr,
        dst_port: u16,
        timestamp: DateTime<Utc>,
    },

    /// A DNS query was observed
    DnsQueryEvent {
        pid: Option<u32>,
        domain: String,
        query_type: String,
        timestamp: DateTime<Utc>,
    },

    /// A DNS response was observed
    DnsResponseEvent {
        domain: String,
        resolved_ips: Vec<IpAddr>,
        response_time_ms: u64,
        timestamp: DateTime<Utc>,
    },

    /// Enriched / aggregated connection (post-processing)
    ConnectionUpdate(Connection),

    /// Enriched DNS query (post-processing)
    DnsUpdate(DnsQuery),

    /// Timeline event
    TimelineEvent(NetworkEvent),

    /// System tick for periodic refresh
    Tick,
}

// ─── Event Bus ───────────────────────────────────────────────────────

/// Broadcast-based event bus for fan-out delivery
pub struct EventBus {
    sender: broadcast::Sender<Event>,
}

impl EventBus {
    /// Create a new event bus with the given channel capacity
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self { sender }
    }

    /// Publish an event to all subscribers
    pub fn publish(&self, event: Event) -> Result<(), broadcast::error::SendError<Event>> {
        self.sender.send(event)?;
        Ok(())
    }

    /// Subscribe to events
    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.sender.subscribe()
    }

    /// Get the number of active subscribers
    pub fn subscriber_count(&self) -> usize {
        self.sender.receiver_count()
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new(4096)
    }
}

// ─── Event Filter ────────────────────────────────────────────────────

/// Filter criteria for events
#[derive(Debug, Clone, Default)]
pub struct EventFilter {
    /// Only show events for these PIDs
    pub pids: Option<Vec<u32>>,
    /// Only show events for these ports
    pub ports: Option<Vec<u16>>,
    /// Only show events with risk above this score
    pub min_risk: Option<f64>,
    /// Only show events matching these domains
    pub domains: Option<Vec<String>>,
}

impl EventFilter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_pid(mut self, pid: u32) -> Self {
        self.pids.get_or_insert_with(Vec::new).push(pid);
        self
    }

    pub fn with_port(mut self, port: u16) -> Self {
        self.ports.get_or_insert_with(Vec::new).push(port);
        self
    }

    pub fn with_min_risk(mut self, score: f64) -> Self {
        self.min_risk = Some(score);
        self
    }

    pub fn with_domain(mut self, domain: String) -> Self {
        self.domains.get_or_insert_with(Vec::new).push(domain);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_bus_pub_sub() {
        let bus = EventBus::new(16);
        let mut rx = bus.subscribe();
        
        bus.publish(Event::Tick).unwrap();
        
        let event = rx.try_recv().unwrap();
        assert!(matches!(event, Event::Tick));
    }

    #[test]
    fn test_event_filter_builder() {
        let filter = EventFilter::new()
            .with_pid(1234)
            .with_port(443)
            .with_min_risk(0.5)
            .with_domain("example.com".to_string());

        assert_eq!(filter.pids.unwrap(), vec![1234]);
        assert_eq!(filter.ports.unwrap(), vec![443]);
        assert_eq!(filter.min_risk.unwrap(), 0.5);
        assert_eq!(filter.domains.unwrap(), vec!["example.com"]);
    }
}
