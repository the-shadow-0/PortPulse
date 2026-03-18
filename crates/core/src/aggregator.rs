use crate::models::*;
use crate::event::Event;
use chrono::Utc;
use std::collections::HashMap;
use std::net::IpAddr;
use uuid::Uuid;

/// Aggregates raw kernel events into enriched Connection and DnsQuery objects.
///
/// The aggregator correlates events by PID and connection tuple (src:port → dst:port),
/// maintaining state maps for active connections and DNS queries.
pub struct Aggregator {
    /// Active connections indexed by connection tuple
    connections: HashMap<ConnectionKey, Connection>,
    /// DNS cache: domain → resolved IPs
    dns_cache: HashMap<String, Vec<IpAddr>>,
    /// Recent DNS queries for timeline
    dns_queries: Vec<DnsQuery>,
    /// Process info cache
    process_cache: HashMap<u32, ProcessInfo>,
    /// Timeline events
    timeline: Vec<NetworkEvent>,
    /// Maximum timeline events to retain
    max_timeline: usize,
}

/// Unique key for a connection (protocol + local + remote endpoints)
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct ConnectionKey {
    protocol: Protocol,
    local_addr: IpAddr,
    local_port: u16,
    remote_addr: IpAddr,
    remote_port: u16,
}

impl Aggregator {
    pub fn new(max_timeline: usize) -> Self {
        Self {
            connections: HashMap::new(),
            dns_cache: HashMap::new(),
            dns_queries: Vec::new(),
            process_cache: HashMap::new(),
            timeline: Vec::new(),
            max_timeline,
        }
    }

    /// Process a raw event and return enriched events to publish
    pub fn process_event(&mut self, event: &Event) -> Vec<Event> {
        match event {
            Event::TcpConnect {
                id,
                pid,
                src_addr,
                src_port,
                dst_addr,
                dst_port,
                timestamp,
            } => {
                let key = ConnectionKey {
                    protocol: Protocol::Tcp,
                    local_addr: *src_addr,
                    local_port: *src_port,
                    remote_addr: *dst_addr,
                    remote_port: *dst_port,
                };

                let process = self.get_process_info(*pid);
                let hostname = self.reverse_lookup(*dst_addr);

                let conn = Connection {
                    id: *id,
                    protocol: Protocol::Tcp,
                    state: ConnectionState::Established,
                    local_addr: *src_addr,
                    local_port: *src_port,
                    remote_addr: *dst_addr,
                    remote_port: *dst_port,
                    remote_hostname: hostname,
                    process,
                    risk: RiskScore::safe(),
                    started_at: *timestamp,
                    last_seen: *timestamp,
                    bytes_sent: 0,
                    bytes_recv: 0,
                };

                self.connections.insert(key, conn.clone());

                let timeline_event = NetworkEvent {
                    id: Uuid::new_v4(),
                    event_type: NetworkEventType::ConnectionOpened,
                    timestamp: *timestamp,
                    pid: Some(*pid),
                    description: format!(
                        "TCP connection: {}:{} → {}:{}",
                        src_addr, src_port, dst_addr, dst_port
                    ),
                    risk: RiskLevel::Safe,
                };
                self.add_timeline_event(timeline_event.clone());

                vec![
                    Event::ConnectionUpdate(conn),
                    Event::TimelineEvent(timeline_event),
                ]
            }

            Event::TcpAccept {
                id,
                pid,
                src_addr,
                src_port,
                dst_addr,
                dst_port,
                timestamp,
            } => {
                let key = ConnectionKey {
                    protocol: Protocol::Tcp,
                    local_addr: *src_addr,
                    local_port: *src_port,
                    remote_addr: *dst_addr,
                    remote_port: *dst_port,
                };

                let process = self.get_process_info(*pid);

                let conn = Connection {
                    id: *id,
                    protocol: Protocol::Tcp,
                    state: ConnectionState::Established,
                    local_addr: *src_addr,
                    local_port: *src_port,
                    remote_addr: *dst_addr,
                    remote_port: *dst_port,
                    remote_hostname: self.reverse_lookup(*dst_addr),
                    process,
                    risk: RiskScore::safe(),
                    started_at: *timestamp,
                    last_seen: *timestamp,
                    bytes_sent: 0,
                    bytes_recv: 0,
                };

                self.connections.insert(key, conn.clone());
                vec![Event::ConnectionUpdate(conn)]
            }

            Event::UdpSend {
                id,
                pid,
                src_addr,
                src_port,
                dst_addr,
                dst_port,
                bytes,
                timestamp,
            } => {
                let key = ConnectionKey {
                    protocol: Protocol::Udp,
                    local_addr: *src_addr,
                    local_port: *src_port,
                    remote_addr: *dst_addr,
                    remote_port: *dst_port,
                };

                let conn = self.connections.entry(key).or_insert_with(|| {
                    let process = self.process_cache
                        .get(pid)
                        .cloned()
                        .unwrap_or_else(|| ProcessInfo::unknown(*pid));
                    Connection {
                        id: *id,
                        protocol: Protocol::Udp,
                        state: ConnectionState::Established,
                        local_addr: *src_addr,
                        local_port: *src_port,
                        remote_addr: *dst_addr,
                        remote_port: *dst_port,
                        remote_hostname: None,
                        process,
                        risk: RiskScore::safe(),
                        started_at: *timestamp,
                        last_seen: *timestamp,
                        bytes_sent: 0,
                        bytes_recv: 0,
                    }
                });

                conn.bytes_sent += bytes;
                conn.last_seen = *timestamp;

                vec![Event::ConnectionUpdate(conn.clone())]
            }

            Event::TcpClose {
                pid,
                src_addr,
                src_port,
                dst_addr,
                dst_port,
                timestamp,
            } => {
                let key = ConnectionKey {
                    protocol: Protocol::Tcp,
                    local_addr: *src_addr,
                    local_port: *src_port,
                    remote_addr: *dst_addr,
                    remote_port: *dst_port,
                };

                if let Some(mut conn) = self.connections.remove(&key) {
                    conn.state = ConnectionState::Close;
                    conn.last_seen = *timestamp;

                    let timeline_event = NetworkEvent {
                        id: Uuid::new_v4(),
                        event_type: NetworkEventType::ConnectionClosed,
                        timestamp: *timestamp,
                        pid: Some(*pid),
                        description: format!(
                            "TCP closed: {}:{} → {}:{}",
                            src_addr, src_port, dst_addr, dst_port
                        ),
                        risk: conn.risk.level,
                    };
                    self.add_timeline_event(timeline_event.clone());

                    vec![
                        Event::ConnectionUpdate(conn),
                        Event::TimelineEvent(timeline_event),
                    ]
                } else {
                    vec![]
                }
            }

            Event::DnsQueryEvent {
                pid,
                domain,
                query_type,
                timestamp,
            } => {
                let dns = DnsQuery {
                    id: Uuid::new_v4(),
                    domain: domain.clone(),
                    query_type: parse_dns_type(query_type),
                    resolved_ips: vec![],
                    process: pid.and_then(|p| self.process_cache.get(&p).cloned()),
                    timestamp: *timestamp,
                    response_time_ms: None,
                    risk: RiskScore::safe(),
                };

                let timeline_event = NetworkEvent {
                    id: Uuid::new_v4(),
                    event_type: NetworkEventType::DnsQuery,
                    timestamp: *timestamp,
                    pid: *pid,
                    description: format!("DNS query: {} ({})", domain, query_type),
                    risk: RiskLevel::Safe,
                };
                self.add_timeline_event(timeline_event.clone());
                self.dns_queries.push(dns.clone());

                vec![
                    Event::DnsUpdate(dns),
                    Event::TimelineEvent(timeline_event),
                ]
            }

            Event::DnsResponseEvent {
                domain,
                resolved_ips,
                response_time_ms,
                timestamp: _,
            } => {
                self.dns_cache
                    .insert(domain.clone(), resolved_ips.clone());

                // Update the latest matching DNS query
                if let Some(query) = self.dns_queries.iter_mut().rev().find(|q| q.domain == *domain) {
                    query.resolved_ips = resolved_ips.clone();
                    query.response_time_ms = Some(*response_time_ms);
                    return vec![Event::DnsUpdate(query.clone())];
                }

                vec![]
            }

            _ => vec![],
        }
    }

    /// Get all active connections
    pub fn connections(&self) -> Vec<&Connection> {
        self.connections.values().collect()
    }

    /// Get all DNS queries
    pub fn dns_queries(&self) -> &[DnsQuery] {
        &self.dns_queries
    }

    /// Get the timeline
    pub fn timeline(&self) -> &[NetworkEvent] {
        &self.timeline
    }

    /// Update process cache
    pub fn update_process(&mut self, info: ProcessInfo) {
        self.process_cache.insert(info.pid, info);
    }

    /// Get process info from cache
    fn get_process_info(&self, pid: u32) -> ProcessInfo {
        self.process_cache
            .get(&pid)
            .cloned()
            .unwrap_or_else(|| ProcessInfo::unknown(pid))
    }

    /// Reverse-lookup an IP from DNS cache
    fn reverse_lookup(&self, addr: IpAddr) -> Option<String> {
        for (domain, ips) in &self.dns_cache {
            if ips.contains(&addr) {
                return Some(domain.clone());
            }
        }
        None
    }

    /// Add an event to the timeline, enforcing max size
    fn add_timeline_event(&mut self, event: NetworkEvent) {
        self.timeline.push(event);
        if self.timeline.len() > self.max_timeline {
            self.timeline.remove(0);
        }
    }

    /// Clear stale connections older than the given duration
    pub fn gc_stale(&mut self, max_age_secs: i64) {
        let now = Utc::now();
        self.connections.retain(|_, conn| {
            (now - conn.last_seen).num_seconds() < max_age_secs
        });
    }
}

/// Parse DNS query type string into enum
fn parse_dns_type(s: &str) -> DnsQueryType {
    match s.to_uppercase().as_str() {
        "A" => DnsQueryType::A,
        "AAAA" => DnsQueryType::AAAA,
        "CNAME" => DnsQueryType::CNAME,
        "MX" => DnsQueryType::MX,
        "TXT" => DnsQueryType::TXT,
        "NS" => DnsQueryType::NS,
        "PTR" => DnsQueryType::PTR,
        "SRV" => DnsQueryType::SRV,
        "SOA" => DnsQueryType::SOA,
        _ => DnsQueryType::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_tcp_connect_creates_connection() {
        let mut agg = Aggregator::new(100);
        let event = Event::TcpConnect {
            id: Uuid::new_v4(),
            pid: 1234,
            src_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            src_port: 54321,
            dst_addr: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            dst_port: 443,
            timestamp: Utc::now(),
        };

        let results = agg.process_event(&event);
        assert!(!results.is_empty());
        assert_eq!(agg.connections().len(), 1);
    }

    #[test]
    fn test_tcp_close_removes_connection() {
        let mut agg = Aggregator::new(100);
        let src = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let dst = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        let now = Utc::now();

        agg.process_event(&Event::TcpConnect {
            id: Uuid::new_v4(),
            pid: 1234,
            src_addr: src,
            src_port: 54321,
            dst_addr: dst,
            dst_port: 443,
            timestamp: now,
        });
        assert_eq!(agg.connections().len(), 1);

        agg.process_event(&Event::TcpClose {
            pid: 1234,
            src_addr: src,
            src_port: 54321,
            dst_addr: dst,
            dst_port: 443,
            timestamp: now,
        });
        assert_eq!(agg.connections().len(), 0);
    }

    #[test]
    fn test_dns_query_and_response() {
        let mut agg = Aggregator::new(100);

        agg.process_event(&Event::DnsQueryEvent {
            pid: Some(1234),
            domain: "example.com".to_string(),
            query_type: "A".to_string(),
            timestamp: Utc::now(),
        });
        assert_eq!(agg.dns_queries().len(), 1);

        agg.process_event(&Event::DnsResponseEvent {
            domain: "example.com".to_string(),
            resolved_ips: vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
            response_time_ms: 42,
            timestamp: Utc::now(),
        });
        assert!(!agg.dns_queries().last().unwrap().resolved_ips.is_empty());
    }
}
