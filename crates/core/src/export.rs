use crate::models::{Connection, DnsQuery, NetworkEvent};
use anyhow::Result;
use serde::Serialize;
use std::io::Write;

/// Export system for connections, DNS queries, and timeline events.
///
/// Supports JSON and CSV output formats for integration with
/// external tools, SIEMs, and reporting systems.
pub struct Exporter;

impl Exporter {
    /// Export connections to JSON
    pub fn connections_to_json<W: Write>(writer: W, connections: &[Connection]) -> Result<()> {
        serde_json::to_writer_pretty(writer, connections)?;
        Ok(())
    }

    /// Export connections to CSV
    pub fn connections_to_csv<W: Write>(writer: W, connections: &[Connection]) -> Result<()> {
        let mut wtr = csv::Writer::from_writer(writer);

        #[derive(Serialize)]
        struct ConnectionRow {
            id: String,
            protocol: String,
            state: String,
            local_addr: String,
            local_port: u16,
            remote_addr: String,
            remote_port: u16,
            remote_hostname: String,
            process_name: String,
            pid: u32,
            user: String,
            container_id: String,
            risk_score: f64,
            risk_level: String,
            started_at: String,
            last_seen: String,
            bytes_sent: u64,
            bytes_recv: u64,
        }

        for conn in connections {
            wtr.serialize(ConnectionRow {
                id: conn.id.to_string(),
                protocol: conn.protocol.to_string(),
                state: conn.state.to_string(),
                local_addr: conn.local_addr.to_string(),
                local_port: conn.local_port,
                remote_addr: conn.remote_addr.to_string(),
                remote_port: conn.remote_port,
                remote_hostname: conn.remote_hostname.clone().unwrap_or_default(),
                process_name: conn.process.name.clone(),
                pid: conn.process.pid,
                user: conn.process.user.clone(),
                container_id: conn.process.container_id.clone().unwrap_or_default(),
                risk_score: conn.risk.score,
                risk_level: conn.risk.level.to_string(),
                started_at: conn.started_at.to_rfc3339(),
                last_seen: conn.last_seen.to_rfc3339(),
                bytes_sent: conn.bytes_sent,
                bytes_recv: conn.bytes_recv,
            })?;
        }

        wtr.flush()?;
        Ok(())
    }

    /// Export DNS queries to JSON
    pub fn dns_to_json<W: Write>(writer: W, queries: &[DnsQuery]) -> Result<()> {
        serde_json::to_writer_pretty(writer, queries)?;
        Ok(())
    }

    /// Export DNS queries to CSV
    pub fn dns_to_csv<W: Write>(writer: W, queries: &[DnsQuery]) -> Result<()> {
        let mut wtr = csv::Writer::from_writer(writer);

        #[derive(Serialize)]
        struct DnsRow {
            id: String,
            domain: String,
            query_type: String,
            resolved_ips: String,
            process_name: String,
            pid: String,
            timestamp: String,
            response_time_ms: String,
            risk_score: f64,
            risk_level: String,
        }

        for query in queries {
            wtr.serialize(DnsRow {
                id: query.id.to_string(),
                domain: query.domain.clone(),
                query_type: query.query_type.to_string(),
                resolved_ips: query
                    .resolved_ips
                    .iter()
                    .map(|ip| ip.to_string())
                    .collect::<Vec<_>>()
                    .join(";"),
                process_name: query
                    .process
                    .as_ref()
                    .map(|p| p.name.clone())
                    .unwrap_or_default(),
                pid: query
                    .process
                    .as_ref()
                    .map(|p| p.pid.to_string())
                    .unwrap_or_default(),
                timestamp: query.timestamp.to_rfc3339(),
                response_time_ms: query
                    .response_time_ms
                    .map(|ms| ms.to_string())
                    .unwrap_or_default(),
                risk_score: query.risk.score,
                risk_level: query.risk.level.to_string(),
            })?;
        }

        wtr.flush()?;
        Ok(())
    }

    /// Export timeline events to JSON
    pub fn timeline_to_json<W: Write>(writer: W, events: &[NetworkEvent]) -> Result<()> {
        serde_json::to_writer_pretty(writer, events)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::*;
    use chrono::Utc;
    use std::net::{IpAddr, Ipv4Addr};
    use uuid::Uuid;

    fn sample_connection() -> Connection {
        Connection {
            id: Uuid::new_v4(),
            protocol: Protocol::Tcp,
            state: ConnectionState::Established,
            local_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            local_port: 54321,
            remote_addr: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            remote_port: 443,
            remote_hostname: Some("example.com".to_string()),
            process: ProcessInfo {
                pid: 1234,
                ppid: 1,
                name: "curl".to_string(),
                cmdline: "curl https://example.com".to_string(),
                user: "testuser".to_string(),
                uid: 1000,
                container_id: None,
                cgroup: None,
                first_seen: Utc::now(),
            },
            risk: RiskScore::safe(),
            started_at: Utc::now(),
            last_seen: Utc::now(),
            bytes_sent: 1024,
            bytes_recv: 4096,
        }
    }

    #[test]
    fn test_json_export() {
        let conns = vec![sample_connection()];
        let mut buf = Vec::new();
        Exporter::connections_to_json(&mut buf, &conns).unwrap();
        let json = String::from_utf8(buf).unwrap();
        assert!(json.contains("example.com"));
        assert!(json.contains("curl"));
    }

    #[test]
    fn test_csv_export() {
        let conns = vec![sample_connection()];
        let mut buf = Vec::new();
        Exporter::connections_to_csv(&mut buf, &conns).unwrap();
        let csv = String::from_utf8(buf).unwrap();
        assert!(csv.contains("example.com"));
        assert!(csv.contains("curl"));
    }
}
