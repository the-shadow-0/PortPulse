use crate::models::*;

/// Risk classifier engine using heuristic scoring.
///
/// Analyzes connections and DNS queries for suspicious patterns,
/// producing a score between 0.0 (safe) and 1.0 (critical) with
/// human-readable explanations.
pub struct RiskClassifier {
    /// Known suspicious TLDs
    suspicious_tlds: Vec<String>,
    /// Known suspicious ports
    suspicious_ports: Vec<u16>,
    /// Known safe domains (allowlist)
    safe_domains: Vec<String>,
    /// Known suspicious domain patterns
    suspicious_patterns: Vec<String>,
}

impl RiskClassifier {
    pub fn new() -> Self {
        Self {
            suspicious_tlds: vec![
                ".tk".into(), ".ml".into(), ".ga".into(), ".cf".into(),
                ".gq".into(), ".xyz".into(), ".top".into(), ".buzz".into(),
                ".club".into(), ".work".into(), ".icu".into(),
            ],
            suspicious_ports: vec![
                4444, 5555, 6666, 6667, 6697, 8080, 8443, 9001, 9050, 9150,
                31337, 12345, 54321, 1337,
            ],
            safe_domains: vec![
                "google.com".into(), "amazonaws.com".into(), "github.com".into(),
                "microsoft.com".into(), "apple.com".into(), "cloudflare.com".into(),
                "fastly.net".into(), "akamai.net".into(), "debian.org".into(),
                "ubuntu.com".into(), "arch.org".into(), "kernel.org".into(),
            ],
            suspicious_patterns: vec![
                "crypto".into(), "miner".into(), "c2".into(), "botnet".into(),
                "malware".into(), "phish".into(), "darkweb".into(),
            ],
        }
    }

    /// Score a connection for risk
    pub fn score_connection(&self, conn: &Connection) -> RiskScore {
        let mut score: f64 = 0.0;
        let mut reasons: Vec<String> = Vec::new();

        // ── Port analysis ──
        if self.suspicious_ports.contains(&conn.remote_port) {
            score += 0.35;
            reasons.push(format!("Suspicious port: {}", conn.remote_port));
        }

        // Non-standard high ports for outbound connections
        if conn.remote_port > 10000 && conn.remote_port != 443 && conn.remote_port != 80 {
            score += 0.1;
            reasons.push(format!("Non-standard high port: {}", conn.remote_port));
        }

        // ── Domain analysis ──
        if let Some(ref hostname) = conn.remote_hostname {
            let hostname_lower = hostname.to_lowercase();

            // Suspicious TLD check
            for tld in &self.suspicious_tlds {
                if hostname_lower.ends_with(tld) {
                    score += 0.3;
                    reasons.push(format!("Suspicious TLD: {}", tld));
                    break;
                }
            }

            // Suspicious pattern check
            for pattern in &self.suspicious_patterns {
                if hostname_lower.contains(pattern) {
                    score += 0.4;
                    reasons.push(format!("Suspicious domain pattern: \"{}\"", pattern));
                    break;
                }
            }

            // IP address as hostname (no DNS resolution)
            if hostname_lower.parse::<std::net::IpAddr>().is_ok() {
                score += 0.15;
                reasons.push("Direct IP connection (no DNS)".into());
            }

            // Very long subdomain (potential DGA)
            let parts: Vec<&str> = hostname_lower.split('.').collect();
            if parts.iter().any(|p| p.len() > 20) {
                score += 0.25;
                reasons.push("Unusually long subdomain (possible DGA)".into());
            }

            // Entropy check — many unique characters suggests generated domain
            if hostname_lower.len() > 10 {
                let unique_chars: std::collections::HashSet<char> = hostname_lower.chars().collect();
                let entropy_ratio = unique_chars.len() as f64 / hostname_lower.len() as f64;
                if entropy_ratio > 0.8 {
                    score += 0.2;
                    reasons.push("High domain entropy (possible DGA)".into());
                }
            }
        } else {
            // No hostname resolved — direct IP connection
            score += 0.1;
            reasons.push("No hostname resolved for target IP".into());
        }

        // ── Process analysis ──
        if conn.process.name.starts_with('<') || conn.process.name.is_empty() {
            score += 0.2;
            reasons.push("Unknown or unnamed process".into());
        }

        if conn.process.uid == 0 && conn.remote_port != 443 && conn.remote_port != 80 {
            score += 0.15;
            reasons.push("Root process making non-HTTP connection".into());
        }

        // ── Safe domain reduction ──
        if let Some(ref hostname) = conn.remote_hostname {
            let hostname_lower = hostname.to_lowercase();
            for safe in &self.safe_domains {
                if hostname_lower.ends_with(safe) {
                    score -= 0.4;
                    reasons.push(format!("Known safe domain: {}", safe));
                    break;
                }
            }
        }

        // Well-known safe ports reduction
        if conn.remote_port == 443 || conn.remote_port == 80 || conn.remote_port == 53 {
            score -= 0.05;
        }

        RiskScore::new(score, reasons)
    }

    /// Score a DNS query for risk
    pub fn score_dns(&self, query: &DnsQuery) -> RiskScore {
        let mut score: f64 = 0.0;
        let mut reasons: Vec<String> = Vec::new();

        let domain_lower = query.domain.to_lowercase();

        // Suspicious TLD
        for tld in &self.suspicious_tlds {
            if domain_lower.ends_with(tld) {
                score += 0.3;
                reasons.push(format!("Suspicious TLD: {}", tld));
                break;
            }
        }

        // Suspicious pattern
        for pattern in &self.suspicious_patterns {
            if domain_lower.contains(pattern) {
                score += 0.4;
                reasons.push(format!("Suspicious pattern: \"{}\"", pattern));
                break;
            }
        }

        // Very long domain (potential data exfil via DNS)
        if domain_lower.len() > 60 {
            score += 0.35;
            reasons.push("Unusually long domain (possible DNS tunneling)".into());
        }

        // Many subdomains
        let dot_count = domain_lower.chars().filter(|&c| c == '.').count();
        if dot_count > 4 {
            score += 0.2;
            reasons.push(format!("Many subdomains ({} levels)", dot_count + 1));
        }

        // No resolved IPs (NXDOMAIN or timeout)
        if query.resolved_ips.is_empty() && query.response_time_ms.is_some() {
            score += 0.15;
            reasons.push("DNS query returned no results".into());
        }

        // Safe domain reduction
        for safe in &self.safe_domains {
            if domain_lower.ends_with(safe) {
                score -= 0.4;
                reasons.push(format!("Known safe domain: {}", safe));
                break;
            }
        }

        RiskScore::new(score, reasons)
    }

    /// Add a custom suspicious domain pattern
    pub fn add_suspicious_pattern(&mut self, pattern: String) {
        self.suspicious_patterns.push(pattern);
    }

    /// Add a custom safe domain
    pub fn add_safe_domain(&mut self, domain: String) {
        self.safe_domains.push(domain);
    }

    /// Add a custom suspicious port
    pub fn add_suspicious_port(&mut self, port: u16) {
        self.suspicious_ports.push(port);
    }
}

impl Default for RiskClassifier {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::net::{IpAddr, Ipv4Addr};
    use uuid::Uuid;

    fn make_connection(remote_port: u16, hostname: Option<&str>, process_name: &str) -> Connection {
        Connection {
            id: Uuid::new_v4(),
            protocol: Protocol::Tcp,
            state: ConnectionState::Established,
            local_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            local_port: 54321,
            remote_addr: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            remote_port,
            remote_hostname: hostname.map(String::from),
            process: ProcessInfo {
                pid: 1234,
                ppid: 1,
                name: process_name.to_string(),
                cmdline: String::new(),
                user: "testuser".to_string(),
                uid: 1000,
                container_id: None,
                cgroup: None,
                first_seen: Utc::now(),
            },
            risk: RiskScore::safe(),
            started_at: Utc::now(),
            last_seen: Utc::now(),
            bytes_sent: 0,
            bytes_recv: 0,
        }
    }

    #[test]
    fn test_safe_connection() {
        let classifier = RiskClassifier::new();
        let conn = make_connection(443, Some("google.com"), "curl");
        let risk = classifier.score_connection(&conn);
        assert!(risk.score < 0.3, "google.com:443 should be low risk, got {}", risk.score);
    }

    #[test]
    fn test_suspicious_port() {
        let classifier = RiskClassifier::new();
        let conn = make_connection(4444, None, "unknown_binary");
        let risk = classifier.score_connection(&conn);
        assert!(risk.score > 0.3, "port 4444 should be suspicious, got {}", risk.score);
    }

    #[test]
    fn test_suspicious_tld() {
        let classifier = RiskClassifier::new();
        let conn = make_connection(80, Some("evil.tk"), "curl");
        let risk = classifier.score_connection(&conn);
        assert!(risk.score > 0.2, ".tk TLD should increase risk, got {}", risk.score);
    }

    #[test]
    fn test_dns_tunneling_detection() {
        let classifier = RiskClassifier::new();
        let query = DnsQuery {
            id: Uuid::new_v4(),
            domain: "aVeryLongSubdomainThatMightBeUsedForDataExfiltrationViaDnsTunneling.evil.tk".to_string(),
            query_type: DnsQueryType::A,
            resolved_ips: vec![],
            process: None,
            timestamp: Utc::now(),
            response_time_ms: Some(100),
            risk: RiskScore::safe(),
        };
        let risk = classifier.score_dns(&query);
        assert!(risk.score > 0.5, "DNS tunneling pattern should be high risk, got {}", risk.score);
    }
}
