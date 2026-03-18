use crate::models::*;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Policy engine that evaluates connections and DNS queries against user-defined rules.
///
/// Rules can block domains, ports, IP ranges, alert on specific processes,
/// or trigger on risk thresholds.
pub struct PolicyEngine {
    /// Active policy rules
    rules: Vec<PolicyRule>,
}

/// A policy violation produced by the engine
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyViolation {
    /// The rule that was violated
    pub rule_name: String,
    /// Description of the violation
    pub description: String,
    /// Severity level
    pub severity: RiskLevel,
    /// Suggested action
    pub suggested_action: PolicyAction,
    /// Timestamp of the violation
    pub timestamp: chrono::DateTime<Utc>,
}

/// Suggested action when a policy is violated
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PolicyAction {
    /// Just log an alert
    Alert,
    /// Suggest blocking via nftables
    SuggestBlock { nft_rule: String },
    /// Suggest killing the process
    SuggestKill { pid: u32 },
    /// Quarantine the domain
    SuggestQuarantine { domain: String },
}

impl PolicyEngine {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Add a policy rule
    pub fn add_rule(&mut self, rule: PolicyRule) {
        self.rules.push(rule);
    }

    /// Remove a policy rule by name
    pub fn remove_rule(&mut self, name: &str) {
        self.rules.retain(|r| r.name != name);
    }

    /// Get all rules
    pub fn rules(&self) -> &[PolicyRule] {
        &self.rules
    }

    /// Evaluate a connection against all active rules
    pub fn evaluate_connection(&self, conn: &Connection) -> Vec<PolicyViolation> {
        let mut violations = Vec::new();

        for rule in &self.rules {
            if !rule.enabled {
                continue;
            }

            match &rule.rule_type {
                PolicyRuleType::BlockDomain { domains } => {
                    if let Some(ref hostname) = conn.remote_hostname {
                        let hostname_lower = hostname.to_lowercase();
                        for domain in domains {
                            if hostname_lower.contains(&domain.to_lowercase()) {
                                violations.push(PolicyViolation {
                                    rule_name: rule.name.clone(),
                                    description: format!(
                                        "Connection to blocked domain '{}' by process {} (PID {})",
                                        hostname, conn.process.name, conn.process.pid
                                    ),
                                    severity: RiskLevel::High,
                                    suggested_action: PolicyAction::SuggestBlock {
                                        nft_rule: format!(
                                            "nft add rule ip filter output ip daddr {} drop # {}",
                                            conn.remote_addr, hostname
                                        ),
                                    },
                                    timestamp: Utc::now(),
                                });
                            }
                        }
                    }
                }

                PolicyRuleType::BlockPort { ports } => {
                    if ports.contains(&conn.remote_port) {
                        violations.push(PolicyViolation {
                            rule_name: rule.name.clone(),
                            description: format!(
                                "Connection to blocked port {} by process {} (PID {})",
                                conn.remote_port, conn.process.name, conn.process.pid
                            ),
                            severity: RiskLevel::Medium,
                            suggested_action: PolicyAction::SuggestBlock {
                                nft_rule: format!(
                                    "nft add rule ip filter output tcp dport {} drop",
                                    conn.remote_port
                                ),
                            },
                            timestamp: Utc::now(),
                        });
                    }
                }

                PolicyRuleType::BlockIpRange { cidrs } => {
                    // Simplified: exact IP match (CIDR matching would need an IP library)
                    let remote_str = conn.remote_addr.to_string();
                    for cidr in cidrs {
                        if remote_str.starts_with(cidr.split('/').next().unwrap_or("")) {
                            violations.push(PolicyViolation {
                                rule_name: rule.name.clone(),
                                description: format!(
                                    "Connection to blocked IP range {} by {}",
                                    cidr, conn.process.name
                                ),
                                severity: RiskLevel::High,
                                suggested_action: PolicyAction::SuggestBlock {
                                    nft_rule: format!(
                                        "nft add rule ip filter output ip daddr {} drop",
                                        cidr
                                    ),
                                },
                                timestamp: Utc::now(),
                            });
                        }
                    }
                }

                PolicyRuleType::AlertOnProcess { process_names } => {
                    let proc_lower = conn.process.name.to_lowercase();
                    for name in process_names {
                        if proc_lower.contains(&name.to_lowercase()) {
                            violations.push(PolicyViolation {
                                rule_name: rule.name.clone(),
                                description: format!(
                                    "Monitored process '{}' (PID {}) made connection to {}:{}",
                                    conn.process.name,
                                    conn.process.pid,
                                    conn.remote_addr,
                                    conn.remote_port
                                ),
                                severity: RiskLevel::Medium,
                                suggested_action: PolicyAction::Alert,
                                timestamp: Utc::now(),
                            });
                        }
                    }
                }

                PolicyRuleType::RiskThreshold { min_score } => {
                    if conn.risk.score >= *min_score {
                        violations.push(PolicyViolation {
                            rule_name: rule.name.clone(),
                            description: format!(
                                "Connection risk {:.2} exceeds threshold {:.2}: {} → {}:{}",
                                conn.risk.score,
                                min_score,
                                conn.process.name,
                                conn.remote_addr,
                                conn.remote_port
                            ),
                            severity: conn.risk.level,
                            suggested_action: PolicyAction::SuggestKill {
                                pid: conn.process.pid,
                            },
                            timestamp: Utc::now(),
                        });
                    }
                }
            }
        }

        violations
    }

    /// Evaluate a DNS query against domain-based rules
    pub fn evaluate_dns(&self, query: &DnsQuery) -> Vec<PolicyViolation> {
        let mut violations = Vec::new();
        let domain_lower = query.domain.to_lowercase();

        for rule in &self.rules {
            if !rule.enabled {
                continue;
            }

            if let PolicyRuleType::BlockDomain { domains } = &rule.rule_type {
                for blocked in domains {
                    if domain_lower.contains(&blocked.to_lowercase()) {
                        violations.push(PolicyViolation {
                            rule_name: rule.name.clone(),
                            description: format!(
                                "DNS query for blocked domain '{}'",
                                query.domain
                            ),
                            severity: RiskLevel::High,
                            suggested_action: PolicyAction::SuggestQuarantine {
                                domain: query.domain.clone(),
                            },
                            timestamp: Utc::now(),
                        });
                    }
                }
            }
        }

        violations
    }

    /// Generate an nftables rule suggestion for quarantining a domain
    pub fn quarantine_domain(domain: &str, resolved_ips: &[IpAddr]) -> Vec<String> {
        let mut rules = Vec::new();
        rules.push(format!("# Quarantine rules for domain: {}", domain));
        for ip in resolved_ips {
            rules.push(format!(
                "nft add rule ip filter output ip daddr {} drop",
                ip
            ));
        }
        if resolved_ips.is_empty() {
            rules.push(format!(
                "# No resolved IPs for {}. Consider DNS-level blocking.",
                domain
            ));
        }
        rules
    }
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use uuid::Uuid;

    fn make_conn_for_policy(hostname: Option<&str>, port: u16, process_name: &str) -> Connection {
        Connection {
            id: Uuid::new_v4(),
            protocol: Protocol::Tcp,
            state: ConnectionState::Established,
            local_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            local_port: 54321,
            remote_addr: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            remote_port: port,
            remote_hostname: hostname.map(String::from),
            process: ProcessInfo {
                pid: 1234,
                ppid: 1,
                name: process_name.to_string(),
                cmdline: String::new(),
                user: "test".to_string(),
                uid: 1000,
                container_id: None,
                cgroup: None,
                first_seen: Utc::now(),
            },
            risk: RiskScore::new(0.8, vec!["test".into()]),
            started_at: Utc::now(),
            last_seen: Utc::now(),
            bytes_sent: 0,
            bytes_recv: 0,
        }
    }

    #[test]
    fn test_domain_block_policy() {
        let mut engine = PolicyEngine::new();
        engine.add_rule(PolicyRule {
            name: "Block evil".into(),
            description: "Block evil.com".into(),
            rule_type: PolicyRuleType::BlockDomain {
                domains: vec!["evil.com".into()],
            },
            enabled: true,
        });

        let conn = make_conn_for_policy(Some("sub.evil.com"), 443, "curl");
        let violations = engine.evaluate_connection(&conn);
        assert!(!violations.is_empty());
    }

    #[test]
    fn test_port_block_policy() {
        let mut engine = PolicyEngine::new();
        engine.add_rule(PolicyRule {
            name: "Block IRC".into(),
            description: "Block IRC ports".into(),
            rule_type: PolicyRuleType::BlockPort {
                ports: vec![6667, 6697],
            },
            enabled: true,
        });

        let conn = make_conn_for_policy(None, 6667, "irssi");
        let violations = engine.evaluate_connection(&conn);
        assert!(!violations.is_empty());
    }

    #[test]
    fn test_risk_threshold_policy() {
        let mut engine = PolicyEngine::new();
        engine.add_rule(PolicyRule {
            name: "High risk alert".into(),
            description: "Alert on high risk".into(),
            rule_type: PolicyRuleType::RiskThreshold { min_score: 0.7 },
            enabled: true,
        });

        let conn = make_conn_for_policy(None, 4444, "suspicious");
        let violations = engine.evaluate_connection(&conn);
        assert!(!violations.is_empty());
    }

    #[test]
    fn test_disabled_rule_ignored() {
        let mut engine = PolicyEngine::new();
        engine.add_rule(PolicyRule {
            name: "Disabled".into(),
            description: "This is disabled".into(),
            rule_type: PolicyRuleType::BlockPort { ports: vec![80] },
            enabled: false,
        });

        let conn = make_conn_for_policy(None, 80, "nginx");
        let violations = engine.evaluate_connection(&conn);
        assert!(violations.is_empty());
    }
}
