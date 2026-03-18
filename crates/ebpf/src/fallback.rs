use anyhow::Result;
use chrono::Utc;
use portpulse_core::event::Event;
use portpulse_core::models::{ConnectionState, Protocol};
use std::collections::HashMap;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use uuid::Uuid;

/// Fallback scanner that reads from /proc/net/* when eBPF is unavailable.
///
/// Polls /proc/net/tcp, /proc/net/tcp6, /proc/net/udp, and /proc/net/udp6
/// to discover active connections. Less efficient than eBPF but works on
/// any Linux system without special capabilities.
pub struct ProcNetScanner {
    /// Previously seen connections (for change detection)
    previous: HashMap<String, ConnectionSnapshot>,
}

#[derive(Debug, Clone)]
struct ConnectionSnapshot {
    protocol: Protocol,
    local_addr: IpAddr,
    local_port: u16,
    remote_addr: IpAddr,
    remote_port: u16,
    state: ConnectionState,
    inode: u64,
    _uid: u32,
}

impl ProcNetScanner {
    pub fn new() -> Self {
        Self {
            previous: HashMap::new(),
        }
    }

    /// Scan /proc/net/* and return events for new/changed connections
    pub fn scan(&mut self) -> Result<Vec<Event>> {
        let mut events = Vec::new();
        let mut current: HashMap<String, ConnectionSnapshot> = HashMap::new();

        // Parse TCP connections
        if let Ok(tcp_entries) = self.parse_proc_net("/proc/net/tcp", Protocol::Tcp, false) {
            for entry in tcp_entries {
                let key = format!(
                    "tcp:{}:{}-{}:{}",
                    entry.local_addr, entry.local_port, entry.remote_addr, entry.remote_port
                );
                current.insert(key, entry);
            }
        }

        // Parse TCP6 connections
        if let Ok(tcp6_entries) = self.parse_proc_net("/proc/net/tcp6", Protocol::Tcp, true) {
            for entry in tcp6_entries {
                let key = format!(
                    "tcp6:{}:{}-{}:{}",
                    entry.local_addr, entry.local_port, entry.remote_addr, entry.remote_port
                );
                current.insert(key, entry);
            }
        }

        // Parse UDP connections
        if let Ok(udp_entries) = self.parse_proc_net("/proc/net/udp", Protocol::Udp, false) {
            for entry in udp_entries {
                let key = format!(
                    "udp:{}:{}-{}:{}",
                    entry.local_addr, entry.local_port, entry.remote_addr, entry.remote_port
                );
                current.insert(key, entry);
            }
        }

        // Detect new connections
        for (key, snap) in &current {
            if !self.previous.contains_key(key) {
                // New connection detected
                let pid = self.find_pid_for_inode(snap.inode).unwrap_or(0);

                match snap.protocol {
                    Protocol::Tcp => {
                        if snap.state == ConnectionState::Established {
                            events.push(Event::TcpConnect {
                                id: Uuid::new_v4(),
                                pid,
                                src_addr: snap.local_addr,
                                src_port: snap.local_port,
                                dst_addr: snap.remote_addr,
                                dst_port: snap.remote_port,
                                timestamp: Utc::now(),
                            });
                        }
                    }
                    Protocol::Udp => {
                        events.push(Event::UdpSend {
                            id: Uuid::new_v4(),
                            pid,
                            src_addr: snap.local_addr,
                            src_port: snap.local_port,
                            dst_addr: snap.remote_addr,
                            dst_port: snap.remote_port,
                            bytes: 0,
                            timestamp: Utc::now(),
                        });
                    }
                    _ => {}
                }
            }
        }

        // Detect closed connections
        for (key, snap) in &self.previous {
            if !current.contains_key(key) && snap.protocol == Protocol::Tcp {
                let pid = self.find_pid_for_inode(snap.inode).unwrap_or(0);
                events.push(Event::TcpClose {
                    pid,
                    src_addr: snap.local_addr,
                    src_port: snap.local_port,
                    dst_addr: snap.remote_addr,
                    dst_port: snap.remote_port,
                    timestamp: Utc::now(),
                });
            }
        }

        self.previous = current;
        Ok(events)
    }

    /// Parse a /proc/net/* file
    fn parse_proc_net(
        &self,
        path: &str,
        protocol: Protocol,
        is_ipv6: bool,
    ) -> Result<Vec<ConnectionSnapshot>> {
        let content = fs::read_to_string(path)?;
        let mut entries = Vec::new();

        for line in content.lines().skip(1) {
            // Skip header
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 10 {
                continue;
            }

            let local_parts: Vec<&str> = fields[1].split(':').collect();
            let remote_parts: Vec<&str> = fields[2].split(':').collect();

            if local_parts.len() != 2 || remote_parts.len() != 2 {
                continue;
            }

            let local_addr = if is_ipv6 {
                parse_ipv6_hex(local_parts[0])
            } else {
                parse_ipv4_hex(local_parts[0])
            };
            let local_port = u16::from_str_radix(local_parts[1], 16).unwrap_or(0);

            let remote_addr = if is_ipv6 {
                parse_ipv6_hex(remote_parts[0])
            } else {
                parse_ipv4_hex(remote_parts[0])
            };
            let remote_port = u16::from_str_radix(remote_parts[1], 16).unwrap_or(0);

            let state_num = u8::from_str_radix(fields[3], 16).unwrap_or(0);
            let uid: u32 = fields[7].parse().unwrap_or(0);
            let inode: u64 = fields[9].parse().unwrap_or(0);

            if let (Some(la), Some(ra)) = (local_addr, remote_addr) {
                entries.push(ConnectionSnapshot {
                    protocol,
                    local_addr: la,
                    local_port,
                    remote_addr: ra,
                    remote_port,
                    state: ConnectionState::from_proc_state(state_num),
                    inode,
                    _uid: uid,
                });
            }
        }

        Ok(entries)
    }

    /// Find the PID that owns a socket inode by scanning /proc/*/fd/
    fn find_pid_for_inode(&self, target_inode: u64) -> Option<u32> {
        if target_inode == 0 {
            return None;
        }

        let proc_dir = match fs::read_dir("/proc") {
            Ok(d) => d,
            Err(_) => return None,
        };

        for entry in proc_dir.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();

            if let Ok(pid) = name_str.parse::<u32>() {
                let fd_dir = format!("/proc/{}/fd", pid);
                if let Ok(fds) = fs::read_dir(&fd_dir) {
                    for fd in fds.flatten() {
                        if let Ok(link) = fs::read_link(fd.path()) {
                            let link_str = link.to_string_lossy();
                            if link_str.starts_with("socket:[") {
                                let inode_str = link_str
                                    .trim_start_matches("socket:[")
                                    .trim_end_matches(']');
                                if let Ok(inode) = inode_str.parse::<u64>() {
                                    if inode == target_inode {
                                        return Some(pid);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        None
    }
}

impl Default for ProcNetScanner {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse a hex IPv4 address from /proc/net/tcp format (little-endian)
fn parse_ipv4_hex(hex: &str) -> Option<IpAddr> {
    let val = u32::from_str_radix(hex, 16).ok()?;
    Some(IpAddr::V4(Ipv4Addr::from(val.to_le_bytes())))
}

/// Parse a hex IPv6 address from /proc/net/tcp6 format
fn parse_ipv6_hex(hex: &str) -> Option<IpAddr> {
    if hex.len() != 32 {
        return None;
    }
    let mut segments = [0u16; 8];
    for (i, seg) in segments.iter_mut().enumerate() {
        let start = i * 4;
        let end = start + 4;
        *seg = u16::from_str_radix(&hex[start..end], 16).ok()?;
    }
    Some(IpAddr::V6(Ipv6Addr::from(segments)))
}
