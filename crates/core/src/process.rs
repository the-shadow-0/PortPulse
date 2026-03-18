use crate::models::ProcessInfo;
use anyhow::Result;
use chrono::Utc;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// Process scanner that reads /proc to build a map of PIDs to process metadata.
///
/// This provides the process attribution layer — connecting network events
/// to the actual processes making them.
pub struct ProcessScanner {
    /// Cache of known processes
    cache: HashMap<u32, ProcessInfo>,
}

impl ProcessScanner {
    pub fn new() -> Self {
        Self {
            cache: HashMap::new(),
        }
    }

    /// Scan /proc for all running processes and update internal cache
    pub fn scan(&mut self) -> Result<&HashMap<u32, ProcessInfo>> {
        let proc_dir = Path::new("/proc");

        if !proc_dir.exists() {
            return Ok(&self.cache);
        }

        let entries = fs::read_dir(proc_dir)?;
        let mut seen_pids: Vec<u32> = Vec::new();

        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();

            // Only process numeric directories (PIDs)
            if let Ok(pid) = name_str.parse::<u32>() {
                seen_pids.push(pid);

                // Skip if already cached and process still exists
                if self.cache.contains_key(&pid) {
                    continue;
                }

                if let Ok(info) = self.read_process_info(pid) {
                    self.cache.insert(pid, info);
                }
            }
        }

        // Remove stale entries for processes that no longer exist
        self.cache.retain(|pid, _| seen_pids.contains(pid));

        Ok(&self.cache)
    }

    /// Read process information from /proc/<pid>/
    fn read_process_info(&self, pid: u32) -> Result<ProcessInfo> {
        let proc_path = format!("/proc/{}", pid);
        let proc_dir = Path::new(&proc_path);

        // Read comm (process name)
        let name = fs::read_to_string(proc_dir.join("comm"))
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| format!("<pid:{}>", pid));

        // Read cmdline
        let cmdline = fs::read_to_string(proc_dir.join("cmdline"))
            .map(|s| s.replace('\0', " ").trim().to_string())
            .unwrap_or_default();

        // Read status for ppid, uid
        let (ppid, uid) = self.read_status(pid);

        // Read user from uid
        let user = self.uid_to_username(uid);

        // Read container ID from cgroup
        let (container_id, cgroup) = self.read_cgroup(pid);

        Ok(ProcessInfo {
            pid,
            ppid,
            name,
            cmdline,
            user,
            uid,
            container_id,
            cgroup,
            first_seen: Utc::now(),
        })
    }

    /// Read ppid and uid from /proc/<pid>/status
    fn read_status(&self, pid: u32) -> (u32, u32) {
        let status_path = format!("/proc/{}/status", pid);
        let content = match fs::read_to_string(&status_path) {
            Ok(c) => c,
            Err(_) => return (0, 0),
        };

        let mut ppid = 0u32;
        let mut uid = 0u32;

        for line in content.lines() {
            if let Some(val) = line.strip_prefix("PPid:\t") {
                ppid = val.trim().parse().unwrap_or(0);
            } else if let Some(val) = line.strip_prefix("Uid:\t") {
                uid = val
                    .split_whitespace()
                    .next()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0);
            }
        }

        (ppid, uid)
    }

    /// Convert UID to username (best-effort)
    fn uid_to_username(&self, uid: u32) -> String {
        if uid == 0 {
            return "root".to_string();
        }

        // Try to read /etc/passwd
        if let Ok(passwd) = fs::read_to_string("/etc/passwd") {
            for line in passwd.lines() {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() >= 3 {
                    if let Ok(line_uid) = parts[2].parse::<u32>() {
                        if line_uid == uid {
                            return parts[0].to_string();
                        }
                    }
                }
            }
        }

        format!("uid:{}", uid)
    }

    /// Read container ID and cgroup from /proc/<pid>/cgroup
    fn read_cgroup(&self, pid: u32) -> (Option<String>, Option<String>) {
        let cgroup_path = format!("/proc/{}/cgroup", pid);
        let content = match fs::read_to_string(&cgroup_path) {
            Ok(c) => c,
            Err(_) => return (None, None),
        };

        let mut container_id = None;
        let mut cgroup_name = None;

        for line in content.lines() {
            let parts: Vec<&str> = line.splitn(3, ':').collect();
            if parts.len() == 3 {
                let path = parts[2];
                cgroup_name = Some(path.to_string());

                // Docker container detection
                if path.contains("/docker/") {
                    if let Some(id) = path.split("/docker/").last() {
                        let short_id = &id[..id.len().min(12)];
                        container_id = Some(short_id.to_string());
                    }
                }
                // containerd/k8s detection
                else if path.contains("/cri-containerd-") {
                    if let Some(id) = path.split("/cri-containerd-").last() {
                        let short_id = &id[..id.len().min(12)];
                        container_id = Some(short_id.to_string());
                    }
                }
            }
        }

        (container_id, cgroup_name)
    }

    /// Get process info by PID (from cache)
    pub fn get(&self, pid: u32) -> Option<&ProcessInfo> {
        self.cache.get(&pid)
    }

    /// Get all cached processes
    pub fn all(&self) -> &HashMap<u32, ProcessInfo> {
        &self.cache
    }

    /// Get process tree (parent → children mapping)
    pub fn process_tree(&self) -> HashMap<u32, Vec<u32>> {
        let mut tree: HashMap<u32, Vec<u32>> = HashMap::new();
        for (pid, info) in &self.cache {
            tree.entry(info.ppid).or_default().push(*pid);
        }
        tree
    }
}

impl Default for ProcessScanner {
    fn default() -> Self {
        Self::new()
    }
}
