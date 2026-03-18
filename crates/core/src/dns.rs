use std::collections::HashMap;
use std::net::IpAddr;

/// DNS resolution cache and reverse-lookup utilities.
///
/// Maps domains to their resolved IPs and provides reverse lookups
/// (IP → domain) for connection enrichment.
pub struct DnsCache {
    /// Forward cache: domain → IPs
    forward: HashMap<String, Vec<IpAddr>>,
    /// Reverse cache: IP → domain
    reverse: HashMap<IpAddr, String>,
    /// Maximum cache entries
    max_entries: usize,
}

impl DnsCache {
    pub fn new(max_entries: usize) -> Self {
        Self {
            forward: HashMap::new(),
            reverse: HashMap::new(),
            max_entries,
        }
    }

    /// Add a DNS resolution to the cache
    pub fn insert(&mut self, domain: String, ips: Vec<IpAddr>) {
        // Enforce max cache size (simple LRU-like eviction)
        if self.forward.len() >= self.max_entries {
            if let Some(oldest_key) = self.forward.keys().next().cloned() {
                if let Some(old_ips) = self.forward.remove(&oldest_key) {
                    for ip in &old_ips {
                        self.reverse.remove(ip);
                    }
                }
            }
        }

        // Populate reverse cache
        for ip in &ips {
            self.reverse.insert(*ip, domain.clone());
        }

        self.forward.insert(domain, ips);
    }

    /// Look up IPs for a domain
    pub fn resolve(&self, domain: &str) -> Option<&Vec<IpAddr>> {
        self.forward.get(domain)
    }

    /// Reverse-lookup: find the domain for an IP
    pub fn reverse_lookup(&self, ip: &IpAddr) -> Option<&String> {
        self.reverse.get(ip)
    }

    /// Get all cached entries
    pub fn entries(&self) -> &HashMap<String, Vec<IpAddr>> {
        &self.forward
    }

    /// Get cache size
    pub fn len(&self) -> usize {
        self.forward.len()
    }

    /// Check if cache is empty
    pub fn is_empty(&self) -> bool {
        self.forward.is_empty()
    }

    /// Clear the cache
    pub fn clear(&mut self) {
        self.forward.clear();
        self.reverse.clear();
    }
}

impl Default for DnsCache {
    fn default() -> Self {
        Self::new(10_000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_dns_cache_insert_and_lookup() {
        let mut cache = DnsCache::new(100);
        let ip = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));

        cache.insert("example.com".to_string(), vec![ip]);

        assert_eq!(cache.resolve("example.com").unwrap(), &vec![ip]);
        assert_eq!(cache.reverse_lookup(&ip).unwrap(), "example.com");
    }

    #[test]
    fn test_dns_cache_eviction() {
        let mut cache = DnsCache::new(2);

        cache.insert("a.com".to_string(), vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))]);
        cache.insert("b.com".to_string(), vec![IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2))]);
        cache.insert("c.com".to_string(), vec![IpAddr::V4(Ipv4Addr::new(3, 3, 3, 3))]);

        assert_eq!(cache.len(), 2);
    }
}
