use anyhow::Result;
use portpulse_core::policy::PolicyEngine;
use std::net::IpAddr;

/// Quarantine a suspicious domain
pub async fn run(domain: &str, apply: bool) -> Result<()> {
    println!("⚡ PortPulse — Quarantine domain: {}", domain);
    println!();

    // Try to resolve the domain
    println!("  Resolving {}...", domain);

    // Simple DNS resolution using system resolver
    let resolved_ips: Vec<IpAddr> = match tokio::net::lookup_host(format!("{}:80", domain)).await {
        Ok(addrs) => addrs.map(|a| a.ip()).collect(),
        Err(e) => {
            println!("  ⚠ Could not resolve {}: {}", domain, e);
            vec![]
        }
    };

    if !resolved_ips.is_empty() {
        println!("  Resolved IPs:");
        for ip in &resolved_ips {
            println!("    - {}", ip);
        }
    }
    println!();

    // Generate quarantine rules
    let rules = PolicyEngine::quarantine_domain(domain, &resolved_ips);

    println!("  📋 Generated nftables rules:");
    println!("  ═══════════════════════════");
    for rule in &rules {
        println!("  {}", rule);
    }
    println!();

    if apply {
        println!("  ⚠ Auto-apply is not yet implemented for safety.");
        println!("    Please review and apply the rules manually:");
        println!();
        println!("    sudo nft -f /dev/stdin <<EOF");
        for rule in &rules {
            if !rule.starts_with('#') {
                println!("    {}", rule);
            }
        }
        println!("    EOF");
    } else {
        println!("  💡 To apply these rules, run:");
        println!("    sudo nft -f /dev/stdin <<EOF");
        for rule in &rules {
            if !rule.starts_with('#') {
                println!("    {}", rule);
            }
        }
        println!("    EOF");
    }

    println!();
    println!("  ⚠ CAUTION: Review rules carefully before applying.");
    println!("    Blocking the wrong domain can break applications.");

    Ok(())
}
