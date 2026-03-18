use anyhow::Result;
use portpulse_core::process::ProcessScanner;
use portpulse_ebpf::fallback::ProcNetScanner;

/// Explain what's using a specific port
pub async fn run(port: u16, _history: bool) -> Result<()> {
    println!("⚡ PortPulse — Explaining port {}", port);
    println!();

    // Common port explanations
    let description = match port {
        22 => "SSH (Secure Shell)",
        53 => "DNS (Domain Name System)",
        80 => "HTTP (Hypertext Transfer Protocol)",
        443 => "HTTPS (HTTP over TLS)",
        3306 => "MySQL Database",
        5432 => "PostgreSQL Database",
        6379 => "Redis",
        8080 => "HTTP Proxy / Alternative HTTP",
        8443 => "HTTPS Alternative",
        27017 => "MongoDB",
        4444 => "⚠ Common backdoor / Metasploit",
        6667 => "⚠ IRC (often used by botnets)",
        31337 => "⚠ Elite / Common backdoor",
        9050 => "⚠ Tor SOCKS proxy",
        _ => "Custom / Unknown",
    };

    println!("  Port:        {}", port);
    println!("  Service:     {}", description);
    println!();

    // Scan for processes using this port
    let mut net_scanner = ProcNetScanner::new();
    let mut proc_scanner = ProcessScanner::new();
    proc_scanner.scan()?;

    println!("  Active connections on port {}:", port);
    println!("  ─────────────────────────────");

    if let Ok(events) = net_scanner.scan() {
        let mut found = 0;
        for event in &events {
            match event {
                portpulse_core::event::Event::TcpConnect {
                    pid,
                    src_addr,
                    src_port,
                    dst_addr,
                    dst_port,
                    ..
                } => {
                    if *src_port == port || *dst_port == port {
                        let proc_name = proc_scanner
                            .get(*pid)
                            .map(|p| p.name.clone())
                            .unwrap_or_else(|| format!("<pid:{}>", pid));
                        println!(
                            "  TCP  {}  {}:{} → {}:{}",
                            proc_name, src_addr, src_port, dst_addr, dst_port
                        );
                        found += 1;
                    }
                }
                portpulse_core::event::Event::UdpSend {
                    pid,
                    src_addr,
                    src_port,
                    dst_addr,
                    dst_port,
                    ..
                } => {
                    if *src_port == port || *dst_port == port {
                        let proc_name = proc_scanner
                            .get(*pid)
                            .map(|p| p.name.clone())
                            .unwrap_or_else(|| format!("<pid:{}>", pid));
                        println!(
                            "  UDP  {}  {}:{} → {}:{}",
                            proc_name, src_addr, src_port, dst_addr, dst_port
                        );
                        found += 1;
                    }
                }
                _ => {}
            }
        }

        if found == 0 {
            println!("  No active connections found on port {}", port);
        }
    }

    println!();
    println!("  💡 Tip: Use 'portpulse live' for real-time monitoring");

    Ok(())
}
