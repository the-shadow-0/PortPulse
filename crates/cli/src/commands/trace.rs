use anyhow::Result;
use portpulse_core::process::ProcessScanner;
use portpulse_ebpf::fallback::ProcNetScanner;


/// Trace a specific process's network activity
pub async fn run(pid: u32, children: bool, format: &str) -> Result<()> {
    println!("⚡ PortPulse — Tracing PID {}", pid);
    println!();

    let mut proc_scanner = ProcessScanner::new();
    proc_scanner.scan()?;

    // Get process info
    match proc_scanner.get(pid) {
        Some(info) => {
            println!("  Process:   {} (PID {})", info.name, info.pid);
            println!("  User:      {}", info.user);
            println!("  Command:   {}", info.cmdline);
            if let Some(ref container) = info.container_id {
                println!("  Container: {}", container);
            }
            println!();
        }
        None => {
            println!("  ⚠ Process {} not found or not accessible", pid);
            println!("  (Try running with sudo)");
            return Ok(());
        }
    }

    // Get children if requested
    if children {
        let tree = proc_scanner.process_tree();
        if let Some(child_pids) = tree.get(&pid) {
            println!("  Child PIDs: {:?}", child_pids);
            println!();
        }
    }

    // Scan connections
    let mut net_scanner = ProcNetScanner::new();
    if let Ok(events) = net_scanner.scan() {
        let mut found = 0;
        for event in &events {
            match event {
                portpulse_core::event::Event::TcpConnect {
                    pid: event_pid,
                    src_addr,
                    src_port,
                    dst_addr,
                    dst_port,
                    ..
                } if *event_pid == pid => {
                    match format {
                        "json" => {
                            println!(
                                r#"  {{"type":"tcp","src":"{}:{}","dst":"{}:{}"}}"#,
                                src_addr, src_port, dst_addr, dst_port
                            );
                        }
                        _ => {
                            println!(
                                "  TCP  {}:{} → {}:{}",
                                src_addr, src_port, dst_addr, dst_port
                            );
                        }
                    }
                    found += 1;
                }
                portpulse_core::event::Event::UdpSend {
                    pid: event_pid,
                    src_addr,
                    src_port,
                    dst_addr,
                    dst_port,
                    bytes,
                    ..
                } if *event_pid == pid => {
                    match format {
                        "json" => {
                            println!(
                                r#"  {{"type":"udp","src":"{}:{}","dst":"{}:{}","bytes":{}}}"#,
                                src_addr, src_port, dst_addr, dst_port, bytes
                            );
                        }
                        _ => {
                            println!(
                                "  UDP  {}:{} → {}:{} ({} bytes)",
                                src_addr, src_port, dst_addr, dst_port, bytes
                            );
                        }
                    }
                    found += 1;
                }
                _ => {}
            }
        }

        if found == 0 {
            println!("  No active connections found for PID {}", pid);
        } else {
            println!();
            println!("  Found {} active connection(s)", found);
        }
    }

    Ok(())
}
