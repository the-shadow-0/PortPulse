use anyhow::Result;

/// Export current connection state to JSON or CSV
pub async fn run(format: &str, what: &str, output: Option<&str>) -> Result<()> {
    println!("⚡ PortPulse — Exporting {} as {}", what, format);
    println!();

    // In a full implementation, this would:
    // 1. Connect to a running PortPulse daemon or scan /proc
    // 2. Collect the requested data (connections, dns, timeline)
    // 3. Use the Exporter to format it
    // 4. Write to stdout or the specified file

    let mut scanner = portpulse_ebpf::fallback::ProcNetScanner::new();
    let mut aggregator = portpulse_core::aggregator::Aggregator::new(500);
    let classifier = portpulse_core::classifier::RiskClassifier::new();

    if let Ok(events) = scanner.scan() {
        for raw_event in events {
            let enriched = aggregator.process_event(&raw_event);
            for mut event in enriched {
                if let portpulse_core::event::Event::ConnectionUpdate(ref mut conn) = event {
                    conn.risk = classifier.score_connection(conn);
                }
            }
        }
    }

    let connections: Vec<portpulse_core::Connection> =
        aggregator.connections().into_iter().cloned().collect();

    let writer: Box<dyn std::io::Write> = match output {
        Some(path) => Box::new(std::fs::File::create(path)?),
        None => Box::new(std::io::stdout()),
    };

    match (what, format) {
        ("connections", "json") | ("all", "json") => {
            portpulse_core::export::Exporter::connections_to_json(writer, &connections)?;
        }
        ("connections", "csv") | ("all", "csv") => {
            portpulse_core::export::Exporter::connections_to_csv(writer, &connections)?;
        }
        ("dns", "json") => {
            let queries: Vec<portpulse_core::DnsQuery> = aggregator.dns_queries().to_vec();
            portpulse_core::export::Exporter::dns_to_json(writer, &queries)?;
        }
        ("dns", "csv") => {
            let queries: Vec<portpulse_core::DnsQuery> = aggregator.dns_queries().to_vec();
            portpulse_core::export::Exporter::dns_to_csv(writer, &queries)?;
        }
        ("timeline", "json") => {
            let events: Vec<portpulse_core::NetworkEvent> = aggregator.timeline().to_vec();
            portpulse_core::export::Exporter::timeline_to_json(writer, &events)?;
        }
        _ => {
            println!("Unsupported combination: {} / {}", what, format);
            println!("Supported: connections|dns|timeline|all × json|csv");
        }
    }

    if let Some(path) = output {
        println!("Exported to: {}", path);
    }

    Ok(())
}
