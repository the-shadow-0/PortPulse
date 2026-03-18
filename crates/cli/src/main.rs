mod commands;

use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

/// ⚡ PortPulse — See every Linux process, port, connection, and DNS lookup live.
///
/// A real-time local observability command center that shows what process
/// is talking, to which domain/IP, through which port, with what risk level —
/// all in ONE interface.
#[derive(Parser, Debug)]
#[command(
    name = "portpulse",
    version,
    about = "⚡ See every Linux process, port, connection, and DNS lookup live in one interactive map",
    long_about = "PortPulse is a real-time local observability command center for Linux.\n\n\
                  It combines the power of eBPF kernel probes with a stunning terminal UI to give you \
                  complete visibility into what every process on your system is doing on the network.\n\n\
                  Features:\n\
                  • Live process-to-port mapping\n\
                  • Active connections (PID, user, container)\n\
                  • DNS query capture\n\
                  • Risk scoring & suspicious activity detection\n\
                  • Animated connection graph\n\
                  • Policy engine & quarantine suggestions",
    after_help = "Examples:\n\
                  portpulse live                    Launch interactive TUI dashboard\n\
                  portpulse trace --pid 1234        Trace a specific process\n\
                  portpulse explain 443             Explain what's using port 443\n\
                  portpulse quarantine bad.com      Quarantine a suspicious domain\n\
                  portpulse export --format json    Export current state to JSON"
)]
struct Cli {
    /// Subcommand to execute
    #[command(subcommand)]
    command: Commands,

    /// Enable verbose logging
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, global = true, default_value = "info")]
    log_level: String,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Launch the interactive TUI dashboard
    ///
    /// Opens a real-time terminal dashboard showing all active connections,
    /// DNS queries, process trees, and an animated connection graph. Includes
    /// a "suspicious lane" at the top highlighting high-risk connections.
    Live {
        /// Risk threshold for suspicious detection (0.0-1.0)
        #[arg(short, long, default_value = "0.5")]
        threshold: f64,

        /// Refresh rate in milliseconds
        #[arg(short, long, default_value = "250")]
        refresh: u64,

        /// Use /proc fallback instead of eBPF
        #[arg(long)]
        no_ebpf: bool,
    },

    /// Trace a specific process's network activity
    ///
    /// Follows all network connections made by a specific PID, showing
    /// real-time updates as the process communicates over the network.
    Trace {
        /// Process ID to trace
        #[arg(short, long)]
        pid: u32,

        /// Also trace child processes
        #[arg(short, long)]
        children: bool,

        /// Output format (table, json, csv)
        #[arg(short, long, default_value = "table")]
        format: String,
    },

    /// Explain what's using a specific port
    ///
    /// Shows all processes currently listening on or connected through
    /// the specified port, with risk assessment and domain information.
    Explain {
        /// Port number to explain
        port: u16,

        /// Show historical connections too
        #[arg(short = 'H', long)]
        history: bool,
    },

    /// Quarantine a suspicious domain
    ///
    /// Generates nftables rules to block all traffic to the specified
    /// domain and its resolved IP addresses. Does NOT automatically
    /// apply rules — just prints them for review.
    Quarantine {
        /// Domain to quarantine
        #[arg(short, long)]
        domain: String,

        /// Apply rules automatically (requires root)
        #[arg(long)]
        apply: bool,
    },

    /// Export current connection state
    ///
    /// Exports all active connections, DNS queries, or timeline events
    /// to JSON or CSV format for analysis in external tools.
    Export {
        /// Export format (json, csv)
        #[arg(short, long, default_value = "json")]
        format: String,

        /// What to export (connections, dns, timeline, all)
        #[arg(short, long, default_value = "connections")]
        what: String,

        /// Output file (stdout if not specified)
        #[arg(short, long)]
        output: Option<String>,
    },

    /// Show system status and eBPF probe information
    Status,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(&cli.log_level));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();

    match cli.command {
        Commands::Live {
            threshold,
            refresh,
            no_ebpf,
        } => {
            commands::live::run(threshold, refresh, no_ebpf).await?;
        }
        Commands::Trace {
            pid,
            children,
            format,
        } => {
            commands::trace::run(pid, children, &format).await?;
        }
        Commands::Explain { port, history } => {
            commands::explain::run(port, history).await?;
        }
        Commands::Quarantine { domain, apply } => {
            commands::quarantine::run(&domain, apply).await?;
        }
        Commands::Export {
            format,
            what,
            output,
        } => {
            commands::export::run(&format, &what, output.as_deref()).await?;
        }
        Commands::Status => {
            commands::status::run().await?;
        }
    }

    Ok(())
}
