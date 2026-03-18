use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use portpulse_core::event::EventBus;
use portpulse_core::aggregator::Aggregator;
use portpulse_core::classifier::RiskClassifier;
use portpulse_ebpf::fallback::ProcNetScanner;
use portpulse_ebpf::loader::EbpfLoader;
use portpulse_ebpf::probes::default_probes;
use portpulse_tui::app::App;
use portpulse_tui::ui;
use ratatui::prelude::*;
use std::io;
use std::time::{Duration, Instant};
use tracing::{info, warn};

/// Run the live TUI dashboard
pub async fn run(threshold: f64, refresh_ms: u64, no_ebpf: bool) -> Result<()> {
    info!("Starting PortPulse live dashboard");
    info!("  Risk threshold: {}", threshold);
    info!("  Refresh rate: {}ms", refresh_ms);
    info!("  eBPF: {}", if no_ebpf { "disabled" } else { "auto" });

    // Initialize components
    let mut app = App::new();
    app.risk_threshold = threshold;

    let _event_bus = EventBus::new(4096);
    let mut aggregator = Aggregator::new(500);
    let classifier = RiskClassifier::new();
    let mut scanner = ProcNetScanner::new();

    // Try eBPF first, fall back to /proc
    if !no_ebpf {
        let mut loader = EbpfLoader::new(default_probes());
        if loader.check_availability() {
            match loader.load_and_attach() {
                Ok(()) => {
                    app.ebpf_active = true;
                    app.status_message = "⚡ PortPulse active — eBPF probes attached".into();
                    info!("eBPF probes attached successfully");
                }
                Err(e) => {
                    warn!("Failed to load eBPF: {}. Falling back to /proc", e);
                    app.status_message =
                        "⚡ PortPulse active — /proc fallback (run as root for eBPF)".into();
                }
            }
        } else {
            app.status_message =
                "⚡ PortPulse active — /proc fallback (eBPF unavailable)".into();
        }
    } else {
        app.status_message = "⚡ PortPulse active — /proc polling mode".into();
    }

    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let tick_rate = Duration::from_millis(refresh_ms);
    let mut last_tick = Instant::now();

    // Main event loop
    loop {
        // Draw UI
        terminal.draw(|frame| {
            ui::render(frame, &app);
        })?;

        // Handle input events
        let timeout = tick_rate.saturating_sub(last_tick.elapsed());
        if event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    app.on_key(key);
                }
            }
        }

        // Check if we should quit
        if !app.running {
            break;
        }

        // Periodic tick
        if last_tick.elapsed() >= tick_rate {
            // Scan /proc for new connections
            if let Ok(events) = scanner.scan() {
                for raw_event in events {
                    let enriched = aggregator.process_event(&raw_event);
                    for mut event in enriched {
                        // Apply risk scoring to connections
                        if let portpulse_core::event::Event::ConnectionUpdate(ref mut conn) = event
                        {
                            conn.risk = classifier.score_connection(conn);
                        }
                        app.process_event(event);
                    }
                }
            }

            app.on_tick();
            last_tick = Instant::now();
        }
    }

    // Cleanup terminal
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    info!("PortPulse terminated cleanly");
    Ok(())
}
