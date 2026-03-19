use crate::app::{ActivePanel, App};
use crate::theme::Theme;
use crate::widgets;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Tabs};
use ratatui::Frame;

/// Render the complete PortPulse UI
///
/// Layout:
/// ```text
/// ┌─────────────────────────────────────────────────────────────┐
/// │  ⚡ PortPulse   │ Dashboard │ Connections │ DNS │ Tree │ Graph │
/// ├─────────────────────────────────────────────────────────────┤
/// │ 🔴 SUSPICIOUS LANE — high-risk connections blink here      │
/// ├──────────────────────────────┬──────────────────────────────┤
/// │                              │                              │
/// │     Main Panel               │     Side Panel               │
/// │     (varies by tab)          │     (DNS log / Timeline)     │
/// │                              │                              │
/// │                              │                              │
/// ├─────────────────────────────────────────────────────────────┤
/// │ Status: ⚡ PortPulse active │ Events: 1234 │ eBPF: ✓      │
/// └─────────────────────────────────────────────────────────────┘
/// ```
pub fn render(frame: &mut Frame, app: &App) {
    let size = frame.area();

    // Clear background
    frame.render_widget(Block::default().style(Theme::base()), size);

    // Main vertical layout
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Tab bar
            Constraint::Length(3), // Suspicious lane
            Constraint::Min(10),   // Main content
            Constraint::Length(1), // Status bar
        ])
        .split(size);

    // ── Tab bar ──
    render_tab_bar(frame, app, chunks[0]);

    // ── Suspicious lane ──
    widgets::suspicious_lane::render(frame, app, chunks[1]);

    // ── Main content ──
    match app.active_panel {
        ActivePanel::Dashboard => render_dashboard(frame, app, chunks[2]),
        ActivePanel::Connections => {
            widgets::connections_table::render(frame, app, chunks[2]);
        }
        ActivePanel::DnsLog => {
            widgets::dns_log::render(frame, app, chunks[2]);
        }
        ActivePanel::ProcessTree => {
            widgets::process_tree::render(frame, app, chunks[2]);
        }
        ActivePanel::Graph => {
            widgets::connection_graph::render(frame, app, chunks[2]);
        }
        ActivePanel::Detail => {
            render_detail(frame, app, chunks[2]);
        }
    }

    // ── Status bar ──
    render_status_bar(frame, app, chunks[3]);
}

/// Render the tab bar at the top
fn render_tab_bar(frame: &mut Frame, app: &App, area: Rect) {
    let titles = vec![
        "1:Dashboard",
        "2:Connections",
        "3:DNS Log",
        "4:Processes",
        "5:Graph",
    ];

    let selected = match app.active_panel {
        ActivePanel::Dashboard => 0,
        ActivePanel::Connections => 1,
        ActivePanel::DnsLog => 2,
        ActivePanel::ProcessTree => 3,
        ActivePanel::Graph => 4,
        ActivePanel::Detail => 0,
    };

    let tabs = Tabs::new(titles)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Theme::border(true))
                .title(Span::styled(" ⚡ PortPulse ", Theme::title())),
        )
        .select(selected)
        .style(Theme::tab_inactive())
        .highlight_style(Theme::tab_active())
        .divider("│");

    frame.render_widget(tabs, area);
}

/// Render the dashboard (split view)
fn render_dashboard(frame: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(area);

    // Left: connections table
    widgets::connections_table::render(frame, app, chunks[0]);

    // Right: vertical split — DNS log + timeline
    let right_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(chunks[1]);

    widgets::dns_log::render(frame, app, right_chunks[0]);
    render_timeline(frame, app, right_chunks[1]);
}

/// Render the timeline panel
fn render_timeline(frame: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Theme::border(false))
        .title(Span::styled(" 📋 Timeline ", Theme::title()));

    let events: Vec<Line> = app
        .timeline
        .iter()
        .rev()
        .take((area.height as usize).saturating_sub(2))
        .map(|evt| {
            let time = evt.timestamp.format("%H:%M:%S").to_string();
            let risk_style = Theme::risk_style(evt.risk);
            Line::from(vec![
                Span::styled(format!("{} ", time), Theme::muted()),
                Span::styled(format!("{} ", evt.event_type), risk_style),
                Span::styled(&evt.description, Style::default().fg(Theme::FG)),
            ])
        })
        .collect();

    let paragraph = Paragraph::new(events).block(block);
    frame.render_widget(paragraph, area);
}

/// Render the detail view for a selected connection
fn render_detail(frame: &mut Frame, app: &App, area: Rect) {
    let conn = match &app.detail_connection {
        Some(c) => c,
        None => {
            let block = Block::default()
                .borders(Borders::ALL)
                .border_style(Theme::border(false))
                .title(Span::styled(" 🔍 Detail ", Theme::title()));
            let msg = Paragraph::new("No connection selected. Press ESC to go back.").block(block);
            frame.render_widget(msg, area);
            return;
        }
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Theme::border(true))
        .title(Span::styled(
            format!(" 🔍 Connection Detail — {} ", conn.process.name),
            Theme::title(),
        ));

    let risk_style = Theme::risk_style(conn.risk.level);

    let lines = vec![
        Line::from(vec![
            Span::styled("  Process:    ", Style::default().fg(Theme::MUTED)),
            Span::styled(
                format!("{} (PID {})", conn.process.name, conn.process.pid),
                Style::default().fg(Theme::ACCENT),
            ),
        ]),
        Line::from(vec![
            Span::styled("  User:       ", Style::default().fg(Theme::MUTED)),
            Span::styled(&conn.process.user, Style::default().fg(Theme::FG)),
        ]),
        Line::from(vec![
            Span::styled("  Command:    ", Style::default().fg(Theme::MUTED)),
            Span::styled(&conn.process.cmdline, Style::default().fg(Theme::FG)),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("  Protocol:   ", Style::default().fg(Theme::MUTED)),
            Span::styled(
                conn.protocol.to_string(),
                Style::default().fg(Theme::protocol_color(&conn.protocol)),
            ),
        ]),
        Line::from(vec![
            Span::styled("  Local:      ", Style::default().fg(Theme::MUTED)),
            Span::styled(
                format!("{}:{}", conn.local_addr, conn.local_port),
                Style::default().fg(Theme::FG),
            ),
        ]),
        Line::from(vec![
            Span::styled("  Remote:     ", Style::default().fg(Theme::MUTED)),
            Span::styled(
                format!("{}:{}", conn.remote_addr, conn.remote_port),
                Style::default().fg(Theme::FG),
            ),
        ]),
        Line::from(vec![
            Span::styled("  Hostname:   ", Style::default().fg(Theme::MUTED)),
            Span::styled(
                conn.remote_hostname.as_deref().unwrap_or("—"),
                Style::default().fg(Theme::ACCENT),
            ),
        ]),
        Line::from(vec![
            Span::styled("  State:      ", Style::default().fg(Theme::MUTED)),
            Span::styled(conn.state.to_string(), Style::default().fg(Theme::FG)),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("  Risk Score: ", Style::default().fg(Theme::MUTED)),
            Span::styled(format!("{:.2}", conn.risk.score), risk_style),
            Span::raw("  "),
            Span::styled(conn.risk.level.to_string(), risk_style),
        ]),
        Line::from(vec![Span::styled(
            "  Reasons:",
            Style::default().fg(Theme::MUTED),
        )]),
    ];

    let mut all_lines = lines;
    for reason in &conn.risk.reasons {
        all_lines.push(Line::from(vec![
            Span::raw("    "),
            Span::styled("• ", risk_style),
            Span::styled(reason.as_str(), Style::default().fg(Theme::FG)),
        ]));
    }

    all_lines.push(Line::from(""));
    all_lines.push(Line::from(vec![
        Span::styled("  Traffic:    ", Style::default().fg(Theme::MUTED)),
        Span::styled(
            format!("↑ {} bytes  ↓ {} bytes", conn.bytes_sent, conn.bytes_recv),
            Style::default().fg(Theme::FG),
        ),
    ]));

    if let Some(ref container) = conn.process.container_id {
        all_lines.push(Line::from(vec![
            Span::styled("  Container:  ", Style::default().fg(Theme::MUTED)),
            Span::styled(container.as_str(), Style::default().fg(Theme::ACCENT)),
        ]));
    }

    all_lines.push(Line::from(""));
    all_lines.push(Line::from(Span::styled(
        "  Press ESC to go back",
        Style::default()
            .fg(Theme::MUTED)
            .add_modifier(Modifier::ITALIC),
    )));

    let paragraph = Paragraph::new(all_lines).block(block);
    frame.render_widget(paragraph, area);
}

/// Render the status bar at the bottom
fn render_status_bar(frame: &mut Frame, app: &App, area: Rect) {
    let ebpf_status = if app.ebpf_active {
        Span::styled("eBPF: ✓ ", Style::default().fg(Theme::SAFE))
    } else {
        Span::styled("eBPF: ✗ (fallback) ", Style::default().fg(Theme::MEDIUM))
    };

    let filter_status = if app.filter_active {
        Span::styled(
            format!(" Filter: {}▋ ", app.filter_text),
            Style::default().fg(Theme::ACCENT),
        )
    } else if !app.filter_text.is_empty() {
        Span::styled(
            format!(" Filter: {} ", app.filter_text),
            Style::default().fg(Theme::ACCENT),
        )
    } else {
        Span::raw("")
    };

    let status = Line::from(vec![
        Span::styled(" ⚡ ", Style::default().fg(Theme::ACCENT)),
        Span::styled(&app.status_message, Theme::status_bar()),
        Span::raw(" │ "),
        Span::styled(
            format!("Events: {} ", app.total_events),
            Style::default().fg(Theme::FG),
        ),
        Span::raw("│ "),
        ebpf_status,
        Span::raw("│ "),
        Span::styled(
            format!("Conn: {} ", app.connections.len()),
            Style::default().fg(Theme::FG),
        ),
        Span::raw("│ "),
        Span::styled(
            format!("Suspicious: {} ", app.suspicious.len()),
            Style::default().fg(if app.suspicious.is_empty() {
                Theme::SAFE
            } else {
                Theme::HIGH
            }),
        ),
        filter_status,
    ]);

    let paragraph = Paragraph::new(status).style(Theme::status_bar());
    frame.render_widget(paragraph, area);
}
