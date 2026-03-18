use crate::app::App;
use crate::theme::Theme;
use ratatui::layout::{Constraint, Rect};
use ratatui::style::Style;
use ratatui::text::Span;
use ratatui::widgets::{Block, Borders, Cell, Row, Table};
use ratatui::Frame;

/// Render the connections table with sortable columns and risk coloring.
///
/// ```text
/// ┌ 🌐 Active Connections (42) ──────────────────────────────────┐
/// │ PID   │ Process  │ Proto │ Remote           │ Port │ State   │ Risk   │
/// ├───────┼──────────┼───────┼──────────────────┼──────┼─────────┼────────┤
/// │ 1234  │ curl     │ TCP   │ example.com      │ 443  │ ESTAB   │ ✓ SAFE │
/// │ 5678  │ python3  │ TCP   │ evil.tk          │ 4444 │ ESTAB   │ ⚠ HIGH │
/// │ 9012  │ chrome   │ UDP   │ dns.google       │ 53   │ ESTAB   │ ✓ SAFE │
/// └───────┴──────────┴───────┴──────────────────┴──────┴─────────┴────────┘
/// ```
pub fn render(frame: &mut Frame, app: &App, area: Rect) {
    let filtered = app.filtered_connections();

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Theme::border(
            app.active_panel == crate::app::ActivePanel::Connections
                || app.active_panel == crate::app::ActivePanel::Dashboard,
        ))
        .title(Span::styled(
            format!(" 🌐 Active Connections ({}) ", filtered.len()),
            Theme::title(),
        ));

    let header_cells = [
        "PID", "Process", "Proto", "Remote", "Port", "State", "Risk",
    ]
    .iter()
    .map(|h| {
        Cell::from(*h).style(Theme::header())
    });
    let header = Row::new(header_cells).height(1);

    let rows: Vec<Row> = filtered
        .iter()
        .enumerate()
        .map(|(i, conn)| {
            let risk_style = Theme::risk_style(conn.risk.level);
            let proto_color = Theme::protocol_color(&conn.protocol);

            let remote_display = conn
                .remote_hostname
                .as_deref()
                .unwrap_or(&conn.remote_addr.to_string())
                .to_string();

            // Truncate long hostnames
            let remote_truncated = if remote_display.len() > 22 {
                format!("{}…", &remote_display[..21])
            } else {
                remote_display
            };

            let style = if i == app.selected_index {
                Theme::selected()
            } else {
                Style::default().fg(Theme::FG)
            };

            Row::new(vec![
                Cell::from(conn.process.pid.to_string()),
                Cell::from(conn.process.name.clone()),
                Cell::from(conn.protocol.to_string())
                    .style(Style::default().fg(proto_color)),
                Cell::from(remote_truncated),
                Cell::from(conn.remote_port.to_string()),
                Cell::from(conn.state.to_string()),
                Cell::from(conn.risk.level.to_string()).style(risk_style),
            ])
            .style(style)
        })
        .collect();

    let widths = [
        Constraint::Length(7),
        Constraint::Length(12),
        Constraint::Length(5),
        Constraint::Min(16),
        Constraint::Length(6),
        Constraint::Length(11),
        Constraint::Length(12),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(block)
        .row_highlight_style(Theme::selected());

    frame.render_widget(table, area);
}
