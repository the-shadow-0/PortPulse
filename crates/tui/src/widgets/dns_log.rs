use crate::app::App;
use crate::theme::Theme;
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

/// Render the DNS query log with timestamps, domains, and response IPs.
///
/// ```text
/// ┌ 🔍 DNS Queries (156) ───────────────────────────────────────┐
/// │ 22:15:03  A     google.com          → 142.250.80.46         │
/// │ 22:15:04  AAAA  github.com          → 140.82.121.4          │
/// │ 22:15:05  A     evil.tk             → 1.2.3.4        ⚠ HIGH │
/// │ 22:15:06  A     cdn.jsdelivr.net    → 104.16.85.20          │
/// └─────────────────────────────────────────────────────────────┘
/// ```
pub fn render(frame: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Theme::border(
            app.active_panel == crate::app::ActivePanel::DnsLog,
        ))
        .title(Span::styled(
            format!(" 🔍 DNS Queries ({}) ", app.dns_queries.len()),
            Theme::title(),
        ));

    let max_lines = (area.height as usize).saturating_sub(2);

    let queries: Vec<Line> = app
        .dns_queries
        .iter()
        .rev()
        .skip(app.dns_scroll)
        .take(max_lines)
        .map(|query| {
            let time = query.timestamp.format("%H:%M:%S").to_string();
            let risk_style = Theme::risk_style(query.risk.level);

            let ips = if query.resolved_ips.is_empty() {
                "NXDOMAIN".to_string()
            } else {
                query
                    .resolved_ips
                    .iter()
                    .map(|ip| ip.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            };

            // Truncate domain if too long
            let domain = if query.domain.len() > 24 {
                format!("{}…", &query.domain[..23])
            } else {
                format!("{:<24}", query.domain)
            };

            let response_time = query
                .response_time_ms
                .map(|ms| format!(" {}ms", ms))
                .unwrap_or_default();

            let risk_indicator = if query.risk.score > 0.3 {
                Span::styled(format!(" {}", query.risk.level), risk_style)
            } else {
                Span::raw("")
            };

            Line::from(vec![
                Span::styled(format!(" {} ", time), Theme::muted()),
                Span::styled(
                    format!("{:<5} ", query.query_type),
                    Style::default().fg(Theme::ACCENT),
                ),
                Span::styled(domain, Style::default().fg(Theme::FG)),
                Span::styled(" → ", Theme::muted()),
                Span::styled(ips, Style::default().fg(Theme::FG)),
                Span::styled(response_time, Theme::muted()),
                risk_indicator,
            ])
        })
        .collect();

    let paragraph = Paragraph::new(queries).block(block);
    frame.render_widget(paragraph, area);
}
