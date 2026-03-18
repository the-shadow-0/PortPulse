use crate::app::App;
use crate::theme::Theme;
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

/// Render the suspicious lane — a top-of-screen alert bar
/// showing high-risk connections with blinking indicators.
///
/// ```text
/// ┌ 🔴 SUSPICIOUS ──────────────────────────────────────────────┐
/// │ ⚠ curl→evil.tk:4444 (0.85)  ⚠ unknown→1.2.3.4:31337 (0.92) │
/// └─────────────────────────────────────────────────────────────┘
/// ```
pub fn render(frame: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(if app.suspicious.is_empty() {
            Theme::border(false)
        } else {
            Style::default().fg(Theme::HIGH)
        })
        .title(Span::styled(
            if app.suspicious.is_empty() {
                " ✓ No Suspicious Activity "
            } else {
                " 🔴 SUSPICIOUS "
            },
            if app.suspicious.is_empty() {
                Style::default().fg(Theme::SAFE)
            } else {
                Theme::suspicious_lane()
            },
        ));

    if app.suspicious.is_empty() {
        let msg = Paragraph::new(Line::from(Span::styled(
            "  All connections appear safe",
            Style::default().fg(Theme::SAFE),
        )))
        .block(block);
        frame.render_widget(msg, area);
        return;
    }

    let items: Vec<Span> = app
        .suspicious
        .iter()
        .take(5)
        .flat_map(|conn| {
            let risk_style = Theme::risk_style(conn.risk.level);
            let addr_string = conn.remote_addr.to_string();
            let target = conn
                .remote_hostname
                .as_deref()
                .unwrap_or(&addr_string);
            let label = format!(
                "{}→{}:{} ({:.2})",
                conn.process.name, target, conn.remote_port, conn.risk.score
            );
            vec![
                Span::styled(" ⚠ ", risk_style),
                Span::styled(label, risk_style),
                Span::raw("  "),
            ]
        })
        .collect();

    let line = Line::from(items);
    let paragraph = Paragraph::new(line).block(block);
    frame.render_widget(paragraph, area);
}
