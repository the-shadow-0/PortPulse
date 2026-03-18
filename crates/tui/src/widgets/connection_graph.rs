use crate::app::{App, GraphNodeType};
use crate::theme::Theme;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::canvas::{Canvas, Circle, Line as CanvasLine};
use ratatui::widgets::{Block, Borders};
use ratatui::Frame;
use portpulse_core::models::RiskLevel;

/// Render the animated connection graph — the WOW feature.
///
/// Processes → Domains with live edge highlighting and risk coloring.
///
/// ```text
/// ┌ ⚡ Connection Graph ─────────────────────────────────────────┐
/// │                                                              │
/// │    [curl]────────────────────────►[example.com]              │
/// │     (1234)           :443                                    │
/// │                                                              │
/// │    [python3]─── ⚠ ──────────────►[evil.tk]                  │
/// │     (5678)           :4444        🔴 SUSPICIOUS              │
/// │                                                              │
/// │    [chrome]──────────────────────►[google.com]               │
/// │     (9012)           :443                                    │
/// │                                                              │
/// └──────────────────────────────────────────────────────────────┘
/// ```
pub fn render(frame: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Theme::border(
            app.active_panel == crate::app::ActivePanel::Graph,
        ))
        .title(Span::styled(" ⚡ Connection Graph ", Theme::title()));

    if app.graph_nodes.is_empty() {
        let empty_canvas = Canvas::default()
            .block(block)
            .x_bounds([0.0, 100.0])
            .y_bounds([0.0, 100.0])
            .paint(|ctx| {
                ctx.print(
                    35.0,
                    50.0,
                    Line::from(Span::styled(
                        "No active connections to display",
                        Theme::muted(),
                    )),
                );
            });
        frame.render_widget(empty_canvas, area);
        return;
    }

    let tick = app.tick;

    // Pre-compute owned data for the closure to avoid lifetime issues
    struct EdgeData {
        from_pos: (f64, f64),
        to_pos: (f64, f64),
        label: String,
        risk: RiskLevel,
        active: bool,
    }

    struct NodeData {
        x: f64,
        y: f64,
        label: String,
        node_type: GraphNodeType,
        risk: RiskLevel,
    }

    // Build node position lookup
    let node_positions: std::collections::HashMap<String, (f64, f64)> = app
        .graph_nodes
        .iter()
        .map(|n| (n.id.clone(), (n.x, n.y)))
        .collect();

    // Pre-resolve edge positions
    let edge_data: Vec<EdgeData> = app
        .graph_edges
        .iter()
        .filter_map(|edge| {
            let from_pos = node_positions.get(&edge.from)?;
            let to_pos = node_positions.get(&edge.to)?;
            Some(EdgeData {
                from_pos: *from_pos,
                to_pos: *to_pos,
                label: edge.label.clone(),
                risk: edge.risk,
                active: edge.active,
            })
        })
        .collect();

    let node_data: Vec<NodeData> = app
        .graph_nodes
        .iter()
        .map(|n| NodeData {
            x: n.x,
            y: n.y,
            label: n.label.clone(),
            node_type: n.node_type,
            risk: n.risk,
        })
        .collect();

    let canvas = Canvas::default()
        .block(block)
        .x_bounds([0.0, 100.0])
        .y_bounds([0.0, 100.0])
        .paint(move |ctx| {
            // Draw edges first (behind nodes)
            for edge in &edge_data {
                let (x1, y1) = edge.from_pos;
                let (x2, y2) = edge.to_pos;

                let (r, g, b) = match edge.risk {
                    RiskLevel::Critical | RiskLevel::High => {
                        if tick % 4 < 2 {
                            (248, 81, 73)
                        } else {
                            (180, 50, 50)
                        }
                    }
                    RiskLevel::Medium => (210, 153, 34),
                    _ => {
                        if edge.active {
                            (88, 166, 255)
                        } else {
                            (72, 79, 88)
                        }
                    }
                };

                let color = ratatui::style::Color::Rgb(r, g, b);

                ctx.draw(&CanvasLine {
                    x1,
                    y1,
                    x2,
                    y2,
                    color,
                });

                // Draw port label at midpoint
                let mid_x = (x1 + x2) / 2.0;
                let mid_y = (y1 + y2) / 2.0;
                ctx.print(
                    mid_x,
                    mid_y,
                    Line::from(Span::styled(
                        edge.label.clone(),
                        Style::default().fg(color),
                    )),
                );
            }

            // Draw nodes
            for node in &node_data {
                let color = match node.node_type {
                    GraphNodeType::Process => {
                        ratatui::style::Color::Rgb(88, 166, 255)
                    }
                    GraphNodeType::Domain => match node.risk {
                        RiskLevel::High | RiskLevel::Critical => {
                            ratatui::style::Color::Rgb(248, 81, 73)
                        }
                        RiskLevel::Medium => {
                            ratatui::style::Color::Rgb(210, 153, 34)
                        }
                        _ => ratatui::style::Color::Rgb(163, 113, 247),
                    },
                    GraphNodeType::IpAddress => {
                        ratatui::style::Color::Rgb(139, 148, 158)
                    }
                };

                // Draw node marker
                ctx.draw(&Circle {
                    x: node.x,
                    y: node.y,
                    radius: 1.5,
                    color,
                });

                // Draw label
                let label_style = Style::default()
                    .fg(color)
                    .add_modifier(Modifier::BOLD);

                ctx.print(
                    node.x,
                    node.y + 3.0,
                    Line::from(Span::styled(node.label.clone(), label_style)),
                );
            }

            // Legend
            ctx.print(
                2.0,
                97.0,
                Line::from(vec![
                    Span::styled("● ", Style::default().fg(ratatui::style::Color::Rgb(88, 166, 255))),
                    Span::styled("Process  ", Theme::muted()),
                    Span::styled("◆ ", Style::default().fg(ratatui::style::Color::Rgb(163, 113, 247))),
                    Span::styled("Domain  ", Theme::muted()),
                    Span::styled("━━ ", Style::default().fg(ratatui::style::Color::Rgb(248, 81, 73))),
                    Span::styled("Suspicious", Style::default().fg(ratatui::style::Color::Rgb(248, 81, 73))),
                ]),
            );
        });

    frame.render_widget(canvas, area);
}
