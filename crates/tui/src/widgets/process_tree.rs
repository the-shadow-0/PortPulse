use crate::app::App;
use crate::theme::Theme;
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;
use std::collections::HashMap;

/// Render the process tree showing parent-child hierarchy with connection counts.
///
/// ```text
/// ┌ 🌳 Process Tree ────────────────────────────────────────────┐
/// │ ▶ systemd (1)                                    2 conns     │
/// │   ├─▶ sshd (456)                                1 conn      │
/// │   │   └─▶ bash (789)                            0 conns     │
/// │   ├─▶ nginx (234)                               5 conns     │
/// │   └─▶ docker (567)                              3 conns     │
/// │       └─▶ node (890)                            3 conns     │
/// └─────────────────────────────────────────────────────────────┘
/// ```
pub fn render(frame: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Theme::border(
            app.active_panel == crate::app::ActivePanel::ProcessTree,
        ))
        .title(Span::styled(" 🌳 Process Tree ", Theme::title()));

    // Build process → connection count map
    let mut conn_counts: HashMap<u32, usize> = HashMap::new();
    for conn in &app.connections {
        *conn_counts.entry(conn.process.pid).or_insert(0) += 1;
    }

    // Build parent → children map
    let mut children: HashMap<u32, Vec<(u32, &str)>> = HashMap::new();
    let mut all_pids: HashMap<u32, &str> = HashMap::new();
    let mut has_parent: std::collections::HashSet<u32> = std::collections::HashSet::new();

    for conn in &app.connections {
        all_pids.insert(conn.process.pid, &conn.process.name);
        if conn.process.ppid > 0 {
            children
                .entry(conn.process.ppid)
                .or_default()
                .push((conn.process.pid, &conn.process.name));
            has_parent.insert(conn.process.pid);
        }
    }

    // Deduplicate children
    for children_list in children.values_mut() {
        children_list.sort_by_key(|(pid, _)| *pid);
        children_list.dedup_by_key(|(pid, _)| *pid);
    }

    // Find root processes (those with no parent in our set)
    let mut roots: Vec<(u32, &str)> = all_pids
        .iter()
        .filter(|(pid, _)| !has_parent.contains(pid))
        .map(|(pid, name)| (*pid, *name))
        .collect();
    roots.sort_by_key(|(pid, _)| *pid);
    roots.dedup_by_key(|(pid, _)| *pid);

    let max_lines = (area.height as usize).saturating_sub(2);
    let mut lines: Vec<Line> = Vec::new();

    for (pid, name) in &roots {
        render_tree_node(
            &mut lines,
            *pid,
            name,
            &children,
            &conn_counts,
            "",
            true,
            max_lines,
            0,
        );
    }

    if lines.is_empty() {
        lines.push(Line::from(Span::styled(
            "  No active processes with connections",
            Theme::muted(),
        )));
    }

    let paragraph = Paragraph::new(lines).block(block);
    frame.render_widget(paragraph, area);
}

/// Recursively render a tree node
fn render_tree_node<'a>(
    lines: &mut Vec<Line<'a>>,
    pid: u32,
    name: &str,
    children: &HashMap<u32, Vec<(u32, &str)>>,
    conn_counts: &HashMap<u32, usize>,
    prefix: &str,
    is_last: bool,
    max_lines: usize,
    depth: usize,
) {
    if lines.len() >= max_lines || depth > 10 {
        return;
    }

    let connector = if prefix.is_empty() {
        "▶ "
    } else if is_last {
        "└─▶ "
    } else {
        "├─▶ "
    };

    let count = conn_counts.get(&pid).copied().unwrap_or(0);
    let count_str = match count {
        0 => String::new(),
        1 => "1 conn".to_string(),
        n => format!("{} conns", n),
    };

    let risk_color = if count > 3 { Theme::MEDIUM } else { Theme::FG };

    lines.push(Line::from(vec![
        Span::styled(format!("  {}{}", prefix, connector), Theme::muted()),
        Span::styled(
            format!("{} ({})", name, pid),
            Style::default().fg(Theme::ACCENT),
        ),
        Span::raw("  "),
        Span::styled(count_str, Style::default().fg(risk_color)),
    ]));

    if let Some(child_list) = children.get(&pid) {
        let child_prefix = if prefix.is_empty() {
            "  ".to_string()
        } else if is_last {
            format!("{}    ", prefix)
        } else {
            format!("{}│   ", prefix)
        };

        for (i, (child_pid, child_name)) in child_list.iter().enumerate() {
            let child_is_last = i == child_list.len() - 1;
            render_tree_node(
                lines,
                *child_pid,
                child_name,
                children,
                conn_counts,
                &child_prefix,
                child_is_last,
                max_lines,
                depth + 1,
            );
        }
    }
}
