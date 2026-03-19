use portpulse_core::models::RiskLevel;
use ratatui::style::{Color, Modifier, Style};

/// PortPulse color theme — a carefully crafted dark theme
/// optimized for terminal readability and visual hierarchy.
///
/// ```text
/// Color Philosophy:
/// ━━━━━━━━━━━━━━━━
/// Background  │ Deep navy (#0D1117) — GitHub-dark inspired
/// Foreground  │ Soft white (#C9D1D9) — easy on the eyes
/// Accent      │ Electric cyan (#58A6FF) — draws attention
/// Safe        │ Emerald green (#3FB950) — all clear
/// Warning     │ Amber orange (#D29922) — caution
/// Danger      │ Vivid red (#F85149) — critical
/// Critical    │ Hot magenta (#F778BA) — maximum alert
/// Muted       │ Slate gray (#8B949E) — secondary info
/// ```
pub struct Theme;

impl Theme {
    // ── Base colors ──────────────────────────────────────────────
    pub const BG: Color = Color::Rgb(13, 17, 23);
    pub const FG: Color = Color::Rgb(201, 209, 217);
    pub const ACCENT: Color = Color::Rgb(88, 166, 255);
    pub const MUTED: Color = Color::Rgb(139, 148, 158);
    pub const BORDER: Color = Color::Rgb(48, 54, 61);
    pub const BORDER_ACTIVE: Color = Color::Rgb(88, 166, 255);
    pub const HEADER_BG: Color = Color::Rgb(22, 27, 34);

    // ── Risk colors ──────────────────────────────────────────────
    pub const SAFE: Color = Color::Rgb(63, 185, 80);
    pub const LOW: Color = Color::Rgb(63, 185, 80);
    pub const MEDIUM: Color = Color::Rgb(210, 153, 34);
    pub const HIGH: Color = Color::Rgb(248, 81, 73);
    pub const CRITICAL: Color = Color::Rgb(247, 120, 186);

    // ── Protocol colors ──────────────────────────────────────────
    pub const TCP: Color = Color::Rgb(121, 192, 255);
    pub const UDP: Color = Color::Rgb(210, 153, 34);
    pub const ICMP: Color = Color::Rgb(163, 113, 247);

    // ── Graph colors ─────────────────────────────────────────────
    pub const GRAPH_PROCESS: Color = Color::Rgb(88, 166, 255);
    pub const GRAPH_DOMAIN: Color = Color::Rgb(163, 113, 247);
    pub const GRAPH_EDGE: Color = Color::Rgb(72, 79, 88);
    pub const GRAPH_EDGE_ACTIVE: Color = Color::Rgb(88, 166, 255);
    pub const GRAPH_EDGE_SUSPICIOUS: Color = Color::Rgb(248, 81, 73);

    // ── Styles ───────────────────────────────────────────────────

    pub fn base() -> Style {
        Style::default().fg(Self::FG).bg(Self::BG)
    }

    pub fn header() -> Style {
        Style::default()
            .fg(Self::ACCENT)
            .bg(Self::HEADER_BG)
            .add_modifier(Modifier::BOLD)
    }

    pub fn title() -> Style {
        Style::default()
            .fg(Self::ACCENT)
            .add_modifier(Modifier::BOLD)
    }

    pub fn selected() -> Style {
        Style::default()
            .fg(Color::Rgb(13, 17, 23))
            .bg(Self::ACCENT)
            .add_modifier(Modifier::BOLD)
    }

    pub fn muted() -> Style {
        Style::default().fg(Self::MUTED)
    }

    pub fn border(active: bool) -> Style {
        if active {
            Style::default().fg(Self::BORDER_ACTIVE)
        } else {
            Style::default().fg(Self::BORDER)
        }
    }

    pub fn risk_style(level: RiskLevel) -> Style {
        let color = Self::risk_color(level);
        let mut style = Style::default().fg(color);
        if level >= RiskLevel::High {
            style = style.add_modifier(Modifier::BOLD);
        }
        if level == RiskLevel::Critical {
            style = style.add_modifier(Modifier::SLOW_BLINK);
        }
        style
    }

    pub fn risk_color(level: RiskLevel) -> Color {
        match level {
            RiskLevel::Safe => Self::SAFE,
            RiskLevel::Low => Self::LOW,
            RiskLevel::Medium => Self::MEDIUM,
            RiskLevel::High => Self::HIGH,
            RiskLevel::Critical => Self::CRITICAL,
        }
    }

    pub fn protocol_color(protocol: &portpulse_core::models::Protocol) -> Color {
        match protocol {
            portpulse_core::models::Protocol::Tcp => Self::TCP,
            portpulse_core::models::Protocol::Udp => Self::UDP,
            portpulse_core::models::Protocol::Icmp => Self::ICMP,
            portpulse_core::models::Protocol::Unknown => Self::MUTED,
        }
    }

    pub fn status_bar() -> Style {
        Style::default().fg(Self::FG).bg(Color::Rgb(22, 27, 34))
    }

    pub fn suspicious_lane() -> Style {
        Style::default()
            .fg(Self::HIGH)
            .bg(Color::Rgb(30, 15, 15))
            .add_modifier(Modifier::BOLD)
    }

    pub fn tab_active() -> Style {
        Style::default()
            .fg(Self::ACCENT)
            .add_modifier(Modifier::BOLD | Modifier::UNDERLINED)
    }

    pub fn tab_inactive() -> Style {
        Style::default().fg(Self::MUTED)
    }
}
