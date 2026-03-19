use portpulse_core::event::Event;
use portpulse_core::models::*;
use std::collections::VecDeque;

/// Active panel/tab in the TUI
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivePanel {
    Dashboard,
    Connections,
    DnsLog,
    ProcessTree,
    Graph,
    Detail,
}

/// Sort column for the connections table
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortColumn {
    Pid,
    Process,
    Protocol,
    RemoteAddr,
    RemotePort,
    State,
    Risk,
    Duration,
}

/// Application state for the TUI
pub struct App {
    /// Whether the app is running
    pub running: bool,
    /// Active panel
    pub active_panel: ActivePanel,
    /// Current connections
    pub connections: Vec<Connection>,
    /// DNS query log
    pub dns_queries: Vec<DnsQuery>,
    /// Timeline events
    pub timeline: VecDeque<NetworkEvent>,
    /// Suspicious connections (risk > threshold)
    pub suspicious: Vec<Connection>,
    /// Selected index in the connections table
    pub selected_index: usize,
    /// Scroll offset for DNS log
    pub dns_scroll: usize,
    /// Scroll offset for timeline
    pub timeline_scroll: usize,
    /// Sort column and direction
    pub sort_column: SortColumn,
    pub sort_ascending: bool,
    /// Filter text
    pub filter_text: String,
    /// Whether filter input is active
    pub filter_active: bool,
    /// Status bar message
    pub status_message: String,
    /// Connection graph nodes
    pub graph_nodes: Vec<GraphNode>,
    /// Connection graph edges
    pub graph_edges: Vec<GraphEdge>,
    /// Tick counter for animations
    pub tick: u64,
    /// Whether eBPF is active (vs fallback)
    pub ebpf_active: bool,
    /// Total events processed
    pub total_events: u64,
    /// Maximum timeline entries
    max_timeline: usize,
    /// Risk threshold for suspicious lane
    pub risk_threshold: f64,
    /// Detail view: selected connection
    pub detail_connection: Option<Connection>,
}

/// A node in the connection graph (process or domain)
#[derive(Debug, Clone)]
pub struct GraphNode {
    pub id: String,
    pub label: String,
    pub node_type: GraphNodeType,
    pub x: f64,
    pub y: f64,
    pub risk: RiskLevel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GraphNodeType {
    Process,
    Domain,
    IpAddress,
}

/// An edge in the connection graph
#[derive(Debug, Clone)]
pub struct GraphEdge {
    pub from: String,
    pub to: String,
    pub label: String,
    pub risk: RiskLevel,
    pub active: bool,
}

impl App {
    pub fn new() -> Self {
        Self {
            running: true,
            active_panel: ActivePanel::Dashboard,
            connections: Vec::new(),
            dns_queries: Vec::new(),
            timeline: VecDeque::new(),
            suspicious: Vec::new(),
            selected_index: 0,
            dns_scroll: 0,
            timeline_scroll: 0,
            sort_column: SortColumn::Risk,
            sort_ascending: false,
            filter_text: String::new(),
            filter_active: false,
            status_message: String::from("⚡ PortPulse active — monitoring connections..."),
            graph_nodes: Vec::new(),
            graph_edges: Vec::new(),
            tick: 0,
            ebpf_active: false,
            total_events: 0,
            max_timeline: 500,
            risk_threshold: 0.5,
            detail_connection: None,
        }
    }

    /// Handle a tick (periodic refresh)
    pub fn on_tick(&mut self) {
        self.tick += 1;
        self.update_suspicious();
        self.rebuild_graph();
    }

    /// Handle keyboard input
    pub fn on_key(&mut self, key: crossterm::event::KeyEvent) {
        use crossterm::event::KeyCode;

        if self.filter_active {
            match key.code {
                KeyCode::Esc => {
                    self.filter_active = false;
                }
                KeyCode::Enter => {
                    self.filter_active = false;
                }
                KeyCode::Backspace => {
                    self.filter_text.pop();
                }
                KeyCode::Char(c) => {
                    self.filter_text.push(c);
                }
                _ => {}
            }
            return;
        }

        match key.code {
            KeyCode::Char('q') | KeyCode::Char('Q') => {
                self.running = false;
            }
            KeyCode::Char('1') => self.active_panel = ActivePanel::Dashboard,
            KeyCode::Char('2') => self.active_panel = ActivePanel::Connections,
            KeyCode::Char('3') => self.active_panel = ActivePanel::DnsLog,
            KeyCode::Char('4') => self.active_panel = ActivePanel::ProcessTree,
            KeyCode::Char('5') => self.active_panel = ActivePanel::Graph,
            KeyCode::Char('/') => {
                self.filter_active = true;
                self.filter_text.clear();
            }
            KeyCode::Up | KeyCode::Char('k') => {
                if self.selected_index > 0 {
                    self.selected_index -= 1;
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                let max = self.filtered_connections().len().saturating_sub(1);
                if self.selected_index < max {
                    self.selected_index += 1;
                }
            }
            KeyCode::Enter => {
                let filtered = self.filtered_connections();
                if let Some(conn) = filtered.get(self.selected_index) {
                    self.detail_connection = Some(conn.clone());
                    self.active_panel = ActivePanel::Detail;
                }
            }
            KeyCode::Esc => {
                if self.active_panel == ActivePanel::Detail {
                    self.active_panel = ActivePanel::Dashboard;
                    self.detail_connection = None;
                }
            }
            KeyCode::Char('s') => {
                self.sort_ascending = !self.sort_ascending;
            }
            KeyCode::Tab => {
                self.active_panel = match self.active_panel {
                    ActivePanel::Dashboard => ActivePanel::Connections,
                    ActivePanel::Connections => ActivePanel::DnsLog,
                    ActivePanel::DnsLog => ActivePanel::ProcessTree,
                    ActivePanel::ProcessTree => ActivePanel::Graph,
                    ActivePanel::Graph => ActivePanel::Dashboard,
                    ActivePanel::Detail => ActivePanel::Dashboard,
                };
            }
            _ => {}
        }
    }

    /// Process an incoming event
    pub fn process_event(&mut self, event: Event) {
        self.total_events += 1;

        match event {
            Event::ConnectionUpdate(conn) => {
                // Update or insert connection
                if let Some(existing) = self.connections.iter_mut().find(|c| c.id == conn.id) {
                    *existing = conn;
                } else {
                    self.connections.push(conn);
                }
            }
            Event::DnsUpdate(query) => {
                self.dns_queries.push(query);
                // Keep bounded
                if self.dns_queries.len() > 1000 {
                    self.dns_queries.remove(0);
                }
            }
            Event::TimelineEvent(event) => {
                self.timeline.push_back(event);
                while self.timeline.len() > self.max_timeline {
                    self.timeline.pop_front();
                }
            }
            _ => {}
        }
    }

    /// Get connections filtered by the current filter text
    pub fn filtered_connections(&self) -> Vec<Connection> {
        if self.filter_text.is_empty() {
            return self.connections.clone();
        }
        let filter_lower = self.filter_text.to_lowercase();
        self.connections
            .iter()
            .filter(|c| {
                c.process.name.to_lowercase().contains(&filter_lower)
                    || c.remote_addr.to_string().contains(&filter_lower)
                    || c.remote_hostname
                        .as_ref()
                        .map(|h| h.to_lowercase().contains(&filter_lower))
                        .unwrap_or(false)
                    || c.remote_port.to_string().contains(&filter_lower)
            })
            .cloned()
            .collect()
    }

    /// Update the suspicious connections list
    fn update_suspicious(&mut self) {
        self.suspicious = self
            .connections
            .iter()
            .filter(|c| c.risk.score >= self.risk_threshold)
            .cloned()
            .collect();
        self.suspicious.sort_by(|a, b| {
            b.risk
                .score
                .partial_cmp(&a.risk.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
    }

    /// Rebuild the connection graph from current connections
    fn rebuild_graph(&mut self) {
        self.graph_nodes.clear();
        self.graph_edges.clear();

        let mut process_nodes: std::collections::HashMap<String, GraphNode> =
            std::collections::HashMap::new();
        let mut domain_nodes: std::collections::HashMap<String, GraphNode> =
            std::collections::HashMap::new();

        for (i, conn) in self.connections.iter().enumerate() {
            let proc_key = format!("proc:{}", conn.process.pid);
            let angle_proc = (i as f64 * 0.5) % std::f64::consts::TAU;

            process_nodes.entry(proc_key.clone()).or_insert(GraphNode {
                id: proc_key.clone(),
                label: format!("{} ({})", conn.process.name, conn.process.pid),
                node_type: GraphNodeType::Process,
                x: 20.0 + 15.0 * angle_proc.cos(),
                y: 50.0 + 30.0 * angle_proc.sin(),
                risk: conn.risk.level,
            });

            let domain_key = conn
                .remote_hostname
                .clone()
                .unwrap_or_else(|| conn.remote_addr.to_string());
            let angle_dom = (i as f64 * 0.7) % std::f64::consts::TAU;

            domain_nodes.entry(domain_key.clone()).or_insert(GraphNode {
                id: format!("dom:{}", domain_key),
                label: domain_key.clone(),
                node_type: GraphNodeType::Domain,
                x: 70.0 + 15.0 * angle_dom.cos(),
                y: 50.0 + 30.0 * angle_dom.sin(),
                risk: conn.risk.level,
            });

            self.graph_edges.push(GraphEdge {
                from: proc_key,
                to: format!("dom:{}", domain_key),
                label: format!(":{}", conn.remote_port),
                risk: conn.risk.level,
                active: (self.tick % 10) < 7, // Blinking animation
            });
        }

        self.graph_nodes.extend(process_nodes.into_values());
        self.graph_nodes.extend(domain_nodes.into_values());
    }
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}
