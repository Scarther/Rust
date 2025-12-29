//! G07_Port_Scanner_GUI - Visual Port Scanner
//! ============================================
//!
//! A comprehensive port scanner with graphical interface for network
//! reconnaissance and security testing.
//!
//! Key Concepts Covered:
//! - Async TCP port scanning
//! - Concurrent connection handling
//! - Service identification
//! - Progress visualization
//! - Result export (JSON, CSV)
//! - Scan history
//! - Common port presets

use arboard::Clipboard;
use chrono::{DateTime, Local};
use eframe::egui;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// Scan status
#[derive(Debug, Clone, Copy, PartialEq)]
enum ScanStatus {
    Idle,
    Running,
    Paused,
    Completed,
    Cancelled,
    Error,
}

impl ScanStatus {
    fn as_str(&self) -> &'static str {
        match self {
            ScanStatus::Idle => "Idle",
            ScanStatus::Running => "Scanning",
            ScanStatus::Paused => "Paused",
            ScanStatus::Completed => "Completed",
            ScanStatus::Cancelled => "Cancelled",
            ScanStatus::Error => "Error",
        }
    }

    fn color(&self) -> egui::Color32 {
        match self {
            ScanStatus::Idle => egui::Color32::GRAY,
            ScanStatus::Running => egui::Color32::from_rgb(100, 180, 255),
            ScanStatus::Paused => egui::Color32::from_rgb(255, 193, 7),
            ScanStatus::Completed => egui::Color32::from_rgb(76, 175, 80),
            ScanStatus::Cancelled => egui::Color32::from_rgb(158, 158, 158),
            ScanStatus::Error => egui::Color32::from_rgb(244, 67, 54),
        }
    }
}

/// Port state
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
enum PortState {
    Open,
    Closed,
    Filtered,
    Unknown,
}

impl PortState {
    fn as_str(&self) -> &'static str {
        match self {
            PortState::Open => "Open",
            PortState::Closed => "Closed",
            PortState::Filtered => "Filtered",
            PortState::Unknown => "Unknown",
        }
    }

    fn color(&self) -> egui::Color32 {
        match self {
            PortState::Open => egui::Color32::from_rgb(76, 175, 80),
            PortState::Closed => egui::Color32::from_rgb(158, 158, 158),
            PortState::Filtered => egui::Color32::from_rgb(255, 193, 7),
            PortState::Unknown => egui::Color32::GRAY,
        }
    }
}

/// Port scan result
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PortResult {
    port: u16,
    state: PortState,
    service: Option<String>,
    banner: Option<String>,
    response_time_ms: Option<u64>,
}

/// Common services by port
fn get_service_name(port: u16) -> Option<&'static str> {
    match port {
        20 => Some("FTP-data"),
        21 => Some("FTP"),
        22 => Some("SSH"),
        23 => Some("Telnet"),
        25 => Some("SMTP"),
        53 => Some("DNS"),
        80 => Some("HTTP"),
        110 => Some("POP3"),
        111 => Some("RPC"),
        135 => Some("MSRPC"),
        139 => Some("NetBIOS"),
        143 => Some("IMAP"),
        443 => Some("HTTPS"),
        445 => Some("SMB"),
        993 => Some("IMAPS"),
        995 => Some("POP3S"),
        1433 => Some("MSSQL"),
        1521 => Some("Oracle"),
        3306 => Some("MySQL"),
        3389 => Some("RDP"),
        5432 => Some("PostgreSQL"),
        5900 => Some("VNC"),
        6379 => Some("Redis"),
        8080 => Some("HTTP-proxy"),
        8443 => Some("HTTPS-alt"),
        27017 => Some("MongoDB"),
        _ => None,
    }
}

/// Port range presets
#[derive(Debug, Clone, Copy, PartialEq)]
enum PortPreset {
    Custom,
    Top20,
    Top100,
    Common,
    WebPorts,
    DatabasePorts,
    All,
}

impl PortPreset {
    fn all() -> Vec<PortPreset> {
        vec![
            PortPreset::Custom,
            PortPreset::Top20,
            PortPreset::Top100,
            PortPreset::Common,
            PortPreset::WebPorts,
            PortPreset::DatabasePorts,
            PortPreset::All,
        ]
    }

    fn as_str(&self) -> &'static str {
        match self {
            PortPreset::Custom => "Custom",
            PortPreset::Top20 => "Top 20 Ports",
            PortPreset::Top100 => "Top 100 Ports",
            PortPreset::Common => "Common Ports (1-1024)",
            PortPreset::WebPorts => "Web Ports",
            PortPreset::DatabasePorts => "Database Ports",
            PortPreset::All => "All Ports (1-65535)",
        }
    }

    fn get_ports(&self) -> Vec<u16> {
        match self {
            PortPreset::Custom => vec![],
            PortPreset::Top20 => vec![
                21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
                143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080,
            ],
            PortPreset::Top100 => {
                let mut ports: Vec<u16> = vec![
                    1, 3, 7, 9, 13, 17, 19, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 82, 88, 100,
                    106, 110, 111, 113, 119, 135, 139, 143, 144, 179, 199, 254, 255, 280, 311, 389,
                    427, 443, 444, 445, 464, 465, 497, 513, 514, 515, 543, 544, 548, 554, 587, 593,
                    625, 631, 636, 646, 787, 808, 873, 902, 990, 993, 995, 1000, 1022, 1024, 1025,
                    1026, 1027, 1028, 1029, 1030, 1110, 1433, 1521, 1720, 1723, 1755, 1900, 2000,
                    2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051,
                    5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6646, 7070, 8000,
                    8008, 8080, 8443, 8888, 9100, 9999, 10000, 32768, 49152,
                ];
                ports.sort();
                ports.dedup();
                ports
            }
            PortPreset::Common => (1..=1024).collect(),
            PortPreset::WebPorts => vec![80, 443, 8000, 8080, 8443, 8888, 3000, 5000, 9000],
            PortPreset::DatabasePorts => vec![1433, 1521, 3306, 5432, 6379, 27017, 9042, 7474],
            PortPreset::All => (1..=65535).collect(),
        }
    }
}

/// Scan result summary
#[derive(Clone)]
struct ScanResult {
    target: String,
    started_at: DateTime<Local>,
    completed_at: Option<DateTime<Local>>,
    ports_scanned: usize,
    ports: Vec<PortResult>,
    status: ScanStatus,
    error_message: Option<String>,
}

impl ScanResult {
    fn new(target: &str) -> Self {
        Self {
            target: target.to_string(),
            started_at: Local::now(),
            completed_at: None,
            ports_scanned: 0,
            ports: Vec::new(),
            status: ScanStatus::Running,
            error_message: None,
        }
    }

    fn open_ports(&self) -> Vec<&PortResult> {
        self.ports.iter().filter(|p| p.state == PortState::Open).collect()
    }

    fn duration(&self) -> Option<chrono::Duration> {
        self.completed_at.map(|end| end - self.started_at)
    }
}

/// Shared state for background scanning
struct SharedState {
    result: Option<ScanResult>,
    current_port: u16,
    total_ports: usize,
    should_cancel: bool,
    is_paused: bool,
}

/// Main application state
struct PortScannerApp {
    // Target settings
    target: String,
    port_preset: PortPreset,
    custom_ports: String,
    timeout_ms: u32,
    threads: u32,

    // Scan state
    shared_state: Arc<Mutex<SharedState>>,

    // History
    scan_history: Vec<ScanResult>,
    selected_history: Option<usize>,

    // View settings
    show_only_open: bool,
    show_closed: bool,
    sort_by_port: bool,
    dark_mode: bool,

    // Export
    export_format: String,

    // UI state
    status_message: Option<String>,
    clipboard: Option<Clipboard>,
}

impl Default for PortScannerApp {
    fn default() -> Self {
        Self {
            target: String::new(),
            port_preset: PortPreset::Top20,
            custom_ports: String::from("22,80,443,8080"),
            timeout_ms: 1000,
            threads: 100,
            shared_state: Arc::new(Mutex::new(SharedState {
                result: None,
                current_port: 0,
                total_ports: 0,
                should_cancel: false,
                is_paused: false,
            })),
            scan_history: Vec::new(),
            selected_history: None,
            show_only_open: false,
            show_closed: true,
            sort_by_port: true,
            dark_mode: true,
            export_format: "JSON".to_string(),
            status_message: None,
            clipboard: Clipboard::new().ok(),
        }
    }
}

impl PortScannerApp {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        cc.egui_ctx.set_visuals(egui::Visuals::dark());
        Self::default()
    }

    /// Validate target (IP or hostname)
    fn validate_target(&self) -> bool {
        let target = self.target.trim();
        if target.is_empty() {
            return false;
        }

        // Check if valid IP
        if target.parse::<IpAddr>().is_ok() {
            return true;
        }

        // Check if valid hostname
        let hostname_regex = Regex::new(
            r"^([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)*[a-zA-Z]{2,}$"
        ).unwrap();

        hostname_regex.is_match(target) || target == "localhost"
    }

    /// Parse custom port string
    fn parse_ports(&self) -> Result<Vec<u16>, String> {
        if self.port_preset != PortPreset::Custom {
            return Ok(self.port_preset.get_ports());
        }

        let mut ports = Vec::new();
        for part in self.custom_ports.split(',') {
            let part = part.trim();
            if part.contains('-') {
                // Range
                let parts: Vec<&str> = part.split('-').collect();
                if parts.len() != 2 {
                    return Err(format!("Invalid range: {}", part));
                }
                let start: u16 = parts[0].trim().parse()
                    .map_err(|_| format!("Invalid port: {}", parts[0]))?;
                let end: u16 = parts[1].trim().parse()
                    .map_err(|_| format!("Invalid port: {}", parts[1]))?;
                for p in start..=end {
                    ports.push(p);
                }
            } else {
                // Single port
                let port: u16 = part.parse()
                    .map_err(|_| format!("Invalid port: {}", part))?;
                ports.push(port);
            }
        }

        ports.sort();
        ports.dedup();
        Ok(ports)
    }

    /// Start scanning
    fn start_scan(&mut self) {
        if !self.validate_target() {
            self.status_message = Some("Invalid target".to_string());
            return;
        }

        let ports = match self.parse_ports() {
            Ok(p) => p,
            Err(e) => {
                self.status_message = Some(e);
                return;
            }
        };

        if ports.is_empty() {
            self.status_message = Some("No ports to scan".to_string());
            return;
        }

        let target = self.target.trim().to_string();
        let timeout = Duration::from_millis(self.timeout_ms as u64);
        let threads = self.threads as usize;
        let shared = self.shared_state.clone();

        // Initialize state
        {
            let mut state = shared.lock().unwrap();
            state.result = Some(ScanResult::new(&target));
            state.current_port = 0;
            state.total_ports = ports.len();
            state.should_cancel = false;
            state.is_paused = false;
        }

        // Spawn scanner thread
        thread::spawn(move || {
            let results: Arc<Mutex<Vec<PortResult>>> = Arc::new(Mutex::new(Vec::new()));

            // Create thread pool
            let chunk_size = (ports.len() / threads).max(1);
            let mut handles = Vec::new();

            for chunk in ports.chunks(chunk_size) {
                let chunk_ports: Vec<u16> = chunk.to_vec();
                let target = target.clone();
                let shared = shared.clone();
                let results = results.clone();

                let handle = thread::spawn(move || {
                    for port in chunk_ports {
                        // Check for cancel/pause
                        {
                            let state = shared.lock().unwrap();
                            if state.should_cancel {
                                return;
                            }
                            while state.is_paused {
                                drop(state);
                                thread::sleep(Duration::from_millis(100));
                                let state = shared.lock().unwrap();
                                if state.should_cancel {
                                    return;
                                }
                            }
                        }

                        // Scan port
                        let addr = format!("{}:{}", target, port);
                        let start = Instant::now();

                        let result = match addr.parse::<SocketAddr>() {
                            Ok(socket_addr) => {
                                match TcpStream::connect_timeout(&socket_addr, timeout) {
                                    Ok(_) => PortResult {
                                        port,
                                        state: PortState::Open,
                                        service: get_service_name(port).map(|s| s.to_string()),
                                        banner: None,
                                        response_time_ms: Some(start.elapsed().as_millis() as u64),
                                    },
                                    Err(_) => PortResult {
                                        port,
                                        state: PortState::Closed,
                                        service: None,
                                        banner: None,
                                        response_time_ms: None,
                                    },
                                }
                            }
                            Err(_) => {
                                // Try DNS resolution
                                use std::net::ToSocketAddrs;
                                match format!("{}:{}", target, port).to_socket_addrs() {
                                    Ok(mut addrs) => {
                                        if let Some(socket_addr) = addrs.next() {
                                            match TcpStream::connect_timeout(&socket_addr, timeout) {
                                                Ok(_) => PortResult {
                                                    port,
                                                    state: PortState::Open,
                                                    service: get_service_name(port).map(|s| s.to_string()),
                                                    banner: None,
                                                    response_time_ms: Some(start.elapsed().as_millis() as u64),
                                                },
                                                Err(_) => PortResult {
                                                    port,
                                                    state: PortState::Closed,
                                                    service: None,
                                                    banner: None,
                                                    response_time_ms: None,
                                                },
                                            }
                                        } else {
                                            PortResult {
                                                port,
                                                state: PortState::Unknown,
                                                service: None,
                                                banner: None,
                                                response_time_ms: None,
                                            }
                                        }
                                    }
                                    Err(_) => PortResult {
                                        port,
                                        state: PortState::Unknown,
                                        service: None,
                                        banner: None,
                                        response_time_ms: None,
                                    },
                                }
                            }
                        };

                        // Store result
                        results.lock().unwrap().push(result);

                        // Update progress
                        let mut state = shared.lock().unwrap();
                        state.current_port = port;
                        if let Some(ref mut scan_result) = state.result {
                            scan_result.ports_scanned += 1;
                        }
                    }
                });

                handles.push(handle);
            }

            // Wait for all threads
            for handle in handles {
                let _ = handle.join();
            }

            // Finalize results
            let mut state = shared.lock().unwrap();
            if let Some(ref mut scan_result) = state.result {
                let final_results = results.lock().unwrap();
                scan_result.ports = final_results.clone();
                scan_result.ports.sort_by_key(|p| p.port);
                scan_result.completed_at = Some(Local::now());
                scan_result.status = if state.should_cancel {
                    ScanStatus::Cancelled
                } else {
                    ScanStatus::Completed
                };
            }
        });
    }

    /// Cancel current scan
    fn cancel_scan(&mut self) {
        let mut state = self.shared_state.lock().unwrap();
        state.should_cancel = true;
    }

    /// Toggle pause
    fn toggle_pause(&mut self) {
        let mut state = self.shared_state.lock().unwrap();
        state.is_paused = !state.is_paused;
    }

    /// Get current scan progress
    fn get_progress(&self) -> (f32, ScanStatus) {
        let state = self.shared_state.lock().unwrap();
        if let Some(ref result) = state.result {
            let progress = if state.total_ports > 0 {
                result.ports_scanned as f32 / state.total_ports as f32
            } else {
                0.0
            };
            (progress, result.status)
        } else {
            (0.0, ScanStatus::Idle)
        }
    }

    /// Export results
    fn export_results(&mut self, result: &ScanResult) -> String {
        if self.export_format == "JSON" {
            serde_json::to_string_pretty(&result.ports).unwrap_or_default()
        } else {
            // CSV
            let mut output = String::from("Port,State,Service,Response Time (ms)\n");
            for port in &result.ports {
                output.push_str(&format!(
                    "{},{},{},{}\n",
                    port.port,
                    port.state.as_str(),
                    port.service.as_deref().unwrap_or("-"),
                    port.response_time_ms.map(|t| t.to_string()).unwrap_or_else(|| "-".to_string())
                ));
            }
            output
        }
    }

    /// Render target input
    fn render_target_input(&mut self, ui: &mut egui::Ui) {
        ui.heading("Target");
        ui.add_space(5.0);

        ui.horizontal(|ui| {
            ui.label("Host:");
            let response = ui.add(
                egui::TextEdit::singleline(&mut self.target)
                    .hint_text("IP address or hostname")
                    .desired_width(200.0)
            );

            // Validation indicator
            if !self.target.is_empty() {
                if self.validate_target() {
                    ui.label(egui::RichText::new("[OK]").color(egui::Color32::GREEN));
                } else {
                    ui.label(egui::RichText::new("[Invalid]").color(egui::Color32::RED));
                }
            }
        });
    }

    /// Render port selection
    fn render_port_selection(&mut self, ui: &mut egui::Ui) {
        ui.heading("Ports");
        ui.add_space(5.0);

        // Preset selector
        egui::ComboBox::from_label("Preset")
            .selected_text(self.port_preset.as_str())
            .show_ui(ui, |ui| {
                for preset in PortPreset::all() {
                    ui.selectable_value(&mut self.port_preset, preset, preset.as_str());
                }
            });

        // Custom ports input
        if self.port_preset == PortPreset::Custom {
            ui.add_space(5.0);
            ui.add(
                egui::TextEdit::singleline(&mut self.custom_ports)
                    .hint_text("22,80,443 or 1-1000")
                    .desired_width(f32::INFINITY)
            );
        }

        // Show port count
        if let Ok(ports) = self.parse_ports() {
            ui.label(format!("{} ports selected", ports.len()));
        }
    }

    /// Render scan settings
    fn render_settings(&mut self, ui: &mut egui::Ui) {
        ui.heading("Settings");
        ui.add_space(5.0);

        egui::Grid::new("settings_grid")
            .num_columns(2)
            .spacing([10.0, 5.0])
            .show(ui, |ui| {
                ui.label("Timeout:");
                ui.add(egui::Slider::new(&mut self.timeout_ms, 100..=10000).suffix(" ms"));
                ui.end_row();

                ui.label("Threads:");
                ui.add(egui::Slider::new(&mut self.threads, 1..=500));
                ui.end_row();
            });
    }

    /// Render scan controls
    fn render_controls(&mut self, ui: &mut egui::Ui) {
        let (progress, status) = self.get_progress();
        let is_running = status == ScanStatus::Running;
        let is_paused = {
            self.shared_state.lock().unwrap().is_paused
        };

        ui.horizontal(|ui| {
            if ui.add_enabled(!is_running, egui::Button::new("Start Scan")).clicked() {
                self.start_scan();
            }

            if ui.add_enabled(is_running, egui::Button::new(if is_paused { "Resume" } else { "Pause" })).clicked() {
                self.toggle_pause();
            }

            if ui.add_enabled(is_running, egui::Button::new("Cancel")).clicked() {
                self.cancel_scan();
            }
        });

        // Progress bar
        if is_running {
            ui.add_space(10.0);
            ui.add(
                egui::ProgressBar::new(progress)
                    .text(format!("{:.1}%", progress * 100.0))
                    .animate(true)
            );

            // Current port
            let current_port = {
                self.shared_state.lock().unwrap().current_port
            };
            ui.label(format!("Scanning port {}...", current_port));
        }
    }

    /// Render current results
    fn render_results(&mut self, ui: &mut egui::Ui) {
        let state = self.shared_state.lock().unwrap();

        if let Some(ref result) = state.result {
            // Header
            ui.horizontal(|ui| {
                ui.heading(format!("Results: {}", result.target));

                // Status badge
                egui::Frame::none()
                    .fill(result.status.color().gamma_multiply(0.3))
                    .inner_margin(egui::vec2(8.0, 2.0))
                    .rounding(4.0)
                    .show(ui, |ui| {
                        ui.label(egui::RichText::new(result.status.as_str()).color(result.status.color()));
                    });
            });

            // Summary
            let open_count = result.open_ports().len();
            ui.label(format!(
                "{} ports scanned, {} open",
                result.ports_scanned, open_count
            ));

            if let Some(duration) = result.duration() {
                ui.label(format!("Duration: {:.2}s", duration.num_milliseconds() as f64 / 1000.0));
            }

            ui.add_space(10.0);

            // Filter controls
            ui.horizontal(|ui| {
                ui.checkbox(&mut self.show_only_open, "Show only open");
                ui.checkbox(&mut self.show_closed, "Show closed");
            });

            ui.add_space(10.0);

            // Results table
            egui::ScrollArea::vertical().max_height(400.0).show(ui, |ui| {
                egui::Grid::new("results_grid")
                    .num_columns(4)
                    .striped(true)
                    .spacing([20.0, 5.0])
                    .show(ui, |ui| {
                        ui.strong("Port");
                        ui.strong("State");
                        ui.strong("Service");
                        ui.strong("Response Time");
                        ui.end_row();

                        for port in &result.ports {
                            // Apply filters
                            if self.show_only_open && port.state != PortState::Open {
                                continue;
                            }
                            if !self.show_closed && port.state == PortState::Closed {
                                continue;
                            }

                            ui.label(format!("{}", port.port));
                            ui.label(egui::RichText::new(port.state.as_str()).color(port.state.color()));
                            ui.label(port.service.as_deref().unwrap_or("-"));
                            ui.label(port.response_time_ms.map(|t| format!("{}ms", t)).unwrap_or_else(|| "-".to_string()));
                            ui.end_row();
                        }
                    });
            });

            // Export buttons
            ui.add_space(10.0);
            ui.horizontal(|ui| {
                egui::ComboBox::from_id_salt("export_format")
                    .selected_text(&self.export_format)
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.export_format, "JSON".to_string(), "JSON");
                        ui.selectable_value(&mut self.export_format, "CSV".to_string(), "CSV");
                    });

                if ui.button("Copy to Clipboard").clicked() {
                    let export = self.export_results(result);
                    if let Some(ref mut clipboard) = self.clipboard {
                        let _ = clipboard.set_text(export);
                        self.status_message = Some("Copied to clipboard".to_string());
                    }
                }

                if ui.button("Save to History").clicked() {
                    self.scan_history.push(result.clone());
                    self.status_message = Some("Saved to history".to_string());
                }
            });
        } else {
            ui.label("No scan results yet. Enter a target and click 'Start Scan'.");
        }
    }

    /// Render scan history
    fn render_history(&mut self, ui: &mut egui::Ui) {
        ui.heading("Scan History");
        ui.add_space(10.0);

        if self.scan_history.is_empty() {
            ui.label("No scans in history");
        } else {
            egui::ScrollArea::vertical().show(ui, |ui| {
                for (i, scan) in self.scan_history.iter().enumerate() {
                    let frame = egui::Frame::none()
                        .fill(egui::Color32::from_rgb(35, 35, 45))
                        .inner_margin(10.0)
                        .rounding(5.0);

                    frame.show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.label(egui::RichText::new(&scan.target).strong());

                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                ui.label(egui::RichText::new(scan.status.as_str()).color(scan.status.color()));
                            });
                        });

                        ui.label(format!(
                            "{} open / {} scanned",
                            scan.open_ports().len(),
                            scan.ports_scanned
                        ));

                        ui.label(
                            egui::RichText::new(scan.started_at.format("%Y-%m-%d %H:%M:%S").to_string())
                                .small()
                                .color(egui::Color32::GRAY)
                        );

                        if ui.small_button("View").clicked() {
                            self.selected_history = Some(i);
                        }
                    });

                    ui.add_space(5.0);
                }
            });

            if ui.button("Clear History").clicked() {
                self.scan_history.clear();
                self.selected_history = None;
            }
        }
    }
}

impl eframe::App for PortScannerApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Request repaint while scanning
        let (_, status) = self.get_progress();
        if status == ScanStatus::Running {
            ctx.request_repaint();
        }

        // Apply theme
        if self.dark_mode {
            ctx.set_visuals(egui::Visuals::dark());
        } else {
            ctx.set_visuals(egui::Visuals::light());
        }

        // Menu bar
        egui::TopBottomPanel::top("menu").show(ctx, |ui| {
            egui::menu::bar(ui, |ui| {
                ui.menu_button("Scan", |ui| {
                    if ui.button("New Scan").clicked() {
                        self.target.clear();
                        ui.close_menu();
                    }
                    ui.separator();
                    if ui.button("Exit").clicked() {
                        std::process::exit(0);
                    }
                });
                ui.menu_button("View", |ui| {
                    ui.checkbox(&mut self.dark_mode, "Dark Mode");
                    ui.checkbox(&mut self.show_only_open, "Show Only Open Ports");
                });
            });
        });

        // Status bar
        egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
            ui.horizontal(|ui| {
                let (progress, status) = self.get_progress();

                ui.label(egui::RichText::new(status.as_str()).color(status.color()));

                if status == ScanStatus::Running {
                    ui.separator();
                    ui.label(format!("{:.1}%", progress * 100.0));
                }

                if let Some(ref msg) = self.status_message {
                    ui.separator();
                    ui.label(msg);
                }
            });
        });

        // Left panel - scan configuration
        egui::SidePanel::left("config")
            .default_width(280.0)
            .min_width(250.0)
            .show(ctx, |ui| {
                egui::ScrollArea::vertical().show(ui, |ui| {
                    self.render_target_input(ui);
                    ui.add_space(15.0);
                    ui.separator();
                    ui.add_space(10.0);

                    self.render_port_selection(ui);
                    ui.add_space(15.0);
                    ui.separator();
                    ui.add_space(10.0);

                    self.render_settings(ui);
                    ui.add_space(15.0);
                    ui.separator();
                    ui.add_space(10.0);

                    self.render_controls(ui);
                });
            });

        // Right panel - history
        egui::SidePanel::right("history")
            .default_width(250.0)
            .min_width(200.0)
            .show(ctx, |ui| {
                self.render_history(ui);
            });

        // Main content - results
        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                self.render_results(ui);
            });
        });
    }
}

fn main() -> eframe::Result<()> {
    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1200.0, 800.0])
            .with_min_inner_size([900.0, 600.0])
            .with_title("G07 - Port Scanner GUI | Rust Security Bible"),
        ..Default::default()
    };

    eframe::run_native(
        "Port Scanner",
        native_options,
        Box::new(|cc| Ok(Box::new(PortScannerApp::new(cc)))),
    )
}
