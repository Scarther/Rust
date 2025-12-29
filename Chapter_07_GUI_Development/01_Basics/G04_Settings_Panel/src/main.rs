//! G04_Settings_Panel - Preferences and Settings UI
//! ===================================================
//!
//! This project demonstrates building a comprehensive settings/preferences
//! panel for security applications using egui.
//!
//! Key Concepts Covered:
//! - Settings categories with tabs/tree
//! - Various input controls for different setting types
//! - Settings persistence (save/load)
//! - Default values and reset functionality
//! - Validation of setting values
//! - Import/export settings
//! - Keyboard shortcuts configuration

use eframe::egui;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

/// Theme options
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
enum Theme {
    Dark,
    Light,
    System,
}

impl Theme {
    fn as_str(&self) -> &'static str {
        match self {
            Theme::Dark => "Dark",
            Theme::Light => "Light",
            Theme::System => "System Default",
        }
    }
}

/// Log level options
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl LogLevel {
    fn all() -> Vec<LogLevel> {
        vec![
            LogLevel::Error,
            LogLevel::Warn,
            LogLevel::Info,
            LogLevel::Debug,
            LogLevel::Trace,
        ]
    }

    fn as_str(&self) -> &'static str {
        match self {
            LogLevel::Error => "Error",
            LogLevel::Warn => "Warning",
            LogLevel::Info => "Info",
            LogLevel::Debug => "Debug",
            LogLevel::Trace => "Trace",
        }
    }
}

/// Proxy type options
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
enum ProxyType {
    None,
    HTTP,
    SOCKS4,
    SOCKS5,
}

impl ProxyType {
    fn all() -> Vec<ProxyType> {
        vec![
            ProxyType::None,
            ProxyType::HTTP,
            ProxyType::SOCKS4,
            ProxyType::SOCKS5,
        ]
    }

    fn as_str(&self) -> &'static str {
        match self {
            ProxyType::None => "No Proxy",
            ProxyType::HTTP => "HTTP",
            ProxyType::SOCKS4 => "SOCKS4",
            ProxyType::SOCKS5 => "SOCKS5",
        }
    }
}

/// General settings
#[derive(Debug, Clone, Serialize, Deserialize)]
struct GeneralSettings {
    theme: Theme,
    language: String,
    font_size: f32,
    show_welcome: bool,
    check_updates: bool,
    auto_save: bool,
    auto_save_interval: u32,
    confirm_exit: bool,
    minimize_to_tray: bool,
    start_minimized: bool,
}

impl Default for GeneralSettings {
    fn default() -> Self {
        Self {
            theme: Theme::Dark,
            language: "English".to_string(),
            font_size: 14.0,
            show_welcome: true,
            check_updates: true,
            auto_save: true,
            auto_save_interval: 5,
            confirm_exit: true,
            minimize_to_tray: false,
            start_minimized: false,
        }
    }
}

/// Security settings
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SecuritySettings {
    enable_encryption: bool,
    encryption_algorithm: String,
    key_length: u32,
    require_password: bool,
    password_timeout: u32,
    secure_delete: bool,
    overwrite_passes: u32,
    enable_audit_log: bool,
    log_level: LogLevel,
    max_log_size_mb: u32,
    log_retention_days: u32,
}

impl Default for SecuritySettings {
    fn default() -> Self {
        Self {
            enable_encryption: true,
            encryption_algorithm: "AES-256-GCM".to_string(),
            key_length: 256,
            require_password: true,
            password_timeout: 15,
            secure_delete: true,
            overwrite_passes: 3,
            enable_audit_log: true,
            log_level: LogLevel::Info,
            max_log_size_mb: 100,
            log_retention_days: 30,
        }
    }
}

/// Network settings
#[derive(Debug, Clone, Serialize, Deserialize)]
struct NetworkSettings {
    proxy_type: ProxyType,
    proxy_host: String,
    proxy_port: u16,
    proxy_username: String,
    proxy_password: String,
    connection_timeout: u32,
    read_timeout: u32,
    max_retries: u32,
    user_agent: String,
    verify_ssl: bool,
    allow_insecure: bool,
    max_concurrent: u32,
    rate_limit: u32,
}

impl Default for NetworkSettings {
    fn default() -> Self {
        Self {
            proxy_type: ProxyType::None,
            proxy_host: String::new(),
            proxy_port: 8080,
            proxy_username: String::new(),
            proxy_password: String::new(),
            connection_timeout: 30,
            read_timeout: 60,
            max_retries: 3,
            user_agent: "SecurityTool/1.0".to_string(),
            verify_ssl: true,
            allow_insecure: false,
            max_concurrent: 10,
            rate_limit: 100,
        }
    }
}

/// Scanner settings
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ScannerSettings {
    default_port_range: String,
    scan_timeout_ms: u32,
    threads: u32,
    enable_service_detection: bool,
    enable_os_detection: bool,
    enable_vuln_scan: bool,
    follow_redirects: bool,
    max_depth: u32,
    excluded_ports: String,
    custom_scripts_path: String,
    save_raw_responses: bool,
}

impl Default for ScannerSettings {
    fn default() -> Self {
        Self {
            default_port_range: "1-1024".to_string(),
            scan_timeout_ms: 1000,
            threads: 100,
            enable_service_detection: true,
            enable_os_detection: false,
            enable_vuln_scan: false,
            follow_redirects: true,
            max_depth: 3,
            excluded_ports: "".to_string(),
            custom_scripts_path: String::new(),
            save_raw_responses: false,
        }
    }
}

/// Notification settings
#[derive(Debug, Clone, Serialize, Deserialize)]
struct NotificationSettings {
    enable_notifications: bool,
    sound_enabled: bool,
    sound_volume: f32,
    notify_on_complete: bool,
    notify_on_error: bool,
    notify_on_warning: bool,
    email_notifications: bool,
    email_address: String,
    smtp_server: String,
    smtp_port: u16,
    slack_webhook: String,
}

impl Default for NotificationSettings {
    fn default() -> Self {
        Self {
            enable_notifications: true,
            sound_enabled: true,
            sound_volume: 0.7,
            notify_on_complete: true,
            notify_on_error: true,
            notify_on_warning: false,
            email_notifications: false,
            email_address: String::new(),
            smtp_server: String::new(),
            smtp_port: 587,
            slack_webhook: String::new(),
        }
    }
}

/// Keyboard shortcut
#[derive(Debug, Clone, Serialize, Deserialize)]
struct KeyboardShortcut {
    action: String,
    keys: String,
    enabled: bool,
}

/// All application settings
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AppSettings {
    general: GeneralSettings,
    security: SecuritySettings,
    network: NetworkSettings,
    scanner: ScannerSettings,
    notifications: NotificationSettings,
    keyboard_shortcuts: Vec<KeyboardShortcut>,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            general: GeneralSettings::default(),
            security: SecuritySettings::default(),
            network: NetworkSettings::default(),
            scanner: ScannerSettings::default(),
            notifications: NotificationSettings::default(),
            keyboard_shortcuts: vec![
                KeyboardShortcut {
                    action: "New Scan".to_string(),
                    keys: "Ctrl+N".to_string(),
                    enabled: true,
                },
                KeyboardShortcut {
                    action: "Open File".to_string(),
                    keys: "Ctrl+O".to_string(),
                    enabled: true,
                },
                KeyboardShortcut {
                    action: "Save".to_string(),
                    keys: "Ctrl+S".to_string(),
                    enabled: true,
                },
                KeyboardShortcut {
                    action: "Settings".to_string(),
                    keys: "Ctrl+,".to_string(),
                    enabled: true,
                },
                KeyboardShortcut {
                    action: "Quick Search".to_string(),
                    keys: "Ctrl+K".to_string(),
                    enabled: true,
                },
                KeyboardShortcut {
                    action: "Toggle Dark Mode".to_string(),
                    keys: "Ctrl+D".to_string(),
                    enabled: true,
                },
                KeyboardShortcut {
                    action: "Exit".to_string(),
                    keys: "Ctrl+Q".to_string(),
                    enabled: true,
                },
            ],
        }
    }
}

impl AppSettings {
    /// Get settings file path
    fn settings_path() -> PathBuf {
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("rust_security_bible")
            .join("settings.toml")
    }

    /// Load settings from file
    fn load() -> Self {
        let path = Self::settings_path();
        if path.exists() {
            match fs::read_to_string(&path) {
                Ok(content) => match toml::from_str(&content) {
                    Ok(settings) => return settings,
                    Err(e) => eprintln!("Error parsing settings: {}", e),
                },
                Err(e) => eprintln!("Error reading settings file: {}", e),
            }
        }
        Self::default()
    }

    /// Save settings to file
    fn save(&self) -> Result<(), String> {
        let path = Self::settings_path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let content = toml::to_string_pretty(self).map_err(|e| e.to_string())?;
        fs::write(&path, content).map_err(|e| e.to_string())
    }

    /// Export settings to JSON
    fn export_json(&self) -> Result<String, String> {
        serde_json::to_string_pretty(self).map_err(|e| e.to_string())
    }

    /// Import settings from JSON
    fn import_json(json: &str) -> Result<Self, String> {
        serde_json::from_str(json).map_err(|e| e.to_string())
    }
}

/// Settings category for navigation
#[derive(Debug, Clone, Copy, PartialEq)]
enum SettingsCategory {
    General,
    Security,
    Network,
    Scanner,
    Notifications,
    Keyboard,
    About,
}

impl SettingsCategory {
    fn all() -> Vec<SettingsCategory> {
        vec![
            SettingsCategory::General,
            SettingsCategory::Security,
            SettingsCategory::Network,
            SettingsCategory::Scanner,
            SettingsCategory::Notifications,
            SettingsCategory::Keyboard,
            SettingsCategory::About,
        ]
    }

    fn as_str(&self) -> &'static str {
        match self {
            SettingsCategory::General => "General",
            SettingsCategory::Security => "Security",
            SettingsCategory::Network => "Network",
            SettingsCategory::Scanner => "Scanner",
            SettingsCategory::Notifications => "Notifications",
            SettingsCategory::Keyboard => "Keyboard Shortcuts",
            SettingsCategory::About => "About",
        }
    }

    fn icon(&self) -> &'static str {
        match self {
            SettingsCategory::General => "[G]",
            SettingsCategory::Security => "[S]",
            SettingsCategory::Network => "[N]",
            SettingsCategory::Scanner => "[Sc]",
            SettingsCategory::Notifications => "[!]",
            SettingsCategory::Keyboard => "[K]",
            SettingsCategory::About => "[i]",
        }
    }
}

/// Main application state
struct SettingsPanelApp {
    // Current settings
    settings: AppSettings,

    // Original settings (for detecting changes)
    original_settings: AppSettings,

    // Active category
    active_category: SettingsCategory,

    // UI state
    search_query: String,
    show_password: bool,
    unsaved_changes: bool,

    // Status messages
    status_message: Option<(String, bool)>,  // (message, is_error)

    // Languages available
    languages: Vec<String>,

    // Encryption algorithms
    encryption_algorithms: Vec<String>,

    // Import/Export
    import_text: String,
    show_import_dialog: bool,
    show_export_dialog: bool,
    export_text: String,
}

impl Default for SettingsPanelApp {
    fn default() -> Self {
        let settings = AppSettings::load();
        Self {
            original_settings: settings.clone(),
            settings,
            active_category: SettingsCategory::General,
            search_query: String::new(),
            show_password: false,
            unsaved_changes: false,
            status_message: None,
            languages: vec![
                "English".to_string(),
                "Spanish".to_string(),
                "French".to_string(),
                "German".to_string(),
                "Chinese".to_string(),
                "Japanese".to_string(),
            ],
            encryption_algorithms: vec![
                "AES-128-GCM".to_string(),
                "AES-256-GCM".to_string(),
                "ChaCha20-Poly1305".to_string(),
                "AES-256-CBC".to_string(),
            ],
            import_text: String::new(),
            show_import_dialog: false,
            show_export_dialog: false,
            export_text: String::new(),
        }
    }
}

impl SettingsPanelApp {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let app = Self::default();

        // Apply theme
        match app.settings.general.theme {
            Theme::Dark => cc.egui_ctx.set_visuals(egui::Visuals::dark()),
            Theme::Light => cc.egui_ctx.set_visuals(egui::Visuals::light()),
            Theme::System => cc.egui_ctx.set_visuals(egui::Visuals::dark()),
        }

        app
    }

    /// Check if settings have changed
    fn check_changes(&mut self) {
        // Simple comparison using serialization
        let current = serde_json::to_string(&self.settings).unwrap_or_default();
        let original = serde_json::to_string(&self.original_settings).unwrap_or_default();
        self.unsaved_changes = current != original;
    }

    /// Save settings
    fn save_settings(&mut self) {
        match self.settings.save() {
            Ok(_) => {
                self.original_settings = self.settings.clone();
                self.unsaved_changes = false;
                self.status_message = Some(("Settings saved successfully!".to_string(), false));
            }
            Err(e) => {
                self.status_message = Some((format!("Error saving settings: {}", e), true));
            }
        }
    }

    /// Reset to defaults
    fn reset_to_defaults(&mut self) {
        self.settings = AppSettings::default();
        self.check_changes();
        self.status_message = Some(("Settings reset to defaults".to_string(), false));
    }

    /// Render category navigation
    fn render_nav(&mut self, ctx: &egui::Context) {
        egui::SidePanel::left("nav_panel")
            .default_width(200.0)
            .min_width(150.0)
            .show(ctx, |ui| {
                ui.add_space(10.0);

                // Search
                ui.add(
                    egui::TextEdit::singleline(&mut self.search_query)
                        .hint_text("Search settings...")
                        .desired_width(f32::INFINITY),
                );

                ui.add_space(10.0);
                ui.separator();
                ui.add_space(10.0);

                // Categories
                for category in SettingsCategory::all() {
                    let selected = self.active_category == category;
                    let text = format!("{} {}", category.icon(), category.as_str());

                    if ui.selectable_label(selected, text).clicked() {
                        self.active_category = category;
                    }
                }

                ui.add_space(20.0);
                ui.separator();

                // Quick actions
                ui.add_space(10.0);
                if ui.button("Reset All to Defaults").clicked() {
                    self.reset_to_defaults();
                }

                if ui.button("Export Settings...").clicked() {
                    match self.settings.export_json() {
                        Ok(json) => {
                            self.export_text = json;
                            self.show_export_dialog = true;
                        }
                        Err(e) => {
                            self.status_message = Some((format!("Export error: {}", e), true));
                        }
                    }
                }

                if ui.button("Import Settings...").clicked() {
                    self.import_text.clear();
                    self.show_import_dialog = true;
                }
            });
    }

    /// Render general settings
    fn render_general_settings(&mut self, ui: &mut egui::Ui) {
        ui.heading("General Settings");
        ui.add_space(10.0);

        egui::Grid::new("general_grid")
            .num_columns(2)
            .spacing([20.0, 10.0])
            .show(ui, |ui| {
                // Theme
                ui.label("Theme:");
                egui::ComboBox::from_id_salt("theme_combo")
                    .selected_text(self.settings.general.theme.as_str())
                    .show_ui(ui, |ui| {
                        for theme in [Theme::Dark, Theme::Light, Theme::System] {
                            if ui
                                .selectable_label(
                                    self.settings.general.theme == theme,
                                    theme.as_str(),
                                )
                                .clicked()
                            {
                                self.settings.general.theme = theme;
                            }
                        }
                    });
                ui.end_row();

                // Language
                ui.label("Language:");
                egui::ComboBox::from_id_salt("lang_combo")
                    .selected_text(&self.settings.general.language)
                    .show_ui(ui, |ui| {
                        for lang in &self.languages {
                            if ui
                                .selectable_label(&self.settings.general.language == lang, lang)
                                .clicked()
                            {
                                self.settings.general.language = lang.clone();
                            }
                        }
                    });
                ui.end_row();

                // Font size
                ui.label("Font Size:");
                ui.add(
                    egui::Slider::new(&mut self.settings.general.font_size, 10.0..=24.0)
                        .suffix(" pt"),
                );
                ui.end_row();

                // Checkboxes
                ui.label("");
                ui.checkbox(
                    &mut self.settings.general.show_welcome,
                    "Show welcome screen on startup",
                );
                ui.end_row();

                ui.label("");
                ui.checkbox(
                    &mut self.settings.general.check_updates,
                    "Check for updates automatically",
                );
                ui.end_row();

                ui.label("");
                ui.checkbox(&mut self.settings.general.confirm_exit, "Confirm before exit");
                ui.end_row();

                ui.label("");
                ui.checkbox(
                    &mut self.settings.general.minimize_to_tray,
                    "Minimize to system tray",
                );
                ui.end_row();

                ui.label("");
                ui.checkbox(
                    &mut self.settings.general.start_minimized,
                    "Start minimized",
                );
                ui.end_row();
            });

        ui.add_space(20.0);
        ui.separator();
        ui.heading("Auto-Save");
        ui.add_space(10.0);

        egui::Grid::new("autosave_grid")
            .num_columns(2)
            .spacing([20.0, 10.0])
            .show(ui, |ui| {
                ui.label("");
                ui.checkbox(&mut self.settings.general.auto_save, "Enable auto-save");
                ui.end_row();

                ui.label("Auto-save interval:");
                ui.add_enabled(
                    self.settings.general.auto_save,
                    egui::Slider::new(&mut self.settings.general.auto_save_interval, 1..=30)
                        .suffix(" min"),
                );
                ui.end_row();
            });
    }

    /// Render security settings
    fn render_security_settings(&mut self, ui: &mut egui::Ui) {
        ui.heading("Security Settings");
        ui.add_space(10.0);

        egui::CollapsingHeader::new("Encryption")
            .default_open(true)
            .show(ui, |ui| {
                egui::Grid::new("encryption_grid")
                    .num_columns(2)
                    .spacing([20.0, 10.0])
                    .show(ui, |ui| {
                        ui.label("");
                        ui.checkbox(
                            &mut self.settings.security.enable_encryption,
                            "Enable encryption for sensitive data",
                        );
                        ui.end_row();

                        ui.label("Algorithm:");
                        egui::ComboBox::from_id_salt("enc_algo")
                            .selected_text(&self.settings.security.encryption_algorithm)
                            .show_ui(ui, |ui| {
                                for algo in &self.encryption_algorithms {
                                    if ui
                                        .selectable_label(
                                            &self.settings.security.encryption_algorithm == algo,
                                            algo,
                                        )
                                        .clicked()
                                    {
                                        self.settings.security.encryption_algorithm = algo.clone();
                                    }
                                }
                            });
                        ui.end_row();

                        ui.label("Key Length:");
                        egui::ComboBox::from_id_salt("key_len")
                            .selected_text(format!("{} bits", self.settings.security.key_length))
                            .show_ui(ui, |ui| {
                                for len in [128, 192, 256] {
                                    if ui
                                        .selectable_label(
                                            self.settings.security.key_length == len,
                                            format!("{} bits", len),
                                        )
                                        .clicked()
                                    {
                                        self.settings.security.key_length = len;
                                    }
                                }
                            });
                        ui.end_row();
                    });
            });

        ui.add_space(10.0);

        egui::CollapsingHeader::new("Password Protection")
            .default_open(true)
            .show(ui, |ui| {
                egui::Grid::new("password_grid")
                    .num_columns(2)
                    .spacing([20.0, 10.0])
                    .show(ui, |ui| {
                        ui.label("");
                        ui.checkbox(
                            &mut self.settings.security.require_password,
                            "Require password on startup",
                        );
                        ui.end_row();

                        ui.label("Session timeout:");
                        ui.add(
                            egui::Slider::new(&mut self.settings.security.password_timeout, 1..=60)
                                .suffix(" min"),
                        );
                        ui.end_row();
                    });
            });

        ui.add_space(10.0);

        egui::CollapsingHeader::new("Secure Deletion")
            .default_open(true)
            .show(ui, |ui| {
                egui::Grid::new("delete_grid")
                    .num_columns(2)
                    .spacing([20.0, 10.0])
                    .show(ui, |ui| {
                        ui.label("");
                        ui.checkbox(
                            &mut self.settings.security.secure_delete,
                            "Securely delete files",
                        );
                        ui.end_row();

                        ui.label("Overwrite passes:");
                        ui.add(
                            egui::Slider::new(&mut self.settings.security.overwrite_passes, 1..=35),
                        );
                        ui.end_row();
                    });
            });

        ui.add_space(10.0);

        egui::CollapsingHeader::new("Audit Logging")
            .default_open(true)
            .show(ui, |ui| {
                egui::Grid::new("audit_grid")
                    .num_columns(2)
                    .spacing([20.0, 10.0])
                    .show(ui, |ui| {
                        ui.label("");
                        ui.checkbox(
                            &mut self.settings.security.enable_audit_log,
                            "Enable audit logging",
                        );
                        ui.end_row();

                        ui.label("Log level:");
                        egui::ComboBox::from_id_salt("log_level")
                            .selected_text(self.settings.security.log_level.as_str())
                            .show_ui(ui, |ui| {
                                for level in LogLevel::all() {
                                    if ui
                                        .selectable_label(
                                            self.settings.security.log_level == level,
                                            level.as_str(),
                                        )
                                        .clicked()
                                    {
                                        self.settings.security.log_level = level;
                                    }
                                }
                            });
                        ui.end_row();

                        ui.label("Max log size:");
                        ui.add(
                            egui::Slider::new(&mut self.settings.security.max_log_size_mb, 10..=1000)
                                .suffix(" MB"),
                        );
                        ui.end_row();

                        ui.label("Retention period:");
                        ui.add(
                            egui::Slider::new(&mut self.settings.security.log_retention_days, 7..=365)
                                .suffix(" days"),
                        );
                        ui.end_row();
                    });
            });
    }

    /// Render network settings
    fn render_network_settings(&mut self, ui: &mut egui::Ui) {
        ui.heading("Network Settings");
        ui.add_space(10.0);

        egui::CollapsingHeader::new("Proxy Configuration")
            .default_open(true)
            .show(ui, |ui| {
                egui::Grid::new("proxy_grid")
                    .num_columns(2)
                    .spacing([20.0, 10.0])
                    .show(ui, |ui| {
                        ui.label("Proxy Type:");
                        egui::ComboBox::from_id_salt("proxy_type")
                            .selected_text(self.settings.network.proxy_type.as_str())
                            .show_ui(ui, |ui| {
                                for proxy in ProxyType::all() {
                                    if ui
                                        .selectable_label(
                                            self.settings.network.proxy_type == proxy,
                                            proxy.as_str(),
                                        )
                                        .clicked()
                                    {
                                        self.settings.network.proxy_type = proxy;
                                    }
                                }
                            });
                        ui.end_row();

                        let proxy_enabled = self.settings.network.proxy_type != ProxyType::None;

                        ui.label("Host:");
                        ui.add_enabled(
                            proxy_enabled,
                            egui::TextEdit::singleline(&mut self.settings.network.proxy_host)
                                .hint_text("proxy.example.com"),
                        );
                        ui.end_row();

                        ui.label("Port:");
                        ui.add_enabled(
                            proxy_enabled,
                            egui::DragValue::new(&mut self.settings.network.proxy_port)
                                .range(1..=65535),
                        );
                        ui.end_row();

                        ui.label("Username:");
                        ui.add_enabled(
                            proxy_enabled,
                            egui::TextEdit::singleline(&mut self.settings.network.proxy_username),
                        );
                        ui.end_row();

                        ui.label("Password:");
                        ui.horizontal(|ui| {
                            let password_field = if self.show_password {
                                egui::TextEdit::singleline(&mut self.settings.network.proxy_password)
                            } else {
                                egui::TextEdit::singleline(&mut self.settings.network.proxy_password)
                                    .password(true)
                            };
                            ui.add_enabled(proxy_enabled, password_field);
                            if ui.button(if self.show_password { "Hide" } else { "Show" }).clicked()
                            {
                                self.show_password = !self.show_password;
                            }
                        });
                        ui.end_row();
                    });
            });

        ui.add_space(10.0);

        egui::CollapsingHeader::new("Connection")
            .default_open(true)
            .show(ui, |ui| {
                egui::Grid::new("connection_grid")
                    .num_columns(2)
                    .spacing([20.0, 10.0])
                    .show(ui, |ui| {
                        ui.label("Connection timeout:");
                        ui.add(
                            egui::Slider::new(&mut self.settings.network.connection_timeout, 5..=120)
                                .suffix(" sec"),
                        );
                        ui.end_row();

                        ui.label("Read timeout:");
                        ui.add(
                            egui::Slider::new(&mut self.settings.network.read_timeout, 10..=300)
                                .suffix(" sec"),
                        );
                        ui.end_row();

                        ui.label("Max retries:");
                        ui.add(egui::Slider::new(&mut self.settings.network.max_retries, 0..=10));
                        ui.end_row();

                        ui.label("Max concurrent:");
                        ui.add(egui::Slider::new(
                            &mut self.settings.network.max_concurrent,
                            1..=100,
                        ));
                        ui.end_row();

                        ui.label("Rate limit:");
                        ui.add(
                            egui::Slider::new(&mut self.settings.network.rate_limit, 0..=1000)
                                .suffix(" req/s"),
                        );
                        ui.end_row();
                    });
            });

        ui.add_space(10.0);

        egui::CollapsingHeader::new("SSL/TLS")
            .default_open(true)
            .show(ui, |ui| {
                ui.checkbox(
                    &mut self.settings.network.verify_ssl,
                    "Verify SSL certificates",
                );
                ui.checkbox(
                    &mut self.settings.network.allow_insecure,
                    "Allow insecure connections (not recommended)",
                );
            });

        ui.add_space(10.0);

        egui::CollapsingHeader::new("User Agent")
            .default_open(false)
            .show(ui, |ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut self.settings.network.user_agent)
                        .desired_width(400.0),
                );
            });
    }

    /// Render scanner settings
    fn render_scanner_settings(&mut self, ui: &mut egui::Ui) {
        ui.heading("Scanner Settings");
        ui.add_space(10.0);

        egui::Grid::new("scanner_grid")
            .num_columns(2)
            .spacing([20.0, 10.0])
            .show(ui, |ui| {
                ui.label("Default port range:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.settings.scanner.default_port_range)
                        .hint_text("1-1024"),
                );
                ui.end_row();

                ui.label("Excluded ports:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.settings.scanner.excluded_ports)
                        .hint_text("22,23,25"),
                );
                ui.end_row();

                ui.label("Scan timeout:");
                ui.add(
                    egui::Slider::new(&mut self.settings.scanner.scan_timeout_ms, 100..=10000)
                        .suffix(" ms"),
                );
                ui.end_row();

                ui.label("Threads:");
                ui.add(egui::Slider::new(&mut self.settings.scanner.threads, 1..=500));
                ui.end_row();

                ui.label("Max depth:");
                ui.add(egui::Slider::new(&mut self.settings.scanner.max_depth, 1..=10));
                ui.end_row();
            });

        ui.add_space(10.0);
        ui.separator();
        ui.add_space(10.0);

        ui.checkbox(
            &mut self.settings.scanner.enable_service_detection,
            "Enable service detection",
        );
        ui.checkbox(
            &mut self.settings.scanner.enable_os_detection,
            "Enable OS detection",
        );
        ui.checkbox(
            &mut self.settings.scanner.enable_vuln_scan,
            "Enable vulnerability scanning",
        );
        ui.checkbox(
            &mut self.settings.scanner.follow_redirects,
            "Follow redirects",
        );
        ui.checkbox(
            &mut self.settings.scanner.save_raw_responses,
            "Save raw responses",
        );

        ui.add_space(10.0);
        ui.label("Custom scripts path:");
        ui.add(
            egui::TextEdit::singleline(&mut self.settings.scanner.custom_scripts_path)
                .hint_text("/path/to/scripts")
                .desired_width(400.0),
        );
    }

    /// Render notification settings
    fn render_notification_settings(&mut self, ui: &mut egui::Ui) {
        ui.heading("Notification Settings");
        ui.add_space(10.0);

        ui.checkbox(
            &mut self.settings.notifications.enable_notifications,
            "Enable notifications",
        );

        ui.add_space(10.0);

        egui::CollapsingHeader::new("Sound")
            .default_open(true)
            .show(ui, |ui| {
                ui.checkbox(
                    &mut self.settings.notifications.sound_enabled,
                    "Enable sound notifications",
                );
                ui.horizontal(|ui| {
                    ui.label("Volume:");
                    ui.add(
                        egui::Slider::new(&mut self.settings.notifications.sound_volume, 0.0..=1.0)
                            .show_value(true),
                    );
                });
            });

        ui.add_space(10.0);

        egui::CollapsingHeader::new("Events")
            .default_open(true)
            .show(ui, |ui| {
                ui.checkbox(
                    &mut self.settings.notifications.notify_on_complete,
                    "Notify on scan complete",
                );
                ui.checkbox(
                    &mut self.settings.notifications.notify_on_error,
                    "Notify on errors",
                );
                ui.checkbox(
                    &mut self.settings.notifications.notify_on_warning,
                    "Notify on warnings",
                );
            });

        ui.add_space(10.0);

        egui::CollapsingHeader::new("Email Notifications")
            .default_open(false)
            .show(ui, |ui| {
                ui.checkbox(
                    &mut self.settings.notifications.email_notifications,
                    "Enable email notifications",
                );

                egui::Grid::new("email_grid")
                    .num_columns(2)
                    .spacing([20.0, 10.0])
                    .show(ui, |ui| {
                        ui.label("Email address:");
                        ui.add(
                            egui::TextEdit::singleline(
                                &mut self.settings.notifications.email_address,
                            )
                            .hint_text("user@example.com"),
                        );
                        ui.end_row();

                        ui.label("SMTP Server:");
                        ui.add(
                            egui::TextEdit::singleline(&mut self.settings.notifications.smtp_server)
                                .hint_text("smtp.example.com"),
                        );
                        ui.end_row();

                        ui.label("SMTP Port:");
                        ui.add(
                            egui::DragValue::new(&mut self.settings.notifications.smtp_port)
                                .range(1..=65535),
                        );
                        ui.end_row();
                    });
            });

        ui.add_space(10.0);

        egui::CollapsingHeader::new("Slack Integration")
            .default_open(false)
            .show(ui, |ui| {
                ui.label("Webhook URL:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.settings.notifications.slack_webhook)
                        .hint_text("https://hooks.slack.com/services/...")
                        .desired_width(400.0),
                );
            });
    }

    /// Render keyboard shortcuts
    fn render_keyboard_settings(&mut self, ui: &mut egui::Ui) {
        ui.heading("Keyboard Shortcuts");
        ui.add_space(10.0);

        egui::Grid::new("shortcuts_grid")
            .num_columns(3)
            .striped(true)
            .spacing([20.0, 8.0])
            .show(ui, |ui| {
                ui.strong("Action");
                ui.strong("Shortcut");
                ui.strong("Enabled");
                ui.end_row();

                for shortcut in &mut self.settings.keyboard_shortcuts {
                    ui.label(&shortcut.action);
                    ui.add(egui::TextEdit::singleline(&mut shortcut.keys).desired_width(120.0));
                    ui.checkbox(&mut shortcut.enabled, "");
                    ui.end_row();
                }
            });

        ui.add_space(20.0);
        if ui.button("Reset Shortcuts to Defaults").clicked() {
            self.settings.keyboard_shortcuts = AppSettings::default().keyboard_shortcuts;
        }
    }

    /// Render about section
    fn render_about(&mut self, ui: &mut egui::Ui) {
        ui.heading("About");
        ui.add_space(20.0);

        ui.vertical_centered(|ui| {
            ui.heading("G04 - Settings Panel");
            ui.add_space(10.0);
            ui.label("Rust Security Bible");
            ui.label("Chapter 07: GUI Development");
            ui.add_space(20.0);

            egui::Frame::none()
                .fill(egui::Color32::from_rgb(40, 40, 50))
                .inner_margin(20.0)
                .rounding(10.0)
                .show(ui, |ui| {
                    ui.label("Version: 1.0.0");
                    ui.label("Build: 2024.01.01");
                    ui.add_space(10.0);
                    ui.label("Built with:");
                    ui.label(format!("- egui {}", egui::__version__()));
                    ui.label("- eframe");
                    ui.label("- serde");
                    ui.label("- toml");
                });

            ui.add_space(20.0);
            ui.hyperlink_to("Documentation", "https://docs.rs/egui");
            ui.hyperlink_to("Source Code", "https://github.com/example/rust-security-bible");
        });
    }

    /// Render import dialog
    fn render_import_dialog(&mut self, ctx: &egui::Context) {
        egui::Window::new("Import Settings")
            .open(&mut self.show_import_dialog)
            .resizable(true)
            .default_size([500.0, 400.0])
            .show(ctx, |ui| {
                ui.label("Paste JSON settings below:");
                ui.add_space(10.0);

                egui::ScrollArea::vertical().max_height(300.0).show(ui, |ui| {
                    ui.add(
                        egui::TextEdit::multiline(&mut self.import_text)
                            .font(egui::TextStyle::Monospace)
                            .desired_width(f32::INFINITY)
                            .desired_rows(15),
                    );
                });

                ui.add_space(10.0);
                ui.horizontal(|ui| {
                    if ui.button("Import").clicked() {
                        match AppSettings::import_json(&self.import_text) {
                            Ok(settings) => {
                                self.settings = settings;
                                self.check_changes();
                                self.status_message =
                                    Some(("Settings imported successfully!".to_string(), false));
                                self.show_import_dialog = false;
                            }
                            Err(e) => {
                                self.status_message =
                                    Some((format!("Import error: {}", e), true));
                            }
                        }
                    }
                    if ui.button("Cancel").clicked() {
                        self.show_import_dialog = false;
                    }
                });
            });
    }

    /// Render export dialog
    fn render_export_dialog(&mut self, ctx: &egui::Context) {
        egui::Window::new("Export Settings")
            .open(&mut self.show_export_dialog)
            .resizable(true)
            .default_size([500.0, 400.0])
            .show(ctx, |ui| {
                ui.label("Copy the JSON settings below:");
                ui.add_space(10.0);

                egui::ScrollArea::vertical().max_height(300.0).show(ui, |ui| {
                    ui.add(
                        egui::TextEdit::multiline(&mut self.export_text.as_str())
                            .font(egui::TextStyle::Monospace)
                            .desired_width(f32::INFINITY)
                            .desired_rows(15),
                    );
                });

                ui.add_space(10.0);
                if ui.button("Close").clicked() {
                    self.show_export_dialog = false;
                }
            });
    }
}

impl eframe::App for SettingsPanelApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Check for changes
        self.check_changes();

        // Apply current theme
        match self.settings.general.theme {
            Theme::Dark => ctx.set_visuals(egui::Visuals::dark()),
            Theme::Light => ctx.set_visuals(egui::Visuals::light()),
            Theme::System => {} // Keep current
        }

        // Menu bar
        egui::TopBottomPanel::top("menu").show(ctx, |ui| {
            egui::menu::bar(ui, |ui| {
                ui.menu_button("File", |ui| {
                    if ui.button("Save Settings").clicked() {
                        self.save_settings();
                        ui.close_menu();
                    }
                    if ui.button("Reload Settings").clicked() {
                        self.settings = AppSettings::load();
                        self.original_settings = self.settings.clone();
                        self.status_message = Some(("Settings reloaded".to_string(), false));
                        ui.close_menu();
                    }
                    ui.separator();
                    if ui.button("Exit").clicked() {
                        std::process::exit(0);
                    }
                });
            });
        });

        // Status bar
        egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
            ui.horizontal(|ui| {
                if self.unsaved_changes {
                    ui.label(egui::RichText::new("Unsaved changes").color(egui::Color32::YELLOW));
                    if ui.button("Save").clicked() {
                        self.save_settings();
                    }
                    if ui.button("Discard").clicked() {
                        self.settings = self.original_settings.clone();
                    }
                } else {
                    ui.label("No unsaved changes");
                }

                if let Some((ref msg, is_error)) = self.status_message {
                    ui.separator();
                    ui.label(egui::RichText::new(msg).color(if *is_error {
                        egui::Color32::RED
                    } else {
                        egui::Color32::GREEN
                    }));
                }
            });
        });

        // Navigation panel
        self.render_nav(ctx);

        // Main content
        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                match self.active_category {
                    SettingsCategory::General => self.render_general_settings(ui),
                    SettingsCategory::Security => self.render_security_settings(ui),
                    SettingsCategory::Network => self.render_network_settings(ui),
                    SettingsCategory::Scanner => self.render_scanner_settings(ui),
                    SettingsCategory::Notifications => self.render_notification_settings(ui),
                    SettingsCategory::Keyboard => self.render_keyboard_settings(ui),
                    SettingsCategory::About => self.render_about(ui),
                }
            });
        });

        // Dialogs
        self.render_import_dialog(ctx);
        self.render_export_dialog(ctx);
    }
}

fn main() -> eframe::Result<()> {
    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1000.0, 700.0])
            .with_min_inner_size([800.0, 600.0])
            .with_title("G04 - Settings Panel | Rust Security Bible"),
        ..Default::default()
    };

    eframe::run_native(
        "Settings Panel",
        native_options,
        Box::new(|cc| Ok(Box::new(SettingsPanelApp::new(cc)))),
    )
}
