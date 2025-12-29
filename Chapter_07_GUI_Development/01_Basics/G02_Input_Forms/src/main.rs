//! G02_Input_Forms - Forms with Text Input and Dropdowns
//! ======================================================
//!
//! This project demonstrates comprehensive form handling in egui,
//! including text inputs, dropdowns, validation, and form submission.
//!
//! Key Concepts Covered:
//! - Text input (single-line and multi-line)
//! - Password fields with visibility toggle
//! - Dropdown/ComboBox selections
//! - Form validation with regex
//! - Error message display
//! - Form state management
//! - Keyboard navigation

use eframe::egui;
use regex::Regex;
use std::collections::HashMap;

/// Validation error types
#[derive(Debug, Clone)]
enum ValidationError {
    Required(String),
    MinLength(String, usize),
    MaxLength(String, usize),
    InvalidFormat(String, String),
    InvalidEmail,
    InvalidIP,
    PasswordMismatch,
    Custom(String),
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidationError::Required(field) => write!(f, "{} is required", field),
            ValidationError::MinLength(field, len) => {
                write!(f, "{} must be at least {} characters", field, len)
            }
            ValidationError::MaxLength(field, len) => {
                write!(f, "{} must be at most {} characters", field, len)
            }
            ValidationError::InvalidFormat(field, format) => {
                write!(f, "{} must be in {} format", field, format)
            }
            ValidationError::InvalidEmail => write!(f, "Invalid email address"),
            ValidationError::InvalidIP => write!(f, "Invalid IP address"),
            ValidationError::PasswordMismatch => write!(f, "Passwords do not match"),
            ValidationError::Custom(msg) => write!(f, "{}", msg),
        }
    }
}

/// Security level options for dropdown
#[derive(Debug, Clone, Copy, PartialEq)]
enum SecurityLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl SecurityLevel {
    fn all() -> Vec<SecurityLevel> {
        vec![
            SecurityLevel::Low,
            SecurityLevel::Medium,
            SecurityLevel::High,
            SecurityLevel::Critical,
        ]
    }

    fn as_str(&self) -> &'static str {
        match self {
            SecurityLevel::Low => "Low",
            SecurityLevel::Medium => "Medium",
            SecurityLevel::High => "High",
            SecurityLevel::Critical => "Critical",
        }
    }

    fn color(&self) -> egui::Color32 {
        match self {
            SecurityLevel::Low => egui::Color32::from_rgb(76, 175, 80),
            SecurityLevel::Medium => egui::Color32::from_rgb(255, 193, 7),
            SecurityLevel::High => egui::Color32::from_rgb(255, 152, 0),
            SecurityLevel::Critical => egui::Color32::from_rgb(244, 67, 54),
        }
    }
}

/// Network protocol options
#[derive(Debug, Clone, Copy, PartialEq)]
enum Protocol {
    TCP,
    UDP,
    ICMP,
    HTTP,
    HTTPS,
    SSH,
    FTP,
}

impl Protocol {
    fn all() -> Vec<Protocol> {
        vec![
            Protocol::TCP,
            Protocol::UDP,
            Protocol::ICMP,
            Protocol::HTTP,
            Protocol::HTTPS,
            Protocol::SSH,
            Protocol::FTP,
        ]
    }

    fn as_str(&self) -> &'static str {
        match self {
            Protocol::TCP => "TCP",
            Protocol::UDP => "UDP",
            Protocol::ICMP => "ICMP",
            Protocol::HTTP => "HTTP",
            Protocol::HTTPS => "HTTPS",
            Protocol::SSH => "SSH",
            Protocol::FTP => "FTP",
        }
    }

    fn default_port(&self) -> u16 {
        match self {
            Protocol::TCP => 0,
            Protocol::UDP => 0,
            Protocol::ICMP => 0,
            Protocol::HTTP => 80,
            Protocol::HTTPS => 443,
            Protocol::SSH => 22,
            Protocol::FTP => 21,
        }
    }
}

/// User registration form data
#[derive(Default, Clone)]
struct RegistrationForm {
    username: String,
    email: String,
    password: String,
    confirm_password: String,
    show_password: bool,
    full_name: String,
    organization: String,
    role: String,
    security_level: Option<SecurityLevel>,
    accept_terms: bool,
    receive_updates: bool,
    notes: String,
}

/// Network configuration form data
#[derive(Clone)]
struct NetworkConfigForm {
    target_ip: String,
    target_port: String,
    protocol: Protocol,
    timeout_seconds: String,
    max_retries: String,
    use_proxy: bool,
    proxy_address: String,
    proxy_port: String,
    custom_headers: String,
}

impl Default for NetworkConfigForm {
    fn default() -> Self {
        Self {
            target_ip: String::new(),
            target_port: String::from("80"),
            protocol: Protocol::HTTP,
            timeout_seconds: String::from("30"),
            max_retries: String::from("3"),
            use_proxy: false,
            proxy_address: String::new(),
            proxy_port: String::from("8080"),
            custom_headers: String::new(),
        }
    }
}

/// Search/filter form data
#[derive(Default, Clone)]
struct SearchForm {
    query: String,
    case_sensitive: bool,
    regex_mode: bool,
    search_in: Vec<bool>,  // [Files, Logs, Config, Network]
    date_from: String,
    date_to: String,
    min_severity: Option<SecurityLevel>,
}

/// Main application state
struct InputFormsApp {
    // Currently active form tab
    active_tab: usize,

    // Form data
    registration_form: RegistrationForm,
    network_form: NetworkConfigForm,
    search_form: SearchForm,

    // Validation errors
    validation_errors: Vec<ValidationError>,

    // Form submission status
    form_submitted: bool,
    submission_message: String,

    // Available roles for dropdown
    available_roles: Vec<String>,

    // Search locations
    search_locations: Vec<String>,

    // Dark mode
    dark_mode: bool,
}

impl Default for InputFormsApp {
    fn default() -> Self {
        Self {
            active_tab: 0,
            registration_form: RegistrationForm::default(),
            network_form: NetworkConfigForm::default(),
            search_form: SearchForm {
                search_in: vec![true, true, false, false],
                ..Default::default()
            },
            validation_errors: Vec::new(),
            form_submitted: false,
            submission_message: String::new(),
            available_roles: vec![
                "Security Analyst".to_string(),
                "Penetration Tester".to_string(),
                "Security Engineer".to_string(),
                "SOC Analyst".to_string(),
                "Incident Responder".to_string(),
                "Security Architect".to_string(),
                "CISO".to_string(),
            ],
            search_locations: vec![
                "Files".to_string(),
                "Logs".to_string(),
                "Config".to_string(),
                "Network".to_string(),
            ],
            dark_mode: true,
        }
    }
}

impl InputFormsApp {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        // Set up custom fonts and styling
        let mut style = (*cc.egui_ctx.style()).clone();
        style.spacing.item_spacing = egui::vec2(8.0, 6.0);
        cc.egui_ctx.set_style(style);
        cc.egui_ctx.set_visuals(egui::Visuals::dark());

        Self::default()
    }

    /// Validate email format
    fn validate_email(email: &str) -> bool {
        let email_regex = Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$").unwrap();
        email_regex.is_match(email)
    }

    /// Validate IP address format
    fn validate_ip(ip: &str) -> bool {
        let ip_regex = Regex::new(
            r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
        ).unwrap();
        ip_regex.is_match(ip) || ip == "localhost"
    }

    /// Validate port number
    fn validate_port(port: &str) -> bool {
        port.parse::<u16>().is_ok()
    }

    /// Validate registration form
    fn validate_registration_form(&mut self) -> bool {
        self.validation_errors.clear();

        let form = &self.registration_form;

        // Username validation
        if form.username.trim().is_empty() {
            self.validation_errors.push(ValidationError::Required("Username".to_string()));
        } else if form.username.len() < 3 {
            self.validation_errors.push(ValidationError::MinLength("Username".to_string(), 3));
        } else if form.username.len() > 20 {
            self.validation_errors.push(ValidationError::MaxLength("Username".to_string(), 20));
        }

        // Email validation
        if form.email.trim().is_empty() {
            self.validation_errors.push(ValidationError::Required("Email".to_string()));
        } else if !Self::validate_email(&form.email) {
            self.validation_errors.push(ValidationError::InvalidEmail);
        }

        // Password validation
        if form.password.is_empty() {
            self.validation_errors.push(ValidationError::Required("Password".to_string()));
        } else if form.password.len() < 8 {
            self.validation_errors.push(ValidationError::MinLength("Password".to_string(), 8));
        }

        // Confirm password
        if form.password != form.confirm_password {
            self.validation_errors.push(ValidationError::PasswordMismatch);
        }

        // Security level
        if form.security_level.is_none() {
            self.validation_errors.push(ValidationError::Required("Security Level".to_string()));
        }

        // Terms acceptance
        if !form.accept_terms {
            self.validation_errors.push(ValidationError::Custom(
                "You must accept the terms and conditions".to_string()
            ));
        }

        self.validation_errors.is_empty()
    }

    /// Validate network configuration form
    fn validate_network_form(&mut self) -> bool {
        self.validation_errors.clear();

        let form = &self.network_form;

        // Target IP validation
        if form.target_ip.trim().is_empty() {
            self.validation_errors.push(ValidationError::Required("Target IP".to_string()));
        } else if !Self::validate_ip(&form.target_ip) {
            self.validation_errors.push(ValidationError::InvalidIP);
        }

        // Port validation
        if form.target_port.trim().is_empty() {
            self.validation_errors.push(ValidationError::Required("Target Port".to_string()));
        } else if !Self::validate_port(&form.target_port) {
            self.validation_errors.push(ValidationError::InvalidFormat(
                "Port".to_string(),
                "0-65535".to_string()
            ));
        }

        // Proxy validation (if enabled)
        if form.use_proxy {
            if form.proxy_address.trim().is_empty() {
                self.validation_errors.push(ValidationError::Required("Proxy Address".to_string()));
            }
            if !Self::validate_port(&form.proxy_port) {
                self.validation_errors.push(ValidationError::InvalidFormat(
                    "Proxy Port".to_string(),
                    "0-65535".to_string()
                ));
            }
        }

        self.validation_errors.is_empty()
    }

    /// Render the tab bar
    fn render_tabs(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            let tabs = ["Registration", "Network Config", "Search & Filter"];
            for (i, tab) in tabs.iter().enumerate() {
                let selected = self.active_tab == i;
                if ui.selectable_label(selected, *tab).clicked() {
                    self.active_tab = i;
                    self.validation_errors.clear();
                    self.form_submitted = false;
                }
            }
        });
        ui.separator();
    }

    /// Render validation errors
    fn render_errors(&self, ui: &mut egui::Ui) {
        if !self.validation_errors.is_empty() {
            egui::Frame::none()
                .fill(egui::Color32::from_rgb(60, 20, 20))
                .inner_margin(10.0)
                .rounding(5.0)
                .show(ui, |ui| {
                    ui.label(egui::RichText::new("Validation Errors:")
                        .color(egui::Color32::from_rgb(255, 100, 100))
                        .strong());
                    for error in &self.validation_errors {
                        ui.label(egui::RichText::new(format!("• {}", error))
                            .color(egui::Color32::from_rgb(255, 150, 150)));
                    }
                });
            ui.add_space(10.0);
        }
    }

    /// Render success message
    fn render_success(&self, ui: &mut egui::Ui) {
        if self.form_submitted && self.validation_errors.is_empty() {
            egui::Frame::none()
                .fill(egui::Color32::from_rgb(20, 60, 20))
                .inner_margin(10.0)
                .rounding(5.0)
                .show(ui, |ui| {
                    ui.label(egui::RichText::new(&self.submission_message)
                        .color(egui::Color32::from_rgb(100, 255, 100))
                        .strong());
                });
            ui.add_space(10.0);
        }
    }

    /// Render registration form
    fn render_registration_form(&mut self, ui: &mut egui::Ui) {
        ui.heading("User Registration");
        ui.label("Create a new security analyst account");
        ui.add_space(10.0);

        self.render_errors(ui);
        self.render_success(ui);

        egui::Grid::new("registration_grid")
            .num_columns(2)
            .spacing([20.0, 10.0])
            .show(ui, |ui| {
                // Username
                ui.label("Username *:");
                ui.add(egui::TextEdit::singleline(&mut self.registration_form.username)
                    .hint_text("Enter username")
                    .desired_width(250.0));
                ui.end_row();

                // Email
                ui.label("Email *:");
                ui.add(egui::TextEdit::singleline(&mut self.registration_form.email)
                    .hint_text("user@example.com")
                    .desired_width(250.0));
                ui.end_row();

                // Password with visibility toggle
                ui.label("Password *:");
                ui.horizontal(|ui| {
                    let password_edit = if self.registration_form.show_password {
                        egui::TextEdit::singleline(&mut self.registration_form.password)
                            .hint_text("Min 8 characters")
                            .desired_width(200.0)
                    } else {
                        egui::TextEdit::singleline(&mut self.registration_form.password)
                            .hint_text("Min 8 characters")
                            .password(true)
                            .desired_width(200.0)
                    };
                    ui.add(password_edit);
                    if ui.button(if self.registration_form.show_password { "Hide" } else { "Show" }).clicked() {
                        self.registration_form.show_password = !self.registration_form.show_password;
                    }
                });
                ui.end_row();

                // Confirm Password
                ui.label("Confirm Password *:");
                let confirm_edit = if self.registration_form.show_password {
                    egui::TextEdit::singleline(&mut self.registration_form.confirm_password)
                        .hint_text("Re-enter password")
                        .desired_width(250.0)
                } else {
                    egui::TextEdit::singleline(&mut self.registration_form.confirm_password)
                        .hint_text("Re-enter password")
                        .password(true)
                        .desired_width(250.0)
                };
                ui.add(confirm_edit);
                ui.end_row();

                ui.label("");
                ui.label("");
                ui.end_row();

                // Full Name
                ui.label("Full Name:");
                ui.add(egui::TextEdit::singleline(&mut self.registration_form.full_name)
                    .hint_text("John Doe")
                    .desired_width(250.0));
                ui.end_row();

                // Organization
                ui.label("Organization:");
                ui.add(egui::TextEdit::singleline(&mut self.registration_form.organization)
                    .hint_text("Company name")
                    .desired_width(250.0));
                ui.end_row();

                // Role dropdown
                ui.label("Role:");
                egui::ComboBox::from_id_salt("role_combo")
                    .selected_text(if self.registration_form.role.is_empty() {
                        "Select a role"
                    } else {
                        &self.registration_form.role
                    })
                    .width(250.0)
                    .show_ui(ui, |ui| {
                        for role in &self.available_roles {
                            ui.selectable_value(
                                &mut self.registration_form.role,
                                role.clone(),
                                role
                            );
                        }
                    });
                ui.end_row();

                // Security Level dropdown with colored options
                ui.label("Security Level *:");
                let level_text = self.registration_form.security_level
                    .map(|l| l.as_str())
                    .unwrap_or("Select level");
                egui::ComboBox::from_id_salt("security_level_combo")
                    .selected_text(level_text)
                    .width(250.0)
                    .show_ui(ui, |ui| {
                        for level in SecurityLevel::all() {
                            let text = egui::RichText::new(level.as_str())
                                .color(level.color());
                            if ui.selectable_label(
                                self.registration_form.security_level == Some(level),
                                text
                            ).clicked() {
                                self.registration_form.security_level = Some(level);
                            }
                        }
                    });
                ui.end_row();

                // Notes (multiline)
                ui.label("Notes:");
                ui.add(egui::TextEdit::multiline(&mut self.registration_form.notes)
                    .hint_text("Additional information...")
                    .desired_width(250.0)
                    .desired_rows(3));
                ui.end_row();

                // Checkboxes
                ui.label("");
                ui.vertical(|ui| {
                    ui.checkbox(&mut self.registration_form.accept_terms, "I accept the terms and conditions *");
                    ui.checkbox(&mut self.registration_form.receive_updates, "Receive security updates via email");
                });
                ui.end_row();
            });

        ui.add_space(20.0);

        // Submit buttons
        ui.horizontal(|ui| {
            if ui.add_sized([120.0, 35.0], egui::Button::new("Register")).clicked() {
                if self.validate_registration_form() {
                    self.form_submitted = true;
                    self.submission_message = format!(
                        "Registration successful! Welcome, {}",
                        self.registration_form.username
                    );
                }
            }

            if ui.add_sized([120.0, 35.0], egui::Button::new("Clear Form")).clicked() {
                self.registration_form = RegistrationForm::default();
                self.validation_errors.clear();
                self.form_submitted = false;
            }
        });
    }

    /// Render network configuration form
    fn render_network_form(&mut self, ui: &mut egui::Ui) {
        ui.heading("Network Configuration");
        ui.label("Configure network scanning parameters");
        ui.add_space(10.0);

        self.render_errors(ui);
        self.render_success(ui);

        egui::Grid::new("network_grid")
            .num_columns(2)
            .spacing([20.0, 10.0])
            .show(ui, |ui| {
                // Target IP
                ui.label("Target IP *:");
                ui.add(egui::TextEdit::singleline(&mut self.network_form.target_ip)
                    .hint_text("192.168.1.1 or localhost")
                    .desired_width(200.0));
                ui.end_row();

                // Protocol dropdown
                ui.label("Protocol:");
                egui::ComboBox::from_id_salt("protocol_combo")
                    .selected_text(self.network_form.protocol.as_str())
                    .width(200.0)
                    .show_ui(ui, |ui| {
                        for protocol in Protocol::all() {
                            if ui.selectable_label(
                                self.network_form.protocol == protocol,
                                protocol.as_str()
                            ).clicked() {
                                self.network_form.protocol = protocol;
                                // Auto-fill default port
                                let default_port = protocol.default_port();
                                if default_port > 0 {
                                    self.network_form.target_port = default_port.to_string();
                                }
                            }
                        }
                    });
                ui.end_row();

                // Target Port
                ui.label("Target Port *:");
                ui.add(egui::TextEdit::singleline(&mut self.network_form.target_port)
                    .hint_text("80")
                    .desired_width(100.0));
                ui.end_row();

                // Timeout
                ui.label("Timeout (seconds):");
                ui.add(egui::TextEdit::singleline(&mut self.network_form.timeout_seconds)
                    .hint_text("30")
                    .desired_width(100.0));
                ui.end_row();

                // Max Retries
                ui.label("Max Retries:");
                ui.add(egui::TextEdit::singleline(&mut self.network_form.max_retries)
                    .hint_text("3")
                    .desired_width(100.0));
                ui.end_row();

                // Proxy toggle
                ui.label("");
                ui.checkbox(&mut self.network_form.use_proxy, "Use Proxy");
                ui.end_row();
            });

        // Proxy settings (conditional)
        if self.network_form.use_proxy {
            ui.add_space(10.0);
            ui.separator();
            ui.label(egui::RichText::new("Proxy Settings").strong());
            ui.add_space(5.0);

            egui::Grid::new("proxy_grid")
                .num_columns(2)
                .spacing([20.0, 10.0])
                .show(ui, |ui| {
                    ui.label("Proxy Address:");
                    ui.add(egui::TextEdit::singleline(&mut self.network_form.proxy_address)
                        .hint_text("proxy.example.com")
                        .desired_width(200.0));
                    ui.end_row();

                    ui.label("Proxy Port:");
                    ui.add(egui::TextEdit::singleline(&mut self.network_form.proxy_port)
                        .hint_text("8080")
                        .desired_width(100.0));
                    ui.end_row();
                });
        }

        ui.add_space(10.0);
        ui.separator();
        ui.label(egui::RichText::new("Custom Headers").strong());
        ui.add_space(5.0);

        ui.add(egui::TextEdit::multiline(&mut self.network_form.custom_headers)
            .hint_text("Header-Name: value\nAnother-Header: value")
            .desired_width(400.0)
            .desired_rows(4)
            .font(egui::TextStyle::Monospace));

        ui.add_space(20.0);

        // Submit buttons
        ui.horizontal(|ui| {
            if ui.add_sized([150.0, 35.0], egui::Button::new("Save Configuration")).clicked() {
                if self.validate_network_form() {
                    self.form_submitted = true;
                    self.submission_message = format!(
                        "Configuration saved: {} -> {}:{}",
                        self.network_form.protocol.as_str(),
                        self.network_form.target_ip,
                        self.network_form.target_port
                    );
                }
            }

            if ui.add_sized([120.0, 35.0], egui::Button::new("Test Connection")).clicked() {
                if self.validate_network_form() {
                    self.form_submitted = true;
                    self.submission_message = "Testing connection...".to_string();
                }
            }

            if ui.add_sized([120.0, 35.0], egui::Button::new("Reset")).clicked() {
                self.network_form = NetworkConfigForm::default();
                self.validation_errors.clear();
                self.form_submitted = false;
            }
        });
    }

    /// Render search and filter form
    fn render_search_form(&mut self, ui: &mut egui::Ui) {
        ui.heading("Search & Filter");
        ui.label("Search logs and security events");
        ui.add_space(10.0);

        self.render_success(ui);

        // Search query with icon-like prefix
        ui.horizontal(|ui| {
            ui.label("Search:");
            ui.add(egui::TextEdit::singleline(&mut self.search_form.query)
                .hint_text("Enter search query...")
                .desired_width(400.0));
        });

        ui.add_space(10.0);

        // Search options
        ui.horizontal(|ui| {
            ui.checkbox(&mut self.search_form.case_sensitive, "Case Sensitive");
            ui.checkbox(&mut self.search_form.regex_mode, "Regex Mode");
        });

        ui.add_space(10.0);
        ui.separator();

        // Search locations
        ui.label(egui::RichText::new("Search In:").strong());
        ui.horizontal(|ui| {
            for (i, location) in self.search_locations.iter().enumerate() {
                if i < self.search_form.search_in.len() {
                    ui.checkbox(&mut self.search_form.search_in[i], location);
                }
            }
        });

        ui.add_space(10.0);
        ui.separator();

        // Date range
        ui.label(egui::RichText::new("Date Range:").strong());
        egui::Grid::new("date_grid")
            .num_columns(4)
            .spacing([10.0, 10.0])
            .show(ui, |ui| {
                ui.label("From:");
                ui.add(egui::TextEdit::singleline(&mut self.search_form.date_from)
                    .hint_text("YYYY-MM-DD")
                    .desired_width(120.0));

                ui.label("To:");
                ui.add(egui::TextEdit::singleline(&mut self.search_form.date_to)
                    .hint_text("YYYY-MM-DD")
                    .desired_width(120.0));
                ui.end_row();
            });

        ui.add_space(10.0);

        // Minimum severity
        ui.horizontal(|ui| {
            ui.label("Min Severity:");
            egui::ComboBox::from_id_salt("severity_combo")
                .selected_text(
                    self.search_form.min_severity
                        .map(|l| l.as_str())
                        .unwrap_or("Any")
                )
                .width(150.0)
                .show_ui(ui, |ui| {
                    if ui.selectable_label(self.search_form.min_severity.is_none(), "Any").clicked() {
                        self.search_form.min_severity = None;
                    }
                    for level in SecurityLevel::all() {
                        let text = egui::RichText::new(level.as_str())
                            .color(level.color());
                        if ui.selectable_label(
                            self.search_form.min_severity == Some(level),
                            text
                        ).clicked() {
                            self.search_form.min_severity = Some(level);
                        }
                    }
                });
        });

        ui.add_space(20.0);

        // Action buttons
        ui.horizontal(|ui| {
            if ui.add_sized([120.0, 35.0], egui::Button::new("Search")).clicked() {
                self.form_submitted = true;
                let locations: Vec<&str> = self.search_locations.iter()
                    .enumerate()
                    .filter(|(i, _)| self.search_form.search_in.get(*i).copied().unwrap_or(false))
                    .map(|(_, s)| s.as_str())
                    .collect();
                self.submission_message = format!(
                    "Searching for '{}' in: {}",
                    self.search_form.query,
                    if locations.is_empty() { "All".to_string() } else { locations.join(", ") }
                );
            }

            if ui.add_sized([120.0, 35.0], egui::Button::new("Clear Filters")).clicked() {
                self.search_form = SearchForm {
                    search_in: vec![true, true, false, false],
                    ..Default::default()
                };
                self.form_submitted = false;
            }

            if ui.add_sized([120.0, 35.0], egui::Button::new("Save Filter")).clicked() {
                self.form_submitted = true;
                self.submission_message = "Filter saved successfully!".to_string();
            }
        });

        // Quick filters
        ui.add_space(20.0);
        ui.separator();
        ui.label(egui::RichText::new("Quick Filters:").strong());
        ui.horizontal(|ui| {
            if ui.button("Last Hour").clicked() {
                self.search_form.query = "timestamp:>now-1h".to_string();
            }
            if ui.button("Last 24 Hours").clicked() {
                self.search_form.query = "timestamp:>now-24h".to_string();
            }
            if ui.button("Critical Only").clicked() {
                self.search_form.min_severity = Some(SecurityLevel::Critical);
            }
            if ui.button("Failed Logins").clicked() {
                self.search_form.query = "event_type:login_failed".to_string();
            }
            if ui.button("Malware Alerts").clicked() {
                self.search_form.query = "category:malware".to_string();
            }
        });
    }
}

impl eframe::App for InputFormsApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Apply theme
        if self.dark_mode {
            ctx.set_visuals(egui::Visuals::dark());
        } else {
            ctx.set_visuals(egui::Visuals::light());
        }

        // Top menu bar
        egui::TopBottomPanel::top("menu_bar").show(ctx, |ui| {
            egui::menu::bar(ui, |ui| {
                ui.menu_button("File", |ui| {
                    if ui.button("Export Form Data").clicked() {
                        ui.close_menu();
                    }
                    if ui.button("Import Form Data").clicked() {
                        ui.close_menu();
                    }
                    ui.separator();
                    if ui.button("Exit").clicked() {
                        std::process::exit(0);
                    }
                });
                ui.menu_button("View", |ui| {
                    ui.checkbox(&mut self.dark_mode, "Dark Mode");
                });
            });
        });

        // Status bar
        egui::TopBottomPanel::bottom("status_bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label("Form Input Demo");
                ui.separator();
                if !self.validation_errors.is_empty() {
                    ui.label(egui::RichText::new(format!("{} validation errors", self.validation_errors.len()))
                        .color(egui::Color32::RED));
                } else if self.form_submitted {
                    ui.label(egui::RichText::new("Form submitted successfully")
                        .color(egui::Color32::GREEN));
                } else {
                    ui.label("Ready");
                }
            });
        });

        // Main content
        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                self.render_tabs(ui);

                match self.active_tab {
                    0 => self.render_registration_form(ui),
                    1 => self.render_network_form(ui),
                    2 => self.render_search_form(ui),
                    _ => {}
                }
            });
        });
    }
}

fn main() -> eframe::Result<()> {
    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([900.0, 700.0])
            .with_min_inner_size([700.0, 500.0])
            .with_title("G02 - Input Forms | Rust Security Bible"),
        ..Default::default()
    };

    eframe::run_native(
        "Input Forms",
        native_options,
        Box::new(|cc| Ok(Box::new(InputFormsApp::new(cc)))),
    )
}
