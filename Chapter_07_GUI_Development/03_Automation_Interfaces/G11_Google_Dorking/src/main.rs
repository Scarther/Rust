//! # G11: Google Dorking Interface
//!
//! A GUI tool for building Google dork queries with templates.

use eframe::egui;
use arboard::Clipboard;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

fn main() -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([800.0, 700.0]),
        ..Default::default()
    };

    eframe::run_native(
        "Google Dorking Tool",
        options,
        Box::new(|cc| Ok(Box::new(DorkingApp::new(cc)))),
    )
}

#[derive(Clone)]
struct DorkTemplate {
    name: &'static str,
    template: &'static str,
    description: &'static str,
    fields: &'static [&'static str],
}

#[derive(Clone)]
struct DorkCategory {
    name: &'static str,
    dorks: &'static [DorkTemplate],
}

#[derive(Serialize, Deserialize, Clone)]
struct HistoryEntry {
    query: String,
    category: String,
}

const DORK_CATEGORIES: &[DorkCategory] = &[
    DorkCategory {
        name: "Files",
        dorks: &[
            DorkTemplate {
                name: "PDF Files",
                template: "site:{domain} filetype:pdf {keyword}",
                description: "Find PDF documents",
                fields: &["domain", "keyword"],
            },
            DorkTemplate {
                name: "Excel Files",
                template: "site:{domain} filetype:xlsx {keyword}",
                description: "Find spreadsheets",
                fields: &["domain", "keyword"],
            },
            DorkTemplate {
                name: "Config Files",
                template: "site:{domain} filetype:conf OR filetype:cfg",
                description: "Find config files",
                fields: &["domain"],
            },
        ],
    },
    DorkCategory {
        name: "Admin Pages",
        dorks: &[
            DorkTemplate {
                name: "Admin Panels",
                template: "site:{domain} inurl:admin OR inurl:login",
                description: "Find admin pages",
                fields: &["domain"],
            },
            DorkTemplate {
                name: "WordPress",
                template: "site:{domain} inurl:wp-admin",
                description: "Find WordPress admin",
                fields: &["domain"],
            },
        ],
    },
    DorkCategory {
        name: "Directories",
        dorks: &[
            DorkTemplate {
                name: "Index Of",
                template: "site:{domain} intitle:\"index of\"",
                description: "Open directories",
                fields: &["domain"],
            },
        ],
    },
    DorkCategory {
        name: "Sensitive",
        dorks: &[
            DorkTemplate {
                name: "Passwords",
                template: "site:{domain} filetype:txt intext:password",
                description: "Password files",
                fields: &["domain"],
            },
            DorkTemplate {
                name: "SQL Dumps",
                template: "site:{domain} filetype:sql",
                description: "Database dumps",
                fields: &["domain"],
            },
        ],
    },
    DorkCategory {
        name: "Custom",
        dorks: &[
            DorkTemplate {
                name: "Custom Query",
                template: "{custom}",
                description: "Your own query",
                fields: &["custom"],
            },
        ],
    },
];

struct DorkingApp {
    selected_category: usize,
    selected_template: usize,
    field_values: HashMap<String, String>,
    generated_query: String,
    history: Vec<HistoryEntry>,
    status: String,
    clipboard: Option<Clipboard>,
}

impl DorkingApp {
    fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        let mut app = Self {
            selected_category: 0,
            selected_template: 0,
            field_values: HashMap::new(),
            generated_query: String::new(),
            history: Vec::new(),
            status: "Ready".to_string(),
            clipboard: Clipboard::new().ok(),
        };
        app.load_history();
        app.field_values.insert("domain".to_string(), String::new());
        app.field_values.insert("keyword".to_string(), String::new());
        app
    }

    fn get_history_path() -> PathBuf {
        let mut path = dirs::config_dir().unwrap_or_else(|| PathBuf::from("."));
        path.push("rust_dorking");
        fs::create_dir_all(&path).ok();
        path.push("history.json");
        path
    }

    fn load_history(&mut self) {
        if let Ok(data) = fs::read_to_string(Self::get_history_path()) {
            if let Ok(history) = serde_json::from_str(&data) {
                self.history = history;
            }
        }
    }

    fn save_history(&self) {
        if let Ok(json) = serde_json::to_string_pretty(&self.history) {
            fs::write(Self::get_history_path(), json).ok();
        }
    }

    fn current_category(&self) -> &DorkCategory {
        &DORK_CATEGORIES[self.selected_category]
    }

    fn current_template(&self) -> &DorkTemplate {
        &self.current_category().dorks[self.selected_template]
    }

    fn generate_query(&mut self) {
        let template = self.current_template();
        let mut query = template.template.to_string();

        for field in template.fields {
            let value = self.field_values.get(*field).map(|s| s.trim()).unwrap_or("");
            query = query.replace(&format!("{{{}}}", field), value);
        }

        self.generated_query = query.split_whitespace().collect::<Vec<_>>().join(" ");
    }

    fn copy_to_clipboard(&mut self) {
        if let Some(ref mut clipboard) = self.clipboard {
            if clipboard.set_text(&self.generated_query).is_ok() {
                self.status = "Copied!".to_string();
            }
        }
    }

    fn open_in_browser(&mut self) {
        if self.generated_query.is_empty() {
            self.status = "Generate query first!".to_string();
            return;
        }
        let encoded = urlencoding(&self.generated_query);
        let url = format!("https://www.google.com/search?q={}", encoded);
        if open::that(&url).is_ok() {
            self.status = "Opened in browser!".to_string();
        }
    }

    fn add_to_history(&mut self) {
        if self.generated_query.is_empty() { return; }

        let entry = HistoryEntry {
            query: self.generated_query.clone(),
            category: self.current_category().name.to_string(),
        };

        if !self.history.iter().any(|h| h.query == entry.query) {
            self.history.insert(0, entry);
            if self.history.len() > 50 { self.history.pop(); }
            self.save_history();
            self.status = "Saved to history!".to_string();
        }
    }
}

fn urlencoding(s: &str) -> String {
    let mut result = String::new();
    for c in s.chars() {
        match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' | '~' => result.push(c),
            ' ' => result.push('+'),
            _ => {
                for byte in c.to_string().bytes() {
                    result.push_str(&format!("%{:02X}", byte));
                }
            }
        }
    }
    result
}

impl eframe::App for DorkingApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::TopBottomPanel::top("header").show(ctx, |ui| {
            ui.heading("Google Dorking Tool");
        });

        egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
            ui.label(&self.status);
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                // Category selection
                ui.group(|ui| {
                    ui.label("Category:");
                    ui.horizontal_wrapped(|ui| {
                        for (i, cat) in DORK_CATEGORIES.iter().enumerate() {
                            if ui.selectable_label(self.selected_category == i, cat.name).clicked() {
                                self.selected_category = i;
                                self.selected_template = 0;
                                self.generate_query();
                            }
                        }
                    });
                });

                ui.add_space(10.0);

                // Template selection
                ui.group(|ui| {
                    ui.label("Templates:");
                    for (i, template) in self.current_category().dorks.iter().enumerate() {
                        ui.horizontal(|ui| {
                            if ui.radio(self.selected_template == i, "").clicked() {
                                self.selected_template = i;
                                self.generate_query();
                            }
                            ui.vertical(|ui| {
                                ui.strong(template.name);
                                ui.code(template.template);
                            });
                        });
                    }
                });

                ui.add_space(10.0);

                // Input fields
                ui.group(|ui| {
                    ui.label("Fill In:");
                    let template = self.current_template();
                    let mut changed = false;

                    for field in template.fields {
                        ui.horizontal(|ui| {
                            ui.label(format!("{}:", field));
                            let value = self.field_values.entry(field.to_string()).or_default();
                            if ui.text_edit_singleline(value).changed() {
                                changed = true;
                            }
                        });
                    }

                    if changed { self.generate_query(); }
                });

                ui.add_space(10.0);

                // Generated query
                ui.group(|ui| {
                    ui.label("Generated Query:");
                    ui.code(&self.generated_query);

                    ui.horizontal(|ui| {
                        if ui.button("Copy").clicked() { self.copy_to_clipboard(); }
                        if ui.button("Open Browser").clicked() { self.open_in_browser(); }
                        if ui.button("Save").clicked() { self.add_to_history(); }
                        if ui.button("Clear").clicked() {
                            for v in self.field_values.values_mut() { v.clear(); }
                            self.generated_query.clear();
                        }
                    });
                });

                ui.add_space(10.0);

                // History
                ui.group(|ui| {
                    ui.horizontal(|ui| {
                        ui.label("History:");
                        if ui.button("Clear All").clicked() {
                            self.history.clear();
                            self.save_history();
                        }
                    });

                    let mut to_remove = None;
                    let mut to_reuse = None;

                    for (i, entry) in self.history.iter().enumerate() {
                        ui.horizontal(|ui| {
                            ui.label(&entry.query);
                            if ui.small_button("Use").clicked() { to_reuse = Some(entry.query.clone()); }
                            if ui.small_button("X").clicked() { to_remove = Some(i); }
                        });
                    }

                    if let Some(i) = to_remove {
                        self.history.remove(i);
                        self.save_history();
                    }
                    if let Some(q) = to_reuse {
                        self.generated_query = q;
                    }
                });
            });
        });
    }
}
