# G11: Google Dorking Interface

## Overview

| Property | Value |
|----------|-------|
| **ID** | G11 |
| **Name** | Google Dorking Interface |
| **Difficulty** | Intermediate |
| **Time** | 2-3 hours |
| **Framework** | egui/eframe |
| **Prerequisites** | G01-G05 completed |

## What You'll Build

A GUI application for constructing Google dork queries with:
- Template-based query builder
- Fill-in-the-blank inputs
- Category-organized dorks
- Query history
- One-click browser launch
- Export functionality

```
┌────────────────────────────────────────────────────────────────────────────┐
│  GOOGLE DORKING TOOL v1.0                                        [_][□][X] │
├────────────────────────────────────────────────────────────────────────────┤
│  ┌─ Category ──────────────────────────────────────────────────────────┐   │
│  │  [Files & Documents ▼]                                              │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                            │
│  ┌─ Dork Templates ────────────────────────────────────────────────────┐   │
│  │  ○ Find PDF files:     site:{domain} filetype:pdf                   │   │
│  │  ● Find Excel files:   site:{domain} filetype:xlsx                  │   │
│  │  ○ Find Word docs:     site:{domain} filetype:docx                  │   │
│  │  ○ Find config files:  site:{domain} filetype:conf OR filetype:cfg  │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                            │
│  ┌─ Fill In The Blanks ────────────────────────────────────────────────┐   │
│  │  Domain:     [example.com_________________________]                 │   │
│  │  Keyword:    [confidential________________________] (optional)      │   │
│  │  File type:  [xlsx_______] (auto-filled from template)              │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                            │
│  ┌─ Generated Query ───────────────────────────────────────────────────┐   │
│  │  site:example.com filetype:xlsx confidential                        │   │
│  │                                                                     │   │
│  │  [Copy to Clipboard]  [Open in Browser]  [Save to History]          │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                            │
│  ┌─ Query History ─────────────────────────────────────────────────────┐   │
│  │  • site:example.com filetype:pdf         [Re-use] [Delete]          │   │
│  │  • inurl:admin site:example.com          [Re-use] [Delete]          │   │
│  │  • intitle:"index of" site:example.com   [Re-use] [Delete]          │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                            │
│  Status: Query generated - Ready to search                                 │
└────────────────────────────────────────────────────────────────────────────┘
```

---

## What You'll Learn

1. Complex form layouts in egui
2. Template string substitution
3. Dynamic UI based on selection
4. Clipboard operations
5. Opening URLs in browser
6. Persistent history (file I/O)
7. Combo boxes and radio buttons

---

## Dork Categories & Templates

```rust
/// Categories of Google dorks organized by purpose
pub const DORK_CATEGORIES: &[DorkCategory] = &[
    DorkCategory {
        name: "Files & Documents",
        dorks: &[
            DorkTemplate {
                name: "PDF Files",
                template: "site:{domain} filetype:pdf {keyword}",
                description: "Find PDF documents on target domain",
                fields: &["domain", "keyword"],
            },
            DorkTemplate {
                name: "Excel Spreadsheets",
                template: "site:{domain} filetype:xlsx OR filetype:xls {keyword}",
                description: "Find Excel files that may contain data",
                fields: &["domain", "keyword"],
            },
            DorkTemplate {
                name: "Word Documents",
                template: "site:{domain} filetype:docx OR filetype:doc {keyword}",
                description: "Find Word documents",
                fields: &["domain", "keyword"],
            },
            DorkTemplate {
                name: "Text Files",
                template: "site:{domain} filetype:txt {keyword}",
                description: "Find plain text files",
                fields: &["domain", "keyword"],
            },
        ],
    },
    DorkCategory {
        name: "Sensitive Information",
        dorks: &[
            DorkTemplate {
                name: "Password Files",
                template: "site:{domain} filetype:txt intext:password",
                description: "Look for exposed password files",
                fields: &["domain"],
            },
            DorkTemplate {
                name: "Config Files",
                template: "site:{domain} filetype:conf OR filetype:cfg OR filetype:ini",
                description: "Find configuration files",
                fields: &["domain"],
            },
            DorkTemplate {
                name: "Database Files",
                template: "site:{domain} filetype:sql OR filetype:db OR filetype:mdb",
                description: "Find database dumps or files",
                fields: &["domain"],
            },
            DorkTemplate {
                name: "Backup Files",
                template: "site:{domain} filetype:bak OR filetype:backup OR filetype:old",
                description: "Find backup files",
                fields: &["domain"],
            },
        ],
    },
    DorkCategory {
        name: "Login & Admin Pages",
        dorks: &[
            DorkTemplate {
                name: "Admin Panels",
                template: "site:{domain} inurl:admin OR inurl:administrator OR inurl:login",
                description: "Find admin login pages",
                fields: &["domain"],
            },
            DorkTemplate {
                name: "CPanel/WHM",
                template: "site:{domain} inurl:cpanel OR inurl:whm OR inurl:webmail",
                description: "Find hosting control panels",
                fields: &["domain"],
            },
            DorkTemplate {
                name: "phpMyAdmin",
                template: "site:{domain} inurl:phpmyadmin",
                description: "Find phpMyAdmin installations",
                fields: &["domain"],
            },
            DorkTemplate {
                name: "WordPress Login",
                template: "site:{domain} inurl:wp-login.php OR inurl:wp-admin",
                description: "Find WordPress admin pages",
                fields: &["domain"],
            },
        ],
    },
    DorkCategory {
        name: "Directory Listings",
        dorks: &[
            DorkTemplate {
                name: "Index Of",
                template: "site:{domain} intitle:\"index of\"",
                description: "Find open directory listings",
                fields: &["domain"],
            },
            DorkTemplate {
                name: "Parent Directory",
                template: "site:{domain} intitle:\"index of\" \"parent directory\"",
                description: "Find browsable directories",
                fields: &["domain"],
            },
            DorkTemplate {
                name: "Specific Directory",
                template: "site:{domain} intitle:\"index of\" \"{directory}\"",
                description: "Find specific directory type",
                fields: &["domain", "directory"],
            },
        ],
    },
    DorkCategory {
        name: "Technology Detection",
        dorks: &[
            DorkTemplate {
                name: "PHP Errors",
                template: "site:{domain} \"PHP Parse error\" OR \"PHP Warning\" OR \"PHP Error\"",
                description: "Find PHP error messages revealing info",
                fields: &["domain"],
            },
            DorkTemplate {
                name: "SQL Errors",
                template: "site:{domain} \"SQL syntax\" OR \"mysql_fetch\" OR \"ORA-\"",
                description: "Find SQL error messages",
                fields: &["domain"],
            },
            DorkTemplate {
                name: "ASP.NET Errors",
                template: "site:{domain} \"ASP.NET\" \"error\" OR \"stack trace\"",
                description: "Find ASP.NET error pages",
                fields: &["domain"],
            },
        ],
    },
    DorkCategory {
        name: "Exposed Data",
        dorks: &[
            DorkTemplate {
                name: "Email Addresses",
                template: "site:{domain} intext:\"@{domain}\" filetype:txt OR filetype:csv",
                description: "Find files containing email addresses",
                fields: &["domain"],
            },
            DorkTemplate {
                name: "API Keys",
                template: "site:{domain} intext:api_key OR intext:apikey OR intext:\"api key\"",
                description: "Find exposed API keys",
                fields: &["domain"],
            },
            DorkTemplate {
                name: "Private Keys",
                template: "site:{domain} \"BEGIN RSA PRIVATE KEY\" OR \"BEGIN PRIVATE KEY\"",
                description: "Find exposed private keys",
                fields: &["domain"],
            },
        ],
    },
    DorkCategory {
        name: "Custom Query",
        dorks: &[
            DorkTemplate {
                name: "Custom Dork",
                template: "{custom_query}",
                description: "Build your own custom query",
                fields: &["custom_query"],
            },
        ],
    },
];
```

---

## The Code

### Cargo.toml

```toml
[package]
name = "g11_google_dorking"
version = "0.1.0"
edition = "2021"
authors = ["Security Student"]
description = "G11: Google Dorking GUI Interface"

[dependencies]
eframe = "0.24"
egui = "0.24"
arboard = "3.2"        # Clipboard support
open = "5.0"           # Open URLs in browser
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"     # Save/load history
dirs = "5.0"           # Find config directory
```

### src/main.rs

```rust
//! # G11: Google Dorking Interface
//!
//! A GUI tool for building Google dork queries with templates.
//!
//! ## Features
//! - Template-based query builder
//! - Fill-in-the-blank inputs
//! - Query history with persistence
//! - One-click browser launch

use eframe::egui;
use arboard::Clipboard;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

fn main() -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions {
        initial_window_size: Some(egui::vec2(800.0, 700.0)),
        ..Default::default()
    };

    eframe::run_native(
        "Google Dorking Tool",
        options,
        Box::new(|cc| Box::new(DorkingApp::new(cc))),
    )
}

// ═══════════════════════════════════════════════════════════════════════════
// Data Structures
// ═══════════════════════════════════════════════════════════════════════════

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
    timestamp: String,
    category: String,
}

// ═══════════════════════════════════════════════════════════════════════════
// Dork Database
// ═══════════════════════════════════════════════════════════════════════════

const DORK_CATEGORIES: &[DorkCategory] = &[
    DorkCategory {
        name: "Files & Documents",
        dorks: &[
            DorkTemplate {
                name: "PDF Files",
                template: "site:{domain} filetype:pdf {keyword}",
                description: "Find PDF documents",
                fields: &["domain", "keyword"],
            },
            DorkTemplate {
                name: "Excel Files",
                template: "site:{domain} filetype:xlsx OR filetype:xls {keyword}",
                description: "Find spreadsheets",
                fields: &["domain", "keyword"],
            },
            DorkTemplate {
                name: "Config Files",
                template: "site:{domain} filetype:conf OR filetype:cfg OR filetype:ini",
                description: "Find configuration files",
                fields: &["domain"],
            },
            DorkTemplate {
                name: "Backup Files",
                template: "site:{domain} filetype:bak OR filetype:backup",
                description: "Find backup files",
                fields: &["domain"],
            },
        ],
    },
    DorkCategory {
        name: "Login & Admin",
        dorks: &[
            DorkTemplate {
                name: "Admin Panels",
                template: "site:{domain} inurl:admin OR inurl:login",
                description: "Find admin pages",
                fields: &["domain"],
            },
            DorkTemplate {
                name: "WordPress Admin",
                template: "site:{domain} inurl:wp-admin OR inurl:wp-login",
                description: "Find WordPress admin",
                fields: &["domain"],
            },
            DorkTemplate {
                name: "phpMyAdmin",
                template: "site:{domain} inurl:phpmyadmin",
                description: "Find phpMyAdmin",
                fields: &["domain"],
            },
        ],
    },
    DorkCategory {
        name: "Directory Listings",
        dorks: &[
            DorkTemplate {
                name: "Index Of",
                template: "site:{domain} intitle:\"index of\"",
                description: "Find open directories",
                fields: &["domain"],
            },
            DorkTemplate {
                name: "Specific Directory",
                template: "site:{domain} intitle:\"index of\" \"{folder}\"",
                description: "Find specific folders",
                fields: &["domain", "folder"],
            },
        ],
    },
    DorkCategory {
        name: "Sensitive Info",
        dorks: &[
            DorkTemplate {
                name: "Password Files",
                template: "site:{domain} filetype:txt intext:password",
                description: "Find password files",
                fields: &["domain"],
            },
            DorkTemplate {
                name: "Database Dumps",
                template: "site:{domain} filetype:sql",
                description: "Find SQL dumps",
                fields: &["domain"],
            },
            DorkTemplate {
                name: "API Keys",
                template: "site:{domain} intext:api_key OR intext:apikey",
                description: "Find API keys",
                fields: &["domain"],
            },
            DorkTemplate {
                name: "Private Keys",
                template: "site:{domain} \"BEGIN RSA PRIVATE KEY\"",
                description: "Find private keys",
                fields: &["domain"],
            },
        ],
    },
    DorkCategory {
        name: "Error Messages",
        dorks: &[
            DorkTemplate {
                name: "PHP Errors",
                template: "site:{domain} \"PHP Parse error\" OR \"PHP Warning\"",
                description: "Find PHP errors",
                fields: &["domain"],
            },
            DorkTemplate {
                name: "SQL Errors",
                template: "site:{domain} \"SQL syntax\" OR \"mysql_fetch\"",
                description: "Find SQL errors",
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

// ═══════════════════════════════════════════════════════════════════════════
// Application State
// ═══════════════════════════════════════════════════════════════════════════

struct DorkingApp {
    // Current selection
    selected_category: usize,
    selected_template: usize,

    // Input fields
    field_values: HashMap<String, String>,

    // Generated query
    generated_query: String,

    // History
    history: Vec<HistoryEntry>,

    // Status message
    status: String,

    // Clipboard
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
            status: "Ready - Select a dork template".to_string(),
            clipboard: Clipboard::new().ok(),
        };

        // Load history
        app.load_history();

        // Initialize default field values
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
        let path = Self::get_history_path();
        if let Ok(data) = fs::read_to_string(&path) {
            if let Ok(history) = serde_json::from_str(&data) {
                self.history = history;
            }
        }
    }

    fn save_history(&self) {
        let path = Self::get_history_path();
        if let Ok(json) = serde_json::to_string_pretty(&self.history) {
            fs::write(path, json).ok();
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

        // Replace placeholders with field values
        for field in template.fields {
            let value = self.field_values
                .get(*field)
                .map(|s| s.trim())
                .unwrap_or("");

            let placeholder = format!("{{{}}}", field);
            query = query.replace(&placeholder, value);
        }

        // Clean up extra spaces
        self.generated_query = query
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
    }

    fn copy_to_clipboard(&mut self) {
        if let Some(ref mut clipboard) = self.clipboard {
            if clipboard.set_text(&self.generated_query).is_ok() {
                self.status = "Query copied to clipboard!".to_string();
            } else {
                self.status = "Failed to copy to clipboard".to_string();
            }
        }
    }

    fn open_in_browser(&mut self) {
        if self.generated_query.is_empty() {
            self.status = "Generate a query first!".to_string();
            return;
        }

        let encoded = urlencoding_simple(&self.generated_query);
        let url = format!("https://www.google.com/search?q={}", encoded);

        if open::that(&url).is_ok() {
            self.status = "Opened in browser!".to_string();
        } else {
            self.status = "Failed to open browser".to_string();
        }
    }

    fn add_to_history(&mut self) {
        if self.generated_query.is_empty() {
            return;
        }

        let entry = HistoryEntry {
            query: self.generated_query.clone(),
            timestamp: chrono_simple_timestamp(),
            category: self.current_category().name.to_string(),
        };

        // Avoid duplicates
        if !self.history.iter().any(|h| h.query == entry.query) {
            self.history.insert(0, entry);

            // Keep only last 50 entries
            if self.history.len() > 50 {
                self.history.pop();
            }

            self.save_history();
            self.status = "Added to history!".to_string();
        }
    }
}

// Simple URL encoding without external crate
fn urlencoding_simple(s: &str) -> String {
    let mut result = String::new();
    for c in s.chars() {
        match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' | '~' => {
                result.push(c);
            }
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

fn chrono_simple_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    format!("{}", secs)
}

// ═══════════════════════════════════════════════════════════════════════════
// UI Implementation
// ═══════════════════════════════════════════════════════════════════════════

impl eframe::App for DorkingApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Top panel with title
        egui::TopBottomPanel::top("header").show(ctx, |ui| {
            ui.add_space(5.0);
            ui.horizontal(|ui| {
                ui.heading("Google Dorking Tool");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label("v1.0.0");
                });
            });
            ui.add_space(5.0);
        });

        // Bottom panel with status
        egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
            ui.add_space(3.0);
            ui.horizontal(|ui| {
                ui.label(&self.status);
            });
            ui.add_space(3.0);
        });

        // Main content
        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                // ═══════════════════════════════════════════════════════════
                // Category Selection
                // ═══════════════════════════════════════════════════════════
                ui.group(|ui| {
                    ui.heading("Category");
                    ui.horizontal_wrapped(|ui| {
                        for (i, category) in DORK_CATEGORIES.iter().enumerate() {
                            if ui.selectable_label(self.selected_category == i, category.name).clicked() {
                                self.selected_category = i;
                                self.selected_template = 0;
                                self.generate_query();
                            }
                        }
                    });
                });

                ui.add_space(10.0);

                // ═══════════════════════════════════════════════════════════
                // Template Selection
                // ═══════════════════════════════════════════════════════════
                ui.group(|ui| {
                    ui.heading("Dork Templates");

                    let category = self.current_category();
                    for (i, template) in category.dorks.iter().enumerate() {
                        ui.horizontal(|ui| {
                            if ui.radio(self.selected_template == i, "").clicked() {
                                self.selected_template = i;
                                self.generate_query();
                            }
                            ui.vertical(|ui| {
                                ui.strong(template.name);
                                ui.label(template.description);
                                ui.code(template.template);
                            });
                        });
                        ui.separator();
                    }
                });

                ui.add_space(10.0);

                // ═══════════════════════════════════════════════════════════
                // Fill-in-the-blank Fields
                // ═══════════════════════════════════════════════════════════
                ui.group(|ui| {
                    ui.heading("Fill In The Blanks");

                    let template = self.current_template();
                    let mut changed = false;

                    for field in template.fields {
                        ui.horizontal(|ui| {
                            ui.label(format!("{}:", field_to_label(field)));

                            let value = self.field_values
                                .entry(field.to_string())
                                .or_insert_with(String::new);

                            let response = ui.add(
                                egui::TextEdit::singleline(value)
                                    .hint_text(field_hint(field))
                                    .desired_width(400.0)
                            );

                            if response.changed() {
                                changed = true;
                            }
                        });
                    }

                    if changed {
                        self.generate_query();
                    }
                });

                ui.add_space(10.0);

                // ═══════════════════════════════════════════════════════════
                // Generated Query
                // ═══════════════════════════════════════════════════════════
                ui.group(|ui| {
                    ui.heading("Generated Query");

                    let query_text = if self.generated_query.is_empty() {
                        "Fill in the fields above to generate a query".to_string()
                    } else {
                        self.generated_query.clone()
                    };

                    ui.add(
                        egui::TextEdit::multiline(&mut query_text.clone())
                            .font(egui::TextStyle::Monospace)
                            .desired_width(f32::INFINITY)
                            .desired_rows(2)
                            .interactive(false)
                    );

                    ui.add_space(5.0);

                    ui.horizontal(|ui| {
                        if ui.button("Copy to Clipboard").clicked() {
                            self.copy_to_clipboard();
                        }

                        if ui.button("Open in Browser").clicked() {
                            self.open_in_browser();
                        }

                        if ui.button("Save to History").clicked() {
                            self.add_to_history();
                        }

                        if ui.button("Clear").clicked() {
                            for value in self.field_values.values_mut() {
                                value.clear();
                            }
                            self.generated_query.clear();
                            self.status = "Cleared".to_string();
                        }
                    });
                });

                ui.add_space(10.0);

                // ═══════════════════════════════════════════════════════════
                // History Panel
                // ═══════════════════════════════════════════════════════════
                ui.group(|ui| {
                    ui.horizontal(|ui| {
                        ui.heading("Query History");
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.button("Clear All").clicked() {
                                self.history.clear();
                                self.save_history();
                            }
                        });
                    });

                    if self.history.is_empty() {
                        ui.label("No history yet. Save queries to see them here.");
                    } else {
                        let mut to_remove: Option<usize> = None;
                        let mut to_reuse: Option<String> = None;

                        for (i, entry) in self.history.iter().enumerate() {
                            ui.horizontal(|ui| {
                                ui.label(format!("[{}]", entry.category));
                                ui.label(&entry.query);

                                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                    if ui.small_button("Delete").clicked() {
                                        to_remove = Some(i);
                                    }
                                    if ui.small_button("Re-use").clicked() {
                                        to_reuse = Some(entry.query.clone());
                                    }
                                });
                            });
                            ui.separator();
                        }

                        if let Some(i) = to_remove {
                            self.history.remove(i);
                            self.save_history();
                        }

                        if let Some(query) = to_reuse {
                            self.generated_query = query;
                            self.status = "Query loaded from history".to_string();
                        }
                    }
                });
            });
        });
    }
}

fn field_to_label(field: &str) -> &str {
    match field {
        "domain" => "Target Domain",
        "keyword" => "Keyword (optional)",
        "folder" => "Folder Name",
        "custom" => "Custom Query",
        _ => field,
    }
}

fn field_hint(field: &str) -> &str {
    match field {
        "domain" => "example.com",
        "keyword" => "confidential, password, etc.",
        "folder" => "backup, admin, etc.",
        "custom" => "Enter your full Google dork query",
        _ => "Enter value...",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_url_encoding() {
        assert_eq!(urlencoding_simple("hello world"), "hello+world");
        assert_eq!(urlencoding_simple("site:example.com"), "site%3Aexample.com");
    }
}
```

---

## Usage Guide

### Basic Workflow

1. **Select Category** - Click on a category tab (Files, Login, etc.)
2. **Choose Template** - Click the radio button next to a dork template
3. **Fill Fields** - Enter the target domain and any optional keywords
4. **Generate** - Query updates automatically as you type
5. **Use Query** - Copy to clipboard or open directly in browser
6. **Save** - Store useful queries in history for later

### Example: Finding PDF Files

1. Select "Files & Documents" category
2. Choose "PDF Files" template
3. Enter `example.com` in Domain field
4. Enter `confidential` in Keyword field
5. Generated: `site:example.com filetype:pdf confidential`
6. Click "Open in Browser"

---

## Red Team Applications

### Reconnaissance Phase
- Find exposed documents with sensitive info
- Discover admin panels and login pages
- Locate backup files and database dumps
- Identify technology stack through error messages

### OPSEC Considerations
- Queries are logged by Google
- Use VPN/Tor for sensitive reconnaissance
- Consider rate limiting between searches
- Save queries locally, not in browser history

---

## Blue Team Applications

### Exposure Assessment
- Regularly check your own domains
- Find accidentally exposed files
- Discover unauthorized admin panels
- Identify information leakage

### Recommended Checks
```
site:yourcompany.com filetype:pdf
site:yourcompany.com intitle:"index of"
site:yourcompany.com inurl:admin
site:yourcompany.com intext:password filetype:txt
site:yourcompany.com "BEGIN RSA PRIVATE KEY"
```

---

## Exercises

1. **Add More Templates**: Expand the dork database with 20+ new templates
2. **Export Feature**: Add button to export history as CSV or JSON
3. **Batch Mode**: Allow running multiple dorks against same domain
4. **Results Parser**: Fetch and parse Google results (advanced)

---

[← G10 Log Viewer](../02_Security_Tools/G10_Log_Viewer/README.md) | [Next: G12 Multi-Tool Launcher →](../G12_Multi_Tool_Launcher/README.md)
