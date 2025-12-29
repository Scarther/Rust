# Chapter 7: GUI Development in Rust

## Overview

Build graphical user interfaces for security tools, automation dashboards, and interactive utilities. This chapter covers multiple GUI frameworks and practical security applications.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         RUST GUI ECOSYSTEM                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  NATIVE GUI FRAMEWORKS                                                       │
│  ═════════════════════                                                       │
│  • egui/eframe    - Immediate mode, pure Rust, easy, cross-platform         │
│  • iced           - Elm-inspired, declarative, beautiful                     │
│  • Tauri          - Web tech frontend (HTML/CSS/JS) + Rust backend          │
│  • gtk-rs         - GTK bindings, native Linux look                         │
│  • druid          - Data-first, experimental                                │
│                                                                              │
│  WEB-BASED (Tauri/Electron alternatives)                                    │
│  ═══════════════════════════════════════                                    │
│  • Tauri          - Lightweight, secure, recommended                        │
│  • Dioxus         - React-like, can target web/desktop/mobile               │
│  • Yew            - WebAssembly frontend framework                          │
│                                                                              │
│  RECOMMENDED FOR SECURITY TOOLS                                             │
│  ═════════════════════════════════                                          │
│  • egui   - Quick prototypes, simple tools, cross-platform                  │
│  • Tauri  - Professional apps, complex UIs, web skills reuse                │
│  • iced   - Native feel, when you want beautiful native apps                │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Chapter Contents

| Section | Description |
|---------|-------------|
| [01_Basics](01_Basics/) | GUI fundamentals with egui |
| [02_Security_Tools](02_Security_Tools/) | Port scanner GUI, hash calculator, etc. |
| [03_Automation_Interfaces](03_Automation_Interfaces/) | Google Dorking, multi-tool launcher |

## Projects Overview

### 01_Basics - Foundation Projects
| Project | Description | Framework |
|---------|-------------|-----------|
| G01 | Hello GUI World | egui |
| G02 | Buttons and Input | egui |
| G03 | Forms and Validation | egui |
| G04 | File Dialogs | egui + rfd |
| G05 | Multi-window Apps | egui |

### 02_Security_Tools - GUI Security Applications
| Project | Description | Framework |
|---------|-------------|-----------|
| G06 | Port Scanner GUI | egui |
| G07 | Hash Calculator GUI | egui |
| G08 | File Integrity Checker | egui |
| G09 | Network Monitor Dashboard | egui |
| G10 | Log Viewer | egui |

### 03_Automation_Interfaces - Advanced Tools
| Project | Description | Framework |
|---------|-------------|-----------|
| G11 | Google Dorking Interface | egui |
| G12 | Multi-Tool Launcher | egui |
| G13 | Reconnaissance Dashboard | egui |
| G14 | Report Generator | egui |
| G15 | API Tester | Tauri |

## Quick Start with egui

### Why egui?

1. **Pure Rust** - No external dependencies, single binary
2. **Immediate Mode** - Simple mental model, no callbacks
3. **Cross-Platform** - Windows, Linux, macOS, Web (WASM)
4. **Fast** - 60 FPS even with complex UIs
5. **Easy** - Get a window with UI in < 50 lines

### Minimal Example

```rust
use eframe::egui;

fn main() -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions::default();
    eframe::run_native(
        "My Security Tool",
        options,
        Box::new(|_cc| Box::new(MyApp::default())),
    )
}

struct MyApp {
    target: String,
    results: Vec<String>,
}

impl Default for MyApp {
    fn default() -> Self {
        Self {
            target: String::new(),
            results: Vec::new(),
        }
    }
}

impl eframe::App for MyApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Security Scanner");

            ui.horizontal(|ui| {
                ui.label("Target:");
                ui.text_edit_singleline(&mut self.target);
                if ui.button("Scan").clicked() {
                    self.results.push(format!("Scanning {}...", self.target));
                }
            });

            ui.separator();

            for result in &self.results {
                ui.label(result);
            }
        });
    }
}
```

### Cargo.toml for egui
```toml
[package]
name = "gui_tool"
version = "0.1.0"
edition = "2021"

[dependencies]
eframe = "0.24"
egui = "0.24"
```

## GUI Patterns for Security Tools

### Pattern 1: Input Form + Results Panel
```
┌────────────────────────────────────────────────────────────┐
│  TOOL NAME                                          [_][□][X]│
├────────────────────────────────────────────────────────────┤
│  ┌─ Input ──────────────────────────────────────────────┐  │
│  │ Target: [_________________________]                   │  │
│  │ Options: [dropdown] [checkbox] [slider]              │  │
│  │                              [  Run  ] [  Clear  ]   │  │
│  └──────────────────────────────────────────────────────┘  │
│  ┌─ Results ────────────────────────────────────────────┐  │
│  │ ▸ Result 1: 192.168.1.1:22 - SSH Open               │  │
│  │ ▸ Result 2: 192.168.1.1:80 - HTTP Open              │  │
│  │ ▸ Result 3: 192.168.1.1:443 - HTTPS Open            │  │
│  │                                                      │  │
│  └──────────────────────────────────────────────────────┘  │
│  Status: Scan complete - 3 ports found                     │
└────────────────────────────────────────────────────────────┘
```

### Pattern 2: Dashboard with Multiple Panels
```
┌────────────────────────────────────────────────────────────┐
│  SECURITY DASHBOARD                                 [_][□][X]│
├──────────────────────┬─────────────────────────────────────┤
│  ┌─ Tools ─────────┐ │  ┌─ Output ───────────────────────┐ │
│  │ ○ Port Scanner  │ │  │                                │ │
│  │ ○ Hash Calc     │ │  │  [Results appear here]         │ │
│  │ ○ DNS Lookup    │ │  │                                │ │
│  │ ○ Whois         │ │  │                                │ │
│  └─────────────────┘ │  └────────────────────────────────┘ │
│  ┌─ Config ────────┐ │  ┌─ Log ──────────────────────────┐ │
│  │ Threads: [100]  │ │  │ [12:00] Started scan           │ │
│  │ Timeout: [1000] │ │  │ [12:01] Found port 22          │ │
│  │ [x] Verbose     │ │  │ [12:02] Scan complete          │ │
│  └─────────────────┘ │  └────────────────────────────────┘ │
└──────────────────────┴─────────────────────────────────────┘
```

## Key Concepts

### Immediate Mode GUI

Unlike traditional "retained mode" GUIs (Qt, GTK), egui uses "immediate mode":

```rust
// Every frame, you describe the entire UI
fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
    egui::CentralPanel::default().show(ctx, |ui| {
        // This runs 60 times per second
        // UI is rebuilt each frame
        // State is stored in your struct, not the framework

        if ui.button("Click me").clicked() {
            // Handle click immediately
            self.counter += 1;
        }

        ui.label(format!("Count: {}", self.counter));
    });
}
```

### Threading for Long Operations

Never block the UI thread! Use channels:

```rust
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread;

struct App {
    tx: Sender<String>,
    rx: Receiver<String>,
    results: Vec<String>,
    scanning: bool,
}

impl App {
    fn start_scan(&mut self, target: String) {
        self.scanning = true;
        let tx = self.tx.clone();

        thread::spawn(move || {
            // Long operation in background
            for port in 1..100 {
                thread::sleep(Duration::from_millis(10));
                tx.send(format!("Scanning port {}", port)).unwrap();
            }
            tx.send("DONE".to_string()).unwrap();
        });
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Check for messages from background thread
        while let Ok(msg) = self.rx.try_recv() {
            if msg == "DONE" {
                self.scanning = false;
            } else {
                self.results.push(msg);
            }
        }

        // Request repaint while scanning
        if self.scanning {
            ctx.request_repaint();
        }

        // ... rest of UI
    }
}
```

## Learning Path

```
G01-G05: GUI Basics
    ↓
G06-G10: Security Tool GUIs
    ↓
G11-G15: Advanced Automation
    ↓
[Integrate with Red/Blue Team tools]
```
