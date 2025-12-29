//! G01_Hello_GUI - Simple GUI Window with Buttons and Text
//! =========================================================
//!
//! This is the first GUI project in the Rust Security Bible, demonstrating
//! fundamental egui/eframe concepts for building desktop applications.
//!
//! Key Concepts Covered:
//! - Setting up an eframe application
//! - Creating windows and panels
//! - Adding buttons, labels, and text
//! - Handling user interactions
//! - Managing application state
//! - Styling and theming basics

use eframe::egui;
use std::time::{Duration, Instant};

/// Main application state structure
///
/// In egui's immediate mode paradigm, we maintain all application state
/// in a struct that persists across frames. Each frame, the UI is rebuilt
/// from scratch using this state.
struct HelloGuiApp {
    // Basic state for demonstrations
    click_count: u32,
    message: String,
    show_about_window: bool,
    show_demo_window: bool,

    // Text that updates based on user actions
    status_text: String,
    last_action: String,

    // For demonstrating animations/updates
    animation_progress: f32,
    is_animating: bool,
    last_update: Instant,

    // Theme settings
    dark_mode: bool,

    // Different button states for demonstration
    toggle_states: [bool; 5],

    // Radio button selection
    selected_option: usize,

    // Slider value
    slider_value: f32,

    // Color picker
    selected_color: egui::Color32,

    // Checkbox states
    checkbox_states: Vec<(String, bool)>,
}

impl Default for HelloGuiApp {
    fn default() -> Self {
        Self {
            click_count: 0,
            message: String::from("Welcome to Rust GUI Development!"),
            show_about_window: false,
            show_demo_window: false,
            status_text: String::from("Ready"),
            last_action: String::from("None"),
            animation_progress: 0.0,
            is_animating: false,
            last_update: Instant::now(),
            dark_mode: true,
            toggle_states: [false; 5],
            selected_option: 0,
            slider_value: 50.0,
            selected_color: egui::Color32::from_rgb(100, 150, 200),
            checkbox_states: vec![
                ("Enable notifications".to_string(), true),
                ("Auto-save".to_string(), false),
                ("Show tooltips".to_string(), true),
                ("Debug mode".to_string(), false),
            ],
        }
    }
}

impl HelloGuiApp {
    /// Create a new instance of the application
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        // Customize the look and feel
        // egui allows extensive customization of visuals
        let mut style = (*cc.egui_ctx.style()).clone();

        // Increase spacing for better readability
        style.spacing.item_spacing = egui::vec2(10.0, 8.0);
        style.spacing.button_padding = egui::vec2(8.0, 4.0);

        cc.egui_ctx.set_style(style);

        // Set default visuals (dark mode)
        cc.egui_ctx.set_visuals(egui::Visuals::dark());

        Self::default()
    }

    /// Render the top menu bar
    ///
    /// Menu bars are common in desktop applications. egui provides
    /// a convenient way to create them with nested menus.
    fn render_menu_bar(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("menu_bar").show(ctx, |ui| {
            egui::menu::bar(ui, |ui| {
                // File menu
                ui.menu_button("File", |ui| {
                    if ui.button("New").clicked() {
                        self.last_action = "File > New clicked".to_string();
                        self.status_text = "Creating new...".to_string();
                        ui.close_menu();
                    }
                    if ui.button("Open").clicked() {
                        self.last_action = "File > Open clicked".to_string();
                        self.status_text = "Opening file...".to_string();
                        ui.close_menu();
                    }
                    if ui.button("Save").clicked() {
                        self.last_action = "File > Save clicked".to_string();
                        self.status_text = "Saving...".to_string();
                        ui.close_menu();
                    }
                    ui.separator();
                    if ui.button("Exit").clicked() {
                        std::process::exit(0);
                    }
                });

                // Edit menu
                ui.menu_button("Edit", |ui| {
                    if ui.button("Undo").clicked() {
                        self.last_action = "Edit > Undo clicked".to_string();
                        ui.close_menu();
                    }
                    if ui.button("Redo").clicked() {
                        self.last_action = "Edit > Redo clicked".to_string();
                        ui.close_menu();
                    }
                    ui.separator();
                    if ui.button("Preferences").clicked() {
                        self.last_action = "Edit > Preferences clicked".to_string();
                        ui.close_menu();
                    }
                });

                // View menu
                ui.menu_button("View", |ui| {
                    if ui.checkbox(&mut self.dark_mode, "Dark Mode").clicked() {
                        // Theme will be updated in the main update loop
                        self.last_action = format!("Dark mode: {}", self.dark_mode);
                    }
                    ui.separator();
                    if ui.button("Reset Layout").clicked() {
                        self.last_action = "View > Reset Layout clicked".to_string();
                        ui.close_menu();
                    }
                });

                // Help menu
                ui.menu_button("Help", |ui| {
                    if ui.button("Documentation").clicked() {
                        self.last_action = "Help > Documentation clicked".to_string();
                        ui.close_menu();
                    }
                    ui.separator();
                    if ui.button("About").clicked() {
                        self.show_about_window = true;
                        ui.close_menu();
                    }
                });
            });
        });
    }

    /// Render the left side panel with navigation/options
    fn render_side_panel(&mut self, ctx: &egui::Context) {
        egui::SidePanel::left("side_panel")
            .resizable(true)
            .default_width(200.0)
            .min_width(150.0)
            .max_width(400.0)
            .show(ctx, |ui| {
                ui.heading("Navigation");
                ui.separator();

                // Collapsing headers organize content
                egui::CollapsingHeader::new("Quick Actions")
                    .default_open(true)
                    .show(ui, |ui| {
                        if ui.button("🏠 Home").clicked() {
                            self.last_action = "Home clicked".to_string();
                        }
                        if ui.button("⚙ Settings").clicked() {
                            self.last_action = "Settings clicked".to_string();
                        }
                        if ui.button("📊 Dashboard").clicked() {
                            self.last_action = "Dashboard clicked".to_string();
                        }
                    });

                egui::CollapsingHeader::new("Toggle Buttons")
                    .default_open(true)
                    .show(ui, |ui| {
                        let toggle_names = ["Option A", "Option B", "Option C", "Option D", "Option E"];
                        for (i, name) in toggle_names.iter().enumerate() {
                            if ui.toggle_value(&mut self.toggle_states[i], *name).clicked() {
                                self.last_action = format!("{} toggled: {}", name, self.toggle_states[i]);
                            }
                        }
                    });

                egui::CollapsingHeader::new("Radio Selection")
                    .default_open(true)
                    .show(ui, |ui| {
                        let options = ["Alpha", "Beta", "Gamma", "Delta"];
                        for (i, option) in options.iter().enumerate() {
                            if ui.radio_value(&mut self.selected_option, i, *option).clicked() {
                                self.last_action = format!("Selected: {}", option);
                            }
                        }
                    });

                ui.separator();

                // Slider demonstration
                ui.label("Slider Value:");
                if ui.add(egui::Slider::new(&mut self.slider_value, 0.0..=100.0)
                    .suffix("%"))
                    .changed() {
                    self.last_action = format!("Slider: {:.1}%", self.slider_value);
                }

                ui.separator();

                // Color picker
                ui.label("Select Color:");
                if ui.color_edit_button_srgba(&mut self.selected_color).changed() {
                    self.last_action = format!("Color: {:?}", self.selected_color);
                }
            });
    }

    /// Render the bottom status bar
    fn render_status_bar(&self, ctx: &egui::Context) {
        egui::TopBottomPanel::bottom("status_bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(format!("Status: {}", self.status_text));
                ui.separator();
                ui.label(format!("Clicks: {}", self.click_count));
                ui.separator();
                ui.label(format!("Last Action: {}", self.last_action));

                // Right-align some info
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label("Rust Security Bible - G01");
                });
            });
        });
    }

    /// Render the central content area
    fn render_central_panel(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().show(ctx, |ui| {
            // Scrollable area for content
            egui::ScrollArea::vertical().show(ui, |ui| {
                // Header with styled text
                ui.heading("Hello, Rust GUI!");
                ui.add_space(10.0);

                // Rich text demonstration
                ui.label(
                    egui::RichText::new(&self.message)
                        .size(16.0)
                        .color(self.selected_color)
                );

                ui.add_space(20.0);
                ui.separator();

                // Button section
                ui.heading("Button Examples");
                ui.add_space(10.0);

                ui.horizontal(|ui| {
                    // Regular button
                    if ui.button("Click Me!").clicked() {
                        self.click_count += 1;
                        self.status_text = "Button clicked!".to_string();
                        self.last_action = "Main button clicked".to_string();
                    }

                    // Button with custom size
                    if ui.add_sized([120.0, 40.0], egui::Button::new("Large Button")).clicked() {
                        self.click_count += 1;
                        self.last_action = "Large button clicked".to_string();
                    }

                    // Styled button
                    if ui.add(
                        egui::Button::new(
                            egui::RichText::new("Styled Button")
                                .color(egui::Color32::WHITE)
                        )
                        .fill(egui::Color32::from_rgb(0, 120, 215))
                    ).clicked() {
                        self.click_count += 1;
                        self.last_action = "Styled button clicked".to_string();
                    }
                });

                ui.add_space(10.0);

                ui.horizontal(|ui| {
                    // Reset button
                    if ui.button("Reset Counter").clicked() {
                        self.click_count = 0;
                        self.status_text = "Counter reset".to_string();
                        self.last_action = "Counter reset".to_string();
                    }

                    // Animation toggle
                    let anim_text = if self.is_animating { "Stop Animation" } else { "Start Animation" };
                    if ui.button(anim_text).clicked() {
                        self.is_animating = !self.is_animating;
                        self.last_action = format!("Animation: {}", self.is_animating);
                    }

                    // Demo window toggle
                    if ui.button("Show Demo").clicked() {
                        self.show_demo_window = true;
                        self.last_action = "Demo window opened".to_string();
                    }
                });

                ui.add_space(20.0);
                ui.separator();

                // Animation/Progress demonstration
                ui.heading("Animation Example");
                ui.add_space(10.0);

                // Progress bar
                let progress = self.animation_progress / 100.0;
                ui.add(egui::ProgressBar::new(progress)
                    .text(format!("{:.1}%", self.animation_progress))
                    .animate(self.is_animating));

                ui.add_space(20.0);
                ui.separator();

                // Checkboxes section
                ui.heading("Checkboxes");
                ui.add_space(10.0);

                for (label, checked) in &mut self.checkbox_states {
                    if ui.checkbox(checked, label.as_str()).clicked() {
                        self.last_action = format!("{}: {}", label, checked);
                    }
                }

                ui.add_space(20.0);
                ui.separator();

                // Grid layout demonstration
                ui.heading("Grid Layout");
                ui.add_space(10.0);

                egui::Grid::new("demo_grid")
                    .num_columns(3)
                    .spacing([20.0, 10.0])
                    .striped(true)
                    .show(ui, |ui| {
                        ui.label("Column 1");
                        ui.label("Column 2");
                        ui.label("Column 3");
                        ui.end_row();

                        ui.label("Row 1, Cell 1");
                        ui.label("Row 1, Cell 2");
                        if ui.button("Action 1").clicked() {
                            self.last_action = "Grid Action 1".to_string();
                        }
                        ui.end_row();

                        ui.label("Row 2, Cell 1");
                        ui.label("Row 2, Cell 2");
                        if ui.button("Action 2").clicked() {
                            self.last_action = "Grid Action 2".to_string();
                        }
                        ui.end_row();

                        ui.label("Row 3, Cell 1");
                        ui.label("Row 3, Cell 2");
                        if ui.button("Action 3").clicked() {
                            self.last_action = "Grid Action 3".to_string();
                        }
                        ui.end_row();
                    });

                ui.add_space(20.0);
                ui.separator();

                // Frames and groups
                ui.heading("Frames and Groups");
                ui.add_space(10.0);

                ui.horizontal(|ui| {
                    // Frame with custom styling
                    egui::Frame::none()
                        .fill(egui::Color32::from_rgb(30, 30, 40))
                        .inner_margin(15.0)
                        .outer_margin(5.0)
                        .rounding(10.0)
                        .stroke(egui::Stroke::new(2.0, egui::Color32::from_rgb(100, 100, 150)))
                        .show(ui, |ui| {
                            ui.label("Styled Frame");
                            ui.label("With custom borders");
                            if ui.button("Frame Button").clicked() {
                                self.last_action = "Frame button clicked".to_string();
                            }
                        });

                    // Another styled frame
                    egui::Frame::none()
                        .fill(egui::Color32::from_rgb(40, 30, 30))
                        .inner_margin(15.0)
                        .outer_margin(5.0)
                        .rounding(10.0)
                        .stroke(egui::Stroke::new(2.0, egui::Color32::from_rgb(150, 100, 100)))
                        .show(ui, |ui| {
                            ui.label("Another Frame");
                            ui.label("Different style");
                            if ui.button("Action").clicked() {
                                self.last_action = "Another frame action".to_string();
                            }
                        });
                });

                ui.add_space(20.0);

                // Footer with version info
                ui.separator();
                ui.horizontal(|ui| {
                    ui.label("Built with egui/eframe");
                    ui.separator();
                    ui.label(format!("egui version: {}", egui::__version__()));
                });
            });
        });
    }

    /// Render the about window
    fn render_about_window(&mut self, ctx: &egui::Context) {
        egui::Window::new("About")
            .open(&mut self.show_about_window)
            .resizable(false)
            .collapsible(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.vertical_centered(|ui| {
                    ui.heading("G01 - Hello GUI");
                    ui.add_space(10.0);
                    ui.label("Rust Security Bible");
                    ui.label("Chapter 07: GUI Development");
                    ui.add_space(10.0);
                    ui.label("This project demonstrates fundamental");
                    ui.label("egui/eframe concepts for building");
                    ui.label("desktop GUI applications in Rust.");
                    ui.add_space(10.0);
                    if ui.button("Close").clicked() {
                        self.show_about_window = false;
                    }
                });
            });
    }

    /// Render a demo window with additional widgets
    fn render_demo_window(&mut self, ctx: &egui::Context) {
        egui::Window::new("Widget Demo")
            .open(&mut self.show_demo_window)
            .default_size([400.0, 300.0])
            .show(ctx, |ui| {
                ui.heading("Additional Widget Examples");
                ui.separator();

                egui::CollapsingHeader::new("Tooltips")
                    .default_open(true)
                    .show(ui, |ui| {
                        ui.label("Hover over items for tooltips")
                            .on_hover_text("This is a tooltip!");

                        ui.button("Button with Tooltip")
                            .on_hover_text("Click me to do something!");
                    });

                egui::CollapsingHeader::new("Links")
                    .default_open(true)
                    .show(ui, |ui| {
                        ui.hyperlink_to("egui documentation", "https://docs.rs/egui");
                        ui.hyperlink_to("Rust website", "https://www.rust-lang.org");
                    });

                egui::CollapsingHeader::new("Misc Widgets")
                    .default_open(true)
                    .show(ui, |ui| {
                        ui.spinner();  // Loading spinner
                        ui.separator();

                        // Code block
                        ui.code("let x = 42;");

                        // Monospace text
                        ui.monospace("Fixed-width text");
                    });
            });
    }
}

/// Implementation of the eframe::App trait
///
/// This is the core trait that makes our struct work with eframe.
/// The update() method is called every frame to rebuild the UI.
impl eframe::App for HelloGuiApp {
    /// Called each frame to update and render the UI
    ///
    /// In immediate mode GUI, we rebuild the entire interface every frame.
    /// This might seem inefficient, but egui is highly optimized for this pattern.
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Update theme based on dark_mode setting
        if self.dark_mode {
            ctx.set_visuals(egui::Visuals::dark());
        } else {
            ctx.set_visuals(egui::Visuals::light());
        }

        // Handle animation updates
        if self.is_animating {
            let now = Instant::now();
            let delta = now.duration_since(self.last_update);

            if delta >= Duration::from_millis(16) {  // ~60 FPS
                self.animation_progress += 0.5;
                if self.animation_progress > 100.0 {
                    self.animation_progress = 0.0;
                }
                self.last_update = now;
            }

            // Request continuous repainting while animating
            ctx.request_repaint();
        }

        // Render all UI components
        self.render_menu_bar(ctx);
        self.render_side_panel(ctx);
        self.render_status_bar(ctx);
        self.render_central_panel(ctx);

        // Render windows (these are separate from panels)
        self.render_about_window(ctx);
        self.render_demo_window(ctx);
    }
}

/// Main entry point
///
/// Sets up the native application with eframe and runs the event loop.
fn main() -> eframe::Result<()> {
    // Configure native window options
    let native_options = eframe::NativeOptions {
        // Set initial window size
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1024.0, 768.0])
            .with_min_inner_size([800.0, 600.0])
            .with_title("G01 - Hello GUI | Rust Security Bible"),

        // Enable multisampling for smoother graphics
        multisampling: 4,

        // Use hardware acceleration
        hardware_acceleration: eframe::HardwareAcceleration::Preferred,

        ..Default::default()
    };

    // Run the application
    // This starts the event loop and doesn't return until the window is closed
    eframe::run_native(
        "Hello GUI",
        native_options,
        Box::new(|cc| Ok(Box::new(HelloGuiApp::new(cc)))),
    )
}
