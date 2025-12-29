//! G05_Progress_Display - Progress Bars and Status Displays
//! =========================================================
//!
//! This project demonstrates various progress indicators and status
//! displays for long-running security operations.
//!
//! Key Concepts Covered:
//! - Determinate progress bars
//! - Indeterminate spinners
//! - Multi-step progress tracking
//! - Task queues and job management
//! - Time estimation (ETA)
//! - Threaded progress updates
//! - Cancel/pause operations

use eframe::egui;
use rand::Rng;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// Task status
#[derive(Debug, Clone, Copy, PartialEq)]
enum TaskStatus {
    Pending,
    Running,
    Paused,
    Completed,
    Failed,
    Cancelled,
}

impl TaskStatus {
    fn as_str(&self) -> &'static str {
        match self {
            TaskStatus::Pending => "Pending",
            TaskStatus::Running => "Running",
            TaskStatus::Paused => "Paused",
            TaskStatus::Completed => "Completed",
            TaskStatus::Failed => "Failed",
            TaskStatus::Cancelled => "Cancelled",
        }
    }

    fn color(&self) -> egui::Color32 {
        match self {
            TaskStatus::Pending => egui::Color32::GRAY,
            TaskStatus::Running => egui::Color32::from_rgb(100, 180, 255),
            TaskStatus::Paused => egui::Color32::from_rgb(255, 193, 7),
            TaskStatus::Completed => egui::Color32::from_rgb(76, 175, 80),
            TaskStatus::Failed => egui::Color32::from_rgb(244, 67, 54),
            TaskStatus::Cancelled => egui::Color32::from_rgb(158, 158, 158),
        }
    }
}

/// Task type for demonstration
#[derive(Debug, Clone, Copy, PartialEq)]
enum TaskType {
    PortScan,
    FileHash,
    NetworkAnalysis,
    LogParsing,
    VulnScan,
    Backup,
}

impl TaskType {
    fn all() -> Vec<TaskType> {
        vec![
            TaskType::PortScan,
            TaskType::FileHash,
            TaskType::NetworkAnalysis,
            TaskType::LogParsing,
            TaskType::VulnScan,
            TaskType::Backup,
        ]
    }

    fn as_str(&self) -> &'static str {
        match self {
            TaskType::PortScan => "Port Scan",
            TaskType::FileHash => "File Hashing",
            TaskType::NetworkAnalysis => "Network Analysis",
            TaskType::LogParsing => "Log Parsing",
            TaskType::VulnScan => "Vulnerability Scan",
            TaskType::Backup => "Backup Operation",
        }
    }

    fn icon(&self) -> &'static str {
        match self {
            TaskType::PortScan => "[PS]",
            TaskType::FileHash => "[FH]",
            TaskType::NetworkAnalysis => "[NA]",
            TaskType::LogParsing => "[LP]",
            TaskType::VulnScan => "[VS]",
            TaskType::Backup => "[BK]",
        }
    }
}

/// A single task with progress tracking
#[derive(Clone)]
struct Task {
    id: u32,
    name: String,
    task_type: TaskType,
    status: TaskStatus,
    progress: f32,          // 0.0 to 1.0
    current_item: String,   // Current item being processed
    total_items: u32,
    processed_items: u32,
    started_at: Option<Instant>,
    completed_at: Option<Instant>,
    error_message: Option<String>,
    sub_tasks: Vec<SubTask>,
}

impl Task {
    fn new(id: u32, name: &str, task_type: TaskType, total_items: u32) -> Self {
        Self {
            id,
            name: name.to_string(),
            task_type,
            status: TaskStatus::Pending,
            progress: 0.0,
            current_item: String::new(),
            total_items,
            processed_items: 0,
            started_at: None,
            completed_at: None,
            error_message: None,
            sub_tasks: Vec::new(),
        }
    }

    fn with_subtasks(mut self, subtasks: Vec<&str>) -> Self {
        self.sub_tasks = subtasks
            .iter()
            .map(|name| SubTask {
                name: name.to_string(),
                status: TaskStatus::Pending,
                progress: 0.0,
            })
            .collect();
        self
    }

    fn elapsed(&self) -> Option<Duration> {
        self.started_at.map(|start| {
            self.completed_at
                .unwrap_or_else(Instant::now)
                .duration_since(start)
        })
    }

    fn elapsed_string(&self) -> String {
        match self.elapsed() {
            Some(d) => format_duration(d),
            None => "--:--".to_string(),
        }
    }

    fn eta(&self) -> Option<Duration> {
        if self.progress > 0.0 && self.progress < 1.0 {
            if let Some(elapsed) = self.elapsed() {
                let total_estimated = elapsed.as_secs_f32() / self.progress;
                let remaining = total_estimated - elapsed.as_secs_f32();
                return Some(Duration::from_secs_f32(remaining.max(0.0)));
            }
        }
        None
    }

    fn eta_string(&self) -> String {
        match self.eta() {
            Some(d) => format_duration(d),
            None => "--:--".to_string(),
        }
    }
}

/// Sub-task for multi-step operations
#[derive(Clone)]
struct SubTask {
    name: String,
    status: TaskStatus,
    progress: f32,
}

/// Format duration as human-readable string
fn format_duration(d: Duration) -> String {
    let secs = d.as_secs();
    let mins = secs / 60;
    let hours = mins / 60;

    if hours > 0 {
        format!("{}h {:02}m {:02}s", hours, mins % 60, secs % 60)
    } else if mins > 0 {
        format!("{}m {:02}s", mins, secs % 60)
    } else {
        format!("{}s", secs)
    }
}

/// Shared state for background progress updates
#[derive(Default)]
struct SharedProgress {
    tasks: Vec<Task>,
    is_running: bool,
}

/// Main application state
struct ProgressDisplayApp {
    // Shared state with background thread
    shared: Arc<Mutex<SharedProgress>>,

    // Task management
    next_task_id: u32,
    selected_task: Option<u32>,

    // Demo controls
    new_task_type: TaskType,
    new_task_name: String,
    new_task_items: u32,
    auto_add_tasks: bool,
    simulation_speed: f32,

    // Queue management
    task_queue: VecDeque<Task>,
    max_concurrent: usize,

    // History
    completed_tasks: Vec<Task>,
    max_history: usize,

    // UI state
    show_completed: bool,
    show_queue: bool,
    dark_mode: bool,

    // Animation
    spinner_angle: f32,
    pulse_value: f32,
    pulse_direction: bool,
}

impl Default for ProgressDisplayApp {
    fn default() -> Self {
        Self {
            shared: Arc::new(Mutex::new(SharedProgress::default())),
            next_task_id: 1,
            selected_task: None,
            new_task_type: TaskType::PortScan,
            new_task_name: String::new(),
            new_task_items: 100,
            auto_add_tasks: false,
            simulation_speed: 1.0,
            task_queue: VecDeque::new(),
            max_concurrent: 3,
            completed_tasks: Vec::new(),
            max_history: 10,
            show_completed: true,
            show_queue: true,
            dark_mode: true,
            spinner_angle: 0.0,
            pulse_value: 0.0,
            pulse_direction: true,
        }
    }
}

impl ProgressDisplayApp {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        cc.egui_ctx.set_visuals(egui::Visuals::dark());
        Self::default()
    }

    /// Add a new task
    fn add_task(&mut self) {
        let name = if self.new_task_name.is_empty() {
            format!("{} #{}", self.new_task_type.as_str(), self.next_task_id)
        } else {
            self.new_task_name.clone()
        };

        let mut task = Task::new(
            self.next_task_id,
            &name,
            self.new_task_type,
            self.new_task_items,
        );

        // Add subtasks for certain task types
        match self.new_task_type {
            TaskType::VulnScan => {
                task = task.with_subtasks(vec![
                    "Initialize scanner",
                    "Port discovery",
                    "Service detection",
                    "Vulnerability check",
                    "Generate report",
                ]);
            }
            TaskType::Backup => {
                task = task.with_subtasks(vec![
                    "Prepare backup",
                    "Copy files",
                    "Compress data",
                    "Verify integrity",
                    "Cleanup",
                ]);
            }
            _ => {}
        }

        self.task_queue.push_back(task);
        self.next_task_id += 1;
        self.new_task_name.clear();

        self.process_queue();
    }

    /// Process task queue and start tasks up to max_concurrent
    fn process_queue(&mut self) {
        let mut shared = self.shared.lock().unwrap();
        let running_count = shared
            .tasks
            .iter()
            .filter(|t| t.status == TaskStatus::Running)
            .count();

        let available_slots = self.max_concurrent.saturating_sub(running_count);

        for _ in 0..available_slots {
            if let Some(mut task) = self.task_queue.pop_front() {
                task.status = TaskStatus::Running;
                task.started_at = Some(Instant::now());
                shared.tasks.push(task);
            }
        }

        if !shared.tasks.is_empty() || !self.task_queue.is_empty() {
            shared.is_running = true;
        }
    }

    /// Update task progress (simulated)
    fn update_progress(&mut self) {
        let mut shared = self.shared.lock().unwrap();
        let mut rng = rand::thread_rng();

        let mut completed_indices = Vec::new();

        for (index, task) in shared.tasks.iter_mut().enumerate() {
            if task.status == TaskStatus::Running {
                // Simulate progress
                let increment = rng.gen_range(0.001..0.02) * self.simulation_speed;
                task.progress = (task.progress + increment).min(1.0);
                task.processed_items = (task.progress * task.total_items as f32) as u32;

                // Update current item
                task.current_item = format!("Processing item {} of {}", task.processed_items, task.total_items);

                // Update subtasks
                if !task.sub_tasks.is_empty() {
                    let sub_progress = task.progress * task.sub_tasks.len() as f32;
                    for (i, sub) in task.sub_tasks.iter_mut().enumerate() {
                        let sub_start = i as f32;
                        let sub_end = (i + 1) as f32;

                        if sub_progress >= sub_end {
                            sub.status = TaskStatus::Completed;
                            sub.progress = 1.0;
                        } else if sub_progress > sub_start {
                            sub.status = TaskStatus::Running;
                            sub.progress = (sub_progress - sub_start).min(1.0);
                        }
                    }
                }

                // Check for completion
                if task.progress >= 1.0 {
                    // Simulate occasional failures
                    if rng.gen_bool(0.05) {
                        task.status = TaskStatus::Failed;
                        task.error_message = Some("Simulated error occurred".to_string());
                    } else {
                        task.status = TaskStatus::Completed;
                        for sub in &mut task.sub_tasks {
                            sub.status = TaskStatus::Completed;
                            sub.progress = 1.0;
                        }
                    }
                    task.completed_at = Some(Instant::now());
                    completed_indices.push(index);
                }
            }
        }

        // Move completed tasks to history
        for index in completed_indices.into_iter().rev() {
            let task = shared.tasks.remove(index);
            drop(shared);  // Release lock before modifying self

            if self.completed_tasks.len() >= self.max_history {
                self.completed_tasks.remove(0);
            }
            self.completed_tasks.push(task);

            shared = self.shared.lock().unwrap();
        }

        drop(shared);
        self.process_queue();
    }

    /// Cancel a task
    fn cancel_task(&mut self, task_id: u32) {
        let mut shared = self.shared.lock().unwrap();
        if let Some(task) = shared.tasks.iter_mut().find(|t| t.id == task_id) {
            task.status = TaskStatus::Cancelled;
            task.completed_at = Some(Instant::now());
        }

        // Also check queue
        self.task_queue.retain(|t| t.id != task_id);
    }

    /// Pause/resume a task
    fn toggle_pause(&mut self, task_id: u32) {
        let mut shared = self.shared.lock().unwrap();
        if let Some(task) = shared.tasks.iter_mut().find(|t| t.id == task_id) {
            match task.status {
                TaskStatus::Running => task.status = TaskStatus::Paused,
                TaskStatus::Paused => task.status = TaskStatus::Running,
                _ => {}
            }
        }
    }

    /// Clear completed tasks
    fn clear_completed(&mut self) {
        self.completed_tasks.clear();
        let mut shared = self.shared.lock().unwrap();
        shared.tasks.retain(|t| {
            t.status != TaskStatus::Completed
                && t.status != TaskStatus::Failed
                && t.status != TaskStatus::Cancelled
        });
    }

    /// Render the add task panel
    fn render_add_task(&mut self, ui: &mut egui::Ui) {
        ui.heading("Add New Task");
        ui.add_space(10.0);

        egui::Grid::new("add_task_grid")
            .num_columns(2)
            .spacing([10.0, 8.0])
            .show(ui, |ui| {
                ui.label("Task Type:");
                egui::ComboBox::from_id_salt("task_type")
                    .selected_text(self.new_task_type.as_str())
                    .show_ui(ui, |ui| {
                        for t in TaskType::all() {
                            ui.selectable_value(&mut self.new_task_type, t, t.as_str());
                        }
                    });
                ui.end_row();

                ui.label("Name:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.new_task_name)
                        .hint_text("Auto-generated if empty"),
                );
                ui.end_row();

                ui.label("Items:");
                ui.add(egui::Slider::new(&mut self.new_task_items, 10..=10000));
                ui.end_row();
            });

        ui.add_space(10.0);
        ui.horizontal(|ui| {
            if ui.button("Add Task").clicked() {
                self.add_task();
            }
            if ui.button("Add 5 Random").clicked() {
                let types = TaskType::all();
                let mut rng = rand::thread_rng();
                for _ in 0..5 {
                    self.new_task_type = types[rng.gen_range(0..types.len())];
                    self.new_task_items = rng.gen_range(50..500);
                    self.add_task();
                }
            }
        });

        ui.add_space(10.0);
        ui.separator();

        // Simulation controls
        ui.heading("Simulation");
        ui.add_space(5.0);

        ui.horizontal(|ui| {
            ui.label("Speed:");
            ui.add(egui::Slider::new(&mut self.simulation_speed, 0.1..=5.0));
        });

        ui.horizontal(|ui| {
            ui.label("Max Concurrent:");
            ui.add(egui::Slider::new(&mut self.max_concurrent, 1..=10));
        });

        ui.checkbox(&mut self.auto_add_tasks, "Auto-add random tasks");
    }

    /// Render a single task card
    fn render_task_card(&mut self, ui: &mut egui::Ui, task: &Task, is_queue: bool) {
        let frame = egui::Frame::none()
            .fill(egui::Color32::from_rgb(35, 35, 45))
            .inner_margin(10.0)
            .rounding(8.0)
            .stroke(egui::Stroke::new(
                1.0,
                if self.selected_task == Some(task.id) {
                    egui::Color32::from_rgb(100, 150, 255)
                } else {
                    egui::Color32::from_rgb(60, 60, 70)
                },
            ));

        frame.show(ui, |ui| {
            ui.horizontal(|ui| {
                // Type icon
                ui.label(
                    egui::RichText::new(task.task_type.icon())
                        .monospace()
                        .color(egui::Color32::from_rgb(150, 150, 200)),
                );

                // Task name
                ui.label(egui::RichText::new(&task.name).strong());

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    // Status badge
                    let badge_color = task.status.color();
                    egui::Frame::none()
                        .fill(badge_color.gamma_multiply(0.3))
                        .inner_margin(egui::vec2(8.0, 2.0))
                        .rounding(4.0)
                        .show(ui, |ui| {
                            ui.label(
                                egui::RichText::new(task.status.as_str())
                                    .color(badge_color)
                                    .small(),
                            );
                        });
                });
            });

            ui.add_space(5.0);

            if !is_queue {
                // Progress bar
                let progress_color = match task.status {
                    TaskStatus::Running => egui::Color32::from_rgb(100, 180, 255),
                    TaskStatus::Paused => egui::Color32::from_rgb(255, 193, 7),
                    TaskStatus::Completed => egui::Color32::from_rgb(76, 175, 80),
                    TaskStatus::Failed => egui::Color32::from_rgb(244, 67, 54),
                    _ => egui::Color32::GRAY,
                };

                ui.add(
                    egui::ProgressBar::new(task.progress)
                        .text(format!("{:.1}%", task.progress * 100.0))
                        .fill(progress_color)
                        .animate(task.status == TaskStatus::Running),
                );

                // Details
                ui.horizontal(|ui| {
                    ui.label(
                        egui::RichText::new(&task.current_item)
                            .small()
                            .color(egui::Color32::GRAY),
                    );

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(
                            egui::RichText::new(format!("ETA: {}", task.eta_string()))
                                .small()
                                .color(egui::Color32::GRAY),
                        );
                        ui.label(
                            egui::RichText::new(format!("Elapsed: {}", task.elapsed_string()))
                                .small()
                                .color(egui::Color32::GRAY),
                        );
                    });
                });

                // Subtasks
                if !task.sub_tasks.is_empty() {
                    ui.add_space(5.0);
                    for sub in &task.sub_tasks {
                        ui.horizontal(|ui| {
                            let icon = match sub.status {
                                TaskStatus::Completed => "[OK]",
                                TaskStatus::Running => "[>>]",
                                _ => "[  ]",
                            };
                            ui.label(
                                egui::RichText::new(icon)
                                    .monospace()
                                    .color(sub.status.color()),
                            );
                            ui.label(&sub.name);

                            if sub.status == TaskStatus::Running {
                                ui.add(
                                    egui::ProgressBar::new(sub.progress)
                                        .desired_width(100.0)
                                        .show_percentage(),
                                );
                            }
                        });
                    }
                }

                // Control buttons
                if task.status == TaskStatus::Running || task.status == TaskStatus::Paused {
                    ui.add_space(5.0);
                    ui.horizontal(|ui| {
                        let pause_text = if task.status == TaskStatus::Paused {
                            "Resume"
                        } else {
                            "Pause"
                        };
                        if ui.small_button(pause_text).clicked() {
                            self.toggle_pause(task.id);
                        }
                        if ui.small_button("Cancel").clicked() {
                            self.cancel_task(task.id);
                        }
                    });
                }

                // Error message
                if let Some(ref error) = task.error_message {
                    ui.add_space(5.0);
                    ui.label(egui::RichText::new(error).color(egui::Color32::RED).small());
                }
            } else {
                // Queue item - just show position
                ui.label(
                    egui::RichText::new(format!("{} items to process", task.total_items))
                        .small()
                        .color(egui::Color32::GRAY),
                );
            }
        });

        ui.add_space(5.0);
    }

    /// Render overview statistics
    fn render_stats(&self, ui: &mut egui::Ui) {
        let shared = self.shared.lock().unwrap();

        let running = shared
            .tasks
            .iter()
            .filter(|t| t.status == TaskStatus::Running)
            .count();
        let paused = shared
            .tasks
            .iter()
            .filter(|t| t.status == TaskStatus::Paused)
            .count();
        let queued = self.task_queue.len();
        let completed = self.completed_tasks.len();
        let failed = self
            .completed_tasks
            .iter()
            .filter(|t| t.status == TaskStatus::Failed)
            .count();

        // Overall progress
        let total_progress: f32 = shared.tasks.iter().map(|t| t.progress).sum();
        let avg_progress = if !shared.tasks.is_empty() {
            total_progress / shared.tasks.len() as f32
        } else {
            0.0
        };

        drop(shared);

        ui.heading("Overview");
        ui.add_space(10.0);

        egui::Grid::new("stats_grid")
            .num_columns(2)
            .spacing([20.0, 8.0])
            .show(ui, |ui| {
                ui.label("Running:");
                ui.label(
                    egui::RichText::new(format!("{}", running))
                        .color(egui::Color32::from_rgb(100, 180, 255)),
                );
                ui.end_row();

                ui.label("Paused:");
                ui.label(
                    egui::RichText::new(format!("{}", paused))
                        .color(egui::Color32::from_rgb(255, 193, 7)),
                );
                ui.end_row();

                ui.label("Queued:");
                ui.label(egui::RichText::new(format!("{}", queued)));
                ui.end_row();

                ui.label("Completed:");
                ui.label(
                    egui::RichText::new(format!("{}", completed))
                        .color(egui::Color32::from_rgb(76, 175, 80)),
                );
                ui.end_row();

                ui.label("Failed:");
                ui.label(
                    egui::RichText::new(format!("{}", failed))
                        .color(egui::Color32::from_rgb(244, 67, 54)),
                );
                ui.end_row();
            });

        ui.add_space(10.0);

        if running > 0 || paused > 0 {
            ui.label("Overall Progress:");
            ui.add(
                egui::ProgressBar::new(avg_progress)
                    .text(format!("{:.1}%", avg_progress * 100.0))
                    .animate(running > 0),
            );
        }

        ui.add_space(10.0);
        ui.separator();

        // Display options
        ui.checkbox(&mut self.show_queue, "Show Queue");
        ui.checkbox(&mut self.show_completed, "Show Completed");

        if ui.button("Clear Completed").clicked() {
            self.clear_completed();
        }
    }

    /// Render animated elements
    fn render_animations(&mut self, ui: &mut egui::Ui) {
        ui.heading("Animation Examples");
        ui.add_space(10.0);

        // Spinner
        ui.horizontal(|ui| {
            ui.label("Spinner:");
            ui.spinner();
        });

        ui.add_space(5.0);

        // Animated progress bar
        ui.label("Animated Bar:");
        ui.add(
            egui::ProgressBar::new(self.pulse_value)
                .animate(true)
                .text("Pulsing"),
        );

        ui.add_space(5.0);

        // Indeterminate progress
        ui.label("Indeterminate:");
        let time = ui.input(|i| i.time) as f32;
        let indeterminate_progress = (time.sin() + 1.0) / 2.0;
        ui.add(
            egui::ProgressBar::new(indeterminate_progress)
                .animate(true)
                .text("Working..."),
        );

        // Custom animated spinner
        ui.add_space(10.0);
        ui.label("Custom Spinner:");

        let spinner_size = 30.0;
        let (rect, _response) =
            ui.allocate_exact_size(egui::vec2(spinner_size, spinner_size), egui::Sense::hover());

        let center = rect.center();
        let radius = spinner_size / 2.0 - 3.0;
        let angle = self.spinner_angle;

        let painter = ui.painter();

        // Draw arc
        let points: Vec<egui::Pos2> = (0..20)
            .map(|i| {
                let a = angle + (i as f32 * std::f32::consts::PI / 10.0);
                egui::pos2(center.x + radius * a.cos(), center.y + radius * a.sin())
            })
            .collect();

        painter.add(egui::Shape::line(
            points,
            egui::Stroke::new(3.0, egui::Color32::from_rgb(100, 180, 255)),
        ));
    }
}

impl eframe::App for ProgressDisplayApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Request continuous repaint for animations
        ctx.request_repaint();

        // Update animations
        self.spinner_angle += 0.1;
        if self.pulse_direction {
            self.pulse_value += 0.01;
            if self.pulse_value >= 1.0 {
                self.pulse_direction = false;
            }
        } else {
            self.pulse_value -= 0.01;
            if self.pulse_value <= 0.0 {
                self.pulse_direction = true;
            }
        }

        // Update task progress
        self.update_progress();

        // Auto-add tasks
        if self.auto_add_tasks {
            let shared = self.shared.lock().unwrap();
            let total_tasks = shared.tasks.len() + self.task_queue.len();
            drop(shared);

            if total_tasks < 3 {
                let types = TaskType::all();
                let mut rng = rand::thread_rng();
                self.new_task_type = types[rng.gen_range(0..types.len())];
                self.new_task_items = rng.gen_range(50..200);
                self.add_task();
            }
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
                ui.menu_button("View", |ui| {
                    ui.checkbox(&mut self.dark_mode, "Dark Mode");
                    ui.checkbox(&mut self.show_queue, "Show Queue");
                    ui.checkbox(&mut self.show_completed, "Show History");
                });
            });
        });

        // Left panel - controls
        egui::SidePanel::left("controls")
            .default_width(280.0)
            .min_width(250.0)
            .show(ctx, |ui| {
                egui::ScrollArea::vertical().show(ui, |ui| {
                    self.render_add_task(ui);
                    ui.add_space(20.0);
                    self.render_stats(ui);
                    ui.add_space(20.0);
                    self.render_animations(ui);
                });
            });

        // Main content - task list
        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                // Active tasks
                ui.heading("Active Tasks");
                ui.add_space(10.0);

                let shared = self.shared.lock().unwrap();
                let tasks = shared.tasks.clone();
                drop(shared);

                if tasks.is_empty() {
                    ui.label("No active tasks");
                } else {
                    for task in &tasks {
                        self.render_task_card(ui, task, false);
                    }
                }

                // Queue
                if self.show_queue && !self.task_queue.is_empty() {
                    ui.add_space(20.0);
                    ui.heading(format!("Queue ({} tasks)", self.task_queue.len()));
                    ui.add_space(10.0);

                    for task in &self.task_queue.clone() {
                        self.render_task_card(ui, task, true);
                    }
                }

                // Completed tasks
                if self.show_completed && !self.completed_tasks.is_empty() {
                    ui.add_space(20.0);
                    ui.heading("Recently Completed");
                    ui.add_space(10.0);

                    for task in self.completed_tasks.iter().rev() {
                        self.render_task_card(ui, task, false);
                    }
                }
            });
        });
    }
}

fn main() -> eframe::Result<()> {
    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1100.0, 750.0])
            .with_min_inner_size([900.0, 600.0])
            .with_title("G05 - Progress Display | Rust Security Bible"),
        ..Default::default()
    };

    eframe::run_native(
        "Progress Display",
        native_options,
        Box::new(|cc| Ok(Box::new(ProgressDisplayApp::new(cc)))),
    )
}
