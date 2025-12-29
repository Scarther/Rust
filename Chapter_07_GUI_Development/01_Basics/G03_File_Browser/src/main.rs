//! G03_File_Browser - File Selection Dialog and Browser
//! ======================================================
//!
//! This project demonstrates file browsing and selection capabilities
//! using egui combined with native file dialogs (rfd).
//!
//! Key Concepts Covered:
//! - Native file dialog integration
//! - Custom file browser widget
//! - Directory tree navigation
//! - File metadata display
//! - File type filtering
//! - Multi-file selection
//! - Drag and drop support

use eframe::egui;
use humansize::{format_size, BINARY};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// Represents a file or directory entry
#[derive(Clone, Debug)]
struct FileEntry {
    path: PathBuf,
    name: String,
    is_dir: bool,
    size: u64,
    modified: Option<SystemTime>,
    is_hidden: bool,
    is_symlink: bool,
    extension: String,
}

impl FileEntry {
    /// Create a new FileEntry from a path
    fn from_path(path: &Path) -> Option<Self> {
        let metadata = fs::metadata(path).ok()?;
        let name = path.file_name()?.to_string_lossy().to_string();
        let is_hidden = name.starts_with('.');
        let is_symlink = fs::symlink_metadata(path)
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false);

        Some(Self {
            path: path.to_path_buf(),
            name,
            is_dir: metadata.is_dir(),
            size: if metadata.is_dir() { 0 } else { metadata.len() },
            modified: metadata.modified().ok(),
            is_hidden,
            is_symlink,
            extension: path
                .extension()
                .map(|e| e.to_string_lossy().to_string())
                .unwrap_or_default(),
        })
    }

    /// Get icon for file type
    fn icon(&self) -> &'static str {
        if self.is_dir {
            "folder"
        } else {
            match self.extension.to_lowercase().as_str() {
                "rs" => "code",
                "py" | "js" | "ts" | "c" | "cpp" | "h" | "java" => "code",
                "txt" | "md" | "log" => "document",
                "jpg" | "jpeg" | "png" | "gif" | "bmp" | "svg" => "image",
                "mp3" | "wav" | "ogg" | "flac" => "audio",
                "mp4" | "avi" | "mkv" | "mov" => "video",
                "zip" | "tar" | "gz" | "7z" | "rar" => "archive",
                "pdf" => "pdf",
                "exe" | "dll" | "so" => "binary",
                "json" | "yaml" | "yml" | "toml" | "xml" => "config",
                "sh" | "bash" | "zsh" => "script",
                _ => "file",
            }
        }
    }

    /// Get formatted size string
    fn size_string(&self) -> String {
        if self.is_dir {
            "--".to_string()
        } else {
            format_size(self.size, BINARY)
        }
    }

    /// Get formatted modification time
    fn modified_string(&self) -> String {
        self.modified
            .map(|t| {
                let datetime: chrono::DateTime<chrono::Local> = t.into();
                datetime.format("%Y-%m-%d %H:%M").to_string()
            })
            .unwrap_or_else(|| "--".to_string())
    }
}

/// File type filter
#[derive(Clone, Debug, PartialEq)]
struct FileFilter {
    name: String,
    extensions: Vec<String>,
}

impl FileFilter {
    fn new(name: &str, extensions: &[&str]) -> Self {
        Self {
            name: name.to_string(),
            extensions: extensions.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn matches(&self, entry: &FileEntry) -> bool {
        if entry.is_dir {
            return true;
        }
        if self.extensions.is_empty() {
            return true;
        }
        self.extensions
            .iter()
            .any(|ext| entry.extension.eq_ignore_ascii_case(ext))
    }
}

/// Sort order for file listing
#[derive(Clone, Copy, Debug, PartialEq)]
enum SortOrder {
    NameAsc,
    NameDesc,
    SizeAsc,
    SizeDesc,
    DateAsc,
    DateDesc,
    TypeAsc,
    TypeDesc,
}

impl SortOrder {
    fn as_str(&self) -> &'static str {
        match self {
            SortOrder::NameAsc => "Name (A-Z)",
            SortOrder::NameDesc => "Name (Z-A)",
            SortOrder::SizeAsc => "Size (Small first)",
            SortOrder::SizeDesc => "Size (Large first)",
            SortOrder::DateAsc => "Date (Oldest first)",
            SortOrder::DateDesc => "Date (Newest first)",
            SortOrder::TypeAsc => "Type (A-Z)",
            SortOrder::TypeDesc => "Type (Z-A)",
        }
    }
}

/// View mode for file listing
#[derive(Clone, Copy, Debug, PartialEq)]
enum ViewMode {
    List,
    Details,
    Grid,
}

/// Main application state
struct FileBrowserApp {
    // Current directory
    current_dir: PathBuf,

    // Directory contents
    entries: Vec<FileEntry>,

    // Navigation history
    history: Vec<PathBuf>,
    history_index: usize,

    // Selection
    selected_files: HashSet<PathBuf>,
    last_selected: Option<PathBuf>,

    // View settings
    view_mode: ViewMode,
    sort_order: SortOrder,
    show_hidden: bool,
    show_preview: bool,

    // Filters
    filters: Vec<FileFilter>,
    active_filter: usize,
    search_query: String,

    // Preview content
    preview_content: Option<String>,
    preview_file: Option<PathBuf>,

    // Status
    status_message: String,
    error_message: Option<String>,

    // Bookmarks
    bookmarks: Vec<PathBuf>,

    // For path input
    path_input: String,
    editing_path: bool,

    // Dark mode
    dark_mode: bool,
}

impl Default for FileBrowserApp {
    fn default() -> Self {
        let home = dirs_home();
        Self {
            current_dir: home.clone(),
            entries: Vec::new(),
            history: vec![home.clone()],
            history_index: 0,
            selected_files: HashSet::new(),
            last_selected: None,
            view_mode: ViewMode::Details,
            sort_order: SortOrder::NameAsc,
            show_hidden: false,
            show_preview: true,
            filters: vec![
                FileFilter::new("All Files", &[]),
                FileFilter::new("Documents", &["txt", "md", "pdf", "doc", "docx"]),
                FileFilter::new("Images", &["jpg", "jpeg", "png", "gif", "bmp", "svg"]),
                FileFilter::new("Source Code", &["rs", "py", "js", "ts", "c", "cpp", "h", "java"]),
                FileFilter::new("Config Files", &["json", "yaml", "yml", "toml", "xml", "ini"]),
                FileFilter::new("Logs", &["log"]),
                FileFilter::new("Archives", &["zip", "tar", "gz", "7z", "rar"]),
            ],
            active_filter: 0,
            search_query: String::new(),
            preview_content: None,
            preview_file: None,
            status_message: "Ready".to_string(),
            error_message: None,
            bookmarks: vec![
                home.clone(),
                PathBuf::from("/"),
                PathBuf::from("/tmp"),
            ],
            path_input: home.to_string_lossy().to_string(),
            editing_path: false,
            dark_mode: true,
        }
    }
}

/// Get home directory
fn dirs_home() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/"))
}

impl FileBrowserApp {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        cc.egui_ctx.set_visuals(egui::Visuals::dark());
        let mut app = Self::default();
        app.refresh_entries();
        app
    }

    /// Navigate to a directory
    fn navigate_to(&mut self, path: &Path) {
        if path.is_dir() {
            // Add to history
            if self.history_index + 1 < self.history.len() {
                self.history.truncate(self.history_index + 1);
            }
            self.history.push(path.to_path_buf());
            self.history_index = self.history.len() - 1;

            self.current_dir = path.to_path_buf();
            self.path_input = path.to_string_lossy().to_string();
            self.selected_files.clear();
            self.preview_content = None;
            self.preview_file = None;
            self.refresh_entries();
            self.status_message = format!("Navigated to: {}", path.display());
            self.error_message = None;
        } else {
            self.error_message = Some(format!("Not a directory: {}", path.display()));
        }
    }

    /// Go back in history
    fn go_back(&mut self) {
        if self.history_index > 0 {
            self.history_index -= 1;
            let path = self.history[self.history_index].clone();
            self.current_dir = path.clone();
            self.path_input = path.to_string_lossy().to_string();
            self.selected_files.clear();
            self.refresh_entries();
        }
    }

    /// Go forward in history
    fn go_forward(&mut self) {
        if self.history_index + 1 < self.history.len() {
            self.history_index += 1;
            let path = self.history[self.history_index].clone();
            self.current_dir = path.clone();
            self.path_input = path.to_string_lossy().to_string();
            self.selected_files.clear();
            self.refresh_entries();
        }
    }

    /// Go to parent directory
    fn go_up(&mut self) {
        if let Some(parent) = self.current_dir.parent() {
            self.navigate_to(&parent.to_path_buf());
        }
    }

    /// Refresh directory entries
    fn refresh_entries(&mut self) {
        self.entries.clear();

        match fs::read_dir(&self.current_dir) {
            Ok(read_dir) => {
                for entry in read_dir.filter_map(|e| e.ok()) {
                    if let Some(file_entry) = FileEntry::from_path(&entry.path()) {
                        // Apply hidden filter
                        if !self.show_hidden && file_entry.is_hidden {
                            continue;
                        }

                        // Apply type filter
                        let filter = &self.filters[self.active_filter];
                        if !filter.matches(&file_entry) {
                            continue;
                        }

                        // Apply search filter
                        if !self.search_query.is_empty() {
                            if !file_entry
                                .name
                                .to_lowercase()
                                .contains(&self.search_query.to_lowercase())
                            {
                                continue;
                            }
                        }

                        self.entries.push(file_entry);
                    }
                }

                self.sort_entries();
                self.status_message = format!(
                    "{} items in {}",
                    self.entries.len(),
                    self.current_dir.display()
                );
            }
            Err(e) => {
                self.error_message = Some(format!("Error reading directory: {}", e));
            }
        }
    }

    /// Sort entries based on current sort order
    fn sort_entries(&mut self) {
        // Directories first
        self.entries.sort_by(|a, b| {
            if a.is_dir != b.is_dir {
                return b.is_dir.cmp(&a.is_dir);
            }

            match self.sort_order {
                SortOrder::NameAsc => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
                SortOrder::NameDesc => b.name.to_lowercase().cmp(&a.name.to_lowercase()),
                SortOrder::SizeAsc => a.size.cmp(&b.size),
                SortOrder::SizeDesc => b.size.cmp(&a.size),
                SortOrder::DateAsc => a.modified.cmp(&b.modified),
                SortOrder::DateDesc => b.modified.cmp(&a.modified),
                SortOrder::TypeAsc => a.extension.to_lowercase().cmp(&b.extension.to_lowercase()),
                SortOrder::TypeDesc => b.extension.to_lowercase().cmp(&a.extension.to_lowercase()),
            }
        });
    }

    /// Load preview for a file
    fn load_preview(&mut self, path: &Path) {
        if path.is_file() {
            self.preview_file = Some(path.to_path_buf());

            // Only preview text files
            let ext = path
                .extension()
                .map(|e| e.to_string_lossy().to_lowercase())
                .unwrap_or_default();

            let text_extensions = [
                "txt", "md", "rs", "py", "js", "ts", "c", "cpp", "h", "java", "json", "yaml",
                "yml", "toml", "xml", "html", "css", "log", "sh", "bash", "ini", "cfg",
            ];

            if text_extensions.contains(&ext.as_str()) {
                match fs::read_to_string(path) {
                    Ok(content) => {
                        // Limit preview size
                        let preview = if content.len() > 10000 {
                            format!("{}...\n\n[Truncated - file too large]", &content[..10000])
                        } else {
                            content
                        };
                        self.preview_content = Some(preview);
                    }
                    Err(e) => {
                        self.preview_content = Some(format!("Error reading file: {}", e));
                    }
                }
            } else {
                self.preview_content = Some(format!(
                    "Preview not available for .{} files\n\nFile: {}\nSize: {}",
                    ext,
                    path.display(),
                    format_size(
                        fs::metadata(path).map(|m| m.len()).unwrap_or(0),
                        BINARY
                    )
                ));
            }
        }
    }

    /// Open native file dialog
    fn open_file_dialog(&mut self) {
        let dialog = rfd::FileDialog::new()
            .set_directory(&self.current_dir)
            .set_title("Select File");

        if let Some(path) = dialog.pick_file() {
            self.selected_files.clear();
            self.selected_files.insert(path.clone());
            self.load_preview(&path);
            self.status_message = format!("Selected: {}", path.display());
        }
    }

    /// Open native folder dialog
    fn open_folder_dialog(&mut self) {
        let dialog = rfd::FileDialog::new()
            .set_directory(&self.current_dir)
            .set_title("Select Folder");

        if let Some(path) = dialog.pick_folder() {
            self.navigate_to(&path);
        }
    }

    /// Render toolbar
    fn render_toolbar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            // Navigation buttons
            if ui
                .add_enabled(self.history_index > 0, egui::Button::new("<"))
                .on_hover_text("Back")
                .clicked()
            {
                self.go_back();
            }

            if ui
                .add_enabled(
                    self.history_index + 1 < self.history.len(),
                    egui::Button::new(">"),
                )
                .on_hover_text("Forward")
                .clicked()
            {
                self.go_forward();
            }

            if ui
                .add_enabled(self.current_dir.parent().is_some(), egui::Button::new("^"))
                .on_hover_text("Up")
                .clicked()
            {
                self.go_up();
            }

            if ui.button("Refresh").clicked() {
                self.refresh_entries();
            }

            ui.separator();

            // Path input
            let path_response = ui.add(
                egui::TextEdit::singleline(&mut self.path_input)
                    .desired_width(400.0)
                    .hint_text("Enter path..."),
            );

            if path_response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                let path = PathBuf::from(&self.path_input);
                if path.is_dir() {
                    self.navigate_to(&path);
                } else {
                    self.error_message = Some("Invalid path".to_string());
                    self.path_input = self.current_dir.to_string_lossy().to_string();
                }
            }

            ui.separator();

            // View mode buttons
            ui.label("View:");
            if ui
                .selectable_label(self.view_mode == ViewMode::List, "List")
                .clicked()
            {
                self.view_mode = ViewMode::List;
            }
            if ui
                .selectable_label(self.view_mode == ViewMode::Details, "Details")
                .clicked()
            {
                self.view_mode = ViewMode::Details;
            }
            if ui
                .selectable_label(self.view_mode == ViewMode::Grid, "Grid")
                .clicked()
            {
                self.view_mode = ViewMode::Grid;
            }
        });
    }

    /// Render sidebar with bookmarks and filters
    fn render_sidebar(&mut self, ctx: &egui::Context) {
        egui::SidePanel::left("sidebar")
            .default_width(180.0)
            .min_width(150.0)
            .show(ctx, |ui| {
                ui.heading("Bookmarks");
                egui::ScrollArea::vertical()
                    .max_height(150.0)
                    .show(ui, |ui| {
                        let bookmarks = self.bookmarks.clone();
                        for bookmark in &bookmarks {
                            let name = bookmark
                                .file_name()
                                .map(|n| n.to_string_lossy().to_string())
                                .unwrap_or_else(|| "/".to_string());

                            if ui.selectable_label(false, &name).clicked() {
                                self.navigate_to(bookmark);
                            }
                        }
                    });

                if ui.button("Add Bookmark").clicked() {
                    if !self.bookmarks.contains(&self.current_dir) {
                        self.bookmarks.push(self.current_dir.clone());
                    }
                }

                ui.separator();

                ui.heading("Filter");
                for (i, filter) in self.filters.iter().enumerate() {
                    if ui.selectable_label(i == self.active_filter, &filter.name).clicked() {
                        self.active_filter = i;
                        self.refresh_entries();
                    }
                }

                ui.separator();

                ui.heading("Options");
                if ui.checkbox(&mut self.show_hidden, "Show Hidden").clicked() {
                    self.refresh_entries();
                }
                ui.checkbox(&mut self.show_preview, "Show Preview");

                ui.separator();

                ui.heading("Sort By");
                let sort_orders = [
                    SortOrder::NameAsc,
                    SortOrder::NameDesc,
                    SortOrder::SizeAsc,
                    SortOrder::SizeDesc,
                    SortOrder::DateAsc,
                    SortOrder::DateDesc,
                ];
                for order in sort_orders {
                    if ui
                        .selectable_label(self.sort_order == order, order.as_str())
                        .clicked()
                    {
                        self.sort_order = order;
                        self.sort_entries();
                    }
                }

                ui.separator();

                // Quick actions
                ui.heading("Actions");
                if ui.button("Open File...").clicked() {
                    self.open_file_dialog();
                }
                if ui.button("Open Folder...").clicked() {
                    self.open_folder_dialog();
                }
            });
    }

    /// Render file list
    fn render_file_list(&mut self, ui: &mut egui::Ui) {
        // Search bar
        ui.horizontal(|ui| {
            ui.label("Search:");
            if ui
                .add(
                    egui::TextEdit::singleline(&mut self.search_query)
                        .hint_text("Filter files...")
                        .desired_width(200.0),
                )
                .changed()
            {
                self.refresh_entries();
            }
            if ui.button("Clear").clicked() {
                self.search_query.clear();
                self.refresh_entries();
            }

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.label(format!("{} items", self.entries.len()));
            });
        });

        ui.separator();

        match self.view_mode {
            ViewMode::List => self.render_list_view(ui),
            ViewMode::Details => self.render_details_view(ui),
            ViewMode::Grid => self.render_grid_view(ui),
        }
    }

    /// Render list view
    fn render_list_view(&mut self, ui: &mut egui::Ui) {
        egui::ScrollArea::vertical().show(ui, |ui| {
            for entry in self.entries.clone() {
                let selected = self.selected_files.contains(&entry.path);
                let icon = if entry.is_dir { "DIR " } else { "    " };
                let text = format!("{}{}", icon, entry.name);

                let response = ui.selectable_label(selected, &text);

                if response.clicked() {
                    if ui.input(|i| i.modifiers.ctrl) {
                        if selected {
                            self.selected_files.remove(&entry.path);
                        } else {
                            self.selected_files.insert(entry.path.clone());
                        }
                    } else {
                        self.selected_files.clear();
                        self.selected_files.insert(entry.path.clone());
                    }
                    self.last_selected = Some(entry.path.clone());

                    if !entry.is_dir {
                        self.load_preview(&entry.path);
                    }
                }

                if response.double_clicked() {
                    if entry.is_dir {
                        self.navigate_to(&entry.path);
                    }
                }
            }
        });
    }

    /// Render details view (table)
    fn render_details_view(&mut self, ui: &mut egui::Ui) {
        egui::ScrollArea::vertical().show(ui, |ui| {
            egui::Grid::new("file_grid")
                .num_columns(4)
                .striped(true)
                .min_col_width(50.0)
                .show(ui, |ui| {
                    // Header
                    ui.strong("Name");
                    ui.strong("Size");
                    ui.strong("Modified");
                    ui.strong("Type");
                    ui.end_row();

                    for entry in self.entries.clone() {
                        let selected = self.selected_files.contains(&entry.path);
                        let icon = if entry.is_dir { "[DIR]" } else { "     " };

                        let response =
                            ui.selectable_label(selected, format!("{} {}", icon, entry.name));

                        if response.clicked() {
                            if ui.input(|i| i.modifiers.ctrl) {
                                if selected {
                                    self.selected_files.remove(&entry.path);
                                } else {
                                    self.selected_files.insert(entry.path.clone());
                                }
                            } else {
                                self.selected_files.clear();
                                self.selected_files.insert(entry.path.clone());
                            }

                            if !entry.is_dir {
                                self.load_preview(&entry.path);
                            }
                        }

                        if response.double_clicked() && entry.is_dir {
                            self.navigate_to(&entry.path);
                        }

                        ui.label(&entry.size_string());
                        ui.label(&entry.modified_string());
                        ui.label(if entry.is_dir {
                            "Folder"
                        } else {
                            &entry.extension
                        });
                        ui.end_row();
                    }
                });
        });
    }

    /// Render grid view
    fn render_grid_view(&mut self, ui: &mut egui::Ui) {
        egui::ScrollArea::vertical().show(ui, |ui| {
            let available_width = ui.available_width();
            let item_width = 100.0;
            let items_per_row = ((available_width / item_width) as usize).max(1);

            egui::Grid::new("grid_view")
                .num_columns(items_per_row)
                .spacing([10.0, 10.0])
                .show(ui, |ui| {
                    for (i, entry) in self.entries.clone().iter().enumerate() {
                        let selected = self.selected_files.contains(&entry.path);

                        let frame = if selected {
                            egui::Frame::none()
                                .fill(egui::Color32::from_rgb(60, 80, 120))
                                .inner_margin(5.0)
                                .rounding(5.0)
                        } else {
                            egui::Frame::none()
                                .fill(egui::Color32::from_rgb(40, 40, 50))
                                .inner_margin(5.0)
                                .rounding(5.0)
                        };

                        let response = frame
                            .show(ui, |ui| {
                                ui.set_min_size(egui::vec2(80.0, 80.0));
                                ui.vertical_centered(|ui| {
                                    let icon_text = if entry.is_dir { "DIR" } else { "FILE" };
                                    ui.label(
                                        egui::RichText::new(icon_text)
                                            .size(24.0)
                                            .color(if entry.is_dir {
                                                egui::Color32::from_rgb(100, 180, 255)
                                            } else {
                                                egui::Color32::from_rgb(200, 200, 200)
                                            }),
                                    );

                                    let name = if entry.name.len() > 12 {
                                        format!("{}...", &entry.name[..10])
                                    } else {
                                        entry.name.clone()
                                    };
                                    ui.label(&name);
                                });
                            })
                            .response;

                        if response.clicked() {
                            self.selected_files.clear();
                            self.selected_files.insert(entry.path.clone());
                            if !entry.is_dir {
                                self.load_preview(&entry.path);
                            }
                        }

                        if response.double_clicked() && entry.is_dir {
                            self.navigate_to(&entry.path);
                        }

                        if (i + 1) % items_per_row == 0 {
                            ui.end_row();
                        }
                    }
                });
        });
    }

    /// Render preview panel
    fn render_preview(&self, ctx: &egui::Context) {
        if !self.show_preview {
            return;
        }

        egui::SidePanel::right("preview")
            .default_width(300.0)
            .min_width(200.0)
            .show(ctx, |ui| {
                ui.heading("Preview");
                ui.separator();

                if let Some(ref path) = self.preview_file {
                    ui.label(
                        egui::RichText::new(path.file_name().unwrap_or_default().to_string_lossy())
                            .strong(),
                    );
                    ui.separator();
                }

                if let Some(ref content) = self.preview_content {
                    egui::ScrollArea::vertical().show(ui, |ui| {
                        ui.add(
                            egui::TextEdit::multiline(&mut content.as_str())
                                .font(egui::TextStyle::Monospace)
                                .desired_width(f32::INFINITY),
                        );
                    });
                } else {
                    ui.label("Select a file to preview");
                }
            });
    }

    /// Render status bar
    fn render_status_bar(&self, ctx: &egui::Context) {
        egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
            ui.horizontal(|ui| {
                if let Some(ref error) = self.error_message {
                    ui.label(egui::RichText::new(error).color(egui::Color32::RED));
                } else {
                    ui.label(&self.status_message);
                }

                ui.separator();
                ui.label(format!("{} selected", self.selected_files.len()));

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(self.current_dir.to_string_lossy());
                });
            });
        });
    }
}

impl eframe::App for FileBrowserApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Apply theme
        if self.dark_mode {
            ctx.set_visuals(egui::Visuals::dark());
        } else {
            ctx.set_visuals(egui::Visuals::light());
        }

        // Menu bar
        egui::TopBottomPanel::top("menu").show(ctx, |ui| {
            egui::menu::bar(ui, |ui| {
                ui.menu_button("File", |ui| {
                    if ui.button("Open File...").clicked() {
                        self.open_file_dialog();
                        ui.close_menu();
                    }
                    if ui.button("Open Folder...").clicked() {
                        self.open_folder_dialog();
                        ui.close_menu();
                    }
                    ui.separator();
                    if ui.button("Exit").clicked() {
                        std::process::exit(0);
                    }
                });

                ui.menu_button("View", |ui| {
                    ui.checkbox(&mut self.dark_mode, "Dark Mode");
                    ui.checkbox(&mut self.show_hidden, "Show Hidden Files");
                    ui.checkbox(&mut self.show_preview, "Show Preview Panel");
                });

                ui.menu_button("Go", |ui| {
                    if ui.button("Home").clicked() {
                        self.navigate_to(&dirs_home());
                        ui.close_menu();
                    }
                    if ui.button("Root (/)").clicked() {
                        self.navigate_to(&PathBuf::from("/"));
                        ui.close_menu();
                    }
                    if ui.button("Tmp").clicked() {
                        self.navigate_to(&PathBuf::from("/tmp"));
                        ui.close_menu();
                    }
                });
            });
        });

        // Toolbar
        egui::TopBottomPanel::top("toolbar").show(ctx, |ui| {
            self.render_toolbar(ui);
        });

        // Status bar
        self.render_status_bar(ctx);

        // Sidebar
        self.render_sidebar(ctx);

        // Preview panel
        self.render_preview(ctx);

        // Main content
        egui::CentralPanel::default().show(ctx, |ui| {
            self.render_file_list(ui);
        });
    }
}

fn main() -> eframe::Result<()> {
    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1200.0, 800.0])
            .with_min_inner_size([800.0, 600.0])
            .with_title("G03 - File Browser | Rust Security Bible"),
        ..Default::default()
    };

    eframe::run_native(
        "File Browser",
        native_options,
        Box::new(|cc| Ok(Box::new(FileBrowserApp::new(cc)))),
    )
}
