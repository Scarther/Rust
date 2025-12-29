//! G06_Hash_Calculator_GUI - GUI Hash Calculator
//! ===============================================
//!
//! A comprehensive hash calculator with GUI for computing and verifying
//! cryptographic hashes of files and text.
//!
//! Key Concepts Covered:
//! - Multiple hash algorithms (MD5, SHA1, SHA256, SHA512, BLAKE2, BLAKE3)
//! - File hashing with progress indication
//! - Text hashing
//! - Hash verification
//! - Batch file processing
//! - Clipboard integration
//! - Async operations for large files

use arboard::Clipboard;
use blake2::{Blake2b512, Blake2s256};
use eframe::egui;
use humansize::{format_size, BINARY};
use md5::Md5;
use rfd::FileDialog;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

/// Supported hash algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum HashAlgorithm {
    MD5,
    SHA1,
    SHA256,
    SHA512,
    Blake2s,
    Blake2b,
    Blake3,
}

impl HashAlgorithm {
    fn all() -> Vec<HashAlgorithm> {
        vec![
            HashAlgorithm::MD5,
            HashAlgorithm::SHA1,
            HashAlgorithm::SHA256,
            HashAlgorithm::SHA512,
            HashAlgorithm::Blake2s,
            HashAlgorithm::Blake2b,
            HashAlgorithm::Blake3,
        ]
    }

    fn as_str(&self) -> &'static str {
        match self {
            HashAlgorithm::MD5 => "MD5",
            HashAlgorithm::SHA1 => "SHA-1",
            HashAlgorithm::SHA256 => "SHA-256",
            HashAlgorithm::SHA512 => "SHA-512",
            HashAlgorithm::Blake2s => "BLAKE2s",
            HashAlgorithm::Blake2b => "BLAKE2b",
            HashAlgorithm::Blake3 => "BLAKE3",
        }
    }

    fn hash_length(&self) -> usize {
        match self {
            HashAlgorithm::MD5 => 32,
            HashAlgorithm::SHA1 => 40,
            HashAlgorithm::SHA256 => 64,
            HashAlgorithm::SHA512 => 128,
            HashAlgorithm::Blake2s => 64,
            HashAlgorithm::Blake2b => 128,
            HashAlgorithm::Blake3 => 64,
        }
    }

    fn is_secure(&self) -> bool {
        match self {
            HashAlgorithm::MD5 | HashAlgorithm::SHA1 => false,
            _ => true,
        }
    }

    fn security_note(&self) -> &'static str {
        match self {
            HashAlgorithm::MD5 => "Cryptographically broken - for legacy use only",
            HashAlgorithm::SHA1 => "Cryptographically weak - avoid for security",
            HashAlgorithm::SHA256 => "Secure - recommended for most uses",
            HashAlgorithm::SHA512 => "Secure - recommended for high security",
            HashAlgorithm::Blake2s => "Secure - fast, optimized for 32-bit",
            HashAlgorithm::Blake2b => "Secure - fast, optimized for 64-bit",
            HashAlgorithm::Blake3 => "Secure - very fast, parallelizable",
        }
    }
}

/// Hash result for a single computation
#[derive(Clone)]
struct HashResult {
    algorithm: HashAlgorithm,
    hash: String,
    duration_ms: u64,
}

/// File entry with hash results
#[derive(Clone)]
struct FileEntry {
    path: PathBuf,
    size: u64,
    hashes: HashMap<HashAlgorithm, HashResult>,
    is_processing: bool,
    progress: f32,
    error: Option<String>,
}

impl FileEntry {
    fn new(path: PathBuf) -> Self {
        let size = std::fs::metadata(&path)
            .map(|m| m.len())
            .unwrap_or(0);

        Self {
            path,
            size,
            hashes: HashMap::new(),
            is_processing: false,
            progress: 0.0,
            error: None,
        }
    }
}

/// Hash mode
#[derive(Debug, Clone, Copy, PartialEq)]
enum HashMode {
    Text,
    File,
    Verify,
}

/// Shared state for background hashing
struct SharedState {
    files: Vec<FileEntry>,
    is_hashing: bool,
    current_file_index: usize,
}

/// Main application state
struct HashCalculatorApp {
    // Mode
    mode: HashMode,

    // Algorithm selection
    selected_algorithms: Vec<bool>,  // Corresponds to HashAlgorithm::all()

    // Text hashing
    input_text: String,
    text_hashes: HashMap<HashAlgorithm, String>,

    // File hashing
    shared_state: Arc<Mutex<SharedState>>,

    // Verification
    verify_hash: String,
    verify_algorithm: HashAlgorithm,
    verify_result: Option<bool>,

    // Settings
    uppercase: bool,
    auto_copy: bool,
    show_timing: bool,

    // UI state
    dark_mode: bool,
    clipboard: Option<Clipboard>,
    status_message: Option<(String, bool)>,  // (message, is_error)
}

impl Default for HashCalculatorApp {
    fn default() -> Self {
        // Default to SHA256 and SHA512
        let mut selected = vec![false; HashAlgorithm::all().len()];
        selected[2] = true;  // SHA256
        selected[3] = true;  // SHA512

        Self {
            mode: HashMode::File,
            selected_algorithms: selected,
            input_text: String::new(),
            text_hashes: HashMap::new(),
            shared_state: Arc::new(Mutex::new(SharedState {
                files: Vec::new(),
                is_hashing: false,
                current_file_index: 0,
            })),
            verify_hash: String::new(),
            verify_algorithm: HashAlgorithm::SHA256,
            verify_result: None,
            uppercase: false,
            auto_copy: false,
            show_timing: true,
            dark_mode: true,
            clipboard: Clipboard::new().ok(),
            status_message: None,
        }
    }
}

impl HashCalculatorApp {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        cc.egui_ctx.set_visuals(egui::Visuals::dark());
        Self::default()
    }

    /// Get selected algorithms
    fn get_selected_algorithms(&self) -> Vec<HashAlgorithm> {
        HashAlgorithm::all()
            .into_iter()
            .enumerate()
            .filter(|(i, _)| self.selected_algorithms.get(*i).copied().unwrap_or(false))
            .map(|(_, algo)| algo)
            .collect()
    }

    /// Hash text with selected algorithms
    fn hash_text(&mut self) {
        self.text_hashes.clear();

        for algo in self.get_selected_algorithms() {
            let hash = compute_hash_bytes(self.input_text.as_bytes(), algo);
            let formatted = if self.uppercase {
                hash.to_uppercase()
            } else {
                hash.to_lowercase()
            };
            self.text_hashes.insert(algo, formatted);
        }

        self.status_message = Some((
            format!("Computed {} hash(es) for text", self.text_hashes.len()),
            false,
        ));
    }

    /// Open file dialog and add files
    fn add_files(&mut self) {
        if let Some(paths) = FileDialog::new()
            .set_title("Select Files to Hash")
            .pick_files()
        {
            let mut state = self.shared_state.lock().unwrap();
            for path in paths {
                if !state.files.iter().any(|f| f.path == path) {
                    state.files.push(FileEntry::new(path));
                }
            }
            self.status_message = Some((
                format!("{} file(s) added", state.files.len()),
                false,
            ));
        }
    }

    /// Start hashing files
    fn start_file_hashing(&mut self) {
        let algorithms = self.get_selected_algorithms();
        if algorithms.is_empty() {
            self.status_message = Some(("No algorithms selected".to_string(), true));
            return;
        }

        let shared = self.shared_state.clone();
        let uppercase = self.uppercase;

        // Reset state
        {
            let mut state = shared.lock().unwrap();
            state.is_hashing = true;
            state.current_file_index = 0;
            for file in &mut state.files {
                file.hashes.clear();
                file.is_processing = false;
                file.progress = 0.0;
                file.error = None;
            }
        }

        // Spawn background thread
        thread::spawn(move || {
            let file_count = {
                shared.lock().unwrap().files.len()
            };

            for file_idx in 0..file_count {
                // Get file info
                let path = {
                    let mut state = shared.lock().unwrap();
                    state.current_file_index = file_idx;
                    if file_idx < state.files.len() {
                        state.files[file_idx].is_processing = true;
                        state.files[file_idx].path.clone()
                    } else {
                        break;
                    }
                };

                // Hash file with each algorithm
                for algo in &algorithms {
                    let start = Instant::now();

                    match hash_file(&path, *algo, |progress| {
                        let mut state = shared.lock().unwrap();
                        if file_idx < state.files.len() {
                            state.files[file_idx].progress = progress;
                        }
                    }) {
                        Ok(hash) => {
                            let duration = start.elapsed().as_millis() as u64;
                            let formatted = if uppercase {
                                hash.to_uppercase()
                            } else {
                                hash.to_lowercase()
                            };

                            let mut state = shared.lock().unwrap();
                            if file_idx < state.files.len() {
                                state.files[file_idx].hashes.insert(*algo, HashResult {
                                    algorithm: *algo,
                                    hash: formatted,
                                    duration_ms: duration,
                                });
                            }
                        }
                        Err(e) => {
                            let mut state = shared.lock().unwrap();
                            if file_idx < state.files.len() {
                                state.files[file_idx].error = Some(e);
                            }
                        }
                    }
                }

                // Mark complete
                let mut state = shared.lock().unwrap();
                if file_idx < state.files.len() {
                    state.files[file_idx].is_processing = false;
                    state.files[file_idx].progress = 1.0;
                }
            }

            // Done
            let mut state = shared.lock().unwrap();
            state.is_hashing = false;
        });
    }

    /// Verify hash
    fn verify_current(&mut self) {
        let expected = self.verify_hash.trim().to_lowercase();

        let state = self.shared_state.lock().unwrap();
        if let Some(file) = state.files.first() {
            if let Some(result) = file.hashes.get(&self.verify_algorithm) {
                let actual = result.hash.to_lowercase();
                self.verify_result = Some(expected == actual);
                return;
            }
        }

        self.verify_result = None;
    }

    /// Copy hash to clipboard
    fn copy_to_clipboard(&mut self, text: &str) {
        if let Some(ref mut clipboard) = self.clipboard {
            if clipboard.set_text(text.to_string()).is_ok() {
                self.status_message = Some(("Copied to clipboard".to_string(), false));
            }
        }
    }

    /// Clear all files
    fn clear_files(&mut self) {
        let mut state = self.shared_state.lock().unwrap();
        state.files.clear();
        state.is_hashing = false;
    }

    /// Render algorithm selection
    fn render_algorithm_selection(&mut self, ui: &mut egui::Ui) {
        ui.heading("Algorithms");
        ui.add_space(5.0);

        egui::Grid::new("algo_grid")
            .num_columns(2)
            .spacing([20.0, 5.0])
            .show(ui, |ui| {
                for (i, algo) in HashAlgorithm::all().iter().enumerate() {
                    let checked = self.selected_algorithms.get(i).copied().unwrap_or(false);

                    let mut new_checked = checked;
                    let checkbox = ui.checkbox(&mut new_checked, algo.as_str());

                    if checkbox.clicked() {
                        if i < self.selected_algorithms.len() {
                            self.selected_algorithms[i] = new_checked;
                        }
                    }

                    // Security indicator
                    let security_color = if algo.is_secure() {
                        egui::Color32::from_rgb(76, 175, 80)
                    } else {
                        egui::Color32::from_rgb(255, 152, 0)
                    };

                    ui.label(
                        egui::RichText::new(if algo.is_secure() { "Secure" } else { "Weak" })
                            .small()
                            .color(security_color),
                    )
                    .on_hover_text(algo.security_note());

                    ui.end_row();
                }
            });

        ui.add_space(10.0);

        // Quick selection buttons
        ui.horizontal(|ui| {
            if ui.button("All").clicked() {
                for i in 0..self.selected_algorithms.len() {
                    self.selected_algorithms[i] = true;
                }
            }
            if ui.button("None").clicked() {
                for i in 0..self.selected_algorithms.len() {
                    self.selected_algorithms[i] = false;
                }
            }
            if ui.button("Secure Only").clicked() {
                for (i, algo) in HashAlgorithm::all().iter().enumerate() {
                    if i < self.selected_algorithms.len() {
                        self.selected_algorithms[i] = algo.is_secure();
                    }
                }
            }
        });
    }

    /// Render settings
    fn render_settings(&mut self, ui: &mut egui::Ui) {
        ui.heading("Options");
        ui.add_space(5.0);

        ui.checkbox(&mut self.uppercase, "Uppercase hash");
        ui.checkbox(&mut self.auto_copy, "Auto-copy first hash");
        ui.checkbox(&mut self.show_timing, "Show timing");
    }

    /// Render text hashing mode
    fn render_text_mode(&mut self, ui: &mut egui::Ui) {
        ui.heading("Text Input");
        ui.add_space(10.0);

        ui.add(
            egui::TextEdit::multiline(&mut self.input_text)
                .hint_text("Enter text to hash...")
                .desired_width(f32::INFINITY)
                .desired_rows(5)
                .font(egui::TextStyle::Monospace),
        );

        ui.add_space(10.0);
        ui.horizontal(|ui| {
            if ui.button("Calculate Hashes").clicked() {
                self.hash_text();
            }
            if ui.button("Clear").clicked() {
                self.input_text.clear();
                self.text_hashes.clear();
            }

            ui.label(format!("{} bytes", self.input_text.len()));
        });

        // Results
        if !self.text_hashes.is_empty() {
            ui.add_space(20.0);
            ui.heading("Results");
            ui.add_space(10.0);

            egui::Grid::new("text_hash_results")
                .num_columns(3)
                .spacing([10.0, 5.0])
                .striped(true)
                .show(ui, |ui| {
                    ui.strong("Algorithm");
                    ui.strong("Hash");
                    ui.strong("");
                    ui.end_row();

                    for algo in HashAlgorithm::all() {
                        if let Some(hash) = self.text_hashes.get(&algo) {
                            ui.label(algo.as_str());
                            ui.add(
                                egui::TextEdit::singleline(&mut hash.as_str())
                                    .font(egui::TextStyle::Monospace)
                                    .desired_width(400.0),
                            );
                            if ui.button("Copy").clicked() {
                                self.copy_to_clipboard(hash);
                            }
                            ui.end_row();
                        }
                    }
                });
        }
    }

    /// Render file hashing mode
    fn render_file_mode(&mut self, ui: &mut egui::Ui) {
        ui.heading("File Hashing");
        ui.add_space(10.0);

        // Buttons
        let is_hashing = {
            self.shared_state.lock().unwrap().is_hashing
        };

        ui.horizontal(|ui| {
            if ui.add_enabled(!is_hashing, egui::Button::new("Add Files...")).clicked() {
                self.add_files();
            }
            if ui.add_enabled(!is_hashing, egui::Button::new("Hash All")).clicked() {
                self.start_file_hashing();
            }
            if ui.add_enabled(!is_hashing, egui::Button::new("Clear")).clicked() {
                self.clear_files();
            }
        });

        ui.add_space(10.0);
        ui.separator();

        // File list
        let state = self.shared_state.lock().unwrap();

        if state.files.is_empty() {
            ui.add_space(20.0);
            ui.label("No files added. Click 'Add Files...' to select files to hash.");
        } else {
            egui::ScrollArea::vertical().show(ui, |ui| {
                for file in &state.files {
                    self.render_file_entry(ui, file);
                }
            });
        }
    }

    /// Render a single file entry
    fn render_file_entry(&mut self, ui: &mut egui::Ui, file: &FileEntry) {
        let frame = egui::Frame::none()
            .fill(egui::Color32::from_rgb(35, 35, 45))
            .inner_margin(10.0)
            .rounding(8.0);

        frame.show(ui, |ui| {
            // File header
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("[F]").monospace().color(egui::Color32::from_rgb(100, 180, 255)));
                ui.label(
                    egui::RichText::new(
                        file.path.file_name()
                            .map(|n| n.to_string_lossy().to_string())
                            .unwrap_or_else(|| "Unknown".to_string())
                    ).strong()
                );

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(format_size(file.size, BINARY));
                });
            });

            // Full path
            ui.label(
                egui::RichText::new(file.path.to_string_lossy())
                    .small()
                    .color(egui::Color32::GRAY)
            );

            // Progress
            if file.is_processing {
                ui.add_space(5.0);
                ui.add(
                    egui::ProgressBar::new(file.progress)
                        .text("Hashing...")
                        .animate(true)
                );
            }

            // Error
            if let Some(ref error) = file.error {
                ui.add_space(5.0);
                ui.label(egui::RichText::new(error).color(egui::Color32::RED));
            }

            // Hash results
            if !file.hashes.is_empty() {
                ui.add_space(10.0);

                for algo in HashAlgorithm::all() {
                    if let Some(result) = file.hashes.get(&algo) {
                        ui.horizontal(|ui| {
                            ui.label(
                                egui::RichText::new(format!("{:>10}:", algo.as_str()))
                                    .monospace()
                                    .color(egui::Color32::from_rgb(150, 150, 200))
                            );

                            let hash_response = ui.add(
                                egui::TextEdit::singleline(&mut result.hash.as_str())
                                    .font(egui::TextStyle::Monospace)
                                    .desired_width(400.0)
                            );

                            if hash_response.double_clicked() {
                                self.copy_to_clipboard(&result.hash);
                            }

                            if ui.small_button("Copy").clicked() {
                                self.copy_to_clipboard(&result.hash);
                            }

                            if self.show_timing {
                                ui.label(
                                    egui::RichText::new(format!("{}ms", result.duration_ms))
                                        .small()
                                        .color(egui::Color32::GRAY)
                                );
                            }
                        });
                    }
                }
            }
        });

        ui.add_space(10.0);
    }

    /// Render verification mode
    fn render_verify_mode(&mut self, ui: &mut egui::Ui) {
        ui.heading("Hash Verification");
        ui.add_space(10.0);

        ui.label("Paste expected hash to verify against:");
        ui.add(
            egui::TextEdit::singleline(&mut self.verify_hash)
                .hint_text("Enter expected hash...")
                .font(egui::TextStyle::Monospace)
                .desired_width(f32::INFINITY)
        );

        ui.add_space(10.0);

        ui.horizontal(|ui| {
            ui.label("Algorithm:");
            egui::ComboBox::from_id_salt("verify_algo")
                .selected_text(self.verify_algorithm.as_str())
                .show_ui(ui, |ui| {
                    for algo in HashAlgorithm::all() {
                        ui.selectable_value(&mut self.verify_algorithm, algo, algo.as_str());
                    }
                });

            if ui.button("Verify").clicked() {
                self.verify_current();
            }
        });

        // Verification result
        if let Some(result) = self.verify_result {
            ui.add_space(20.0);

            let (icon, text, color) = if result {
                ("[OK]", "MATCH - Hashes are identical", egui::Color32::from_rgb(76, 175, 80))
            } else {
                ("[X]", "MISMATCH - Hashes do not match", egui::Color32::from_rgb(244, 67, 54))
            };

            egui::Frame::none()
                .fill(color.gamma_multiply(0.2))
                .inner_margin(15.0)
                .rounding(8.0)
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new(icon).size(24.0).color(color));
                        ui.label(egui::RichText::new(text).size(16.0).color(color));
                    });
                });
        }

        ui.add_space(20.0);
        ui.separator();

        // Show file section for verification
        ui.label("Load a file to verify:");

        let is_hashing = {
            self.shared_state.lock().unwrap().is_hashing
        };

        ui.horizontal(|ui| {
            if ui.add_enabled(!is_hashing, egui::Button::new("Select File...")).clicked() {
                self.add_files();
            }
            if ui.add_enabled(!is_hashing, egui::Button::new("Hash Selected")).clicked() {
                self.start_file_hashing();
            }
        });

        // Show loaded file
        let state = self.shared_state.lock().unwrap();
        if let Some(file) = state.files.first() {
            ui.add_space(10.0);
            self.render_file_entry(ui, file);
        }
    }
}

/// Compute hash for bytes
fn compute_hash_bytes(data: &[u8], algorithm: HashAlgorithm) -> String {
    match algorithm {
        HashAlgorithm::MD5 => {
            let mut hasher = Md5::new();
            hasher.update(data);
            hex::encode(hasher.finalize())
        }
        HashAlgorithm::SHA1 => {
            let mut hasher = Sha1::new();
            hasher.update(data);
            hex::encode(hasher.finalize())
        }
        HashAlgorithm::SHA256 => {
            let mut hasher = Sha256::new();
            hasher.update(data);
            hex::encode(hasher.finalize())
        }
        HashAlgorithm::SHA512 => {
            let mut hasher = Sha512::new();
            hasher.update(data);
            hex::encode(hasher.finalize())
        }
        HashAlgorithm::Blake2s => {
            let mut hasher = Blake2s256::new();
            hasher.update(data);
            hex::encode(hasher.finalize())
        }
        HashAlgorithm::Blake2b => {
            let mut hasher = Blake2b512::new();
            hasher.update(data);
            hex::encode(hasher.finalize())
        }
        HashAlgorithm::Blake3 => {
            let hash = blake3::hash(data);
            hash.to_hex().to_string()
        }
    }
}

/// Hash a file with progress callback
fn hash_file<F>(path: &PathBuf, algorithm: HashAlgorithm, progress_callback: F) -> Result<String, String>
where
    F: Fn(f32),
{
    let file = File::open(path).map_err(|e| e.to_string())?;
    let file_size = file.metadata().map(|m| m.len()).unwrap_or(0);
    let mut reader = BufReader::with_capacity(1024 * 1024, file);  // 1MB buffer

    let mut bytes_read: u64 = 0;
    let mut buffer = vec![0u8; 64 * 1024];  // 64KB chunks

    macro_rules! hash_with {
        ($hasher:expr) => {{
            let mut hasher = $hasher;
            loop {
                let n = reader.read(&mut buffer).map_err(|e| e.to_string())?;
                if n == 0 {
                    break;
                }
                hasher.update(&buffer[..n]);
                bytes_read += n as u64;
                if file_size > 0 {
                    progress_callback(bytes_read as f32 / file_size as f32);
                }
            }
            hex::encode(hasher.finalize())
        }};
    }

    let hash = match algorithm {
        HashAlgorithm::MD5 => hash_with!(Md5::new()),
        HashAlgorithm::SHA1 => hash_with!(Sha1::new()),
        HashAlgorithm::SHA256 => hash_with!(Sha256::new()),
        HashAlgorithm::SHA512 => hash_with!(Sha512::new()),
        HashAlgorithm::Blake2s => hash_with!(Blake2s256::new()),
        HashAlgorithm::Blake2b => hash_with!(Blake2b512::new()),
        HashAlgorithm::Blake3 => {
            let mut hasher = blake3::Hasher::new();
            loop {
                let n = reader.read(&mut buffer).map_err(|e| e.to_string())?;
                if n == 0 {
                    break;
                }
                hasher.update(&buffer[..n]);
                bytes_read += n as u64;
                if file_size > 0 {
                    progress_callback(bytes_read as f32 / file_size as f32);
                }
            }
            hasher.finalize().to_hex().to_string()
        }
    };

    Ok(hash)
}

impl eframe::App for HashCalculatorApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Request repaint while hashing
        let is_hashing = {
            self.shared_state.lock().unwrap().is_hashing
        };
        if is_hashing {
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
                ui.menu_button("File", |ui| {
                    if ui.button("Add Files...").clicked() {
                        self.add_files();
                        ui.close_menu();
                    }
                    ui.separator();
                    if ui.button("Exit").clicked() {
                        std::process::exit(0);
                    }
                });
                ui.menu_button("View", |ui| {
                    ui.checkbox(&mut self.dark_mode, "Dark Mode");
                    ui.checkbox(&mut self.uppercase, "Uppercase Hashes");
                    ui.checkbox(&mut self.show_timing, "Show Timing");
                });
            });
        });

        // Status bar
        egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
            ui.horizontal(|ui| {
                if is_hashing {
                    ui.spinner();
                    ui.label("Hashing...");
                } else if let Some((ref msg, is_error)) = self.status_message {
                    ui.label(
                        egui::RichText::new(msg).color(
                            if *is_error {
                                egui::Color32::RED
                            } else {
                                egui::Color32::GREEN
                            }
                        )
                    );
                } else {
                    ui.label("Ready");
                }

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label("Hash Calculator");
                });
            });
        });

        // Left panel - algorithm selection and settings
        egui::SidePanel::left("settings")
            .default_width(200.0)
            .min_width(180.0)
            .show(ctx, |ui| {
                egui::ScrollArea::vertical().show(ui, |ui| {
                    self.render_algorithm_selection(ui);
                    ui.add_space(20.0);
                    ui.separator();
                    ui.add_space(10.0);
                    self.render_settings(ui);
                });
            });

        // Main content
        egui::CentralPanel::default().show(ctx, |ui| {
            // Mode tabs
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.mode, HashMode::File, "File Hashing");
                ui.selectable_value(&mut self.mode, HashMode::Text, "Text Hashing");
                ui.selectable_value(&mut self.mode, HashMode::Verify, "Verify Hash");
            });
            ui.separator();
            ui.add_space(10.0);

            egui::ScrollArea::vertical().show(ui, |ui| {
                match self.mode {
                    HashMode::Text => self.render_text_mode(ui),
                    HashMode::File => self.render_file_mode(ui),
                    HashMode::Verify => self.render_verify_mode(ui),
                }
            });
        });
    }
}

fn main() -> eframe::Result<()> {
    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1000.0, 700.0])
            .with_min_inner_size([800.0, 500.0])
            .with_title("G06 - Hash Calculator GUI | Rust Security Bible"),
        ..Default::default()
    };

    eframe::run_native(
        "Hash Calculator",
        native_options,
        Box::new(|cc| Ok(Box::new(HashCalculatorApp::new(cc)))),
    )
}
