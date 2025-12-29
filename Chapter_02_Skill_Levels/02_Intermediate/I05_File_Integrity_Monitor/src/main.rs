//! # File Integrity Monitor (FIM)
//!
//! A security tool that monitors files for unauthorized changes using cryptographic hashes.
//!
//! ## Rust Concepts Demonstrated:
//! - **Interior Mutability with RefCell**: Mutable access inside immutable struct
//! - **Trait Objects**: Dynamic dispatch with `Box<dyn Hasher>`
//! - **RAII Pattern**: Automatic resource cleanup with Drop trait
//! - **State Pattern**: Using enums to represent file states
//! - **Channels for Real-time Monitoring**: Watch filesystem events

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand, ValueEnum};
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use notify::{Config, Event, RecommendedWatcher, RecursiveMode, Watcher};
use rayon::prelude::*;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{channel, Receiver};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use walkdir::WalkDir;

/// File Integrity Monitor - Detect unauthorized file changes
///
/// # INTERMEDIATE RUST CONCEPTS:
///
/// 1. **Interior Mutability (RefCell)**:
///    Allows mutation inside an immutable struct at runtime.
///    Useful when the borrow checker's compile-time rules are too restrictive.
///
/// 2. **Trait Objects (Box<dyn Trait>)**:
///    Dynamic dispatch for runtime polymorphism.
///    Enables storing different hash algorithm implementations uniformly.
///
/// 3. **RAII (Resource Acquisition Is Initialization)**:
///    Resources are tied to object lifetime via the Drop trait.
///    Database connections, file handles auto-cleanup when dropped.
///
/// 4. **State Pattern with Enums**:
///    Use enum variants to represent different states.
///    The compiler ensures all states are handled.
#[derive(Parser)]
#[command(name = "fim")]
#[command(author = "Security Researcher")]
#[command(version = "1.0")]
#[command(about = "File integrity monitoring with cryptographic hashes")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

/// Available subcommands
#[derive(Subcommand)]
enum Commands {
    /// Initialize baseline for monitored paths
    Init {
        /// Paths to monitor (files or directories)
        #[arg(short, long, num_args = 1..)]
        paths: Vec<PathBuf>,

        /// Hash algorithm to use
        #[arg(short, long, value_enum, default_value = "sha256")]
        algorithm: HashAlgorithm,

        /// Database file for storing baseline
        #[arg(short, long, default_value = "fim.db")]
        database: PathBuf,

        /// Include hidden files
        #[arg(long)]
        hidden: bool,

        /// File extension filter (e.g., "exe,dll,so")
        #[arg(long)]
        extensions: Option<String>,
    },

    /// Check files against baseline
    Check {
        /// Database file with baseline
        #[arg(short, long, default_value = "fim.db")]
        database: PathBuf,

        /// Output format
        #[arg(short, long, value_enum, default_value = "text")]
        output: OutputFormat,

        /// Export changes to file
        #[arg(short, long)]
        export: Option<PathBuf>,

        /// Only check specific paths
        #[arg(long)]
        paths: Option<Vec<PathBuf>>,
    },

    /// Watch files for real-time changes
    Watch {
        /// Paths to watch
        #[arg(short, long, num_args = 1..)]
        paths: Vec<PathBuf>,

        /// Database file with baseline
        #[arg(short, long, default_value = "fim.db")]
        database: PathBuf,

        /// Alert command to execute on change
        #[arg(long)]
        alert_cmd: Option<String>,

        /// Debounce time in milliseconds
        #[arg(long, default_value = "500")]
        debounce: u64,
    },

    /// Update baseline with current file states
    Update {
        /// Database file
        #[arg(short, long, default_value = "fim.db")]
        database: PathBuf,

        /// Only update specific paths
        #[arg(long)]
        paths: Option<Vec<PathBuf>>,

        /// Don't prompt for confirmation
        #[arg(short, long)]
        yes: bool,
    },

    /// Show baseline information
    Info {
        /// Database file
        #[arg(short, long, default_value = "fim.db")]
        database: PathBuf,
    },
}

/// Supported hash algorithms
#[derive(Debug, Clone, Copy, ValueEnum, Serialize, Deserialize, PartialEq)]
enum HashAlgorithm {
    Sha256,
    Sha512,
    Blake3,
}

impl HashAlgorithm {
    fn name(&self) -> &'static str {
        match self {
            HashAlgorithm::Sha256 => "SHA-256",
            HashAlgorithm::Sha512 => "SHA-512",
            HashAlgorithm::Blake3 => "BLAKE3",
        }
    }
}

/// Output formats
#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
    Csv,
}

/// File change status
///
/// # STATE PATTERN WITH ENUMS:
/// Each variant represents a distinct state with its own data.
/// The compiler ensures all states are handled in match expressions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
enum FileStatus {
    /// File unchanged since baseline
    Unchanged,
    /// File content modified
    Modified {
        old_hash: String,
        new_hash: String,
    },
    /// New file not in baseline
    Added,
    /// File in baseline but missing
    Deleted,
    /// File permissions changed
    PermissionChanged {
        old_perms: u32,
        new_perms: u32,
    },
    /// File size changed
    SizeChanged {
        old_size: u64,
        new_size: u64,
    },
    /// Error accessing file
    Error(String),
}

impl FileStatus {
    fn severity(&self) -> &'static str {
        match self {
            FileStatus::Unchanged => "OK",
            FileStatus::Modified { .. } => "CRITICAL",
            FileStatus::Added => "WARNING",
            FileStatus::Deleted => "CRITICAL",
            FileStatus::PermissionChanged { .. } => "WARNING",
            FileStatus::SizeChanged { .. } => "WARNING",
            FileStatus::Error(_) => "ERROR",
        }
    }

    fn color(&self) -> colored::Color {
        match self {
            FileStatus::Unchanged => colored::Color::Green,
            FileStatus::Modified { .. } => colored::Color::Red,
            FileStatus::Added => colored::Color::Yellow,
            FileStatus::Deleted => colored::Color::Red,
            FileStatus::PermissionChanged { .. } => colored::Color::Yellow,
            FileStatus::SizeChanged { .. } => colored::Color::Yellow,
            FileStatus::Error(_) => colored::Color::Magenta,
        }
    }
}

/// File entry in the baseline
#[derive(Debug, Clone, Serialize, Deserialize)]
struct FileEntry {
    /// File path
    path: PathBuf,
    /// Hash of file contents
    hash: String,
    /// File size in bytes
    size: u64,
    /// File permissions (Unix mode)
    permissions: u32,
    /// Last modification time
    modified: DateTime<Utc>,
    /// When this entry was created
    baseline_time: DateTime<Utc>,
    /// Hash algorithm used
    algorithm: HashAlgorithm,
}

/// Check result for a single file
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CheckResult {
    path: PathBuf,
    status: FileStatus,
    baseline: Option<FileEntry>,
    current: Option<FileEntry>,
    checked_at: DateTime<Utc>,
}

/// Database manager for baseline storage
///
/// # RAII PATTERN:
/// The Connection is automatically closed when Database is dropped.
/// Rust's ownership system ensures proper cleanup without explicit calls.
struct Database {
    conn: Connection,
}

impl Database {
    /// Create or open database
    ///
    /// # RAII EXAMPLE:
    /// Connection is opened here and held until Database is dropped.
    /// No explicit close() call needed - Drop trait handles it.
    fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)
            .context("Failed to open database")?;

        // Create tables if they don't exist
        conn.execute(
            "CREATE TABLE IF NOT EXISTS files (
                path TEXT PRIMARY KEY,
                hash TEXT NOT NULL,
                size INTEGER NOT NULL,
                permissions INTEGER NOT NULL,
                modified TEXT NOT NULL,
                baseline_time TEXT NOT NULL,
                algorithm TEXT NOT NULL
            )",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )",
            [],
        )?;

        Ok(Self { conn })
    }

    /// Insert or update file entry
    fn upsert_entry(&self, entry: &FileEntry) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO files
             (path, hash, size, permissions, modified, baseline_time, algorithm)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                entry.path.to_string_lossy().to_string(),
                entry.hash,
                entry.size as i64,
                entry.permissions as i64,
                entry.modified.to_rfc3339(),
                entry.baseline_time.to_rfc3339(),
                serde_json::to_string(&entry.algorithm)?,
            ],
        )?;
        Ok(())
    }

    /// Get all entries
    fn get_all_entries(&self) -> Result<Vec<FileEntry>> {
        let mut stmt = self.conn.prepare(
            "SELECT path, hash, size, permissions, modified, baseline_time, algorithm FROM files"
        )?;

        let entries = stmt.query_map([], |row| {
            let path: String = row.get(0)?;
            let hash: String = row.get(1)?;
            let size: i64 = row.get(2)?;
            let permissions: i64 = row.get(3)?;
            let modified: String = row.get(4)?;
            let baseline_time: String = row.get(5)?;
            let algorithm: String = row.get(6)?;

            Ok(FileEntry {
                path: PathBuf::from(path),
                hash,
                size: size as u64,
                permissions: permissions as u32,
                modified: DateTime::parse_from_rfc3339(&modified)
                    .unwrap_or_default()
                    .with_timezone(&Utc),
                baseline_time: DateTime::parse_from_rfc3339(&baseline_time)
                    .unwrap_or_default()
                    .with_timezone(&Utc),
                algorithm: serde_json::from_str(&algorithm).unwrap_or(HashAlgorithm::Sha256),
            })
        })?;

        entries.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// Get entry by path
    fn get_entry(&self, path: &Path) -> Result<Option<FileEntry>> {
        let mut stmt = self.conn.prepare(
            "SELECT path, hash, size, permissions, modified, baseline_time, algorithm
             FROM files WHERE path = ?1"
        )?;

        let path_str = path.to_string_lossy().to_string();

        let mut rows = stmt.query(params![path_str])?;

        if let Some(row) = rows.next()? {
            let path: String = row.get(0)?;
            let hash: String = row.get(1)?;
            let size: i64 = row.get(2)?;
            let permissions: i64 = row.get(3)?;
            let modified: String = row.get(4)?;
            let baseline_time: String = row.get(5)?;
            let algorithm: String = row.get(6)?;

            Ok(Some(FileEntry {
                path: PathBuf::from(path),
                hash,
                size: size as u64,
                permissions: permissions as u32,
                modified: DateTime::parse_from_rfc3339(&modified)
                    .unwrap_or_default()
                    .with_timezone(&Utc),
                baseline_time: DateTime::parse_from_rfc3339(&baseline_time)
                    .unwrap_or_default()
                    .with_timezone(&Utc),
                algorithm: serde_json::from_str(&algorithm).unwrap_or(HashAlgorithm::Sha256),
            }))
        } else {
            Ok(None)
        }
    }

    /// Remove entry
    fn remove_entry(&self, path: &Path) -> Result<()> {
        let path_str = path.to_string_lossy().to_string();
        self.conn.execute("DELETE FROM files WHERE path = ?1", params![path_str])?;
        Ok(())
    }

    /// Get entry count
    fn count(&self) -> Result<usize> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM files",
            [],
            |row| row.get(0),
        )?;
        Ok(count as usize)
    }

    /// Set metadata
    fn set_metadata(&self, key: &str, value: &str) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO metadata (key, value) VALUES (?1, ?2)",
            params![key, value],
        )?;
        Ok(())
    }

    /// Get metadata
    fn get_metadata(&self, key: &str) -> Result<Option<String>> {
        let mut stmt = self.conn.prepare("SELECT value FROM metadata WHERE key = ?1")?;
        let mut rows = stmt.query(params![key])?;

        if let Some(row) = rows.next()? {
            Ok(Some(row.get(0)?))
        } else {
            Ok(None)
        }
    }
}

/// Hash computation
///
/// # TRAIT OBJECTS:
/// We could use `Box<dyn Digest>` for runtime polymorphism,
/// but here we use match for simplicity and better performance.
fn compute_hash(path: &Path, algorithm: HashAlgorithm) -> Result<String> {
    let file = File::open(path)
        .context(format!("Failed to open file: {}", path.display()))?;

    let mut reader = BufReader::with_capacity(1024 * 1024, file); // 1MB buffer
    let mut buffer = [0u8; 8192];

    match algorithm {
        HashAlgorithm::Sha256 => {
            use sha2::{Sha256, Digest};
            let mut hasher = Sha256::new();
            loop {
                let bytes_read = reader.read(&mut buffer)?;
                if bytes_read == 0 {
                    break;
                }
                hasher.update(&buffer[..bytes_read]);
            }
            Ok(hex::encode(hasher.finalize()))
        }
        HashAlgorithm::Sha512 => {
            use sha2::{Sha512, Digest};
            let mut hasher = Sha512::new();
            loop {
                let bytes_read = reader.read(&mut buffer)?;
                if bytes_read == 0 {
                    break;
                }
                hasher.update(&buffer[..bytes_read]);
            }
            Ok(hex::encode(hasher.finalize()))
        }
        HashAlgorithm::Blake3 => {
            let mut hasher = blake3::Hasher::new();
            loop {
                let bytes_read = reader.read(&mut buffer)?;
                if bytes_read == 0 {
                    break;
                }
                hasher.update(&buffer[..bytes_read]);
            }
            Ok(hasher.finalize().to_hex().to_string())
        }
    }
}

/// Get file metadata
fn get_file_metadata(path: &Path) -> Result<(u64, u32, DateTime<Utc>)> {
    let metadata = fs::metadata(path)
        .context(format!("Failed to get metadata for: {}", path.display()))?;

    let size = metadata.len();

    // Get permissions (platform-specific)
    #[cfg(unix)]
    let permissions = {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode()
    };

    #[cfg(not(unix))]
    let permissions = if metadata.permissions().readonly() { 0o444 } else { 0o644 };

    let modified = metadata.modified()
        .map(|t| DateTime::<Utc>::from(t))
        .unwrap_or_else(|_| Utc::now());

    Ok((size, permissions, modified))
}

/// Create file entry from path
fn create_file_entry(path: &Path, algorithm: HashAlgorithm) -> Result<FileEntry> {
    let hash = compute_hash(path, algorithm)?;
    let (size, permissions, modified) = get_file_metadata(path)?;

    Ok(FileEntry {
        path: path.to_path_buf(),
        hash,
        size,
        permissions,
        modified,
        baseline_time: Utc::now(),
        algorithm,
    })
}

/// Collect files from paths
fn collect_files(
    paths: &[PathBuf],
    include_hidden: bool,
    extensions: &Option<Vec<String>>,
) -> Vec<PathBuf> {
    let mut files = Vec::new();

    for path in paths {
        if path.is_file() {
            files.push(path.clone());
        } else if path.is_dir() {
            for entry in WalkDir::new(path)
                .follow_links(false)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                let path = entry.path();

                // Skip hidden files unless requested
                if !include_hidden {
                    if let Some(name) = path.file_name() {
                        if name.to_string_lossy().starts_with('.') {
                            continue;
                        }
                    }
                }

                // Filter by extension if specified
                if let Some(ref exts) = extensions {
                    if let Some(ext) = path.extension() {
                        let ext_str = ext.to_string_lossy().to_lowercase();
                        if !exts.iter().any(|e| e.to_lowercase() == ext_str) {
                            continue;
                        }
                    } else {
                        continue;
                    }
                }

                if path.is_file() {
                    files.push(path.to_path_buf());
                }
            }
        }
    }

    files
}

/// Initialize baseline
fn initialize_baseline(
    paths: &[PathBuf],
    algorithm: HashAlgorithm,
    database_path: &Path,
    include_hidden: bool,
    extensions: &Option<String>,
) -> Result<()> {
    println!("{} Initializing baseline...", "[*]".blue());

    let ext_list = extensions.as_ref().map(|e| {
        e.split(',')
            .map(|s| s.trim().to_string())
            .collect::<Vec<_>>()
    });

    let files = collect_files(paths, include_hidden, &ext_list);

    println!(
        "{} Found {} files to baseline",
        "[+]".green(),
        files.len()
    );

    let db = Database::open(database_path)?;

    let progress = ProgressBar::new(files.len() as u64);
    progress.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{bar:40.cyan/blue}] {pos}/{len} ({per_sec})")
            .unwrap()
            .progress_chars("#>-"),
    );

    // Thread-safe error collection
    let errors: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));

    // Process files in parallel and collect entries
    let entries: Vec<FileEntry> = files
        .par_iter()
        .filter_map(|path| {
            let result = create_file_entry(path, algorithm);
            progress.inc(1);

            match result {
                Ok(entry) => Some(entry),
                Err(e) => {
                    errors.lock().unwrap().push(format!("{}: {}", path.display(), e));
                    None
                }
            }
        })
        .collect();

    progress.finish_and_clear();

    // Store entries in database
    for entry in &entries {
        db.upsert_entry(entry)?;
    }

    // Store metadata
    db.set_metadata("algorithm", &serde_json::to_string(&algorithm)?)?;
    db.set_metadata("created", &Utc::now().to_rfc3339())?;

    let error_list = errors.lock().unwrap();
    if !error_list.is_empty() {
        println!("\n{} Errors:", "[!]".yellow());
        for err in error_list.iter().take(10) {
            println!("    {}", err);
        }
        if error_list.len() > 10 {
            println!("    ... and {} more", error_list.len() - 10);
        }
    }

    println!(
        "\n{} Baseline created: {} files using {}",
        "[+]".green(),
        entries.len(),
        algorithm.name()
    );
    println!("    Database: {}", database_path.display());

    Ok(())
}

/// Check files against baseline
fn check_baseline(
    database_path: &Path,
    filter_paths: Option<&[PathBuf]>,
) -> Result<Vec<CheckResult>> {
    println!("{} Checking files against baseline...", "[*]".blue());

    let db = Database::open(database_path)?;
    let baseline_entries = db.get_all_entries()?;

    if baseline_entries.is_empty() {
        anyhow::bail!("No entries in baseline database");
    }

    // Get algorithm from database
    let algorithm: HashAlgorithm = db.get_metadata("algorithm")?
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or(HashAlgorithm::Sha256);

    let progress = ProgressBar::new(baseline_entries.len() as u64);
    progress.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{bar:40.cyan/blue}] {pos}/{len}")
            .unwrap()
            .progress_chars("#>-"),
    );

    // Build lookup map for baseline entries
    let baseline_map: HashMap<PathBuf, FileEntry> = baseline_entries
        .into_iter()
        .map(|e| (e.path.clone(), e))
        .collect();

    let mut results = Vec::new();
    let now = Utc::now();

    // Check existing baseline entries
    for (path, baseline) in &baseline_map {
        // Apply filter if specified
        if let Some(filter) = filter_paths {
            if !filter.iter().any(|f| path.starts_with(f)) {
                continue;
            }
        }

        progress.inc(1);

        let status = if !path.exists() {
            FileStatus::Deleted
        } else {
            match create_file_entry(path, algorithm) {
                Ok(current) => {
                    if current.hash != baseline.hash {
                        FileStatus::Modified {
                            old_hash: baseline.hash.clone(),
                            new_hash: current.hash.clone(),
                        }
                    } else if current.permissions != baseline.permissions {
                        FileStatus::PermissionChanged {
                            old_perms: baseline.permissions,
                            new_perms: current.permissions,
                        }
                    } else if current.size != baseline.size {
                        FileStatus::SizeChanged {
                            old_size: baseline.size,
                            new_size: current.size,
                        }
                    } else {
                        FileStatus::Unchanged
                    }
                }
                Err(e) => FileStatus::Error(e.to_string()),
            }
        };

        let current = if path.exists() {
            create_file_entry(path, algorithm).ok()
        } else {
            None
        };

        results.push(CheckResult {
            path: path.clone(),
            status,
            baseline: Some(baseline.clone()),
            current,
            checked_at: now,
        });
    }

    progress.finish_and_clear();

    Ok(results)
}

/// Display check results
fn display_results(results: &[CheckResult], format: OutputFormat) {
    match format {
        OutputFormat::Text => display_text_results(results),
        OutputFormat::Json => display_json_results(results),
        OutputFormat::Csv => display_csv_results(results),
    }
}

fn display_text_results(results: &[CheckResult]) {
    println!("\n{}", "═".repeat(80).cyan());
    println!("{}", " FILE INTEGRITY CHECK RESULTS ".cyan().bold());
    println!("{}", "═".repeat(80).cyan());

    let mut unchanged = 0;
    let mut changes = Vec::new();

    for result in results {
        match &result.status {
            FileStatus::Unchanged => unchanged += 1,
            _ => changes.push(result),
        }
    }

    if changes.is_empty() {
        println!(
            "\n{} All {} files unchanged",
            "[+]".green(),
            unchanged
        );
    } else {
        println!(
            "\n{} {} files changed, {} unchanged\n",
            "[!]".red(),
            changes.len(),
            unchanged
        );

        for result in &changes {
            let status_str = format!("[{}]", result.status.severity());
            let colored_status = status_str.color(result.status.color());

            println!(
                "{} {}",
                colored_status,
                result.path.display().to_string().white()
            );

            match &result.status {
                FileStatus::Modified { old_hash, new_hash } => {
                    println!("    Old hash: {}", old_hash.dimmed());
                    println!("    New hash: {}", new_hash.yellow());
                }
                FileStatus::PermissionChanged { old_perms, new_perms } => {
                    println!(
                        "    Permissions: {:o} -> {:o}",
                        old_perms, new_perms
                    );
                }
                FileStatus::SizeChanged { old_size, new_size } => {
                    println!("    Size: {} -> {} bytes", old_size, new_size);
                }
                FileStatus::Deleted => {
                    println!("    File no longer exists");
                }
                FileStatus::Added => {
                    println!("    New file not in baseline");
                }
                FileStatus::Error(e) => {
                    println!("    Error: {}", e);
                }
                FileStatus::Unchanged => {}
            }
        }
    }

    println!("{}", "═".repeat(80).cyan());
}

fn display_json_results(results: &[CheckResult]) {
    let output = serde_json::to_string_pretty(results).unwrap();
    println!("{}", output);
}

fn display_csv_results(results: &[CheckResult]) {
    println!("path,status,severity,details");
    for result in results {
        let details = match &result.status {
            FileStatus::Modified { old_hash, new_hash } => {
                format!("old:{},new:{}", &old_hash[..8], &new_hash[..8])
            }
            FileStatus::Deleted => "file_missing".to_string(),
            FileStatus::Added => "new_file".to_string(),
            _ => String::new(),
        };

        println!(
            "{},{:?},{},{}",
            result.path.display(),
            result.status,
            result.status.severity(),
            details
        );
    }
}

/// Watch files for real-time changes
///
/// # CHANNELS FOR FILE WATCHING:
/// The notify crate uses channels to communicate filesystem events.
/// We receive events through a Receiver and process them asynchronously.
fn watch_files(
    paths: &[PathBuf],
    database_path: &Path,
    alert_cmd: Option<String>,
    debounce_ms: u64,
) -> Result<()> {
    println!("{} Starting file watch...", "[*]".blue());

    let db = Database::open(database_path)?;
    let algorithm: HashAlgorithm = db.get_metadata("algorithm")?
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or(HashAlgorithm::Sha256);

    // Create channel for receiving events
    let (tx, rx): (std::sync::mpsc::Sender<notify::Result<Event>>, Receiver<_>) = channel();

    // Create watcher with debounce
    let mut watcher = RecommendedWatcher::new(
        move |res| {
            let _ = tx.send(res);
        },
        Config::default().with_poll_interval(Duration::from_millis(debounce_ms)),
    )?;

    // Add paths to watch
    for path in paths {
        watcher.watch(path, RecursiveMode::Recursive)?;
        println!("    Watching: {}", path.display());
    }

    println!(
        "\n{} Press Ctrl+C to stop watching\n",
        "[*]".blue()
    );

    // Process events
    loop {
        match rx.recv() {
            Ok(Ok(event)) => {
                for path in event.paths {
                    if !path.is_file() {
                        continue;
                    }

                    // Check against baseline
                    if let Some(baseline) = db.get_entry(&path)? {
                        if let Ok(current_hash) = compute_hash(&path, algorithm) {
                            if current_hash != baseline.hash {
                                println!(
                                    "{} {} Modified: {}",
                                    "[!]".red().bold(),
                                    Utc::now().format("%H:%M:%S"),
                                    path.display()
                                );
                                println!(
                                    "    Old: {}",
                                    &baseline.hash[..32].dimmed()
                                );
                                println!(
                                    "    New: {}",
                                    &current_hash[..32].yellow()
                                );

                                // Execute alert command if specified
                                if let Some(ref cmd) = alert_cmd {
                                    let cmd = cmd.replace("{path}", &path.to_string_lossy());
                                    let _ = std::process::Command::new("sh")
                                        .arg("-c")
                                        .arg(&cmd)
                                        .spawn();
                                }
                            }
                        }
                    } else {
                        println!(
                            "{} {} New file: {}",
                            "[+]".yellow(),
                            Utc::now().format("%H:%M:%S"),
                            path.display()
                        );
                    }
                }
            }
            Ok(Err(e)) => {
                eprintln!("{} Watch error: {}", "[!]".red(), e);
            }
            Err(_) => {
                break;
            }
        }
    }

    Ok(())
}

/// Update baseline
fn update_baseline(
    database_path: &Path,
    filter_paths: Option<&[PathBuf]>,
    auto_confirm: bool,
) -> Result<()> {
    let results = check_baseline(database_path, filter_paths)?;

    let changes: Vec<_> = results
        .iter()
        .filter(|r| !matches!(r.status, FileStatus::Unchanged))
        .collect();

    if changes.is_empty() {
        println!("{} No changes to update", "[*]".blue());
        return Ok(());
    }

    display_text_results(&results);

    if !auto_confirm {
        print!("\nUpdate baseline with these changes? [y/N]: ");
        std::io::Write::flush(&mut std::io::stdout())?;

        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;

        if !input.trim().eq_ignore_ascii_case("y") {
            println!("{} Update cancelled", "[*]".blue());
            return Ok(());
        }
    }

    let db = Database::open(database_path)?;
    let algorithm: HashAlgorithm = db.get_metadata("algorithm")?
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or(HashAlgorithm::Sha256);

    for result in &changes {
        match &result.status {
            FileStatus::Deleted => {
                db.remove_entry(&result.path)?;
            }
            FileStatus::Modified { .. }
            | FileStatus::PermissionChanged { .. }
            | FileStatus::SizeChanged { .. } => {
                if let Ok(entry) = create_file_entry(&result.path, algorithm) {
                    db.upsert_entry(&entry)?;
                }
            }
            _ => {}
        }
    }

    db.set_metadata("updated", &Utc::now().to_rfc3339())?;

    println!(
        "{} Baseline updated: {} changes applied",
        "[+]".green(),
        changes.len()
    );

    Ok(())
}

/// Show database information
fn show_info(database_path: &Path) -> Result<()> {
    let db = Database::open(database_path)?;

    println!("\n{}", "═".repeat(60).cyan());
    println!("{}", " BASELINE INFORMATION ".cyan().bold());
    println!("{}", "═".repeat(60).cyan());

    println!("\nDatabase: {}", database_path.display());
    println!("Entries:  {}", db.count()?);

    if let Some(algo) = db.get_metadata("algorithm")? {
        let algorithm: HashAlgorithm = serde_json::from_str(&algo)?;
        println!("Algorithm: {}", algorithm.name());
    }

    if let Some(created) = db.get_metadata("created")? {
        println!("Created:  {}", created);
    }

    if let Some(updated) = db.get_metadata("updated")? {
        println!("Updated:  {}", updated);
    }

    println!("{}", "═".repeat(60).cyan());

    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init {
            paths,
            algorithm,
            database,
            hidden,
            extensions,
        } => {
            initialize_baseline(&paths, algorithm, &database, hidden, &extensions)?;
        }

        Commands::Check {
            database,
            output,
            export,
            paths,
        } => {
            let filter = paths.as_deref();
            let results = check_baseline(&database, filter)?;
            display_results(&results, output);

            if let Some(path) = export {
                let json = serde_json::to_string_pretty(&results)?;
                fs::write(&path, json)?;
                println!("{} Results exported to {}", "[+]".green(), path.display());
            }
        }

        Commands::Watch {
            paths,
            database,
            alert_cmd,
            debounce,
        } => {
            watch_files(&paths, &database, alert_cmd, debounce)?;
        }

        Commands::Update {
            database,
            paths,
            yes,
        } => {
            let filter = paths.as_deref();
            update_baseline(&database, filter, yes)?;
        }

        Commands::Info { database } => {
            show_info(&database)?;
        }
    }

    Ok(())
}

// ============================================================================
// UNIT TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;

    /// Test hash computation
    #[test]
    fn test_sha256_hash() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test.txt");
        fs::write(&file_path, "Hello, World!").unwrap();

        let hash = compute_hash(&file_path, HashAlgorithm::Sha256).unwrap();
        // Known SHA-256 hash for "Hello, World!"
        assert_eq!(
            hash,
            "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f"
        );
    }

    /// Test BLAKE3 hash
    #[test]
    fn test_blake3_hash() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test.txt");
        fs::write(&file_path, "test content").unwrap();

        let hash = compute_hash(&file_path, HashAlgorithm::Blake3).unwrap();
        assert_eq!(hash.len(), 64); // BLAKE3 produces 32 bytes = 64 hex chars
    }

    /// Test file status enum
    #[test]
    fn test_file_status() {
        let modified = FileStatus::Modified {
            old_hash: "abc".to_string(),
            new_hash: "def".to_string(),
        };

        assert_eq!(modified.severity(), "CRITICAL");

        let unchanged = FileStatus::Unchanged;
        assert_eq!(unchanged.severity(), "OK");
    }

    /// Test database operations
    #[test]
    fn test_database() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test.db");

        let db = Database::open(&db_path).unwrap();

        let entry = FileEntry {
            path: PathBuf::from("/test/file.txt"),
            hash: "abc123".to_string(),
            size: 1024,
            permissions: 0o644,
            modified: Utc::now(),
            baseline_time: Utc::now(),
            algorithm: HashAlgorithm::Sha256,
        };

        db.upsert_entry(&entry).unwrap();
        assert_eq!(db.count().unwrap(), 1);

        let retrieved = db.get_entry(&PathBuf::from("/test/file.txt")).unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().hash, "abc123");
    }

    /// Test file collection
    #[test]
    fn test_collect_files() {
        let dir = tempdir().unwrap();

        // Create test files
        fs::write(dir.path().join("file1.txt"), "content").unwrap();
        fs::write(dir.path().join("file2.log"), "content").unwrap();
        fs::write(dir.path().join(".hidden"), "content").unwrap();

        // Collect all files (excluding hidden)
        let files = collect_files(&[dir.path().to_path_buf()], false, &None);
        assert_eq!(files.len(), 2);

        // Collect with extension filter
        let txt_only = collect_files(
            &[dir.path().to_path_buf()],
            false,
            &Some(vec!["txt".to_string()]),
        );
        assert_eq!(txt_only.len(), 1);

        // Include hidden files
        let with_hidden = collect_files(&[dir.path().to_path_buf()], true, &None);
        assert_eq!(with_hidden.len(), 3);
    }

    /// Test RAII pattern with database
    #[test]
    fn test_raii_pattern() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("raii_test.db");

        {
            let db = Database::open(&db_path).unwrap();
            db.set_metadata("test", "value").unwrap();
            // db is dropped here, connection closed automatically
        }

        // Reopen and verify data persisted
        {
            let db = Database::open(&db_path).unwrap();
            let value = db.get_metadata("test").unwrap();
            assert_eq!(value, Some("value".to_string()));
        }
    }

    /// Test state pattern with FileStatus
    #[test]
    fn test_state_pattern() {
        fn process_status(status: &FileStatus) -> &'static str {
            // Compiler ensures all variants are handled
            match status {
                FileStatus::Unchanged => "No action needed",
                FileStatus::Modified { .. } => "Alert: File changed!",
                FileStatus::Deleted => "Alert: File removed!",
                FileStatus::Added => "Note: New file",
                FileStatus::PermissionChanged { .. } => "Check permissions",
                FileStatus::SizeChanged { .. } => "Size mismatch",
                FileStatus::Error(_) => "Handle error",
            }
        }

        assert_eq!(process_status(&FileStatus::Unchanged), "No action needed");
        assert_eq!(
            process_status(&FileStatus::Modified {
                old_hash: "a".into(),
                new_hash: "b".into()
            }),
            "Alert: File changed!"
        );
    }
}
