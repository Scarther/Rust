//! # BT03 - Forensic Timeline Builder
//!
//! A comprehensive forensic timeline construction tool for incident investigation.
//!
//! ## Forensic Concepts
//!
//! **Timeline Analysis** is a critical forensic technique that reconstructs the
//! sequence of events during a security incident. Key concepts include:
//!
//! - **MACB Times**: Modified, Accessed, Changed, Born (created) timestamps
//! - **Artifact Correlation**: Connecting events from multiple sources
//! - **Gap Analysis**: Identifying missing or suspicious time gaps
//! - **Pivot Points**: Key events that changed the attack trajectory
//!
//! ## Timeline Sources
//!
//! Common sources for timeline construction:
//! - File system metadata (creation, modification, access times)
//! - Log files (syslog, auth.log, application logs)
//! - Browser history and cache
//! - Shell history files
//! - Database timestamps
//! - Network logs and PCAP metadata
//!
//! ## Super Timeline Concept
//!
//! A "super timeline" combines events from all available sources into a single,
//! chronologically ordered view. This provides:
//! - Holistic view of system activity
//! - Cross-source correlation
//! - Attack chain reconstruction
//! - Evidence timeline for legal proceedings
//!
//! ## Usage Examples
//!
//! ```bash
//! # Build timeline from directory
//! timeline-builder --source /case/evidence --output timeline.csv
//!
//! # Include log file parsing
//! timeline-builder --source /var/log --parse-logs --output report.html
//!
//! # Filter by date range
//! timeline-builder --source /home --start "2024-01-01" --end "2024-01-31"
//! ```

use anyhow::{Context, Result};
use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use clap::{Parser, ValueEnum};
use colored::*;
use maud::{html, DOCTYPE};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

// ============================================================================
// CLI ARGUMENT DEFINITIONS
// ============================================================================

/// Timeline Builder - Forensic timeline construction tool
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Source directory or file to analyze
    #[arg(short, long)]
    source: PathBuf,

    /// Output file for timeline
    #[arg(short, long)]
    output: PathBuf,

    /// Output format
    #[arg(short, long, value_enum, default_value = "csv")]
    format: OutputFormat,

    /// Parse log files for additional events
    #[arg(long)]
    parse_logs: bool,

    /// Start date filter (YYYY-MM-DD)
    #[arg(long)]
    start: Option<String>,

    /// End date filter (YYYY-MM-DD)
    #[arg(long)]
    end: Option<String>,

    /// Include hidden files
    #[arg(long)]
    include_hidden: bool,

    /// Follow symbolic links
    #[arg(long)]
    follow_symlinks: bool,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,

    /// Case identifier for report
    #[arg(long)]
    case_id: Option<String>,

    /// Investigator name
    #[arg(long)]
    investigator: Option<String>,
}

#[derive(Debug, Clone, ValueEnum)]
enum OutputFormat {
    Csv,
    Json,
    Html,
    Bodyfile,
}

// ============================================================================
// TIMELINE DATA STRUCTURES
// ============================================================================

/// Represents a single event in the forensic timeline
///
/// ## Event Structure
///
/// Each event captures:
/// - When: Precise timestamp of the event
/// - What: Type of activity (file access, log entry, etc.)
/// - Where: Source file or artifact
/// - Who: User or process (if available)
/// - Context: Additional metadata
#[derive(Debug, Serialize, Deserialize, Clone)]
struct TimelineEvent {
    /// Event timestamp
    timestamp: DateTime<Utc>,
    /// Type of timestamp (M/A/C/B)
    timestamp_type: TimestampType,
    /// Source of this event
    source: EventSource,
    /// Path or identifier
    path: PathBuf,
    /// Event description
    description: String,
    /// User associated (if known)
    user: Option<String>,
    /// Additional metadata
    metadata: EventMetadata,
    /// Tags for categorization
    tags: Vec<String>,
}

/// MACB timestamp types following forensic standards
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
enum TimestampType {
    /// Modified time - content changed
    Modified,
    /// Accessed time - file read
    Accessed,
    /// Changed time - metadata changed (inode on Unix)
    Changed,
    /// Born/Created time - file creation
    Born,
    /// Log entry timestamp
    LogEntry,
    /// Custom/Other
    Other(String),
}

impl std::fmt::Display for TimestampType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TimestampType::Modified => write!(f, "M"),
            TimestampType::Accessed => write!(f, "A"),
            TimestampType::Changed => write!(f, "C"),
            TimestampType::Born => write!(f, "B"),
            TimestampType::LogEntry => write!(f, "L"),
            TimestampType::Other(s) => write!(f, "{}", s),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
enum EventSource {
    FileSystem,
    SysLog,
    AuthLog,
    BashHistory,
    WebHistory,
    ApplicationLog,
    Custom(String),
}

impl std::fmt::Display for EventSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EventSource::FileSystem => write!(f, "FileSystem"),
            EventSource::SysLog => write!(f, "SysLog"),
            EventSource::AuthLog => write!(f, "AuthLog"),
            EventSource::BashHistory => write!(f, "BashHistory"),
            EventSource::WebHistory => write!(f, "WebHistory"),
            EventSource::ApplicationLog => write!(f, "AppLog"),
            EventSource::Custom(s) => write!(f, "{}", s),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
struct EventMetadata {
    /// File size in bytes
    size: Option<u64>,
    /// File type/extension
    file_type: Option<String>,
    /// Permissions (Unix mode)
    permissions: Option<u32>,
    /// Owner UID
    uid: Option<u32>,
    /// Group GID
    gid: Option<u32>,
    /// Inode number
    inode: Option<u64>,
    /// SHA256 hash (if calculated)
    sha256: Option<String>,
    /// Additional notes
    notes: Option<String>,
}

/// Complete forensic timeline
#[derive(Debug, Serialize, Deserialize)]
struct ForensicTimeline {
    /// Case information
    case_info: CaseInfo,
    /// Collection metadata
    collection_info: CollectionInfo,
    /// All timeline events (sorted)
    events: Vec<TimelineEvent>,
    /// Statistics
    stats: TimelineStats,
}

#[derive(Debug, Serialize, Deserialize)]
struct CaseInfo {
    case_id: String,
    investigator: String,
    description: String,
    created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
struct CollectionInfo {
    source_path: PathBuf,
    collection_started: DateTime<Utc>,
    collection_completed: DateTime<Utc>,
    hostname: String,
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct TimelineStats {
    total_events: usize,
    earliest_event: Option<DateTime<Utc>>,
    latest_event: Option<DateTime<Utc>>,
    events_by_source: HashMap<String, usize>,
    events_by_type: HashMap<String, usize>,
    files_processed: usize,
    logs_parsed: usize,
}

// ============================================================================
// TIMELINE BUILDER IMPLEMENTATION
// ============================================================================

/// Main timeline builder structure
struct TimelineBuilder {
    /// Collected events
    events: Vec<TimelineEvent>,
    /// Date range filter start
    start_filter: Option<DateTime<Utc>>,
    /// Date range filter end
    end_filter: Option<DateTime<Utc>>,
    /// Include hidden files
    include_hidden: bool,
    /// Parse log files
    parse_logs: bool,
    /// Verbose mode
    verbose: bool,
    /// Statistics
    stats: TimelineStats,
    /// Log parsers
    log_parsers: Vec<LogParser>,
}

impl TimelineBuilder {
    /// Create a new timeline builder
    fn new(
        start: Option<String>,
        end: Option<String>,
        include_hidden: bool,
        parse_logs: bool,
        verbose: bool,
    ) -> Result<Self> {
        let start_filter = start
            .map(|s| parse_date_filter(&s))
            .transpose()?;
        let end_filter = end
            .map(|s| parse_date_filter(&s))
            .transpose()?;

        Ok(TimelineBuilder {
            events: Vec::new(),
            start_filter,
            end_filter,
            include_hidden,
            parse_logs,
            verbose,
            stats: TimelineStats::default(),
            log_parsers: LogParser::default_parsers(),
        })
    }

    /// Process a source path (file or directory)
    fn process_source(&mut self, source: &Path, follow_symlinks: bool) -> Result<()> {
        if source.is_file() {
            self.process_file(source)?;
        } else if source.is_dir() {
            self.process_directory(source, follow_symlinks)?;
        }
        Ok(())
    }

    /// Process a directory recursively
    fn process_directory(&mut self, dir: &Path, follow_symlinks: bool) -> Result<()> {
        let walker = WalkDir::new(dir)
            .follow_links(follow_symlinks)
            .into_iter()
            .filter_entry(|e| self.should_process_entry(e));

        for entry in walker.filter_map(|e| e.ok()) {
            let path = entry.path();

            if path.is_file() {
                match self.process_file(path) {
                    Ok(_) => self.stats.files_processed += 1,
                    Err(e) => {
                        if self.verbose {
                            eprintln!("Error processing {:?}: {}", path, e);
                        }
                    }
                }
            }

            // Progress indicator
            if self.verbose && self.stats.files_processed % 1000 == 0 {
                println!("Processed {} files...", self.stats.files_processed);
            }
        }

        Ok(())
    }

    /// Check if entry should be processed
    fn should_process_entry(&self, entry: &walkdir::DirEntry) -> bool {
        if !self.include_hidden {
            let name = entry.file_name().to_string_lossy();
            if name.starts_with('.') {
                return false;
            }
        }
        true
    }

    /// Process a single file for timeline events
    fn process_file(&mut self, path: &Path) -> Result<()> {
        let metadata = fs::metadata(path)
            .with_context(|| format!("Failed to get metadata for {:?}", path))?;

        // Extract file metadata
        let event_metadata = self.extract_metadata(&metadata);
        let file_type = path.extension()
            .map(|e| e.to_string_lossy().to_string());

        // Create events for each timestamp type
        // Modified time
        if let Ok(modified) = metadata.modified() {
            let ts: DateTime<Utc> = modified.into();
            if self.in_date_range(&ts) {
                self.events.push(TimelineEvent {
                    timestamp: ts,
                    timestamp_type: TimestampType::Modified,
                    source: EventSource::FileSystem,
                    path: path.to_path_buf(),
                    description: format!("File modified: {}", path.display()),
                    user: None,
                    metadata: event_metadata.clone(),
                    tags: self.auto_tag(path, &file_type),
                });
            }
        }

        // Accessed time
        if let Ok(accessed) = metadata.accessed() {
            let ts: DateTime<Utc> = accessed.into();
            if self.in_date_range(&ts) {
                self.events.push(TimelineEvent {
                    timestamp: ts,
                    timestamp_type: TimestampType::Accessed,
                    source: EventSource::FileSystem,
                    path: path.to_path_buf(),
                    description: format!("File accessed: {}", path.display()),
                    user: None,
                    metadata: event_metadata.clone(),
                    tags: self.auto_tag(path, &file_type),
                });
            }
        }

        // Created/Born time
        if let Ok(created) = metadata.created() {
            let ts: DateTime<Utc> = created.into();
            if self.in_date_range(&ts) {
                self.events.push(TimelineEvent {
                    timestamp: ts,
                    timestamp_type: TimestampType::Born,
                    source: EventSource::FileSystem,
                    path: path.to_path_buf(),
                    description: format!("File created: {}", path.display()),
                    user: None,
                    metadata: event_metadata.clone(),
                    tags: self.auto_tag(path, &file_type),
                });
            }
        }

        // Changed time (Unix only - inode change time)
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let ctime = metadata.ctime();
            if ctime > 0 {
                let ts = Utc.timestamp_opt(ctime, 0).single();
                if let Some(ts) = ts {
                    if self.in_date_range(&ts) {
                        self.events.push(TimelineEvent {
                            timestamp: ts,
                            timestamp_type: TimestampType::Changed,
                            source: EventSource::FileSystem,
                            path: path.to_path_buf(),
                            description: format!("File metadata changed: {}", path.display()),
                            user: None,
                            metadata: event_metadata.clone(),
                            tags: self.auto_tag(path, &file_type),
                        });
                    }
                }
            }
        }

        // Parse log files if enabled
        if self.parse_logs && Self::is_log_file(path) {
            self.parse_log_file(path)?;
        }

        Ok(())
    }

    /// Extract metadata from file
    fn extract_metadata(&self, metadata: &fs::Metadata) -> EventMetadata {
        let mut em = EventMetadata::default();
        em.size = Some(metadata.len());

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            em.permissions = Some(metadata.mode());
            em.uid = Some(metadata.uid());
            em.gid = Some(metadata.gid());
            em.inode = Some(metadata.ino());
        }

        em
    }

    /// Check if file is a log file
    fn is_log_file(path: &Path) -> bool {
        let name = path.file_name()
            .map(|n| n.to_string_lossy().to_lowercase())
            .unwrap_or_default();

        let ext = path.extension()
            .map(|e| e.to_string_lossy().to_lowercase())
            .unwrap_or_default();

        // Common log file patterns
        name.contains("log") ||
        name.contains("history") ||
        name == "messages" ||
        name == "syslog" ||
        name == "auth.log" ||
        name == "secure" ||
        ext == "log"
    }

    /// Parse a log file for timeline events
    fn parse_log_file(&mut self, path: &Path) -> Result<()> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);

        let source = self.determine_log_source(path);

        for line in reader.lines().filter_map(|l| l.ok()) {
            for parser in &self.log_parsers {
                if let Some(event) = parser.parse_line(&line, path, &source) {
                    if self.in_date_range(&event.timestamp) {
                        self.events.push(event);
                        self.stats.logs_parsed += 1;
                    }
                }
            }
        }

        Ok(())
    }

    /// Determine log source type from path
    fn determine_log_source(&self, path: &Path) -> EventSource {
        let name = path.file_name()
            .map(|n| n.to_string_lossy().to_lowercase())
            .unwrap_or_default();

        if name.contains("auth") || name.contains("secure") {
            EventSource::AuthLog
        } else if name.contains("syslog") || name == "messages" {
            EventSource::SysLog
        } else if name.contains("history") {
            EventSource::BashHistory
        } else {
            EventSource::ApplicationLog
        }
    }

    /// Auto-tag based on file characteristics
    fn auto_tag(&self, path: &Path, file_type: &Option<String>) -> Vec<String> {
        let mut tags = Vec::new();
        let path_str = path.to_string_lossy().to_lowercase();

        // Location-based tags
        if path_str.contains("/tmp/") || path_str.contains("\\temp\\") {
            tags.push("temporary".to_string());
        }
        if path_str.contains("/.") || path_str.contains("\\.") {
            tags.push("hidden".to_string());
        }
        if path_str.contains("/bin/") || path_str.contains("/sbin/") {
            tags.push("executable".to_string());
        }
        if path_str.contains("/etc/") {
            tags.push("config".to_string());
        }
        if path_str.contains("/var/log/") {
            tags.push("log".to_string());
        }

        // Type-based tags
        if let Some(ext) = file_type {
            match ext.as_str() {
                "exe" | "dll" | "so" | "dylib" => tags.push("binary".to_string()),
                "sh" | "bash" | "ps1" | "py" | "rb" => tags.push("script".to_string()),
                "conf" | "cfg" | "ini" | "yaml" | "yml" => tags.push("config".to_string()),
                "log" | "txt" => tags.push("text".to_string()),
                "zip" | "tar" | "gz" | "rar" | "7z" => tags.push("archive".to_string()),
                _ => {}
            }
        }

        tags
    }

    /// Check if timestamp is within filter range
    fn in_date_range(&self, ts: &DateTime<Utc>) -> bool {
        if let Some(start) = &self.start_filter {
            if ts < start {
                return false;
            }
        }
        if let Some(end) = &self.end_filter {
            if ts > end {
                return false;
            }
        }
        true
    }

    /// Sort events chronologically
    fn sort_events(&mut self) {
        self.events.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
    }

    /// Calculate statistics
    fn calculate_stats(&mut self) {
        self.stats.total_events = self.events.len();

        if !self.events.is_empty() {
            self.stats.earliest_event = Some(self.events.first().unwrap().timestamp);
            self.stats.latest_event = Some(self.events.last().unwrap().timestamp);
        }

        for event in &self.events {
            *self.stats.events_by_source
                .entry(event.source.to_string())
                .or_insert(0) += 1;
            *self.stats.events_by_type
                .entry(event.timestamp_type.to_string())
                .or_insert(0) += 1;
        }
    }

    /// Build the complete timeline
    fn build(mut self, source: &Path, case_info: CaseInfo) -> Result<ForensicTimeline> {
        let collection_started = Utc::now();

        let hostname = hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "unknown".to_string());

        self.sort_events();
        self.calculate_stats();

        Ok(ForensicTimeline {
            case_info,
            collection_info: CollectionInfo {
                source_path: source.to_path_buf(),
                collection_started,
                collection_completed: Utc::now(),
                hostname,
            },
            events: self.events,
            stats: self.stats,
        })
    }
}

// ============================================================================
// LOG PARSERS
// ============================================================================

/// Generic log parser for timeline events
struct LogParser {
    name: String,
    pattern: Regex,
    source: EventSource,
}

impl LogParser {
    /// Create default log parsers for common formats
    fn default_parsers() -> Vec<Self> {
        vec![
            // Syslog format: Jan  1 12:00:00 hostname service[pid]: message
            LogParser {
                name: "syslog".to_string(),
                pattern: Regex::new(
                    r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[\d+\])?:\s*(.*)$"
                ).unwrap(),
                source: EventSource::SysLog,
            },
            // Auth log format
            LogParser {
                name: "auth".to_string(),
                pattern: Regex::new(
                    r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+(sshd|sudo|su|login)(?:\[\d+\])?:\s*(.*)$"
                ).unwrap(),
                source: EventSource::AuthLog,
            },
            // ISO timestamp format
            LogParser {
                name: "iso".to_string(),
                pattern: Regex::new(
                    r"^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+(.*)$"
                ).unwrap(),
                source: EventSource::ApplicationLog,
            },
            // Apache/Nginx access log
            LogParser {
                name: "web".to_string(),
                pattern: Regex::new(
                    r#"^(\S+)\s+\S+\s+(\S+)\s+\[([^\]]+)\]\s+"([^"]+)"\s+(\d+)"#
                ).unwrap(),
                source: EventSource::WebHistory,
            },
        ]
    }

    /// Parse a log line and return an event if matched
    fn parse_line(&self, line: &str, path: &Path, source: &EventSource) -> Option<TimelineEvent> {
        if let Some(caps) = self.pattern.captures(line) {
            let timestamp_str = caps.get(1)?.as_str();

            // Try to parse timestamp
            let timestamp = parse_log_timestamp(timestamp_str)?;

            let description = caps.get(caps.len() - 1)
                .map(|m| m.as_str().to_string())
                .unwrap_or_else(|| line.to_string());

            // Extract user if present in auth logs
            let user = if matches!(source, EventSource::AuthLog) {
                extract_user_from_log(&description)
            } else {
                None
            };

            Some(TimelineEvent {
                timestamp,
                timestamp_type: TimestampType::LogEntry,
                source: source.clone(),
                path: path.to_path_buf(),
                description,
                user,
                metadata: EventMetadata::default(),
                tags: vec!["log".to_string()],
            })
        } else {
            None
        }
    }
}

/// Parse various timestamp formats
fn parse_log_timestamp(s: &str) -> Option<DateTime<Utc>> {
    // Try ISO format first
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Some(dt.with_timezone(&Utc));
    }

    // Try common log format: "Jan  1 12:00:00"
    let current_year = Utc::now().year();
    let syslog_format = format!("{} {}", current_year, s);
    if let Ok(naive) = NaiveDateTime::parse_from_str(&syslog_format, "%Y %b %d %H:%M:%S") {
        return Some(Utc.from_utc_datetime(&naive));
    }

    // Try Apache format: "01/Jan/2024:12:00:00 +0000"
    if let Ok(dt) = DateTime::parse_from_str(s, "%d/%b/%Y:%H:%M:%S %z") {
        return Some(dt.with_timezone(&Utc));
    }

    None
}

/// Extract username from log line
fn extract_user_from_log(line: &str) -> Option<String> {
    let patterns = [
        Regex::new(r"user[= ](\w+)").ok()?,
        Regex::new(r"for (\w+) from").ok()?,
        Regex::new(r"(\w+)\s*:").ok()?,
    ];

    for pattern in &patterns {
        if let Some(caps) = pattern.captures(line) {
            if let Some(user) = caps.get(1) {
                let username = user.as_str().to_string();
                if !["TTY", "PWD", "USER", "COMMAND"].contains(&username.as_str()) {
                    return Some(username);
                }
            }
        }
    }

    None
}

/// Parse date filter string
fn parse_date_filter(s: &str) -> Result<DateTime<Utc>> {
    // Try YYYY-MM-DD format
    if let Ok(naive) = NaiveDateTime::parse_from_str(&format!("{} 00:00:00", s), "%Y-%m-%d %H:%M:%S") {
        return Ok(Utc.from_utc_datetime(&naive));
    }

    // Try full datetime
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Ok(dt.with_timezone(&Utc));
    }

    anyhow::bail!("Invalid date format: {}. Use YYYY-MM-DD", s)
}

use chrono::Datelike;

// ============================================================================
// OUTPUT GENERATION
// ============================================================================

/// Generate output in specified format
fn generate_output(timeline: &ForensicTimeline, format: &OutputFormat, output: &Path) -> Result<()> {
    match format {
        OutputFormat::Csv => generate_csv(timeline, output),
        OutputFormat::Json => generate_json(timeline, output),
        OutputFormat::Html => generate_html(timeline, output),
        OutputFormat::Bodyfile => generate_bodyfile(timeline, output),
    }
}

fn generate_csv(timeline: &ForensicTimeline, output: &Path) -> Result<()> {
    let mut writer = csv::Writer::from_path(output)?;

    // Write header
    writer.write_record(&[
        "Timestamp", "Type", "Source", "Path", "Description", "User", "Size", "Tags"
    ])?;

    for event in &timeline.events {
        writer.write_record(&[
            event.timestamp.to_rfc3339(),
            event.timestamp_type.to_string(),
            event.source.to_string(),
            event.path.display().to_string(),
            event.description.clone(),
            event.user.clone().unwrap_or_default(),
            event.metadata.size.map(|s| s.to_string()).unwrap_or_default(),
            event.tags.join(", "),
        ])?;
    }

    writer.flush()?;
    Ok(())
}

fn generate_json(timeline: &ForensicTimeline, output: &Path) -> Result<()> {
    let file = File::create(output)?;
    serde_json::to_writer_pretty(file, timeline)?;
    Ok(())
}

fn generate_html(timeline: &ForensicTimeline, output: &Path) -> Result<()> {
    let markup = html! {
        (DOCTYPE)
        html {
            head {
                meta charset="utf-8";
                title { "Forensic Timeline Report" }
                style {
                    r#"
                    body { font-family: Arial, sans-serif; margin: 20px; }
                    h1 { color: #333; }
                    table { border-collapse: collapse; width: 100%; margin-top: 20px; }
                    th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                    th { background-color: #4CAF50; color: white; }
                    tr:nth-child(even) { background-color: #f2f2f2; }
                    .critical { background-color: #ffcccc; }
                    .stats { background-color: #e7f3fe; padding: 15px; margin: 10px 0; }
                    .tag { background-color: #e0e0e0; padding: 2px 6px; margin: 2px; border-radius: 3px; font-size: 0.8em; }
                    "#
                }
            }
            body {
                h1 { "Forensic Timeline Report" }

                div class="stats" {
                    h2 { "Case Information" }
                    p { "Case ID: " (timeline.case_info.case_id) }
                    p { "Investigator: " (timeline.case_info.investigator) }
                    p { "Created: " (timeline.case_info.created_at.to_rfc3339()) }
                }

                div class="stats" {
                    h2 { "Collection Statistics" }
                    p { "Source: " (timeline.collection_info.source_path.display()) }
                    p { "Total Events: " (timeline.stats.total_events) }
                    p { "Files Processed: " (timeline.stats.files_processed) }
                    @if let Some(earliest) = timeline.stats.earliest_event {
                        p { "Earliest Event: " (earliest.to_rfc3339()) }
                    }
                    @if let Some(latest) = timeline.stats.latest_event {
                        p { "Latest Event: " (latest.to_rfc3339()) }
                    }
                }

                h2 { "Timeline Events" }
                table {
                    thead {
                        tr {
                            th { "Timestamp" }
                            th { "Type" }
                            th { "Source" }
                            th { "Path" }
                            th { "Description" }
                            th { "Tags" }
                        }
                    }
                    tbody {
                        @for event in &timeline.events {
                            tr {
                                td { (event.timestamp.format("%Y-%m-%d %H:%M:%S")) }
                                td { (event.timestamp_type.to_string()) }
                                td { (event.source.to_string()) }
                                td { (event.path.display()) }
                                td { (event.description.chars().take(100).collect::<String>()) }
                                td {
                                    @for tag in &event.tags {
                                        span class="tag" { (tag) }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    };

    let mut file = File::create(output)?;
    file.write_all(markup.into_string().as_bytes())?;
    Ok(())
}

/// Generate body file format (compatible with log2timeline/plaso)
fn generate_bodyfile(timeline: &ForensicTimeline, output: &Path) -> Result<()> {
    let mut file = File::create(output)?;

    // Body file format: MD5|name|inode|mode|uid|gid|size|atime|mtime|ctime|crtime
    for event in &timeline.events {
        let (atime, mtime, ctime, crtime) = match event.timestamp_type {
            TimestampType::Accessed => (event.timestamp.timestamp(), 0, 0, 0),
            TimestampType::Modified => (0, event.timestamp.timestamp(), 0, 0),
            TimestampType::Changed => (0, 0, event.timestamp.timestamp(), 0),
            TimestampType::Born => (0, 0, 0, event.timestamp.timestamp()),
            _ => (0, 0, 0, 0),
        };

        let md5 = event.metadata.sha256.clone().unwrap_or_else(|| "0".to_string());
        let inode = event.metadata.inode.unwrap_or(0);
        let mode = event.metadata.permissions.unwrap_or(0);
        let uid = event.metadata.uid.unwrap_or(0);
        let gid = event.metadata.gid.unwrap_or(0);
        let size = event.metadata.size.unwrap_or(0);

        writeln!(
            file,
            "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
            md5,
            event.path.display(),
            inode,
            mode,
            uid,
            gid,
            size,
            atime,
            mtime,
            ctime,
            crtime
        )?;
    }

    Ok(())
}

// ============================================================================
// MAIN ENTRY POINT
// ============================================================================

fn main() -> Result<()> {
    let args = Args::parse();

    println!("{}", "=".repeat(60).blue());
    println!("{}", "Timeline Builder - Forensic Timeline Construction".blue().bold());
    println!("{}", "=".repeat(60).blue());

    // Validate source exists
    if !args.source.exists() {
        anyhow::bail!("Source path does not exist: {:?}", args.source);
    }

    let case_info = CaseInfo {
        case_id: args.case_id.unwrap_or_else(|| format!("CASE-{}", Utc::now().timestamp())),
        investigator: args.investigator.unwrap_or_else(|| "Unknown".to_string()),
        description: format!("Timeline extraction from {:?}", args.source),
        created_at: Utc::now(),
    };

    println!("Case ID: {}", case_info.case_id.yellow());
    println!("Source: {}", args.source.display().to_string().cyan());
    println!("Output: {}", args.output.display().to_string().cyan());
    println!("Format: {:?}", args.format);

    if let Some(start) = &args.start {
        println!("Start Filter: {}", start);
    }
    if let Some(end) = &args.end {
        println!("End Filter: {}", end);
    }

    println!("{}", "-".repeat(60).blue());
    println!("Processing...");

    // Create builder and process source
    let mut builder = TimelineBuilder::new(
        args.start,
        args.end,
        args.include_hidden,
        args.parse_logs,
        args.verbose,
    )?;

    builder.process_source(&args.source, args.follow_symlinks)?;

    println!("Building timeline...");
    let timeline = builder.build(&args.source, case_info)?;

    println!("{}", "-".repeat(60).blue());
    println!("{}", "Timeline Statistics".green().bold());
    println!("Total Events: {}", timeline.stats.total_events);
    println!("Files Processed: {}", timeline.stats.files_processed);
    println!("Logs Parsed: {}", timeline.stats.logs_parsed);

    if let Some(earliest) = timeline.stats.earliest_event {
        println!("Earliest Event: {}", earliest.format("%Y-%m-%d %H:%M:%S"));
    }
    if let Some(latest) = timeline.stats.latest_event {
        println!("Latest Event: {}", latest.format("%Y-%m-%d %H:%M:%S"));
    }

    println!("\nEvents by Source:");
    for (source, count) in &timeline.stats.events_by_source {
        println!("  {}: {}", source, count);
    }

    println!("\nEvents by Type:");
    for (typ, count) in &timeline.stats.events_by_type {
        println!("  {}: {}", typ, count);
    }

    // Generate output
    println!("{}", "-".repeat(60).blue());
    println!("Generating output...");
    generate_output(&timeline, &args.format, &args.output)?;

    println!("{}", "=".repeat(60).blue());
    println!("{}", "Timeline generation complete!".green().bold());
    println!("Output saved to: {}", args.output.display());
    println!("{}", "=".repeat(60).blue());

    Ok(())
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use std::io::Write;

    #[test]
    fn test_timeline_builder_creation() {
        let builder = TimelineBuilder::new(None, None, false, false, false);
        assert!(builder.is_ok());
    }

    #[test]
    fn test_date_filter_parsing() {
        let result = parse_date_filter("2024-01-15");
        assert!(result.is_ok());

        let result = parse_date_filter("invalid");
        assert!(result.is_err());
    }

    #[test]
    fn test_log_timestamp_parsing() {
        // ISO format
        let ts = parse_log_timestamp("2024-01-15T12:00:00Z");
        assert!(ts.is_some());

        // Syslog format
        let ts = parse_log_timestamp("Jan 15 12:00:00");
        assert!(ts.is_some());
    }

    #[test]
    fn test_file_processing() {
        let temp_dir = tempdir().unwrap();
        let file_path = temp_dir.path().join("test.txt");

        let mut file = File::create(&file_path).unwrap();
        file.write_all(b"test content").unwrap();

        let mut builder = TimelineBuilder::new(None, None, false, false, false).unwrap();
        let result = builder.process_file(&file_path);

        assert!(result.is_ok());
        assert!(!builder.events.is_empty());
    }

    #[test]
    fn test_auto_tagging() {
        let builder = TimelineBuilder::new(None, None, false, false, false).unwrap();

        let tags = builder.auto_tag(Path::new("/tmp/test.sh"), &Some("sh".to_string()));
        assert!(tags.contains(&"temporary".to_string()));
        assert!(tags.contains(&"script".to_string()));

        let tags = builder.auto_tag(Path::new("/etc/config.conf"), &Some("conf".to_string()));
        assert!(tags.contains(&"config".to_string()));
    }

    #[test]
    fn test_is_log_file() {
        assert!(TimelineBuilder::is_log_file(Path::new("/var/log/syslog")));
        assert!(TimelineBuilder::is_log_file(Path::new("/var/log/auth.log")));
        assert!(TimelineBuilder::is_log_file(Path::new("access.log")));
        assert!(!TimelineBuilder::is_log_file(Path::new("document.pdf")));
    }

    #[test]
    fn test_timestamp_type_display() {
        assert_eq!(TimestampType::Modified.to_string(), "M");
        assert_eq!(TimestampType::Accessed.to_string(), "A");
        assert_eq!(TimestampType::Changed.to_string(), "C");
        assert_eq!(TimestampType::Born.to_string(), "B");
    }

    #[test]
    fn test_event_source_display() {
        assert_eq!(EventSource::FileSystem.to_string(), "FileSystem");
        assert_eq!(EventSource::AuthLog.to_string(), "AuthLog");
    }

    #[test]
    fn test_log_parser_creation() {
        let parsers = LogParser::default_parsers();
        assert!(!parsers.is_empty());
    }

    #[test]
    fn test_syslog_parsing() {
        let parsers = LogParser::default_parsers();
        let syslog_parser = parsers.iter().find(|p| p.name == "syslog").unwrap();

        let line = "Jan  1 12:00:00 server sshd[1234]: Accepted password for user";
        let event = syslog_parser.parse_line(line, Path::new("/var/log/auth.log"), &EventSource::AuthLog);

        assert!(event.is_some());
    }

    #[test]
    fn test_user_extraction() {
        let user = extract_user_from_log("Accepted password for admin from 192.168.1.1");
        assert_eq!(user, Some("admin".to_string()));

        let user = extract_user_from_log("user=testuser logged in");
        assert_eq!(user, Some("testuser".to_string()));
    }

    #[test]
    fn test_date_range_filtering() {
        let builder = TimelineBuilder::new(
            Some("2024-01-01".to_string()),
            Some("2024-01-31".to_string()),
            false,
            false,
            false,
        ).unwrap();

        let in_range = Utc.with_ymd_and_hms(2024, 1, 15, 12, 0, 0).unwrap();
        let out_of_range = Utc.with_ymd_and_hms(2024, 2, 15, 12, 0, 0).unwrap();

        assert!(builder.in_date_range(&in_range));
        assert!(!builder.in_date_range(&out_of_range));
    }

    #[test]
    fn test_event_sorting() {
        let mut builder = TimelineBuilder::new(None, None, false, false, false).unwrap();

        builder.events.push(TimelineEvent {
            timestamp: Utc.with_ymd_and_hms(2024, 1, 2, 0, 0, 0).unwrap(),
            timestamp_type: TimestampType::Modified,
            source: EventSource::FileSystem,
            path: PathBuf::from("/test1"),
            description: "Event 2".to_string(),
            user: None,
            metadata: EventMetadata::default(),
            tags: vec![],
        });

        builder.events.push(TimelineEvent {
            timestamp: Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap(),
            timestamp_type: TimestampType::Modified,
            source: EventSource::FileSystem,
            path: PathBuf::from("/test2"),
            description: "Event 1".to_string(),
            user: None,
            metadata: EventMetadata::default(),
            tags: vec![],
        });

        builder.sort_events();

        assert_eq!(builder.events[0].description, "Event 1");
        assert_eq!(builder.events[1].description, "Event 2");
    }

    #[test]
    fn test_stats_calculation() {
        let mut builder = TimelineBuilder::new(None, None, false, false, false).unwrap();

        builder.events.push(TimelineEvent {
            timestamp: Utc::now(),
            timestamp_type: TimestampType::Modified,
            source: EventSource::FileSystem,
            path: PathBuf::from("/test"),
            description: "Test".to_string(),
            user: None,
            metadata: EventMetadata::default(),
            tags: vec![],
        });

        builder.calculate_stats();

        assert_eq!(builder.stats.total_events, 1);
        assert!(builder.stats.earliest_event.is_some());
    }

    #[test]
    fn test_hidden_file_filtering() {
        let builder = TimelineBuilder::new(None, None, false, false, false).unwrap();
        assert!(!builder.include_hidden);
    }

    #[test]
    fn test_timeline_serialization() {
        let timeline = ForensicTimeline {
            case_info: CaseInfo {
                case_id: "TEST-001".to_string(),
                investigator: "Tester".to_string(),
                description: "Test case".to_string(),
                created_at: Utc::now(),
            },
            collection_info: CollectionInfo {
                source_path: PathBuf::from("/test"),
                collection_started: Utc::now(),
                collection_completed: Utc::now(),
                hostname: "test".to_string(),
            },
            events: vec![],
            stats: TimelineStats::default(),
        };

        let json = serde_json::to_string(&timeline);
        assert!(json.is_ok());
    }
}
