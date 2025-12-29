//! # BT04 - Forensic Artifact Collector
//!
//! A comprehensive forensic artifact collection tool for incident response.
//!
//! ## Forensic Concepts
//!
//! **Artifact Collection** is the systematic gathering of forensic evidence from
//! systems during incident response. Key principles include:
//!
//! - **Order of Volatility**: Collect most volatile data first (RAM > logs > files)
//! - **Chain of Custody**: Document all collection activities
//! - **Evidence Integrity**: Hash all collected artifacts
//! - **Minimal Footprint**: Avoid altering the system being investigated
//!
//! ## Artifact Categories
//!
//! ### System Artifacts
//! - OS configuration files
//! - User account information
//! - Installed software lists
//! - System logs
//!
//! ### User Artifacts
//! - Browser history and cache
//! - Shell history files
//! - Recent documents
//! - SSH keys and known hosts
//!
//! ### Network Artifacts
//! - Network configuration
//! - Active connections
//! - DNS cache
//! - Firewall rules
//!
//! ### Security Artifacts
//! - Authentication logs
//! - Audit logs
//! - Security configurations
//! - Cron jobs and scheduled tasks
//!
//! ## Usage Examples
//!
//! ```bash
//! # Collect all artifacts
//! artifact-collector --output /case/evidence.tar.gz
//!
//! # Collect specific categories
//! artifact-collector --category system --category user --output evidence.zip
//!
//! # Quick triage collection
//! artifact-collector --triage --output triage.tar.gz
//! ```

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use clap::{Parser, ValueEnum};
use colored::*;
use flate2::write::GzEncoder;
use flate2::Compression;
use md5::Md5;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

// ============================================================================
// CLI ARGUMENT DEFINITIONS
// ============================================================================

/// Artifact Collector - Forensic evidence collection tool
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Output file for collected artifacts
    #[arg(short, long)]
    output: PathBuf,

    /// Artifact categories to collect
    #[arg(short, long)]
    category: Vec<ArtifactCategory>,

    /// Output format
    #[arg(short, long, value_enum, default_value = "tar-gz")]
    format: OutputFormat,

    /// Quick triage mode (essential artifacts only)
    #[arg(long)]
    triage: bool,

    /// Include file contents (not just metadata)
    #[arg(long)]
    include_contents: bool,

    /// Maximum file size to collect (MB)
    #[arg(long, default_value = "50")]
    max_file_size: u64,

    /// Case ID for documentation
    #[arg(long)]
    case_id: Option<String>,

    /// Investigator name
    #[arg(long)]
    investigator: Option<String>,

    /// Custom artifact paths to collect
    #[arg(long)]
    custom_path: Vec<PathBuf>,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,

    /// Dry run (show what would be collected)
    #[arg(long)]
    dry_run: bool,
}

#[derive(Debug, Clone, ValueEnum, PartialEq, Eq, Hash, Serialize, Deserialize)]
enum ArtifactCategory {
    System,
    User,
    Network,
    Security,
    Browser,
    Application,
    All,
}

#[derive(Debug, Clone, ValueEnum)]
enum OutputFormat {
    TarGz,
    Zip,
    Directory,
}

// ============================================================================
// ARTIFACT DEFINITIONS
// ============================================================================

/// Definition of a forensic artifact to collect
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ArtifactDefinition {
    /// Unique identifier
    id: String,
    /// Human-readable name
    name: String,
    /// Description of the artifact
    description: String,
    /// Category
    category: ArtifactCategory,
    /// Paths to collect (supports glob patterns)
    paths: Vec<String>,
    /// Platform (linux, windows, macos, all)
    platform: String,
    /// Is this a triage artifact?
    triage: bool,
    /// Forensic significance (1-10)
    significance: u8,
    /// MITRE ATT&CK relevance
    mitre_relevance: Vec<String>,
}

/// Collected artifact with metadata
#[derive(Debug, Serialize, Deserialize)]
struct CollectedArtifact {
    /// Artifact definition ID
    artifact_id: String,
    /// Original path on system
    source_path: PathBuf,
    /// Path in collection archive
    archive_path: PathBuf,
    /// File size in bytes
    size: u64,
    /// SHA256 hash
    sha256: String,
    /// MD5 hash (for compatibility)
    md5: String,
    /// Collection timestamp
    collected_at: DateTime<Utc>,
    /// File modified time
    modified: Option<DateTime<Utc>>,
    /// File created time
    created: Option<DateTime<Utc>>,
    /// File permissions (Unix)
    permissions: Option<u32>,
    /// Owner UID
    uid: Option<u32>,
    /// Group GID
    gid: Option<u32>,
    /// Notes
    notes: Option<String>,
}

/// Complete collection manifest
#[derive(Debug, Serialize, Deserialize)]
struct CollectionManifest {
    /// Case information
    case_info: CaseInfo,
    /// Collection metadata
    collection_info: CollectionInfo,
    /// System information
    system_info: SystemInfo,
    /// All collected artifacts
    artifacts: Vec<CollectedArtifact>,
    /// Collection statistics
    stats: CollectionStats,
    /// Errors encountered
    errors: Vec<CollectionError>,
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
    tool_version: String,
    collection_started: DateTime<Utc>,
    collection_completed: DateTime<Utc>,
    categories_collected: Vec<ArtifactCategory>,
    triage_mode: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct SystemInfo {
    hostname: String,
    os: String,
    os_version: String,
    kernel: Option<String>,
    architecture: String,
    current_user: Option<String>,
    uptime: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct CollectionStats {
    total_artifacts: usize,
    total_bytes: u64,
    artifacts_by_category: HashMap<String, usize>,
    files_skipped: usize,
    errors_encountered: usize,
}

#[derive(Debug, Serialize, Deserialize)]
struct CollectionError {
    path: PathBuf,
    error: String,
    timestamp: DateTime<Utc>,
}

// ============================================================================
// ARTIFACT DEFINITIONS DATABASE
// ============================================================================

impl ArtifactDefinition {
    /// Get default artifact definitions for Linux systems
    fn linux_artifacts() -> Vec<Self> {
        vec![
            // System Artifacts
            ArtifactDefinition {
                id: "linux-passwd".to_string(),
                name: "User Accounts".to_string(),
                description: "User account information".to_string(),
                category: ArtifactCategory::System,
                paths: vec![
                    "/etc/passwd".to_string(),
                    "/etc/shadow".to_string(),
                    "/etc/group".to_string(),
                    "/etc/sudoers".to_string(),
                    "/etc/sudoers.d/*".to_string(),
                ],
                platform: "linux".to_string(),
                triage: true,
                significance: 9,
                mitre_relevance: vec!["T1087".to_string(), "T1078".to_string()],
            },
            ArtifactDefinition {
                id: "linux-hostname".to_string(),
                name: "System Identification".to_string(),
                description: "System hostname and identification".to_string(),
                category: ArtifactCategory::System,
                paths: vec![
                    "/etc/hostname".to_string(),
                    "/etc/hosts".to_string(),
                    "/etc/machine-id".to_string(),
                    "/etc/os-release".to_string(),
                    "/etc/lsb-release".to_string(),
                ],
                platform: "linux".to_string(),
                triage: true,
                significance: 7,
                mitre_relevance: vec!["T1082".to_string()],
            },
            ArtifactDefinition {
                id: "linux-cron".to_string(),
                name: "Scheduled Tasks".to_string(),
                description: "Cron jobs and scheduled tasks".to_string(),
                category: ArtifactCategory::Security,
                paths: vec![
                    "/etc/crontab".to_string(),
                    "/etc/cron.d/*".to_string(),
                    "/etc/cron.daily/*".to_string(),
                    "/etc/cron.hourly/*".to_string(),
                    "/etc/cron.weekly/*".to_string(),
                    "/etc/cron.monthly/*".to_string(),
                    "/var/spool/cron/crontabs/*".to_string(),
                ],
                platform: "linux".to_string(),
                triage: true,
                significance: 9,
                mitre_relevance: vec!["T1053.003".to_string()],
            },
            ArtifactDefinition {
                id: "linux-services".to_string(),
                name: "System Services".to_string(),
                description: "Systemd and init service configurations".to_string(),
                category: ArtifactCategory::System,
                paths: vec![
                    "/etc/systemd/system/*.service".to_string(),
                    "/etc/init.d/*".to_string(),
                    "/lib/systemd/system/*.service".to_string(),
                ],
                platform: "linux".to_string(),
                triage: false,
                significance: 8,
                mitre_relevance: vec!["T1543.002".to_string()],
            },
            // Security Artifacts
            ArtifactDefinition {
                id: "linux-auth-logs".to_string(),
                name: "Authentication Logs".to_string(),
                description: "SSH and authentication logs".to_string(),
                category: ArtifactCategory::Security,
                paths: vec![
                    "/var/log/auth.log".to_string(),
                    "/var/log/auth.log.1".to_string(),
                    "/var/log/secure".to_string(),
                    "/var/log/btmp".to_string(),
                    "/var/log/wtmp".to_string(),
                    "/var/log/lastlog".to_string(),
                    "/var/log/faillog".to_string(),
                ],
                platform: "linux".to_string(),
                triage: true,
                significance: 10,
                mitre_relevance: vec!["T1110".to_string(), "T1078".to_string()],
            },
            ArtifactDefinition {
                id: "linux-syslog".to_string(),
                name: "System Logs".to_string(),
                description: "General system logs".to_string(),
                category: ArtifactCategory::System,
                paths: vec![
                    "/var/log/syslog".to_string(),
                    "/var/log/syslog.1".to_string(),
                    "/var/log/messages".to_string(),
                    "/var/log/kern.log".to_string(),
                    "/var/log/dmesg".to_string(),
                ],
                platform: "linux".to_string(),
                triage: true,
                significance: 8,
                mitre_relevance: vec![],
            },
            ArtifactDefinition {
                id: "linux-audit".to_string(),
                name: "Audit Logs".to_string(),
                description: "Linux audit subsystem logs".to_string(),
                category: ArtifactCategory::Security,
                paths: vec![
                    "/var/log/audit/audit.log".to_string(),
                    "/var/log/audit/audit.log.1".to_string(),
                    "/etc/audit/auditd.conf".to_string(),
                    "/etc/audit/audit.rules".to_string(),
                ],
                platform: "linux".to_string(),
                triage: true,
                significance: 10,
                mitre_relevance: vec!["T1562.001".to_string()],
            },
            // User Artifacts
            ArtifactDefinition {
                id: "linux-bash-history".to_string(),
                name: "Shell History".to_string(),
                description: "User shell command history".to_string(),
                category: ArtifactCategory::User,
                paths: vec![
                    "/home/*/.bash_history".to_string(),
                    "/home/*/.zsh_history".to_string(),
                    "/root/.bash_history".to_string(),
                    "/root/.zsh_history".to_string(),
                ],
                platform: "linux".to_string(),
                triage: true,
                significance: 10,
                mitre_relevance: vec!["T1059.004".to_string()],
            },
            ArtifactDefinition {
                id: "linux-ssh".to_string(),
                name: "SSH Configuration".to_string(),
                description: "SSH keys and configuration".to_string(),
                category: ArtifactCategory::User,
                paths: vec![
                    "/home/*/.ssh/authorized_keys".to_string(),
                    "/home/*/.ssh/known_hosts".to_string(),
                    "/home/*/.ssh/config".to_string(),
                    "/root/.ssh/authorized_keys".to_string(),
                    "/root/.ssh/known_hosts".to_string(),
                    "/etc/ssh/sshd_config".to_string(),
                    "/etc/ssh/ssh_config".to_string(),
                ],
                platform: "linux".to_string(),
                triage: true,
                significance: 9,
                mitre_relevance: vec!["T1098.004".to_string(), "T1021.004".to_string()],
            },
            ArtifactDefinition {
                id: "linux-profile".to_string(),
                name: "User Profiles".to_string(),
                description: "User profile and startup scripts".to_string(),
                category: ArtifactCategory::User,
                paths: vec![
                    "/home/*/.bashrc".to_string(),
                    "/home/*/.bash_profile".to_string(),
                    "/home/*/.profile".to_string(),
                    "/home/*/.zshrc".to_string(),
                    "/root/.bashrc".to_string(),
                    "/root/.profile".to_string(),
                    "/etc/profile".to_string(),
                    "/etc/profile.d/*".to_string(),
                    "/etc/bash.bashrc".to_string(),
                ],
                platform: "linux".to_string(),
                triage: true,
                significance: 8,
                mitre_relevance: vec!["T1546.004".to_string()],
            },
            // Network Artifacts
            ArtifactDefinition {
                id: "linux-network-config".to_string(),
                name: "Network Configuration".to_string(),
                description: "Network interface and routing configuration".to_string(),
                category: ArtifactCategory::Network,
                paths: vec![
                    "/etc/network/interfaces".to_string(),
                    "/etc/netplan/*.yaml".to_string(),
                    "/etc/NetworkManager/NetworkManager.conf".to_string(),
                    "/etc/resolv.conf".to_string(),
                    "/etc/hosts.allow".to_string(),
                    "/etc/hosts.deny".to_string(),
                ],
                platform: "linux".to_string(),
                triage: false,
                significance: 7,
                mitre_relevance: vec!["T1016".to_string()],
            },
            ArtifactDefinition {
                id: "linux-firewall".to_string(),
                name: "Firewall Rules".to_string(),
                description: "IPtables and firewall configuration".to_string(),
                category: ArtifactCategory::Network,
                paths: vec![
                    "/etc/iptables/rules.v4".to_string(),
                    "/etc/iptables/rules.v6".to_string(),
                    "/etc/ufw/user.rules".to_string(),
                    "/etc/ufw/user6.rules".to_string(),
                ],
                platform: "linux".to_string(),
                triage: false,
                significance: 8,
                mitre_relevance: vec!["T1562.004".to_string()],
            },
            // Browser Artifacts
            ArtifactDefinition {
                id: "linux-firefox".to_string(),
                name: "Firefox Data".to_string(),
                description: "Firefox browser history and data".to_string(),
                category: ArtifactCategory::Browser,
                paths: vec![
                    "/home/*/.mozilla/firefox/*/places.sqlite".to_string(),
                    "/home/*/.mozilla/firefox/*/cookies.sqlite".to_string(),
                    "/home/*/.mozilla/firefox/*/formhistory.sqlite".to_string(),
                    "/home/*/.mozilla/firefox/*/downloads.sqlite".to_string(),
                ],
                platform: "linux".to_string(),
                triage: false,
                significance: 7,
                mitre_relevance: vec!["T1539".to_string()],
            },
            ArtifactDefinition {
                id: "linux-chrome".to_string(),
                name: "Chrome Data".to_string(),
                description: "Chrome browser history and data".to_string(),
                category: ArtifactCategory::Browser,
                paths: vec![
                    "/home/*/.config/google-chrome/Default/History".to_string(),
                    "/home/*/.config/google-chrome/Default/Cookies".to_string(),
                    "/home/*/.config/google-chrome/Default/Login Data".to_string(),
                    "/home/*/.config/chromium/Default/History".to_string(),
                ],
                platform: "linux".to_string(),
                triage: false,
                significance: 7,
                mitre_relevance: vec!["T1539".to_string()],
            },
            // Application Artifacts
            ArtifactDefinition {
                id: "linux-docker".to_string(),
                name: "Docker Configuration".to_string(),
                description: "Docker and container configurations".to_string(),
                category: ArtifactCategory::Application,
                paths: vec![
                    "/etc/docker/daemon.json".to_string(),
                    "/var/lib/docker/containers/*/*.log".to_string(),
                ],
                platform: "linux".to_string(),
                triage: false,
                significance: 6,
                mitre_relevance: vec!["T1610".to_string()],
            },
            ArtifactDefinition {
                id: "linux-webserver".to_string(),
                name: "Web Server Logs".to_string(),
                description: "Apache and Nginx logs".to_string(),
                category: ArtifactCategory::Application,
                paths: vec![
                    "/var/log/apache2/access.log".to_string(),
                    "/var/log/apache2/error.log".to_string(),
                    "/var/log/nginx/access.log".to_string(),
                    "/var/log/nginx/error.log".to_string(),
                    "/var/log/httpd/access_log".to_string(),
                    "/var/log/httpd/error_log".to_string(),
                ],
                platform: "linux".to_string(),
                triage: true,
                significance: 8,
                mitre_relevance: vec!["T1190".to_string()],
            },
        ]
    }
}

// ============================================================================
// ARTIFACT COLLECTOR IMPLEMENTATION
// ============================================================================

/// Main artifact collector structure
struct ArtifactCollector {
    /// Artifact definitions to collect
    definitions: Vec<ArtifactDefinition>,
    /// Categories to collect
    categories: Vec<ArtifactCategory>,
    /// Triage mode
    triage_mode: bool,
    /// Include file contents
    include_contents: bool,
    /// Maximum file size
    max_file_size: u64,
    /// Custom paths
    custom_paths: Vec<PathBuf>,
    /// Verbose mode
    verbose: bool,
    /// Dry run mode
    dry_run: bool,
    /// Collected artifacts
    collected: Vec<CollectedArtifact>,
    /// Errors encountered
    errors: Vec<CollectionError>,
    /// Statistics
    stats: CollectionStats,
}

impl ArtifactCollector {
    /// Create a new artifact collector
    fn new(
        categories: Vec<ArtifactCategory>,
        triage_mode: bool,
        include_contents: bool,
        max_file_size: u64,
        custom_paths: Vec<PathBuf>,
        verbose: bool,
        dry_run: bool,
    ) -> Self {
        // Get all definitions
        let mut definitions = ArtifactDefinition::linux_artifacts();

        // Filter by category if specified
        let effective_categories = if categories.is_empty() || categories.contains(&ArtifactCategory::All) {
            vec![
                ArtifactCategory::System,
                ArtifactCategory::User,
                ArtifactCategory::Network,
                ArtifactCategory::Security,
                ArtifactCategory::Browser,
                ArtifactCategory::Application,
            ]
        } else {
            categories.clone()
        };

        // Filter definitions
        definitions.retain(|d| effective_categories.contains(&d.category));

        // Filter by triage if enabled
        if triage_mode {
            definitions.retain(|d| d.triage);
        }

        ArtifactCollector {
            definitions,
            categories: effective_categories,
            triage_mode,
            include_contents,
            max_file_size: max_file_size * 1024 * 1024,
            custom_paths,
            verbose,
            dry_run,
            collected: Vec::new(),
            errors: Vec::new(),
            stats: CollectionStats::default(),
        }
    }

    /// Run the collection process
    fn collect(&mut self) -> Result<()> {
        println!("{}", "Starting artifact collection...".green().bold());
        println!("Categories: {:?}", self.categories);
        println!("Triage mode: {}", self.triage_mode);
        println!("Definitions loaded: {}", self.definitions.len());
        println!("{}", "-".repeat(60));

        // Collect artifacts from definitions
        for def in self.definitions.clone() {
            if self.verbose {
                println!("\nProcessing: {} ({})", def.name.cyan(), def.id);
            }

            for path_pattern in &def.paths {
                self.collect_pattern(&def, path_pattern);
            }
        }

        // Collect custom paths
        for path in self.custom_paths.clone() {
            if self.verbose {
                println!("\nCollecting custom path: {}", path.display());
            }
            self.collect_file(
                &path,
                "custom",
                &format!("Custom artifact: {}", path.display()),
            );
        }

        // Update statistics
        self.stats.total_artifacts = self.collected.len();
        self.stats.total_bytes = self.collected.iter().map(|a| a.size).sum();
        self.stats.errors_encountered = self.errors.len();

        for artifact in &self.collected {
            // Find the category from the artifact definition
            if let Some(def) = self.definitions.iter().find(|d| d.id == artifact.artifact_id) {
                *self.stats.artifacts_by_category
                    .entry(format!("{:?}", def.category))
                    .or_insert(0) += 1;
            }
        }

        Ok(())
    }

    /// Collect files matching a pattern
    fn collect_pattern(&mut self, def: &ArtifactDefinition, pattern: &str) {
        // Handle glob patterns
        if pattern.contains('*') {
            self.collect_glob(def, pattern);
        } else {
            // Direct path
            let path = Path::new(pattern);
            if path.exists() {
                self.collect_file(path, &def.id, &def.description);
            }
        }
    }

    /// Collect files matching a glob pattern
    fn collect_glob(&mut self, def: &ArtifactDefinition, pattern: &str) {
        // Split pattern into base and glob parts
        let parts: Vec<&str> = pattern.splitn(2, '*').collect();
        if parts.is_empty() {
            return;
        }

        let base_path = Path::new(parts[0].trim_end_matches('/'));
        if !base_path.exists() {
            return;
        }

        // Walk the base path
        let walker = WalkDir::new(base_path)
            .max_depth(3) // Limit depth for safety
            .into_iter()
            .filter_map(|e| e.ok());

        for entry in walker {
            let path = entry.path();
            if path.is_file() {
                // Simple pattern matching
                let path_str = path.to_string_lossy();
                if self.matches_pattern(&path_str, pattern) {
                    self.collect_file(path, &def.id, &def.description);
                }
            }
        }
    }

    /// Simple glob pattern matching
    fn matches_pattern(&self, path: &str, pattern: &str) -> bool {
        let pattern_parts: Vec<&str> = pattern.split('*').collect();
        let mut pos = 0;

        for (i, part) in pattern_parts.iter().enumerate() {
            if part.is_empty() {
                continue;
            }

            if let Some(found) = path[pos..].find(part) {
                if i == 0 && found != 0 {
                    // First part must match at start
                    return false;
                }
                pos += found + part.len();
            } else {
                return false;
            }
        }

        true
    }

    /// Collect a single file
    fn collect_file(&mut self, path: &Path, artifact_id: &str, description: &str) {
        if self.dry_run {
            println!("  Would collect: {}", path.display());
            return;
        }

        // Check file exists and is readable
        let metadata = match fs::metadata(path) {
            Ok(m) => m,
            Err(e) => {
                self.record_error(path, &e.to_string());
                return;
            }
        };

        // Check file size
        if metadata.len() > self.max_file_size {
            if self.verbose {
                println!("  Skipping (too large): {} ({} MB)",
                    path.display(),
                    metadata.len() / 1024 / 1024
                );
            }
            self.stats.files_skipped += 1;
            return;
        }

        // Calculate hashes
        let (sha256, md5) = match self.calculate_hashes(path) {
            Ok(hashes) => hashes,
            Err(e) => {
                self.record_error(path, &e.to_string());
                return;
            }
        };

        // Get timestamps
        let modified = metadata.modified().ok().map(|t| t.into());
        let created = metadata.created().ok().map(|t| t.into());

        // Get Unix metadata
        #[cfg(unix)]
        let (permissions, uid, gid) = {
            use std::os::unix::fs::MetadataExt;
            (Some(metadata.mode()), Some(metadata.uid()), Some(metadata.gid()))
        };

        #[cfg(not(unix))]
        let (permissions, uid, gid) = (None, None, None);

        // Create archive path
        let archive_path = self.create_archive_path(path, artifact_id);

        let artifact = CollectedArtifact {
            artifact_id: artifact_id.to_string(),
            source_path: path.to_path_buf(),
            archive_path,
            size: metadata.len(),
            sha256,
            md5,
            collected_at: Utc::now(),
            modified,
            created,
            permissions,
            uid,
            gid,
            notes: Some(description.to_string()),
        };

        if self.verbose {
            println!("  Collected: {} ({} bytes)", path.display(), artifact.size);
        }

        self.collected.push(artifact);
    }

    /// Calculate file hashes
    fn calculate_hashes(&self, path: &Path) -> Result<(String, String)> {
        let mut file = File::open(path)?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;

        let sha256 = hex::encode(Sha256::digest(&buffer));
        let md5 = hex::encode(Md5::digest(&buffer));

        Ok((sha256, md5))
    }

    /// Create archive path for artifact
    fn create_archive_path(&self, source: &Path, artifact_id: &str) -> PathBuf {
        let filename = source.file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "unknown".to_string());

        // Create structured path in archive
        PathBuf::from(format!(
            "{}/{}",
            artifact_id,
            source.to_string_lossy().replace('/', "_").trim_start_matches('_')
        ))
    }

    /// Record a collection error
    fn record_error(&mut self, path: &Path, error: &str) {
        if self.verbose {
            eprintln!("  Error: {} - {}", path.display(), error);
        }

        self.errors.push(CollectionError {
            path: path.to_path_buf(),
            error: error.to_string(),
            timestamp: Utc::now(),
        });
    }

    /// Get system information
    fn get_system_info() -> SystemInfo {
        let hostname = hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "unknown".to_string());

        #[cfg(unix)]
        let kernel = std::process::Command::new("uname")
            .arg("-r")
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());

        #[cfg(not(unix))]
        let kernel = None;

        let current_user = std::env::var("USER").ok();

        SystemInfo {
            hostname,
            os: std::env::consts::OS.to_string(),
            os_version: "Unknown".to_string(),
            kernel,
            architecture: std::env::consts::ARCH.to_string(),
            current_user,
            uptime: None,
        }
    }

    /// Create the final collection manifest
    fn create_manifest(&self, case_info: CaseInfo, start_time: DateTime<Utc>) -> CollectionManifest {
        CollectionManifest {
            case_info,
            collection_info: CollectionInfo {
                tool_version: env!("CARGO_PKG_VERSION").to_string(),
                collection_started: start_time,
                collection_completed: Utc::now(),
                categories_collected: self.categories.clone(),
                triage_mode: self.triage_mode,
            },
            system_info: Self::get_system_info(),
            artifacts: self.collected.clone(),
            stats: self.stats.clone(),
            errors: self.errors.clone(),
        }
    }
}

// ============================================================================
// OUTPUT GENERATION
// ============================================================================

/// Create output archive
fn create_output(
    collector: &ArtifactCollector,
    manifest: &CollectionManifest,
    output: &Path,
    format: &OutputFormat,
    include_contents: bool,
) -> Result<()> {
    match format {
        OutputFormat::TarGz => create_tar_gz(collector, manifest, output, include_contents),
        OutputFormat::Zip => create_zip(collector, manifest, output, include_contents),
        OutputFormat::Directory => create_directory(collector, manifest, output, include_contents),
    }
}

fn create_tar_gz(
    collector: &ArtifactCollector,
    manifest: &CollectionManifest,
    output: &Path,
    include_contents: bool,
) -> Result<()> {
    let file = File::create(output)?;
    let enc = GzEncoder::new(file, Compression::default());
    let mut tar = tar::Builder::new(enc);

    // Add manifest
    let manifest_json = serde_json::to_string_pretty(manifest)?;
    let manifest_bytes = manifest_json.as_bytes();
    let mut header = tar::Header::new_gnu();
    header.set_path("manifest.json")?;
    header.set_size(manifest_bytes.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    tar.append(&header, manifest_bytes)?;

    // Add collected files if including contents
    if include_contents {
        for artifact in &collector.collected {
            if let Ok(file) = File::open(&artifact.source_path) {
                let mut reader = BufReader::new(file);
                let mut buffer = Vec::new();
                if reader.read_to_end(&mut buffer).is_ok() {
                    let mut header = tar::Header::new_gnu();
                    header.set_path(&artifact.archive_path)?;
                    header.set_size(buffer.len() as u64);
                    header.set_mode(artifact.permissions.unwrap_or(0o644));
                    header.set_cksum();
                    tar.append(&header, buffer.as_slice())?;
                }
            }
        }
    }

    tar.finish()?;
    Ok(())
}

fn create_zip(
    collector: &ArtifactCollector,
    manifest: &CollectionManifest,
    output: &Path,
    include_contents: bool,
) -> Result<()> {
    let file = File::create(output)?;
    let mut zip = zip::ZipWriter::new(file);

    let options = zip::write::FileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);

    // Add manifest
    zip.start_file("manifest.json", options)?;
    let manifest_json = serde_json::to_string_pretty(manifest)?;
    zip.write_all(manifest_json.as_bytes())?;

    // Add collected files if including contents
    if include_contents {
        for artifact in &collector.collected {
            if let Ok(mut file) = File::open(&artifact.source_path) {
                let archive_path = artifact.archive_path.to_string_lossy();
                zip.start_file(archive_path.as_ref(), options)?;

                let mut buffer = Vec::new();
                if file.read_to_end(&mut buffer).is_ok() {
                    zip.write_all(&buffer)?;
                }
            }
        }
    }

    zip.finish()?;
    Ok(())
}

fn create_directory(
    collector: &ArtifactCollector,
    manifest: &CollectionManifest,
    output: &Path,
    include_contents: bool,
) -> Result<()> {
    fs::create_dir_all(output)?;

    // Write manifest
    let manifest_path = output.join("manifest.json");
    let mut manifest_file = File::create(&manifest_path)?;
    let manifest_json = serde_json::to_string_pretty(manifest)?;
    manifest_file.write_all(manifest_json.as_bytes())?;

    // Copy collected files if including contents
    if include_contents {
        for artifact in &collector.collected {
            let dest_path = output.join(&artifact.archive_path);
            if let Some(parent) = dest_path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::copy(&artifact.source_path, &dest_path).ok();
        }
    }

    Ok(())
}

// ============================================================================
// MAIN ENTRY POINT
// ============================================================================

fn main() -> Result<()> {
    let args = Args::parse();

    println!("{}", "=".repeat(60).blue());
    println!("{}", "Artifact Collector - Forensic Evidence Collection".blue().bold());
    println!("{}", "=".repeat(60).blue());

    let start_time = Utc::now();

    let case_info = CaseInfo {
        case_id: args.case_id.unwrap_or_else(|| format!("CASE-{}", Utc::now().timestamp())),
        investigator: args.investigator.unwrap_or_else(|| "Unknown".to_string()),
        description: "Forensic artifact collection".to_string(),
        created_at: Utc::now(),
    };

    println!("Case ID: {}", case_info.case_id.yellow());
    println!("Investigator: {}", case_info.investigator);
    println!("Output: {}", args.output.display().to_string().cyan());
    println!("Format: {:?}", args.format);
    println!("Triage Mode: {}", args.triage);
    println!("Include Contents: {}", args.include_contents);
    println!("{}", "-".repeat(60));

    // Create collector
    let mut collector = ArtifactCollector::new(
        args.category,
        args.triage,
        args.include_contents,
        args.max_file_size,
        args.custom_path,
        args.verbose,
        args.dry_run,
    );

    // Run collection
    collector.collect()?;

    if args.dry_run {
        println!("\n{}", "Dry run complete. No files were collected.".yellow());
        return Ok(());
    }

    // Create manifest
    let manifest = collector.create_manifest(case_info, start_time);

    // Print summary
    println!("{}", "-".repeat(60).blue());
    println!("{}", "Collection Summary".green().bold());
    println!("Total Artifacts: {}", manifest.stats.total_artifacts);
    println!("Total Size: {} bytes ({:.2} MB)",
        manifest.stats.total_bytes,
        manifest.stats.total_bytes as f64 / 1024.0 / 1024.0
    );
    println!("Files Skipped: {}", manifest.stats.files_skipped);
    println!("Errors: {}", manifest.stats.errors_encountered);

    if !manifest.stats.artifacts_by_category.is_empty() {
        println!("\nArtifacts by Category:");
        for (cat, count) in &manifest.stats.artifacts_by_category {
            println!("  {}: {}", cat, count);
        }
    }

    // Create output
    println!("{}", "-".repeat(60));
    println!("Creating output archive...");
    create_output(&collector, &manifest, &args.output, &args.format, args.include_contents)?;

    println!("{}", "=".repeat(60).blue());
    println!("{}", "Collection complete!".green().bold());
    println!("Output saved to: {}", args.output.display());

    // Print hash of output for chain of custody
    if args.output.exists() && !matches!(args.format, OutputFormat::Directory) {
        let mut file = File::open(&args.output)?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;
        let sha256 = hex::encode(Sha256::digest(&buffer));
        println!("Output SHA256: {}", sha256.yellow());
    }

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
    fn test_artifact_collector_creation() {
        let collector = ArtifactCollector::new(
            vec![],
            false,
            false,
            50,
            vec![],
            false,
            false,
        );
        assert!(!collector.definitions.is_empty());
    }

    #[test]
    fn test_triage_mode_filtering() {
        let collector = ArtifactCollector::new(
            vec![],
            true, // triage mode
            false,
            50,
            vec![],
            false,
            false,
        );

        // All definitions should have triage=true
        for def in &collector.definitions {
            assert!(def.triage, "Non-triage artifact found: {}", def.id);
        }
    }

    #[test]
    fn test_category_filtering() {
        let collector = ArtifactCollector::new(
            vec![ArtifactCategory::Security],
            false,
            false,
            50,
            vec![],
            false,
            false,
        );

        // All definitions should be Security category
        for def in &collector.definitions {
            assert_eq!(def.category, ArtifactCategory::Security);
        }
    }

    #[test]
    fn test_pattern_matching() {
        let collector = ArtifactCollector::new(vec![], false, false, 50, vec![], false, false);

        assert!(collector.matches_pattern("/etc/passwd", "/etc/passwd"));
        assert!(collector.matches_pattern("/home/user/.bash_history", "/home/*/.bash_history"));
        assert!(collector.matches_pattern("/var/log/auth.log", "/var/log/*.log"));
        assert!(!collector.matches_pattern("/etc/shadow", "/etc/passwd"));
    }

    #[test]
    fn test_hash_calculation() {
        let temp_dir = tempdir().unwrap();
        let file_path = temp_dir.path().join("test.txt");

        let mut file = File::create(&file_path).unwrap();
        file.write_all(b"test content").unwrap();

        let collector = ArtifactCollector::new(vec![], false, false, 50, vec![], false, false);
        let (sha256, md5) = collector.calculate_hashes(&file_path).unwrap();

        assert_eq!(sha256.len(), 64);
        assert_eq!(md5.len(), 32);
    }

    #[test]
    fn test_archive_path_creation() {
        let collector = ArtifactCollector::new(vec![], false, false, 50, vec![], false, false);

        let source = Path::new("/var/log/auth.log");
        let archive_path = collector.create_archive_path(source, "linux-auth-logs");

        assert!(archive_path.to_string_lossy().contains("linux-auth-logs"));
        assert!(archive_path.to_string_lossy().contains("var_log_auth.log"));
    }

    #[test]
    fn test_system_info_collection() {
        let info = ArtifactCollector::get_system_info();
        assert!(!info.hostname.is_empty());
        assert!(!info.os.is_empty());
        assert!(!info.architecture.is_empty());
    }

    #[test]
    fn test_dry_run_mode() {
        let temp_dir = tempdir().unwrap();
        let file_path = temp_dir.path().join("test.txt");
        File::create(&file_path).unwrap();

        let mut collector = ArtifactCollector::new(
            vec![],
            false,
            false,
            50,
            vec![file_path.clone()],
            false,
            true, // dry run
        );

        collector.collect().unwrap();

        // In dry run mode, nothing should be collected
        assert!(collector.collected.is_empty());
    }

    #[test]
    fn test_file_size_limit() {
        let mut collector = ArtifactCollector::new(
            vec![],
            false,
            false,
            0, // 0 MB limit
            vec![],
            false,
            false,
        );

        // This should skip any file due to size limit
        collector.max_file_size = 0;

        let temp_dir = tempdir().unwrap();
        let file_path = temp_dir.path().join("test.txt");
        let mut file = File::create(&file_path).unwrap();
        file.write_all(b"test content").unwrap();

        collector.collect_file(&file_path, "test", "Test file");

        assert!(collector.collected.is_empty());
        assert_eq!(collector.stats.files_skipped, 1);
    }

    #[test]
    fn test_manifest_creation() {
        let collector = ArtifactCollector::new(vec![], false, false, 50, vec![], false, false);

        let case_info = CaseInfo {
            case_id: "TEST-001".to_string(),
            investigator: "Tester".to_string(),
            description: "Test case".to_string(),
            created_at: Utc::now(),
        };

        let manifest = collector.create_manifest(case_info, Utc::now());

        assert_eq!(manifest.case_info.case_id, "TEST-001");
        assert!(!manifest.collection_info.tool_version.is_empty());
    }

    #[test]
    fn test_error_recording() {
        let mut collector = ArtifactCollector::new(vec![], false, false, 50, vec![], false, false);

        collector.record_error(Path::new("/nonexistent"), "File not found");

        assert_eq!(collector.errors.len(), 1);
        assert!(collector.errors[0].error.contains("not found"));
    }

    #[test]
    fn test_artifact_definition_structure() {
        let artifacts = ArtifactDefinition::linux_artifacts();

        for artifact in artifacts {
            assert!(!artifact.id.is_empty());
            assert!(!artifact.name.is_empty());
            assert!(!artifact.paths.is_empty());
            assert!(artifact.significance >= 1 && artifact.significance <= 10);
        }
    }

    #[test]
    fn test_collected_artifact_serialization() {
        let artifact = CollectedArtifact {
            artifact_id: "test".to_string(),
            source_path: PathBuf::from("/test"),
            archive_path: PathBuf::from("test/file"),
            size: 100,
            sha256: "abc".to_string(),
            md5: "def".to_string(),
            collected_at: Utc::now(),
            modified: None,
            created: None,
            permissions: Some(0o644),
            uid: Some(1000),
            gid: Some(1000),
            notes: Some("Test".to_string()),
        };

        let json = serde_json::to_string(&artifact);
        assert!(json.is_ok());
    }
}
