//! IOC Scanner - Indicator of Compromise Detection Tool
//!
//! A fast, parallel scanner for detecting malicious indicators in file systems.
//! Supports hash-based detection, pattern matching, and YARA-like rules.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use colored::Colorize;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use log::{debug, error, info, warn};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

mod database;
mod output;
mod scanner;

use database::IocDatabase;
use output::OutputFormat;
use scanner::{Finding, ScanConfig, Scanner};

/// IOC Scanner - Detect malicious indicators in file systems
#[derive(Parser)]
#[command(name = "iocscan")]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Verbosity level (-v, -vv, -vvv)
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,

    /// Output format
    #[arg(short, long, default_value = "text", global = true)]
    format: OutputFormat,

    /// Output file (stdout if not specified)
    #[arg(short = 'O', long, global = true)]
    output: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan files and directories for IOCs
    Scan {
        /// Path to scan
        #[arg(short, long)]
        path: PathBuf,

        /// IOC database file (JSON or YAML)
        #[arg(short, long)]
        database: PathBuf,

        /// Number of parallel workers
        #[arg(short = 'j', long, default_value = "4")]
        workers: usize,

        /// Maximum file size to scan (in MB)
        #[arg(short = 'm', long, default_value = "100")]
        max_size: u64,

        /// Follow symbolic links
        #[arg(short = 'L', long)]
        follow_links: bool,

        /// Scan file contents for patterns
        #[arg(short = 'c', long)]
        content_scan: bool,

        /// Maximum directory depth
        #[arg(short, long)]
        depth: Option<usize>,
    },

    /// Create or update IOC database
    Database {
        #[command(subcommand)]
        action: DatabaseAction,
    },

    /// Watch a directory for changes and scan in real-time
    Watch {
        /// Path to watch
        #[arg(short, long)]
        path: PathBuf,

        /// IOC database file
        #[arg(short, long)]
        database: PathBuf,
    },

    /// Generate sample IOC database
    Init {
        /// Output file path
        #[arg(short, long, default_value = "ioc_database.yaml")]
        output: PathBuf,
    },
}

#[derive(Subcommand)]
enum DatabaseAction {
    /// Add IOCs to the database
    Add {
        /// Database file
        #[arg(short, long)]
        database: PathBuf,

        /// IOC type (hash, domain, ip, path, pattern)
        #[arg(short = 't', long)]
        ioc_type: String,

        /// IOC value
        #[arg(short, long)]
        value: String,

        /// Description
        #[arg(short = 'D', long)]
        description: Option<String>,

        /// Severity (low, medium, high, critical)
        #[arg(short, long, default_value = "medium")]
        severity: String,
    },

    /// List IOCs in the database
    List {
        /// Database file
        #[arg(short, long)]
        database: PathBuf,

        /// Filter by type
        #[arg(short = 't', long)]
        ioc_type: Option<String>,
    },

    /// Import IOCs from a file
    Import {
        /// Database file
        #[arg(short, long)]
        database: PathBuf,

        /// Import file (CSV, JSON, or plain text)
        #[arg(short, long)]
        input: PathBuf,
    },

    /// Export IOCs to a file
    Export {
        /// Database file
        #[arg(short, long)]
        database: PathBuf,

        /// Export file
        #[arg(short, long)]
        output: PathBuf,

        /// Export format (csv, json, stix)
        #[arg(short, long, default_value = "csv")]
        format: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    let log_level = match cli.verbose {
        0 => log::LevelFilter::Warn,
        1 => log::LevelFilter::Info,
        2 => log::LevelFilter::Debug,
        _ => log::LevelFilter::Trace,
    };

    env_logger::Builder::new()
        .filter_level(log_level)
        .format_timestamp_secs()
        .init();

    info!("IOC Scanner starting");

    let result = match cli.command {
        Commands::Scan {
            path,
            database,
            workers,
            max_size,
            follow_links,
            content_scan,
            depth,
        } => {
            run_scan(
                &path,
                &database,
                workers,
                max_size * 1024 * 1024,
                follow_links,
                content_scan,
                depth,
                cli.format,
                cli.output.as_deref(),
            )
            .await
        }
        Commands::Database { action } => run_database_command(action).await,
        Commands::Watch { path, database } => run_watch(&path, &database).await,
        Commands::Init { output } => generate_sample_database(&output),
    };

    if let Err(e) = result {
        error!("Error: {}", e);
        eprintln!("{} {}", "Error:".red().bold(), e);
        std::process::exit(1);
    }

    Ok(())
}

async fn run_scan(
    path: &PathBuf,
    database_path: &PathBuf,
    workers: usize,
    max_size: u64,
    follow_links: bool,
    content_scan: bool,
    max_depth: Option<usize>,
    format: OutputFormat,
    output_path: Option<&std::path::Path>,
) -> Result<()> {
    // Verify paths exist
    if !path.exists() {
        anyhow::bail!("Scan path does not exist: {:?}", path);
    }

    if !database_path.exists() {
        anyhow::bail!("IOC database not found: {:?}", database_path);
    }

    println!(
        "{} Loading IOC database from {:?}",
        "[*]".blue(),
        database_path
    );

    // Load IOC database
    let db = IocDatabase::load(database_path).context("Failed to load IOC database")?;

    println!(
        "{} Loaded {} IOCs ({} hashes, {} domains, {} IPs, {} patterns)",
        "[+]".green(),
        db.total_count(),
        db.hashes.len(),
        db.domains.len(),
        db.ip_addresses.len(),
        db.patterns.len()
    );

    // Configure scanner
    let config = ScanConfig {
        workers,
        max_file_size: max_size,
        follow_symlinks: follow_links,
        scan_content: content_scan,
        max_depth,
    };

    println!(
        "{} Scanning {:?} with {} workers",
        "[*]".blue(),
        path,
        workers
    );

    // Create progress bars
    let multi_progress = MultiProgress::new();
    let files_pb = multi_progress.add(ProgressBar::new_spinner());
    files_pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} {msg}")
            .unwrap(),
    );
    files_pb.set_message("Scanning files...");

    // Run scanner
    let scanner = Scanner::new(db, config);
    let start_time = std::time::Instant::now();

    let findings = Arc::new(Mutex::new(Vec::new()));
    let findings_clone = findings.clone();

    let scan_handle = tokio::spawn(async move {
        scanner.scan(path, move |finding| {
            let findings = findings_clone.clone();
            async move {
                findings.lock().await.push(finding);
            }
        }).await
    });

    // Wait for scan to complete
    let stats = scan_handle.await??;

    files_pb.finish_with_message(format!(
        "Scanned {} files ({} errors)",
        stats.files_scanned, stats.errors
    ));

    let duration = start_time.elapsed();
    let findings = Arc::try_unwrap(findings)
        .unwrap_or_else(|_| panic!("Failed to unwrap findings"))
        .into_inner();

    // Print results
    println!();
    output::print_scan_results(&findings, &stats, duration, format, output_path)?;

    if !findings.is_empty() {
        eprintln!(
            "\n{} {} potential threats detected!",
            "[!]".red().bold(),
            findings.len()
        );
    }

    Ok(())
}

async fn run_database_command(action: DatabaseAction) -> Result<()> {
    match action {
        DatabaseAction::Add {
            database,
            ioc_type,
            value,
            description,
            severity,
        } => {
            let mut db = if database.exists() {
                IocDatabase::load(&database)?
            } else {
                IocDatabase::new()
            };

            db.add_ioc(&ioc_type, &value, description.as_deref(), &severity)?;
            db.save(&database)?;

            println!("{} Added IOC to database", "[+]".green());
        }
        DatabaseAction::List { database, ioc_type } => {
            let db = IocDatabase::load(&database)?;
            db.list(ioc_type.as_deref());
        }
        DatabaseAction::Import { database, input } => {
            let mut db = if database.exists() {
                IocDatabase::load(&database)?
            } else {
                IocDatabase::new()
            };

            let count = db.import(&input)?;
            db.save(&database)?;

            println!("{} Imported {} IOCs", "[+]".green(), count);
        }
        DatabaseAction::Export {
            database,
            output,
            format,
        } => {
            let db = IocDatabase::load(&database)?;
            db.export(&output, &format)?;
            println!("{} Exported IOCs to {:?}", "[+]".green(), output);
        }
    }

    Ok(())
}

async fn run_watch(path: &PathBuf, database_path: &PathBuf) -> Result<()> {
    use notify::{RecursiveMode, Watcher};

    println!(
        "{} Watching {:?} for changes (Ctrl+C to stop)",
        "[*]".blue(),
        path
    );

    let db = IocDatabase::load(database_path)?;
    let config = ScanConfig::default();
    let scanner = Scanner::new(db, config);

    let (tx, mut rx) = tokio::sync::mpsc::channel(100);

    let mut watcher = notify::recommended_watcher(move |res: Result<notify::Event, _>| {
        if let Ok(event) = res {
            let _ = tx.blocking_send(event);
        }
    })?;

    watcher.watch(path, RecursiveMode::Recursive)?;

    while let Some(event) = rx.recv().await {
        for path in event.paths {
            if path.is_file() {
                debug!("File changed: {:?}", path);

                if let Some(finding) = scanner.scan_file(&path).await? {
                    println!(
                        "{} ALERT: {} - {}",
                        "[!]".red().bold(),
                        finding.ioc_type,
                        path.display()
                    );
                }
            }
        }
    }

    Ok(())
}

fn generate_sample_database(output: &PathBuf) -> Result<()> {
    let sample = r#"# IOC Scanner Database
# Sample database for demonstration

version: "1.0"
name: "Sample IOC Database"
description: "Example indicators of compromise for testing"
created: "2024-01-01T00:00:00Z"
updated: "2024-01-01T00:00:00Z"

# Known malicious file hashes
hashes:
  - hash: "e99a18c428cb38d5f260853678922e03"
    type: "md5"
    description: "Known malware sample"
    severity: "critical"
    tags: ["malware", "trojan"]

  - hash: "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"
    type: "sha1"
    description: "Suspicious executable"
    severity: "high"
    tags: ["suspicious"]

  - hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    type: "sha256"
    description: "Empty file (potential dropper)"
    severity: "low"

# Malicious domains
domains:
  - domain: "malware-c2.example.com"
    description: "Known C2 domain"
    severity: "critical"
    tags: ["c2", "apt"]

  - domain: "phishing-site.example.net"
    description: "Phishing domain"
    severity: "high"
    tags: ["phishing"]

# Malicious IP addresses
ip_addresses:
  - ip: "10.0.0.1"
    description: "Test malicious IP"
    severity: "medium"

# File path patterns
file_paths:
  - path: "/tmp/.hidden"
    description: "Hidden temp file (potential persistence)"
    severity: "medium"

  - path: "/.backdoor"
    description: "Backdoor indicator"
    severity: "critical"

# Content patterns (regex)
patterns:
  - pattern: "eval\\s*\\(\\s*base64_decode"
    description: "PHP webshell pattern"
    severity: "critical"
    tags: ["webshell", "php"]

  - pattern: "powershell.*-enc.*[A-Za-z0-9+/=]{50,}"
    description: "Encoded PowerShell command"
    severity: "high"
    tags: ["powershell", "encoded"]

# MITRE ATT&CK mappings
mitre_mappings:
  "c2": ["T1071", "T1571"]
  "persistence": ["T1053", "T1547"]
  "webshell": ["T1505.003"]
"#;

    std::fs::write(output, sample)?;
    println!("{} Created sample database at {:?}", "[+]".green(), output);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_parsing() {
        let cli = Cli::try_parse_from(["iocscan", "init", "--output", "test.yaml"]);
        assert!(cli.is_ok());
    }
}
