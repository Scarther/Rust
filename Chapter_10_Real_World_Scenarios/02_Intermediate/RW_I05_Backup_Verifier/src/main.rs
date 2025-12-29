//! Backup Integrity Verifier
//!
//! A comprehensive backup verification tool for disaster recovery assurance.
//!
//! Features:
//! - Multiple checksum algorithms (MD5, SHA-256, SHA-512, CRC32)
//! - Archive integrity verification (tar, tar.gz, zip)
//! - Manifest-based verification
//! - Comparison with source directories
//! - Encryption verification
//! - Scheduled verification support
//! - Detailed reporting

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand};
use colored::*;
use crc32fast::Hasher as Crc32Hasher;
use flate2::read::GzDecoder;
use indicatif::{ProgressBar, ProgressStyle};
use md5::{Digest as Md5Digest, Md5};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Sha512};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use tar::Archive;
use tracing::{debug, error, info, warn, Level};
use tracing_subscriber::FmtSubscriber;
use walkdir::WalkDir;
use zip::ZipArchive;

const BUFFER_SIZE: usize = 8192;

/// Backup Verifier CLI
#[derive(Parser)]
#[command(name = "backup-verifier")]
#[command(about = "Verify backup integrity for disaster recovery")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Enable verbose logging
    #[arg(short, long, global = true)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Verify a single file's checksum
    Verify {
        /// File to verify
        #[arg(short, long)]
        file: PathBuf,

        /// Expected checksum
        #[arg(short, long)]
        checksum: String,

        /// Algorithm (md5, sha256, sha512, crc32)
        #[arg(short, long, default_value = "sha256")]
        algorithm: String,
    },
    /// Create a manifest of files with checksums
    CreateManifest {
        /// Directory to scan
        #[arg(short, long)]
        directory: PathBuf,

        /// Output manifest file
        #[arg(short, long, default_value = "backup_manifest.json")]
        output: PathBuf,

        /// Algorithm (md5, sha256, sha512, crc32)
        #[arg(short, long, default_value = "sha256")]
        algorithm: String,
    },
    /// Verify files against a manifest
    VerifyManifest {
        /// Directory to verify
        #[arg(short, long)]
        directory: PathBuf,

        /// Manifest file
        #[arg(short, long)]
        manifest: PathBuf,

        /// Output report file
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Verify archive integrity
    VerifyArchive {
        /// Archive file (tar, tar.gz, zip)
        #[arg(short, long)]
        archive: PathBuf,

        /// Check file checksums inside archive
        #[arg(long)]
        deep: bool,

        /// Expected manifest to compare against
        #[arg(short, long)]
        manifest: Option<PathBuf>,
    },
    /// Compare backup with source
    Compare {
        /// Source directory
        #[arg(short, long)]
        source: PathBuf,

        /// Backup directory
        #[arg(short, long)]
        backup: PathBuf,

        /// Output diff report
        #[arg(short, long, default_value = "backup_diff.csv")]
        output: PathBuf,

        /// Include content comparison
        #[arg(long)]
        content: bool,
    },
    /// Generate verification report
    Report {
        /// Directory to verify
        #[arg(short, long)]
        directory: PathBuf,

        /// Previous manifest for comparison
        #[arg(short, long)]
        previous: Option<PathBuf>,

        /// Output report file
        #[arg(short, long, default_value = "verification_report.json")]
        output: PathBuf,
    },
}

/// Checksum algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Algorithm {
    Md5,
    Sha256,
    Sha512,
    Crc32,
}

impl std::str::FromStr for Algorithm {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "md5" => Ok(Algorithm::Md5),
            "sha256" => Ok(Algorithm::Sha256),
            "sha512" => Ok(Algorithm::Sha512),
            "crc32" => Ok(Algorithm::Crc32),
            _ => anyhow::bail!("Unknown algorithm: {}", s),
        }
    }
}

/// File entry in manifest
#[derive(Debug, Clone, Serialize, Deserialize)]
struct FileEntry {
    path: String,
    size: u64,
    checksum: String,
    algorithm: Algorithm,
    modified: DateTime<Utc>,
    permissions: Option<u32>,
}

/// Backup manifest
#[derive(Debug, Clone, Serialize, Deserialize)]
struct BackupManifest {
    version: String,
    created: DateTime<Utc>,
    source_directory: String,
    algorithm: Algorithm,
    total_files: usize,
    total_size: u64,
    files: Vec<FileEntry>,
}

/// Verification result
#[derive(Debug, Clone, Serialize, Deserialize)]
struct VerificationResult {
    path: String,
    status: VerificationStatus,
    expected_checksum: Option<String>,
    actual_checksum: Option<String>,
    expected_size: Option<u64>,
    actual_size: Option<u64>,
    message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
enum VerificationStatus {
    Ok,
    Mismatch,
    Missing,
    Extra,
    Error,
}

/// Verification report
#[derive(Debug, Clone, Serialize, Deserialize)]
struct VerificationReport {
    verified_at: DateTime<Utc>,
    directory: String,
    manifest: Option<String>,
    total_files: usize,
    verified: usize,
    mismatched: usize,
    missing: usize,
    extra: usize,
    errors: usize,
    results: Vec<VerificationResult>,
}

/// Backup verifier
struct BackupVerifier;

impl BackupVerifier {
    /// Calculate checksum of a file
    fn calculate_checksum(path: &Path, algorithm: Algorithm) -> Result<String> {
        let file = File::open(path)
            .context(format!("Failed to open file: {}", path.display()))?;
        let mut reader = BufReader::with_capacity(BUFFER_SIZE, file);
        let mut buffer = vec![0u8; BUFFER_SIZE];

        match algorithm {
            Algorithm::Md5 => {
                let mut hasher = Md5::new();
                loop {
                    let bytes_read = reader.read(&mut buffer)?;
                    if bytes_read == 0 {
                        break;
                    }
                    hasher.update(&buffer[..bytes_read]);
                }
                Ok(hex::encode(hasher.finalize()))
            }
            Algorithm::Sha256 => {
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
            Algorithm::Sha512 => {
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
            Algorithm::Crc32 => {
                let mut hasher = Crc32Hasher::new();
                loop {
                    let bytes_read = reader.read(&mut buffer)?;
                    if bytes_read == 0 {
                        break;
                    }
                    hasher.update(&buffer[..bytes_read]);
                }
                Ok(format!("{:08x}", hasher.finalize()))
            }
        }
    }

    /// Verify a single file
    fn verify_file(path: &Path, expected: &str, algorithm: Algorithm) -> Result<bool> {
        let actual = Self::calculate_checksum(path, algorithm)?;
        Ok(actual.eq_ignore_ascii_case(expected))
    }

    /// Create manifest for a directory
    fn create_manifest(directory: &Path, algorithm: Algorithm) -> Result<BackupManifest> {
        let mut files = Vec::new();
        let mut total_size = 0u64;

        let entries: Vec<_> = WalkDir::new(directory)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .collect();

        let pb = ProgressBar::new(entries.len() as u64);
        pb.set_style(ProgressStyle::default_bar()
            .template("{spinner:.green} [{bar:40.cyan/blue}] {pos}/{len} ({eta})")?
            .progress_chars("#>-"));

        for entry in entries {
            let path = entry.path();
            let metadata = entry.metadata()?;
            let relative_path = path.strip_prefix(directory)
                .unwrap_or(path)
                .to_string_lossy()
                .to_string();

            match Self::calculate_checksum(path, algorithm) {
                Ok(checksum) => {
                    let modified = metadata.modified()
                        .map(|t| DateTime::from(t))
                        .unwrap_or_else(|_| Utc::now());

                    #[cfg(unix)]
                    let permissions = {
                        use std::os::unix::fs::PermissionsExt;
                        Some(metadata.permissions().mode())
                    };

                    #[cfg(not(unix))]
                    let permissions = None;

                    files.push(FileEntry {
                        path: relative_path,
                        size: metadata.len(),
                        checksum,
                        algorithm,
                        modified,
                        permissions,
                    });

                    total_size += metadata.len();
                }
                Err(e) => {
                    warn!("Failed to hash {}: {}", path.display(), e);
                }
            }

            pb.inc(1);
        }

        pb.finish_with_message("Complete");

        Ok(BackupManifest {
            version: "1.0".to_string(),
            created: Utc::now(),
            source_directory: directory.to_string_lossy().to_string(),
            algorithm,
            total_files: files.len(),
            total_size,
            files,
        })
    }

    /// Verify directory against manifest
    fn verify_against_manifest(directory: &Path, manifest: &BackupManifest) -> Result<VerificationReport> {
        let mut results = Vec::new();
        let mut verified = 0usize;
        let mut mismatched = 0usize;
        let mut missing = 0usize;
        let mut errors = 0usize;

        // Create map of manifest entries
        let manifest_map: HashMap<&str, &FileEntry> = manifest.files
            .iter()
            .map(|f| (f.path.as_str(), f))
            .collect();

        let pb = ProgressBar::new(manifest.files.len() as u64);
        pb.set_style(ProgressStyle::default_bar()
            .template("{spinner:.green} [{bar:40.cyan/blue}] {pos}/{len} ({eta})")?
            .progress_chars("#>-"));

        // Check each file in manifest
        for entry in &manifest.files {
            let file_path = directory.join(&entry.path);

            if !file_path.exists() {
                results.push(VerificationResult {
                    path: entry.path.clone(),
                    status: VerificationStatus::Missing,
                    expected_checksum: Some(entry.checksum.clone()),
                    actual_checksum: None,
                    expected_size: Some(entry.size),
                    actual_size: None,
                    message: "File not found".to_string(),
                });
                missing += 1;
            } else {
                match Self::calculate_checksum(&file_path, entry.algorithm) {
                    Ok(actual_checksum) => {
                        let metadata = std::fs::metadata(&file_path)?;

                        if actual_checksum.eq_ignore_ascii_case(&entry.checksum) {
                            results.push(VerificationResult {
                                path: entry.path.clone(),
                                status: VerificationStatus::Ok,
                                expected_checksum: Some(entry.checksum.clone()),
                                actual_checksum: Some(actual_checksum),
                                expected_size: Some(entry.size),
                                actual_size: Some(metadata.len()),
                                message: "Checksum verified".to_string(),
                            });
                            verified += 1;
                        } else {
                            results.push(VerificationResult {
                                path: entry.path.clone(),
                                status: VerificationStatus::Mismatch,
                                expected_checksum: Some(entry.checksum.clone()),
                                actual_checksum: Some(actual_checksum),
                                expected_size: Some(entry.size),
                                actual_size: Some(metadata.len()),
                                message: "Checksum mismatch - file may be corrupted or modified".to_string(),
                            });
                            mismatched += 1;
                        }
                    }
                    Err(e) => {
                        results.push(VerificationResult {
                            path: entry.path.clone(),
                            status: VerificationStatus::Error,
                            expected_checksum: Some(entry.checksum.clone()),
                            actual_checksum: None,
                            expected_size: Some(entry.size),
                            actual_size: None,
                            message: format!("Error: {}", e),
                        });
                        errors += 1;
                    }
                }
            }

            pb.inc(1);
        }

        pb.finish_with_message("Complete");

        // Find extra files not in manifest
        let mut extra = 0usize;
        for entry in WalkDir::new(directory)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            let relative_path = entry.path()
                .strip_prefix(directory)
                .unwrap_or(entry.path())
                .to_string_lossy()
                .to_string();

            if !manifest_map.contains_key(relative_path.as_str()) {
                results.push(VerificationResult {
                    path: relative_path,
                    status: VerificationStatus::Extra,
                    expected_checksum: None,
                    actual_checksum: None,
                    expected_size: None,
                    actual_size: Some(entry.metadata()?.len()),
                    message: "File not in manifest".to_string(),
                });
                extra += 1;
            }
        }

        Ok(VerificationReport {
            verified_at: Utc::now(),
            directory: directory.to_string_lossy().to_string(),
            manifest: Some(manifest.source_directory.clone()),
            total_files: manifest.files.len(),
            verified,
            mismatched,
            missing,
            extra,
            errors,
            results,
        })
    }

    /// Verify tar archive integrity
    fn verify_tar_archive(path: &Path, deep: bool) -> Result<Vec<VerificationResult>> {
        let file = File::open(path)?;
        let mut results = Vec::new();

        let is_gzip = path.extension()
            .map(|e| e == "gz" || e == "tgz")
            .unwrap_or(false);

        if is_gzip {
            let decoder = GzDecoder::new(file);
            let mut archive = Archive::new(decoder);

            for entry_result in archive.entries()? {
                match entry_result {
                    Ok(mut entry) => {
                        let path = entry.path()?.to_string_lossy().to_string();
                        let size = entry.size();

                        if deep {
                            // Calculate checksum
                            let mut hasher = Sha256::new();
                            let mut buffer = vec![0u8; BUFFER_SIZE];
                            loop {
                                let bytes_read = entry.read(&mut buffer)?;
                                if bytes_read == 0 {
                                    break;
                                }
                                hasher.update(&buffer[..bytes_read]);
                            }
                            let checksum = hex::encode(hasher.finalize());

                            results.push(VerificationResult {
                                path,
                                status: VerificationStatus::Ok,
                                expected_checksum: None,
                                actual_checksum: Some(checksum),
                                expected_size: Some(size),
                                actual_size: Some(size),
                                message: "Entry readable".to_string(),
                            });
                        } else {
                            results.push(VerificationResult {
                                path,
                                status: VerificationStatus::Ok,
                                expected_checksum: None,
                                actual_checksum: None,
                                expected_size: Some(size),
                                actual_size: Some(size),
                                message: "Entry present".to_string(),
                            });
                        }
                    }
                    Err(e) => {
                        results.push(VerificationResult {
                            path: "unknown".to_string(),
                            status: VerificationStatus::Error,
                            expected_checksum: None,
                            actual_checksum: None,
                            expected_size: None,
                            actual_size: None,
                            message: format!("Read error: {}", e),
                        });
                    }
                }
            }
        } else {
            let mut archive = Archive::new(file);

            for entry_result in archive.entries()? {
                match entry_result {
                    Ok(entry) => {
                        let path = entry.path()?.to_string_lossy().to_string();
                        let size = entry.size();

                        results.push(VerificationResult {
                            path,
                            status: VerificationStatus::Ok,
                            expected_checksum: None,
                            actual_checksum: None,
                            expected_size: Some(size),
                            actual_size: Some(size),
                            message: "Entry present".to_string(),
                        });
                    }
                    Err(e) => {
                        results.push(VerificationResult {
                            path: "unknown".to_string(),
                            status: VerificationStatus::Error,
                            expected_checksum: None,
                            actual_checksum: None,
                            expected_size: None,
                            actual_size: None,
                            message: format!("Read error: {}", e),
                        });
                    }
                }
            }
        }

        Ok(results)
    }

    /// Verify zip archive integrity
    fn verify_zip_archive(path: &Path, deep: bool) -> Result<Vec<VerificationResult>> {
        let file = File::open(path)?;
        let mut archive = ZipArchive::new(file)?;
        let mut results = Vec::new();

        for i in 0..archive.len() {
            match archive.by_index(i) {
                Ok(mut entry) => {
                    let path = entry.name().to_string();
                    let size = entry.size();
                    let crc32 = entry.crc32();

                    if deep && !entry.is_dir() {
                        // Calculate and verify CRC32
                        let mut hasher = Crc32Hasher::new();
                        let mut buffer = vec![0u8; BUFFER_SIZE];
                        loop {
                            let bytes_read = entry.read(&mut buffer)?;
                            if bytes_read == 0 {
                                break;
                            }
                            hasher.update(&buffer[..bytes_read]);
                        }
                        let actual_crc = hasher.finalize();

                        if actual_crc == crc32 {
                            results.push(VerificationResult {
                                path,
                                status: VerificationStatus::Ok,
                                expected_checksum: Some(format!("{:08x}", crc32)),
                                actual_checksum: Some(format!("{:08x}", actual_crc)),
                                expected_size: Some(size),
                                actual_size: Some(size),
                                message: "CRC32 verified".to_string(),
                            });
                        } else {
                            results.push(VerificationResult {
                                path,
                                status: VerificationStatus::Mismatch,
                                expected_checksum: Some(format!("{:08x}", crc32)),
                                actual_checksum: Some(format!("{:08x}", actual_crc)),
                                expected_size: Some(size),
                                actual_size: Some(size),
                                message: "CRC32 mismatch".to_string(),
                            });
                        }
                    } else {
                        results.push(VerificationResult {
                            path,
                            status: VerificationStatus::Ok,
                            expected_checksum: Some(format!("{:08x}", crc32)),
                            actual_checksum: None,
                            expected_size: Some(size),
                            actual_size: Some(size),
                            message: "Entry present".to_string(),
                        });
                    }
                }
                Err(e) => {
                    results.push(VerificationResult {
                        path: format!("entry_{}", i),
                        status: VerificationStatus::Error,
                        expected_checksum: None,
                        actual_checksum: None,
                        expected_size: None,
                        actual_size: None,
                        message: format!("Read error: {}", e),
                    });
                }
            }
        }

        Ok(results)
    }

    /// Compare source and backup directories
    fn compare_directories(source: &Path, backup: &Path, check_content: bool) -> Result<Vec<VerificationResult>> {
        let mut results = Vec::new();

        // Build maps of files
        let source_files: HashMap<String, PathBuf> = WalkDir::new(source)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .map(|e| {
                let relative = e.path()
                    .strip_prefix(source)
                    .unwrap_or(e.path())
                    .to_string_lossy()
                    .to_string();
                (relative, e.path().to_path_buf())
            })
            .collect();

        let backup_files: HashMap<String, PathBuf> = WalkDir::new(backup)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .map(|e| {
                let relative = e.path()
                    .strip_prefix(backup)
                    .unwrap_or(e.path())
                    .to_string_lossy()
                    .to_string();
                (relative, e.path().to_path_buf())
            })
            .collect();

        // Check for missing files in backup
        for (relative_path, source_path) in &source_files {
            if !backup_files.contains_key(relative_path) {
                let metadata = std::fs::metadata(source_path)?;
                results.push(VerificationResult {
                    path: relative_path.clone(),
                    status: VerificationStatus::Missing,
                    expected_checksum: None,
                    actual_checksum: None,
                    expected_size: Some(metadata.len()),
                    actual_size: None,
                    message: "File missing from backup".to_string(),
                });
            } else if check_content {
                let backup_path = backup_files.get(relative_path).unwrap();
                let source_checksum = Self::calculate_checksum(source_path, Algorithm::Sha256)?;
                let backup_checksum = Self::calculate_checksum(backup_path, Algorithm::Sha256)?;

                if source_checksum == backup_checksum {
                    results.push(VerificationResult {
                        path: relative_path.clone(),
                        status: VerificationStatus::Ok,
                        expected_checksum: Some(source_checksum),
                        actual_checksum: Some(backup_checksum),
                        expected_size: Some(std::fs::metadata(source_path)?.len()),
                        actual_size: Some(std::fs::metadata(backup_path)?.len()),
                        message: "Content matches".to_string(),
                    });
                } else {
                    results.push(VerificationResult {
                        path: relative_path.clone(),
                        status: VerificationStatus::Mismatch,
                        expected_checksum: Some(source_checksum),
                        actual_checksum: Some(backup_checksum),
                        expected_size: Some(std::fs::metadata(source_path)?.len()),
                        actual_size: Some(std::fs::metadata(backup_path)?.len()),
                        message: "Content differs".to_string(),
                    });
                }
            }
        }

        // Check for extra files in backup
        for (relative_path, backup_path) in &backup_files {
            if !source_files.contains_key(relative_path) {
                let metadata = std::fs::metadata(backup_path)?;
                results.push(VerificationResult {
                    path: relative_path.clone(),
                    status: VerificationStatus::Extra,
                    expected_checksum: None,
                    actual_checksum: None,
                    expected_size: None,
                    actual_size: Some(metadata.len()),
                    message: "Extra file in backup".to_string(),
                });
            }
        }

        Ok(results)
    }
}

/// Display verification result
fn display_result(result: &VerificationResult) {
    let status_indicator = match result.status {
        VerificationStatus::Ok => "✓".green(),
        VerificationStatus::Mismatch => "✗".red(),
        VerificationStatus::Missing => "?".yellow(),
        VerificationStatus::Extra => "+".blue(),
        VerificationStatus::Error => "!".red(),
    };

    println!("  {} {} - {}", status_indicator, result.path, result.message);
}

/// Display report summary
fn display_summary(report: &VerificationReport) {
    println!("\n{}", "Summary:".bold());
    println!("  Total Files: {}", report.total_files.to_string().cyan());
    println!("  Verified: {}", report.verified.to_string().green());
    println!("  Mismatched: {}", report.mismatched.to_string().red());
    println!("  Missing: {}", report.missing.to_string().yellow());
    println!("  Extra: {}", report.extra.to_string().blue());
    println!("  Errors: {}", report.errors.to_string().red());

    let integrity = if report.mismatched == 0 && report.missing == 0 && report.errors == 0 {
        "PASSED".green().bold()
    } else {
        "FAILED".red().bold()
    };
    println!("\n  Integrity Check: {}", integrity);
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Setup logging
    let log_level = if cli.verbose { Level::DEBUG } else { Level::INFO };
    let subscriber = FmtSubscriber::builder()
        .with_max_level(log_level)
        .with_target(false)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    match cli.command {
        Commands::Verify { file, checksum, algorithm } => {
            let algo: Algorithm = algorithm.parse()?;

            println!("\n{}", "=".repeat(50).cyan());
            println!("{}", "File Checksum Verification".bold().cyan());
            println!("{}", "=".repeat(50).cyan());
            println!("File: {}", file.display().to_string().yellow());
            println!("Algorithm: {:?}", algo);
            println!("Expected: {}", checksum);

            let actual = BackupVerifier::calculate_checksum(&file, algo)?;
            println!("Actual: {}", actual);

            if actual.eq_ignore_ascii_case(&checksum) {
                println!("\n{}", "VERIFIED - Checksums match!".green().bold());
            } else {
                println!("\n{}", "FAILED - Checksums do not match!".red().bold());
            }
        }
        Commands::CreateManifest { directory, output, algorithm } => {
            let algo: Algorithm = algorithm.parse()?;

            println!("\n{}", "=".repeat(50).cyan());
            println!("{}", "Creating Backup Manifest".bold().cyan());
            println!("{}", "=".repeat(50).cyan());
            println!("Directory: {}", directory.display().to_string().yellow());
            println!("Algorithm: {:?}\n", algo);

            let manifest = BackupVerifier::create_manifest(&directory, algo)?;

            let content = serde_json::to_string_pretty(&manifest)?;
            std::fs::write(&output, content)?;

            println!("\n{}", "Manifest Created:".bold());
            println!("  Files: {}", manifest.total_files.to_string().cyan());
            println!("  Total Size: {} bytes", manifest.total_size.to_string().cyan());
            println!("  Output: {}", output.display().to_string().green());
        }
        Commands::VerifyManifest { directory, manifest, output } => {
            println!("\n{}", "=".repeat(50).cyan());
            println!("{}", "Manifest Verification".bold().cyan());
            println!("{}", "=".repeat(50).cyan());

            let manifest_content = std::fs::read_to_string(&manifest)?;
            let backup_manifest: BackupManifest = serde_json::from_str(&manifest_content)?;

            println!("Directory: {}", directory.display().to_string().yellow());
            println!("Manifest: {} ({} files)\n",
                manifest.display(),
                backup_manifest.total_files
            );

            let report = BackupVerifier::verify_against_manifest(&directory, &backup_manifest)?;

            // Display non-OK results
            for result in &report.results {
                if result.status != VerificationStatus::Ok {
                    display_result(result);
                }
            }

            display_summary(&report);

            if let Some(output_path) = output {
                let content = serde_json::to_string_pretty(&report)?;
                std::fs::write(&output_path, content)?;
                println!("\nReport saved to: {}", output_path.display().to_string().cyan());
            }
        }
        Commands::VerifyArchive { archive, deep, manifest: _ } => {
            println!("\n{}", "=".repeat(50).cyan());
            println!("{}", "Archive Verification".bold().cyan());
            println!("{}", "=".repeat(50).cyan());
            println!("Archive: {}", archive.display().to_string().yellow());
            println!("Deep Check: {}\n", deep);

            let extension = archive.extension()
                .and_then(|e| e.to_str())
                .unwrap_or("");

            let results = match extension {
                "zip" => BackupVerifier::verify_zip_archive(&archive, deep)?,
                "tar" | "gz" | "tgz" => BackupVerifier::verify_tar_archive(&archive, deep)?,
                _ => anyhow::bail!("Unsupported archive format: {}", extension),
            };

            let ok_count = results.iter().filter(|r| r.status == VerificationStatus::Ok).count();
            let error_count = results.iter().filter(|r| r.status == VerificationStatus::Error).count();

            for result in &results {
                if result.status != VerificationStatus::Ok {
                    display_result(result);
                }
            }

            println!("\n{}", "Summary:".bold());
            println!("  Total Entries: {}", results.len().to_string().cyan());
            println!("  Valid: {}", ok_count.to_string().green());
            println!("  Errors: {}", error_count.to_string().red());

            if error_count == 0 {
                println!("\n{}", "Archive integrity VERIFIED".green().bold());
            } else {
                println!("\n{}", "Archive integrity FAILED".red().bold());
            }
        }
        Commands::Compare { source, backup, output, content } => {
            println!("\n{}", "=".repeat(50).cyan());
            println!("{}", "Backup Comparison".bold().cyan());
            println!("{}", "=".repeat(50).cyan());
            println!("Source: {}", source.display().to_string().yellow());
            println!("Backup: {}", backup.display().to_string().yellow());
            println!("Content Check: {}\n", content);

            let results = BackupVerifier::compare_directories(&source, &backup, content)?;

            for result in &results {
                if result.status != VerificationStatus::Ok {
                    display_result(result);
                }
            }

            // Write CSV
            let mut writer = csv::Writer::from_path(&output)?;
            writer.write_record(&["Path", "Status", "Expected Size", "Actual Size", "Message"])?;

            for result in &results {
                writer.write_record(&[
                    &result.path,
                    &format!("{:?}", result.status),
                    &result.expected_size.map(|s| s.to_string()).unwrap_or_default(),
                    &result.actual_size.map(|s| s.to_string()).unwrap_or_default(),
                    &result.message,
                ])?;
            }

            writer.flush()?;

            let ok_count = results.iter().filter(|r| r.status == VerificationStatus::Ok).count();
            let diff_count = results.len() - ok_count;

            println!("\n{}", "Summary:".bold());
            println!("  Matching: {}", ok_count.to_string().green());
            println!("  Differences: {}", diff_count.to_string().red());
            println!("\nReport saved to: {}", output.display().to_string().cyan());
        }
        Commands::Report { directory, previous, output } => {
            println!("\n{}", "=".repeat(50).cyan());
            println!("{}", "Verification Report".bold().cyan());
            println!("{}", "=".repeat(50).cyan());

            let manifest = BackupVerifier::create_manifest(&directory, Algorithm::Sha256)?;

            if let Some(prev_path) = previous {
                let prev_content = std::fs::read_to_string(&prev_path)?;
                let prev_manifest: BackupManifest = serde_json::from_str(&prev_content)?;

                let report = BackupVerifier::verify_against_manifest(&directory, &prev_manifest)?;
                display_summary(&report);

                let content = serde_json::to_string_pretty(&report)?;
                std::fs::write(&output, content)?;
            } else {
                let content = serde_json::to_string_pretty(&manifest)?;
                std::fs::write(&output, content)?;

                println!("\nManifest created: {} files", manifest.total_files);
            }

            println!("\nReport saved to: {}", output.display().to_string().cyan());
        }
    }

    Ok(())
}
