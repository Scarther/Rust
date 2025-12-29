//! Core scanning functionality

use crate::database::IocDatabase;
use anyhow::Result;
use log::{debug, warn};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use walkdir::WalkDir;

/// Scan configuration
#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub workers: usize,
    pub max_file_size: u64,
    pub follow_symlinks: bool,
    pub scan_content: bool,
    pub max_depth: Option<usize>,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            workers: 4,
            max_file_size: 100 * 1024 * 1024, // 100 MB
            follow_symlinks: false,
            scan_content: true,
            max_depth: None,
        }
    }
}

/// A detected IOC finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub file_path: String,
    pub ioc_type: String,
    pub ioc_value: String,
    pub description: String,
    pub severity: String,
    pub line_number: Option<usize>,
    pub context: Option<String>,
    pub timestamp: String,
}

/// Scan statistics
#[derive(Debug, Default)]
pub struct ScanStats {
    pub files_scanned: usize,
    pub bytes_scanned: u64,
    pub files_skipped: usize,
    pub errors: usize,
}

/// IOC Scanner
pub struct Scanner {
    database: IocDatabase,
    config: ScanConfig,
}

impl Scanner {
    pub fn new(database: IocDatabase, config: ScanConfig) -> Self {
        Self { database, config }
    }

    /// Scan a path (file or directory)
    pub async fn scan<F, Fut>(&self, path: &Path, on_finding: F) -> Result<ScanStats>
    where
        F: Fn(Finding) -> Fut + Send + Sync + Clone,
        Fut: std::future::Future<Output = ()> + Send,
    {
        let files_scanned = Arc::new(AtomicUsize::new(0));
        let files_skipped = Arc::new(AtomicUsize::new(0));
        let errors = Arc::new(AtomicUsize::new(0));
        let bytes_scanned = Arc::new(AtomicUsize::new(0));

        // Collect all files first
        let files: Vec<PathBuf> = self.collect_files(path)?;
        debug!("Collected {} files to scan", files.len());

        // Process files in parallel using rayon
        let findings: Vec<Finding> = files
            .par_iter()
            .filter_map(|file| {
                match self.scan_file_sync(file) {
                    Ok(Some(finding)) => {
                        files_scanned.fetch_add(1, Ordering::Relaxed);
                        if let Ok(meta) = std::fs::metadata(file) {
                            bytes_scanned.fetch_add(meta.len() as usize, Ordering::Relaxed);
                        }
                        Some(finding)
                    }
                    Ok(None) => {
                        files_scanned.fetch_add(1, Ordering::Relaxed);
                        if let Ok(meta) = std::fs::metadata(file) {
                            bytes_scanned.fetch_add(meta.len() as usize, Ordering::Relaxed);
                        }
                        None
                    }
                    Err(e) => {
                        debug!("Error scanning {:?}: {}", file, e);
                        errors.fetch_add(1, Ordering::Relaxed);
                        None
                    }
                }
            })
            .collect();

        // Call the callback for each finding
        for finding in findings {
            on_finding(finding).await;
        }

        Ok(ScanStats {
            files_scanned: files_scanned.load(Ordering::Relaxed),
            bytes_scanned: bytes_scanned.load(Ordering::Relaxed) as u64,
            files_skipped: files_skipped.load(Ordering::Relaxed),
            errors: errors.load(Ordering::Relaxed),
        })
    }

    /// Collect all files to scan
    fn collect_files(&self, path: &Path) -> Result<Vec<PathBuf>> {
        let mut walker = WalkDir::new(path).follow_links(self.config.follow_symlinks);

        if let Some(depth) = self.config.max_depth {
            walker = walker.max_depth(depth);
        }

        let files: Vec<PathBuf> = walker
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_file())
            .filter(|e| {
                if let Ok(meta) = e.metadata() {
                    meta.len() <= self.config.max_file_size
                } else {
                    false
                }
            })
            .map(|e| e.path().to_path_buf())
            .collect();

        Ok(files)
    }

    /// Scan a single file (async wrapper)
    pub async fn scan_file(&self, path: &Path) -> Result<Option<Finding>> {
        self.scan_file_sync(path)
    }

    /// Scan a single file (synchronous)
    fn scan_file_sync(&self, path: &Path) -> Result<Option<Finding>> {
        let path_str = path.to_string_lossy();

        // Check path patterns first (fastest)
        for path_ioc in &self.database.file_paths {
            if path_str.contains(&path_ioc.path) {
                return Ok(Some(Finding {
                    file_path: path_str.to_string(),
                    ioc_type: "file_path".to_string(),
                    ioc_value: path_ioc.path.clone(),
                    description: path_ioc.description.clone().unwrap_or_default(),
                    severity: path_ioc.severity.clone(),
                    line_number: None,
                    context: None,
                    timestamp: chrono::Utc::now().to_rfc3339(),
                }));
            }
        }

        // Calculate file hash
        let hash = self.compute_file_hash(path)?;

        // Check hash against database
        for hash_ioc in &self.database.hashes {
            if hash_ioc.hash.to_lowercase() == hash.to_lowercase() {
                return Ok(Some(Finding {
                    file_path: path_str.to_string(),
                    ioc_type: "hash".to_string(),
                    ioc_value: hash.clone(),
                    description: hash_ioc.description.clone().unwrap_or_default(),
                    severity: hash_ioc.severity.clone(),
                    line_number: None,
                    context: None,
                    timestamp: chrono::Utc::now().to_rfc3339(),
                }));
            }
        }

        // Scan file contents if enabled
        if self.config.scan_content {
            if let Some(finding) = self.scan_file_content(path)? {
                return Ok(Some(finding));
            }
        }

        Ok(None)
    }

    /// Compute SHA-256 hash of a file
    fn compute_file_hash(&self, path: &Path) -> Result<String> {
        let mut file = File::open(path)?;
        let mut hasher = Sha256::new();
        let mut buffer = [0; 8192];

        loop {
            let bytes_read = file.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }
            hasher.update(&buffer[..bytes_read]);
        }

        Ok(hex::encode(hasher.finalize()))
    }

    /// Scan file content for patterns
    fn scan_file_content(&self, path: &Path) -> Result<Option<Finding>> {
        // Skip binary files
        if is_binary_file(path)? {
            return Ok(None);
        }

        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let path_str = path.to_string_lossy().to_string();

        for (line_num, line) in reader.lines().enumerate() {
            let line = match line {
                Ok(l) => l,
                Err(_) => continue,
            };

            // Check domain IOCs
            for domain_ioc in &self.database.domains {
                if line.contains(&domain_ioc.domain) {
                    return Ok(Some(Finding {
                        file_path: path_str,
                        ioc_type: "domain".to_string(),
                        ioc_value: domain_ioc.domain.clone(),
                        description: domain_ioc.description.clone().unwrap_or_default(),
                        severity: domain_ioc.severity.clone(),
                        line_number: Some(line_num + 1),
                        context: Some(truncate_line(&line, 100)),
                        timestamp: chrono::Utc::now().to_rfc3339(),
                    }));
                }
            }

            // Check IP IOCs
            for ip_ioc in &self.database.ip_addresses {
                if line.contains(&ip_ioc.ip) {
                    return Ok(Some(Finding {
                        file_path: path_str,
                        ioc_type: "ip_address".to_string(),
                        ioc_value: ip_ioc.ip.clone(),
                        description: ip_ioc.description.clone().unwrap_or_default(),
                        severity: ip_ioc.severity.clone(),
                        line_number: Some(line_num + 1),
                        context: Some(truncate_line(&line, 100)),
                        timestamp: chrono::Utc::now().to_rfc3339(),
                    }));
                }
            }

            // Check regex patterns
            for pattern_ioc in &self.database.patterns {
                if let Ok(re) = regex::Regex::new(&pattern_ioc.pattern) {
                    if re.is_match(&line) {
                        return Ok(Some(Finding {
                            file_path: path_str,
                            ioc_type: "pattern".to_string(),
                            ioc_value: pattern_ioc.pattern.clone(),
                            description: pattern_ioc.description.clone().unwrap_or_default(),
                            severity: pattern_ioc.severity.clone(),
                            line_number: Some(line_num + 1),
                            context: Some(truncate_line(&line, 100)),
                            timestamp: chrono::Utc::now().to_rfc3339(),
                        }));
                    }
                }
            }
        }

        Ok(None)
    }
}

/// Check if a file is binary
fn is_binary_file(path: &Path) -> Result<bool> {
    let mut file = File::open(path)?;
    let mut buffer = [0; 512];

    let bytes_read = file.read(&mut buffer)?;
    if bytes_read == 0 {
        return Ok(false);
    }

    // Check for null bytes (common in binary files)
    let null_count = buffer[..bytes_read].iter().filter(|&&b| b == 0).count();
    let null_ratio = null_count as f64 / bytes_read as f64;

    Ok(null_ratio > 0.1)
}

/// Truncate a line for context display
fn truncate_line(line: &str, max_len: usize) -> String {
    if line.len() <= max_len {
        line.to_string()
    } else {
        format!("{}...", &line[..max_len])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use std::io::Write;

    #[test]
    fn test_is_binary_file() {
        let dir = tempdir().unwrap();

        // Text file
        let text_path = dir.path().join("text.txt");
        std::fs::write(&text_path, "Hello, World!").unwrap();
        assert!(!is_binary_file(&text_path).unwrap());

        // Binary file
        let bin_path = dir.path().join("binary.bin");
        let mut file = File::create(&bin_path).unwrap();
        file.write_all(&[0, 1, 2, 0, 3, 0, 4, 0]).unwrap();
        assert!(is_binary_file(&bin_path).unwrap());
    }

    #[test]
    fn test_truncate_line() {
        assert_eq!(truncate_line("short", 10), "short");
        assert_eq!(truncate_line("this is a longer line", 10), "this is a ...");
    }
}
