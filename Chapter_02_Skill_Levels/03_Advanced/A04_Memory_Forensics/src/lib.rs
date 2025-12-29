//! # Memory Forensics Library
//!
//! This module provides advanced memory forensics capabilities for analyzing
//! process memory on Linux systems. It demonstrates:
//!
//! - Reading process memory via /proc/[pid]/mem
//! - Memory map analysis and classification
//! - Pattern recognition in memory
//! - String extraction from binary data
//! - Heap and stack analysis concepts
//! - Memory artifact detection
//!
//! ## Memory Forensics Overview
//!
//! Memory forensics is the analysis of a computer's memory (RAM) to:
//! - Extract evidence of malware
//! - Find encryption keys and passwords
//! - Reconstruct user activity
//! - Detect hidden processes
//! - Analyze network connections
//!
//! ## Technical Background
//!
//! On Linux, process memory can be accessed through:
//! 1. `/proc/[pid]/mem` - Direct memory access
//! 2. `/proc/[pid]/maps` - Memory layout information
//! 3. ptrace - Debugger interface
//!
//! This tool focuses on non-invasive analysis using /proc.

use anyhow::{Context, Result};
use byteorder::{LittleEndian, ReadBytesExt};
use chrono::{DateTime, Utc};
use log::{debug, error, info, warn};
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Custom error types for memory forensics operations
#[derive(Error, Debug)]
pub enum ForensicsError {
    #[error("Process not found: {0}")]
    ProcessNotFound(i32),

    #[error("Memory access denied: {0}")]
    MemoryAccessDenied(String),

    #[error("Invalid memory address: {0:#x}")]
    InvalidAddress(u64),

    #[error("Parse error: {0}")]
    ParseError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

/// Memory region types based on content analysis
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum RegionType {
    /// Executable code
    Code,
    /// Program data
    Data,
    /// Heap memory
    Heap,
    /// Stack memory
    Stack,
    /// Memory-mapped file
    MappedFile,
    /// Shared library
    SharedLibrary,
    /// Anonymous mapping
    Anonymous,
    /// Video/GPU memory
    Device,
    /// Virtual dynamic shared object
    Vdso,
    /// Virtual system call page
    Vsyscall,
    /// Unknown type
    Unknown,
}

/// Memory region with enhanced information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryRegion {
    pub start: u64,
    pub end: u64,
    pub size: u64,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
    pub shared: bool,
    pub offset: u64,
    pub device: String,
    pub inode: u64,
    pub pathname: Option<PathBuf>,
    pub region_type: RegionType,
}

impl MemoryRegion {
    /// Check if an address is within this region
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.start && addr < self.end
    }

    /// Get human-readable permission string
    pub fn permissions(&self) -> String {
        format!(
            "{}{}{}{}",
            if self.readable { 'r' } else { '-' },
            if self.writable { 'w' } else { '-' },
            if self.executable { 'x' } else { '-' },
            if self.shared { 's' } else { 'p' }
        )
    }
}

/// Extracted string with context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedString {
    pub address: u64,
    pub content: String,
    pub encoding: StringEncoding,
    pub region_type: RegionType,
    pub is_interesting: bool,
}

/// String encoding types
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum StringEncoding {
    Ascii,
    Utf8,
    Utf16Le,
    Utf16Be,
}

/// Memory artifact - interesting patterns found in memory
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryArtifact {
    pub address: u64,
    pub artifact_type: ArtifactType,
    pub description: String,
    pub data: Vec<u8>,
    pub context: HashMap<String, String>,
}

/// Types of memory artifacts
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum ArtifactType {
    /// Potential password or credential
    Credential,
    /// URL or network indicator
    NetworkIndicator,
    /// File path
    FilePath,
    /// Encryption key material
    CryptoMaterial,
    /// Email address
    EmailAddress,
    /// IP address
    IpAddress,
    /// Credit card number pattern
    CreditCard,
    /// Base64 encoded data
    Base64Data,
    /// Shell command
    ShellCommand,
    /// Environment variable
    EnvVariable,
    /// Registry key (Wine/Windows)
    RegistryKey,
    /// PE/ELF header
    ExecutableHeader,
    /// Unknown but interesting
    Unknown,
}

/// Heap chunk information (simplified)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeapChunk {
    pub address: u64,
    pub size: u64,
    pub in_use: bool,
    pub data_preview: Vec<u8>,
}

/// Stack frame information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackFrame {
    pub frame_pointer: u64,
    pub return_address: u64,
    pub local_variables: Vec<(u64, Vec<u8>)>,
}

/// Process memory snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemorySnapshot {
    pub pid: i32,
    pub process_name: String,
    pub timestamp: DateTime<Utc>,
    pub regions: Vec<MemoryRegion>,
    pub total_mapped: u64,
    pub total_readable: u64,
}

/// Main memory forensics analyzer
pub struct MemoryAnalyzer {
    /// Target process ID
    pid: i32,
    /// Memory regions
    regions: Vec<MemoryRegion>,
    /// File handle for /proc/[pid]/mem
    mem_file: Option<File>,
    /// Extracted artifacts
    artifacts: Vec<MemoryArtifact>,
    /// Patterns for artifact detection
    patterns: ArtifactPatterns,
}

/// Compiled patterns for artifact detection
struct ArtifactPatterns {
    url: Regex,
    email: Regex,
    ipv4: Regex,
    base64: Regex,
    filepath_unix: Regex,
    credit_card: Regex,
    env_var: Regex,
    password_hint: Regex,
}

impl Default for ArtifactPatterns {
    fn default() -> Self {
        Self {
            url: Regex::new(r"https?://[^\s<>\"']+").unwrap(),
            email: Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}").unwrap(),
            ipv4: Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").unwrap(),
            base64: Regex::new(r"[A-Za-z0-9+/]{20,}={0,2}").unwrap(),
            filepath_unix: Regex::new(r"/(?:[a-zA-Z0-9._-]+/)+[a-zA-Z0-9._-]+").unwrap(),
            credit_card: Regex::new(r"\b(?:\d{4}[- ]?){3}\d{4}\b").unwrap(),
            env_var: Regex::new(r"[A-Z_]{2,}=[^\s]+").unwrap(),
            password_hint: Regex::new(r"(?i)(?:password|passwd|pwd|secret|key|token)[:=]\s*\S+").unwrap(),
        }
    }
}

impl MemoryAnalyzer {
    /// Create a new memory analyzer for a process
    ///
    /// # Arguments
    /// * `pid` - The process ID to analyze
    ///
    /// # Returns
    /// A new MemoryAnalyzer instance or an error
    pub fn new(pid: i32) -> Result<Self> {
        // Verify process exists
        let proc_path = format!("/proc/{}", pid);
        if !Path::new(&proc_path).exists() {
            return Err(ForensicsError::ProcessNotFound(pid).into());
        }

        let mut analyzer = Self {
            pid,
            regions: Vec::new(),
            mem_file: None,
            artifacts: Vec::new(),
            patterns: ArtifactPatterns::default(),
        };

        // Parse memory maps
        analyzer.refresh_regions()?;

        // Open mem file
        let mem_path = format!("/proc/{}/mem", pid);
        analyzer.mem_file = File::open(&mem_path).ok();

        Ok(analyzer)
    }

    /// Refresh memory region information
    pub fn refresh_regions(&mut self) -> Result<()> {
        self.regions = Self::parse_maps(self.pid)?;
        Ok(())
    }

    /// Parse /proc/[pid]/maps into structured regions
    ///
    /// # Map File Format
    /// ```text
    /// address           perms offset   dev   inode   pathname
    /// 00400000-00452000 r-xp 00000000 08:02 173521   /usr/bin/program
    /// ```
    fn parse_maps(pid: i32) -> Result<Vec<MemoryRegion>> {
        let maps_path = format!("/proc/{}/maps", pid);
        let file = File::open(&maps_path)
            .context(format!("Failed to open {}", maps_path))?;
        let reader = BufReader::new(file);
        let mut regions = Vec::new();

        let map_regex = Regex::new(
            r"^([0-9a-f]+)-([0-9a-f]+)\s+([rwxsp-]{4})\s+([0-9a-f]+)\s+(\S+)\s+(\d+)\s*(.*)$"
        )?;

        for line in reader.lines().flatten() {
            if let Some(caps) = map_regex.captures(&line) {
                let start = u64::from_str_radix(&caps[1], 16)?;
                let end = u64::from_str_radix(&caps[2], 16)?;
                let perms = &caps[3];
                let offset = u64::from_str_radix(&caps[4], 16)?;
                let device = caps[5].to_string();
                let inode: u64 = caps[6].parse()?;
                let pathname = if caps.get(7).is_some() && !caps[7].trim().is_empty() {
                    Some(PathBuf::from(caps[7].trim()))
                } else {
                    None
                };

                let region_type = Self::classify_region(&pathname, perms, &device);

                regions.push(MemoryRegion {
                    start,
                    end,
                    size: end - start,
                    readable: perms.contains('r'),
                    writable: perms.contains('w'),
                    executable: perms.contains('x'),
                    shared: perms.contains('s'),
                    offset,
                    device,
                    inode,
                    pathname,
                    region_type,
                });
            }
        }

        Ok(regions)
    }

    /// Classify a memory region based on its properties
    fn classify_region(pathname: &Option<PathBuf>, perms: &str, _device: &str) -> RegionType {
        if let Some(path) = pathname {
            let path_str = path.to_string_lossy();

            if path_str.contains("[heap]") {
                return RegionType::Heap;
            }
            if path_str.contains("[stack]") {
                return RegionType::Stack;
            }
            if path_str.contains("[vdso]") {
                return RegionType::Vdso;
            }
            if path_str.contains("[vsyscall]") {
                return RegionType::Vsyscall;
            }
            if path_str.ends_with(".so") || path_str.contains(".so.") {
                return RegionType::SharedLibrary;
            }
            if path_str.starts_with("/dev/") {
                return RegionType::Device;
            }
            if !path_str.starts_with('[') {
                return RegionType::MappedFile;
            }
        }

        // Anonymous mappings
        if pathname.is_none() {
            if perms.contains('x') {
                return RegionType::Code;
            }
            return RegionType::Anonymous;
        }

        RegionType::Unknown
    }

    /// Read memory from a specific address
    ///
    /// # Arguments
    /// * `address` - Starting address to read
    /// * `size` - Number of bytes to read
    ///
    /// # Returns
    /// The bytes read, or an error
    pub fn read_memory(&self, address: u64, size: usize) -> Result<Vec<u8>> {
        // Verify address is in a readable region
        let region = self.regions.iter().find(|r| r.contains(address));

        if region.is_none() {
            return Err(ForensicsError::InvalidAddress(address).into());
        }

        let region = region.unwrap();
        if !region.readable {
            return Err(ForensicsError::MemoryAccessDenied(
                format!("Region at {:#x} is not readable", address)
            ).into());
        }

        // Use /proc/[pid]/mem for reading
        if let Some(ref mem_file) = self.mem_file {
            let mut buffer = vec![0u8; size];
            match mem_file.read_at(&mut buffer, address) {
                Ok(bytes_read) => {
                    buffer.truncate(bytes_read);
                    Ok(buffer)
                }
                Err(e) => {
                    debug!("Failed to read at {:#x}: {}", address, e);
                    Err(e.into())
                }
            }
        } else {
            Err(ForensicsError::MemoryAccessDenied(
                "Cannot open /proc/[pid]/mem".to_string()
            ).into())
        }
    }

    /// Read an entire memory region
    pub fn read_region(&self, region: &MemoryRegion) -> Result<Vec<u8>> {
        if !region.readable {
            return Err(ForensicsError::MemoryAccessDenied(
                format!("Region at {:#x} is not readable", region.start)
            ).into());
        }

        // Limit read size to avoid OOM
        let max_size = 100 * 1024 * 1024; // 100 MB
        let read_size = std::cmp::min(region.size as usize, max_size);

        self.read_memory(region.start, read_size)
    }

    /// Extract printable strings from a memory region
    ///
    /// # Arguments
    /// * `data` - Raw memory data
    /// * `base_address` - Base address of the data
    /// * `min_length` - Minimum string length to extract
    ///
    /// # Returns
    /// Vector of extracted strings with metadata
    pub fn extract_strings(
        &self,
        data: &[u8],
        base_address: u64,
        min_length: usize,
    ) -> Vec<ExtractedString> {
        let mut strings = Vec::new();
        let mut current_string = String::new();
        let mut string_start: Option<u64> = None;

        for (i, &byte) in data.iter().enumerate() {
            if Self::is_printable_ascii(byte) {
                if string_start.is_none() {
                    string_start = Some(base_address + i as u64);
                }
                current_string.push(byte as char);
            } else {
                if current_string.len() >= min_length {
                    let address = string_start.unwrap();
                    let is_interesting = self.is_interesting_string(&current_string);

                    // Determine region type
                    let region_type = self.regions
                        .iter()
                        .find(|r| r.contains(address))
                        .map(|r| r.region_type)
                        .unwrap_or(RegionType::Unknown);

                    strings.push(ExtractedString {
                        address,
                        content: current_string.clone(),
                        encoding: StringEncoding::Ascii,
                        region_type,
                        is_interesting,
                    });
                }
                current_string.clear();
                string_start = None;
            }
        }

        // Don't forget the last string
        if current_string.len() >= min_length {
            if let Some(address) = string_start {
                let is_interesting = self.is_interesting_string(&current_string);
                let region_type = self.regions
                    .iter()
                    .find(|r| r.contains(address))
                    .map(|r| r.region_type)
                    .unwrap_or(RegionType::Unknown);

                strings.push(ExtractedString {
                    address,
                    content: current_string,
                    encoding: StringEncoding::Ascii,
                    region_type,
                    is_interesting,
                });
            }
        }

        strings
    }

    /// Check if a byte is printable ASCII
    fn is_printable_ascii(byte: u8) -> bool {
        byte >= 0x20 && byte < 0x7f
    }

    /// Check if a string is "interesting" for forensics
    fn is_interesting_string(&self, s: &str) -> bool {
        // Check against patterns
        self.patterns.url.is_match(s)
            || self.patterns.email.is_match(s)
            || self.patterns.password_hint.is_match(s)
            || self.patterns.filepath_unix.is_match(s)
            || s.contains("password")
            || s.contains("secret")
            || s.contains("token")
            || s.contains("key")
            || s.contains("BEGIN RSA")
            || s.contains("BEGIN PRIVATE")
    }

    /// Scan memory for artifacts
    pub fn scan_for_artifacts(&mut self) -> Result<Vec<MemoryArtifact>> {
        let mut artifacts = Vec::new();

        for region in &self.regions {
            if !region.readable {
                continue;
            }

            // Skip very large regions for performance
            if region.size > 50 * 1024 * 1024 {
                debug!("Skipping large region at {:#x}", region.start);
                continue;
            }

            let data = match self.read_region(region) {
                Ok(d) => d,
                Err(e) => {
                    debug!("Could not read region at {:#x}: {}", region.start, e);
                    continue;
                }
            };

            // Extract and analyze strings
            let strings = self.extract_strings(&data, region.start, 6);

            for extracted in strings {
                if extracted.is_interesting {
                    // Categorize the artifact
                    let artifact_type = self.categorize_string(&extracted.content);

                    if artifact_type != ArtifactType::Unknown {
                        artifacts.push(MemoryArtifact {
                            address: extracted.address,
                            artifact_type,
                            description: format!(
                                "Found {} in {} region",
                                format!("{:?}", artifact_type),
                                format!("{:?}", extracted.region_type)
                            ),
                            data: extracted.content.as_bytes().to_vec(),
                            context: HashMap::from([
                                ("region_type".to_string(), format!("{:?}", extracted.region_type)),
                                ("encoding".to_string(), format!("{:?}", extracted.encoding)),
                            ]),
                        });
                    }
                }
            }

            // Look for executable headers
            if let Some(artifact) = self.find_executable_header(&data, region.start) {
                artifacts.push(artifact);
            }
        }

        self.artifacts = artifacts.clone();
        Ok(artifacts)
    }

    /// Categorize a string as a specific artifact type
    fn categorize_string(&self, s: &str) -> ArtifactType {
        if self.patterns.url.is_match(s) {
            return ArtifactType::NetworkIndicator;
        }
        if self.patterns.email.is_match(s) {
            return ArtifactType::EmailAddress;
        }
        if self.patterns.password_hint.is_match(s) {
            return ArtifactType::Credential;
        }
        if self.patterns.ipv4.is_match(s) {
            return ArtifactType::IpAddress;
        }
        if self.patterns.filepath_unix.is_match(s) {
            return ArtifactType::FilePath;
        }
        if self.patterns.credit_card.is_match(s) {
            return ArtifactType::CreditCard;
        }
        if self.patterns.base64.is_match(s) && s.len() > 30 {
            return ArtifactType::Base64Data;
        }
        if self.patterns.env_var.is_match(s) {
            return ArtifactType::EnvVariable;
        }
        if s.contains("BEGIN RSA") || s.contains("BEGIN PRIVATE") || s.contains("BEGIN CERTIFICATE") {
            return ArtifactType::CryptoMaterial;
        }

        ArtifactType::Unknown
    }

    /// Look for ELF or PE headers in memory
    fn find_executable_header(&self, data: &[u8], base_address: u64) -> Option<MemoryArtifact> {
        // ELF magic: 0x7f ELF
        const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
        // PE magic: MZ
        const PE_MAGIC: [u8; 2] = [b'M', b'Z'];

        // Check for ELF
        if data.len() >= 4 && data[..4] == ELF_MAGIC {
            let header_data = data[..std::cmp::min(64, data.len())].to_vec();

            let elf_class = if data.len() > 4 {
                match data[4] {
                    1 => "ELF32",
                    2 => "ELF64",
                    _ => "Unknown",
                }
            } else {
                "Unknown"
            };

            return Some(MemoryArtifact {
                address: base_address,
                artifact_type: ArtifactType::ExecutableHeader,
                description: format!("{} executable header found at {:#x}", elf_class, base_address),
                data: header_data,
                context: HashMap::from([
                    ("format".to_string(), "ELF".to_string()),
                    ("class".to_string(), elf_class.to_string()),
                ]),
            });
        }

        // Check for PE (MZ header)
        if data.len() >= 2 && data[..2] == PE_MAGIC {
            let header_data = data[..std::cmp::min(256, data.len())].to_vec();

            return Some(MemoryArtifact {
                address: base_address,
                artifact_type: ArtifactType::ExecutableHeader,
                description: format!("PE/MZ executable header found at {:#x}", base_address),
                data: header_data,
                context: HashMap::from([
                    ("format".to_string(), "PE".to_string()),
                ]),
            });
        }

        None
    }

    /// Search for a specific pattern in memory
    pub fn search_pattern(&self, pattern: &[u8]) -> Result<Vec<u64>> {
        let mut matches = Vec::new();

        for region in &self.regions {
            if !region.readable {
                continue;
            }

            let data = match self.read_region(region) {
                Ok(d) => d,
                Err(_) => continue,
            };

            // Simple pattern search
            for (i, window) in data.windows(pattern.len()).enumerate() {
                if window == pattern {
                    matches.push(region.start + i as u64);
                }
            }
        }

        Ok(matches)
    }

    /// Search for a string in memory
    pub fn search_string(&self, needle: &str) -> Result<Vec<u64>> {
        self.search_pattern(needle.as_bytes())
    }

    /// Search using regex pattern
    pub fn search_regex(&self, pattern: &str) -> Result<Vec<(u64, String)>> {
        let regex = Regex::new(pattern).context("Invalid regex pattern")?;
        let mut matches = Vec::new();

        for region in &self.regions {
            if !region.readable {
                continue;
            }

            let data = match self.read_region(region) {
                Ok(d) => d,
                Err(_) => continue,
            };

            // Convert to string (lossy) for regex matching
            let text = String::from_utf8_lossy(&data);

            for mat in regex.find_iter(&text) {
                let addr = region.start + mat.start() as u64;
                matches.push((addr, mat.as_str().to_string()));
            }
        }

        Ok(matches)
    }

    /// Dump a memory region to a file
    pub fn dump_region(&self, region: &MemoryRegion, output_path: &Path) -> Result<u64> {
        let data = self.read_region(region)?;
        fs::write(output_path, &data)?;
        Ok(data.len() as u64)
    }

    /// Dump all readable memory to files
    pub fn dump_all(&self, output_dir: &Path) -> Result<Vec<PathBuf>> {
        fs::create_dir_all(output_dir)?;
        let mut dumped_files = Vec::new();

        for (i, region) in self.regions.iter().enumerate() {
            if !region.readable {
                continue;
            }

            let filename = format!(
                "{:016x}-{:016x}_{}.bin",
                region.start,
                region.end,
                region.pathname
                    .as_ref()
                    .map(|p| p.file_name().unwrap_or_default().to_string_lossy().to_string())
                    .unwrap_or_else(|| format!("region_{}", i))
                    .replace('/', "_")
            );

            let output_path = output_dir.join(&filename);

            match self.dump_region(region, &output_path) {
                Ok(size) => {
                    debug!("Dumped {} bytes to {:?}", size, output_path);
                    dumped_files.push(output_path);
                }
                Err(e) => {
                    warn!("Could not dump region at {:#x}: {}", region.start, e);
                }
            }
        }

        Ok(dumped_files)
    }

    /// Get a memory snapshot
    pub fn create_snapshot(&self) -> Result<MemorySnapshot> {
        let process_name = self.get_process_name()?;
        let total_mapped: u64 = self.regions.iter().map(|r| r.size).sum();
        let total_readable: u64 = self.regions
            .iter()
            .filter(|r| r.readable)
            .map(|r| r.size)
            .sum();

        Ok(MemorySnapshot {
            pid: self.pid,
            process_name,
            timestamp: Utc::now(),
            regions: self.regions.clone(),
            total_mapped,
            total_readable,
        })
    }

    /// Get process name
    fn get_process_name(&self) -> Result<String> {
        let comm_path = format!("/proc/{}/comm", self.pid);
        let name = fs::read_to_string(&comm_path)?;
        Ok(name.trim().to_string())
    }

    /// Get memory regions
    pub fn get_regions(&self) -> &[MemoryRegion] {
        &self.regions
    }

    /// Get artifacts
    pub fn get_artifacts(&self) -> &[MemoryArtifact] {
        &self.artifacts
    }

    /// Calculate hash of a memory region
    pub fn hash_region(&self, region: &MemoryRegion) -> Result<String> {
        let data = self.read_region(region)?;
        let mut hasher = Sha256::new();
        hasher.update(&data);
        Ok(hex::encode(hasher.finalize()))
    }

    /// Analyze heap for interesting data (simplified)
    pub fn analyze_heap(&self) -> Result<Vec<HeapChunk>> {
        let heap_region = self.regions
            .iter()
            .find(|r| r.region_type == RegionType::Heap);

        if heap_region.is_none() {
            return Ok(Vec::new());
        }

        let heap = heap_region.unwrap();
        let data = self.read_region(heap)?;

        // This is a simplified heap analysis
        // Real heap analysis would parse malloc metadata
        let mut chunks = Vec::new();
        let chunk_size = 64; // Sample every 64 bytes

        for (i, chunk) in data.chunks(chunk_size).enumerate().take(1000) {
            let address = heap.start + (i * chunk_size) as u64;

            chunks.push(HeapChunk {
                address,
                size: chunk_size as u64,
                in_use: true, // Would need malloc metadata to determine
                data_preview: chunk[..std::cmp::min(16, chunk.len())].to_vec(),
            });
        }

        Ok(chunks)
    }

    /// Generate forensics report
    pub fn generate_report(&self) -> Result<String> {
        let snapshot = self.create_snapshot()?;

        let report = serde_json::json!({
            "timestamp": Utc::now().to_rfc3339(),
            "process": {
                "pid": self.pid,
                "name": snapshot.process_name,
            },
            "memory": {
                "total_regions": self.regions.len(),
                "total_mapped_bytes": snapshot.total_mapped,
                "total_readable_bytes": snapshot.total_readable,
                "readable_regions": self.regions.iter().filter(|r| r.readable).count(),
                "executable_regions": self.regions.iter().filter(|r| r.executable).count(),
                "writable_regions": self.regions.iter().filter(|r| r.writable).count(),
            },
            "artifacts": {
                "total": self.artifacts.len(),
                "by_type": self.artifacts.iter()
                    .map(|a| format!("{:?}", a.artifact_type))
                    .collect::<Vec<_>>(),
            },
            "regions": snapshot.regions,
        });

        serde_json::to_string_pretty(&report).context("Failed to serialize report")
    }
}

impl Default for ArtifactPatterns {
    fn default() -> Self {
        Self::default()
    }
}

/// Hexdump utility
pub fn hexdump(data: &[u8], base_address: u64) -> String {
    let mut output = String::new();
    let bytes_per_line = 16;

    for (i, chunk) in data.chunks(bytes_per_line).enumerate() {
        let addr = base_address + (i * bytes_per_line) as u64;
        output.push_str(&format!("{:016x}  ", addr));

        // Hex bytes
        for (j, byte) in chunk.iter().enumerate() {
            output.push_str(&format!("{:02x} ", byte));
            if j == 7 {
                output.push(' ');
            }
        }

        // Padding
        if chunk.len() < bytes_per_line {
            let padding = bytes_per_line - chunk.len();
            for j in 0..padding {
                output.push_str("   ");
                if chunk.len() + j == 7 {
                    output.push(' ');
                }
            }
        }

        // ASCII
        output.push_str(" |");
        for byte in chunk {
            if *byte >= 0x20 && *byte < 0x7f {
                output.push(*byte as char);
            } else {
                output.push('.');
            }
        }
        output.push_str("|\n");
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_printable_ascii() {
        assert!(MemoryAnalyzer::is_printable_ascii(b'A'));
        assert!(MemoryAnalyzer::is_printable_ascii(b' '));
        assert!(MemoryAnalyzer::is_printable_ascii(b'~'));
        assert!(!MemoryAnalyzer::is_printable_ascii(0x00));
        assert!(!MemoryAnalyzer::is_printable_ascii(0x7f));
        assert!(!MemoryAnalyzer::is_printable_ascii(0xff));
    }

    #[test]
    fn test_hexdump() {
        let data = b"Hello, World!";
        let output = hexdump(data, 0x1000);
        assert!(output.contains("1000"));
        assert!(output.contains("Hello"));
    }

    #[test]
    fn test_region_permissions() {
        let region = MemoryRegion {
            start: 0x1000,
            end: 0x2000,
            size: 0x1000,
            readable: true,
            writable: false,
            executable: true,
            shared: false,
            offset: 0,
            device: "00:00".to_string(),
            inode: 0,
            pathname: None,
            region_type: RegionType::Code,
        };

        assert_eq!(region.permissions(), "r-xp");
    }

    #[test]
    fn test_region_contains() {
        let region = MemoryRegion {
            start: 0x1000,
            end: 0x2000,
            size: 0x1000,
            readable: true,
            writable: true,
            executable: false,
            shared: false,
            offset: 0,
            device: "00:00".to_string(),
            inode: 0,
            pathname: None,
            region_type: RegionType::Data,
        };

        assert!(region.contains(0x1000));
        assert!(region.contains(0x1500));
        assert!(!region.contains(0x2000));
        assert!(!region.contains(0x0fff));
    }

    #[test]
    fn test_artifact_patterns() {
        let patterns = ArtifactPatterns::default();

        assert!(patterns.url.is_match("https://example.com/path"));
        assert!(patterns.email.is_match("test@example.com"));
        assert!(patterns.ipv4.is_match("192.168.1.1"));
        assert!(patterns.filepath_unix.is_match("/etc/passwd"));
    }
}
