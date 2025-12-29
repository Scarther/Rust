//! # Process Injector Library
//!
//! This module provides EDUCATIONAL process memory analysis capabilities.
//! It demonstrates advanced low-level Rust programming including:
//!
//! - ptrace system calls for process debugging
//! - Raw memory reading and writing via /proc/[pid]/mem
//! - Memory mapping analysis
//! - ELF binary parsing concepts
//! - Unsafe Rust for system programming
//!
//! ## IMPORTANT DISCLAIMER
//!
//! This code is for EDUCATIONAL PURPOSES ONLY. Process injection techniques
//! can be used maliciously. This tool is designed to teach:
//! - How debuggers work internally
//! - Memory forensics techniques
//! - Security research methodologies
//!
//! Using these techniques without authorization is ILLEGAL.
//!
//! ## Technical Background
//!
//! On Linux, the ptrace system call allows one process to:
//! - Attach to another process
//! - Read/write its memory
//! - Read/write its registers
//! - Control its execution
//!
//! This is the foundation of debuggers like GDB.

use anyhow::{Context, Result};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use log::{debug, error, info, warn};
use nix::sys::ptrace;
use nix::sys::signal::{kill, Signal};
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::Pid;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Custom error types for process injection operations
#[derive(Error, Debug)]
pub enum InjectorError {
    #[error("Failed to attach to process {pid}: {reason}")]
    AttachFailed { pid: i32, reason: String },

    #[error("Process {0} not found")]
    ProcessNotFound(i32),

    #[error("Memory access denied at address {addr:#x}: {reason}")]
    MemoryAccessDenied { addr: u64, reason: String },

    #[error("Invalid memory region: {0}")]
    InvalidMemoryRegion(String),

    #[error("Ptrace error: {0}")]
    PtraceError(#[from] nix::Error),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Permission denied: {0}")]
    PermissionDenied(String),
}

/// Represents a memory region from /proc/[pid]/maps
///
/// Memory mappings tell us:
/// - Where code and data are loaded
/// - What permissions each region has
/// - Which files are mapped into memory
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryRegion {
    /// Start address of the region
    pub start: u64,
    /// End address of the region
    pub end: u64,
    /// Permission flags (r/w/x/p or s)
    pub permissions: Permissions,
    /// Offset in the mapped file
    pub offset: u64,
    /// Device major:minor
    pub device: String,
    /// Inode number
    pub inode: u64,
    /// Path to the mapped file (if any)
    pub pathname: Option<PathBuf>,
}

impl MemoryRegion {
    /// Get the size of this memory region
    pub fn size(&self) -> u64 {
        self.end - self.start
    }

    /// Check if an address falls within this region
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.start && addr < self.end
    }

    /// Check if this is an executable region
    pub fn is_executable(&self) -> bool {
        self.permissions.execute
    }

    /// Check if this is a writable region
    pub fn is_writable(&self) -> bool {
        self.permissions.write
    }
}

/// Memory permission flags
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Permissions {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
    pub shared: bool, // false = private
}

impl std::fmt::Display for Permissions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}{}{}{}",
            if self.read { 'r' } else { '-' },
            if self.write { 'w' } else { '-' },
            if self.execute { 'x' } else { '-' },
            if self.shared { 's' } else { 'p' }
        )
    }
}

/// CPU register state (x86_64)
///
/// These registers control program execution.
/// Understanding them is crucial for debugging and injection.
///
/// # Key Registers:
/// - RIP: Instruction pointer (next instruction to execute)
/// - RSP: Stack pointer
/// - RAX: Return value / accumulator
/// - RDI, RSI, RDX, RCX, R8, R9: Function arguments (System V ABI)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[repr(C)]
pub struct Registers {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub orig_rax: u64,
    pub rip: u64,
    pub cs: u64,
    pub eflags: u64,
    pub rsp: u64,
    pub ss: u64,
    pub fs_base: u64,
    pub gs_base: u64,
    pub ds: u64,
    pub es: u64,
    pub fs: u64,
    pub gs: u64,
}

/// Information about an attached process
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: i32,
    pub name: String,
    pub exe_path: Option<PathBuf>,
    pub cmdline: String,
    pub state: ProcessState,
    pub uid: u32,
    pub gid: u32,
    pub parent_pid: i32,
    pub threads: Vec<i32>,
}

/// Process execution state
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum ProcessState {
    Running,
    Stopped,
    Sleeping,
    Zombie,
    Dead,
    Unknown,
}

impl std::fmt::Display for ProcessState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProcessState::Running => write!(f, "Running"),
            ProcessState::Stopped => write!(f, "Stopped"),
            ProcessState::Sleeping => write!(f, "Sleeping"),
            ProcessState::Zombie => write!(f, "Zombie"),
            ProcessState::Dead => write!(f, "Dead"),
            ProcessState::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Main process analyzer/injector struct
///
/// This struct manages the connection to a target process
/// and provides methods for memory analysis.
pub struct ProcessAnalyzer {
    /// Target process ID
    pid: Pid,
    /// Whether we're currently attached
    attached: bool,
    /// Cached memory maps
    memory_maps: Vec<MemoryRegion>,
    /// Original registers (saved before modification)
    original_registers: Option<libc::user_regs_struct>,
    /// File handle for /proc/[pid]/mem
    mem_file: Option<File>,
}

impl ProcessAnalyzer {
    /// Create a new ProcessAnalyzer for the given PID
    ///
    /// This does NOT attach to the process yet - call attach() explicitly.
    ///
    /// # Arguments
    /// * `pid` - The process ID to analyze
    ///
    /// # Returns
    /// A new ProcessAnalyzer instance
    pub fn new(pid: i32) -> Result<Self> {
        // Verify the process exists
        let proc_path = format!("/proc/{}", pid);
        if !Path::new(&proc_path).exists() {
            return Err(InjectorError::ProcessNotFound(pid).into());
        }

        Ok(Self {
            pid: Pid::from_raw(pid),
            attached: false,
            memory_maps: Vec::new(),
            original_registers: None,
            mem_file: None,
        })
    }

    /// Attach to the target process using ptrace
    ///
    /// # How ptrace attach works:
    /// 1. PTRACE_ATTACH sends SIGSTOP to the target
    /// 2. The target stops and becomes a tracee
    /// 3. We can then read/write memory and registers
    ///
    /// # Safety Considerations
    /// - Requires CAP_SYS_PTRACE or same UID as target
    /// - Target must not be protected by Yama LSM
    /// - ptrace_scope sysctl affects what we can attach to
    ///
    /// # Security Note
    /// Attaching to a process is invasive - only do this
    /// on processes you own or have explicit permission to debug.
    pub fn attach(&mut self) -> Result<()> {
        info!("Attaching to process {}", self.pid);

        // PTRACE_ATTACH: Attach to the process
        // This is the same call GDB uses to start debugging
        ptrace::attach(self.pid).map_err(|e| InjectorError::AttachFailed {
            pid: self.pid.as_raw(),
            reason: e.to_string(),
        })?;

        // Wait for the process to stop
        // After attach, the kernel sends SIGSTOP to the target
        match waitpid(self.pid, Some(WaitPidFlag::WSTOPPED)) {
            Ok(WaitStatus::Stopped(_, Signal::SIGSTOP)) => {
                debug!("Process {} stopped successfully", self.pid);
            }
            Ok(status) => {
                warn!("Unexpected wait status after attach: {:?}", status);
            }
            Err(e) => {
                return Err(InjectorError::AttachFailed {
                    pid: self.pid.as_raw(),
                    reason: format!("Wait failed: {}", e),
                }
                .into());
            }
        }

        self.attached = true;

        // Parse memory maps while attached
        self.refresh_memory_maps()?;

        // Open /proc/[pid]/mem for direct memory access
        let mem_path = format!("/proc/{}/mem", self.pid.as_raw());
        self.mem_file = Some(
            File::options()
                .read(true)
                .write(true)
                .open(&mem_path)
                .context("Failed to open /proc/[pid]/mem")?,
        );

        Ok(())
    }

    /// Detach from the target process
    ///
    /// This resumes the process and removes our tracer relationship.
    pub fn detach(&mut self) -> Result<()> {
        if !self.attached {
            return Ok(());
        }

        info!("Detaching from process {}", self.pid);

        // If we modified registers, restore them
        if let Some(ref orig_regs) = self.original_registers {
            unsafe {
                self.set_registers_raw(orig_regs)?;
            }
        }

        // PTRACE_DETACH: Resume and detach from the process
        ptrace::detach(self.pid, None)?;

        self.attached = false;
        self.mem_file = None;

        Ok(())
    }

    /// Get process information
    pub fn get_process_info(&self) -> Result<ProcessInfo> {
        let pid = self.pid.as_raw();

        // Read /proc/[pid]/stat for basic info
        let stat_path = format!("/proc/{}/stat", pid);
        let stat_content = fs::read_to_string(&stat_path)?;

        // Parse stat file - format is: pid (comm) state ppid ...
        // The comm can contain spaces and parentheses, so we parse carefully
        let name = stat_content
            .split('(')
            .nth(1)
            .and_then(|s| s.rsplit(')').nth(1))
            .map(|s| s.to_string())
            .unwrap_or_else(|| "unknown".to_string());

        // Get state character
        let state_char = stat_content
            .rsplit(')')
            .next()
            .and_then(|s| s.chars().nth(1))
            .unwrap_or('?');

        let state = match state_char {
            'R' => ProcessState::Running,
            'S' | 'D' => ProcessState::Sleeping,
            'T' | 't' => ProcessState::Stopped,
            'Z' => ProcessState::Zombie,
            'X' | 'x' => ProcessState::Dead,
            _ => ProcessState::Unknown,
        };

        // Read cmdline
        let cmdline_path = format!("/proc/{}/cmdline", pid);
        let cmdline = fs::read_to_string(&cmdline_path)
            .unwrap_or_default()
            .replace('\0', " ")
            .trim()
            .to_string();

        // Read exe symlink
        let exe_path = format!("/proc/{}/exe", pid);
        let exe = fs::read_link(&exe_path).ok();

        // Read status for UID/GID
        let status_path = format!("/proc/{}/status", pid);
        let status_content = fs::read_to_string(&status_path)?;

        let mut uid = 0u32;
        let mut gid = 0u32;
        let mut ppid = 0i32;

        for line in status_content.lines() {
            if line.starts_with("Uid:") {
                uid = line
                    .split_whitespace()
                    .nth(1)
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
            } else if line.starts_with("Gid:") {
                gid = line
                    .split_whitespace()
                    .nth(1)
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
            } else if line.starts_with("PPid:") {
                ppid = line
                    .split_whitespace()
                    .nth(1)
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
            }
        }

        // Get thread IDs from /proc/[pid]/task
        let task_path = format!("/proc/{}/task", pid);
        let threads: Vec<i32> = fs::read_dir(&task_path)
            .map(|entries| {
                entries
                    .flatten()
                    .filter_map(|e| e.file_name().to_string_lossy().parse().ok())
                    .collect()
            })
            .unwrap_or_default();

        Ok(ProcessInfo {
            pid,
            name,
            exe_path: exe,
            cmdline,
            state,
            uid,
            gid,
            parent_pid: ppid,
            threads,
        })
    }

    /// Refresh the cached memory maps
    pub fn refresh_memory_maps(&mut self) -> Result<()> {
        self.memory_maps = Self::parse_memory_maps(self.pid.as_raw())?;
        Ok(())
    }

    /// Get the cached memory maps
    pub fn get_memory_maps(&self) -> &[MemoryRegion] {
        &self.memory_maps
    }

    /// Parse /proc/[pid]/maps to get memory regions
    ///
    /// # Format of /proc/[pid]/maps
    /// ```text
    /// address           perms offset   dev   inode   pathname
    /// 00400000-00452000 r-xp 00000000 08:02 173521   /usr/bin/dbus-daemon
    /// ```
    ///
    /// This is crucial for:
    /// - Finding executable code regions
    /// - Locating the heap and stack
    /// - Understanding the process's memory layout
    pub fn parse_memory_maps(pid: i32) -> Result<Vec<MemoryRegion>> {
        let maps_path = format!("/proc/{}/maps", pid);
        let file = File::open(&maps_path)?;
        let reader = BufReader::new(file);
        let mut regions = Vec::new();

        // Regex to parse map lines
        let map_regex = Regex::new(
            r"^([0-9a-f]+)-([0-9a-f]+)\s+([rwxsp-]{4})\s+([0-9a-f]+)\s+(\S+)\s+(\d+)\s*(.*)$",
        )?;

        for line in reader.lines() {
            let line = line?;
            if let Some(caps) = map_regex.captures(&line) {
                let start = u64::from_str_radix(&caps[1], 16)?;
                let end = u64::from_str_radix(&caps[2], 16)?;
                let perms = &caps[3];
                let offset = u64::from_str_radix(&caps[4], 16)?;
                let device = caps[5].to_string();
                let inode = caps[6].parse()?;
                let pathname = if caps.get(7).is_some() && !caps[7].trim().is_empty() {
                    Some(PathBuf::from(caps[7].trim()))
                } else {
                    None
                };

                let permissions = Permissions {
                    read: perms.contains('r'),
                    write: perms.contains('w'),
                    execute: perms.contains('x'),
                    shared: perms.contains('s'),
                };

                regions.push(MemoryRegion {
                    start,
                    end,
                    permissions,
                    offset,
                    device,
                    inode,
                    pathname,
                });
            }
        }

        Ok(regions)
    }

    /// Read memory from the target process
    ///
    /// # Method 1: Using /proc/[pid]/mem
    /// This is the most efficient method. We can read arbitrary
    /// amounts of memory in a single syscall.
    ///
    /// # Method 2: Using PTRACE_PEEKDATA
    /// Reads one word (8 bytes on x86_64) at a time.
    /// Less efficient but works when /proc/[pid]/mem fails.
    ///
    /// # Safety
    /// Memory reads can fail if:
    /// - The address is not mapped
    /// - The region doesn't have read permission
    /// - The process has exited
    pub fn read_memory(&self, address: u64, size: usize) -> Result<Vec<u8>> {
        if !self.attached {
            return Err(InjectorError::AttachFailed {
                pid: self.pid.as_raw(),
                reason: "Not attached".to_string(),
            }
            .into());
        }

        // Try to use /proc/[pid]/mem first (more efficient)
        if let Some(ref mem_file) = self.mem_file {
            let mut buffer = vec![0u8; size];
            match mem_file.read_at(&mut buffer, address) {
                Ok(bytes_read) => {
                    buffer.truncate(bytes_read);
                    return Ok(buffer);
                }
                Err(e) => {
                    debug!(
                        "Failed to read via /proc/[pid]/mem, falling back to ptrace: {}",
                        e
                    );
                }
            }
        }

        // Fallback: Use PTRACE_PEEKDATA
        // This reads one word at a time
        self.read_memory_ptrace(address, size)
    }

    /// Read memory using PTRACE_PEEKDATA
    ///
    /// PTRACE_PEEKDATA reads a word from the tracee's memory.
    /// On x86_64, a word is 8 bytes.
    ///
    /// # Implementation Details
    /// - We read word-aligned chunks
    /// - Handle unaligned addresses by reading extra and trimming
    fn read_memory_ptrace(&self, address: u64, size: usize) -> Result<Vec<u8>> {
        let word_size = std::mem::size_of::<libc::c_long>();
        let mut buffer = Vec::with_capacity(size);

        // Align to word boundary
        let start_offset = (address as usize) % word_size;
        let aligned_addr = address - start_offset as u64;

        // Calculate how many words we need to read
        let total_bytes = size + start_offset;
        let words_to_read = (total_bytes + word_size - 1) / word_size;

        for i in 0..words_to_read {
            let addr = aligned_addr + (i * word_size) as u64;

            // SAFETY: ptrace::read is unsafe because it reads from another process's memory
            // We've verified we're attached and the address is within valid ranges
            let word = ptrace::read(self.pid, addr as *mut libc::c_void)?;

            // Convert word to bytes
            let bytes = word.to_ne_bytes();
            buffer.extend_from_slice(&bytes);
        }

        // Trim to requested size, accounting for alignment
        Ok(buffer[start_offset..start_offset + size].to_vec())
    }

    /// Write memory to the target process
    ///
    /// # EDUCATIONAL NOTE
    /// This demonstrates how memory modification works.
    /// In real debugging scenarios, this is used for:
    /// - Setting breakpoints (writing int3 / 0xCC)
    /// - Patching code
    /// - Modifying variables
    ///
    /// # Security Warning
    /// Writing to process memory is powerful and dangerous.
    /// Only use this for legitimate debugging/research.
    pub fn write_memory(&self, address: u64, data: &[u8]) -> Result<()> {
        if !self.attached {
            return Err(InjectorError::AttachFailed {
                pid: self.pid.as_raw(),
                reason: "Not attached".to_string(),
            }
            .into());
        }

        // Verify the address is in a writable region
        let is_writable = self.memory_maps.iter().any(|r| {
            r.contains(address) && r.permissions.write
        });

        if !is_writable {
            warn!(
                "Writing to non-writable region at {:#x} - this may fail",
                address
            );
        }

        // Try /proc/[pid]/mem first
        if let Some(ref mem_file) = self.mem_file {
            match mem_file.write_at(data, address) {
                Ok(bytes_written) if bytes_written == data.len() => {
                    return Ok(());
                }
                Ok(bytes_written) => {
                    warn!(
                        "Partial write: {} of {} bytes",
                        bytes_written,
                        data.len()
                    );
                }
                Err(e) => {
                    debug!(
                        "Failed to write via /proc/[pid]/mem, falling back to ptrace: {}",
                        e
                    );
                }
            }
        }

        // Fallback: Use PTRACE_POKEDATA
        self.write_memory_ptrace(address, data)
    }

    /// Write memory using PTRACE_POKEDATA
    ///
    /// Similar to reading, we write one word at a time.
    /// For partial word writes, we read-modify-write.
    fn write_memory_ptrace(&self, address: u64, data: &[u8]) -> Result<()> {
        let word_size = std::mem::size_of::<libc::c_long>();
        let start_offset = (address as usize) % word_size;
        let aligned_addr = address - start_offset as u64;

        let total_bytes = data.len() + start_offset;
        let words_to_write = (total_bytes + word_size - 1) / word_size;

        let mut data_offset = 0;

        for i in 0..words_to_write {
            let addr = aligned_addr + (i * word_size) as u64;

            // Read the current word (for partial writes)
            let current_word = ptrace::read(self.pid, addr as *mut libc::c_void)?;
            let mut word_bytes = current_word.to_ne_bytes();

            // Calculate which bytes in this word we're modifying
            let word_start = if i == 0 { start_offset } else { 0 };
            let word_end = std::cmp::min(
                word_size,
                word_start + (data.len() - data_offset),
            );

            // Copy data into the word
            for j in word_start..word_end {
                word_bytes[j] = data[data_offset];
                data_offset += 1;
            }

            // Write the modified word back
            let new_word = libc::c_long::from_ne_bytes(word_bytes);

            // SAFETY: We're writing to a process we're attached to
            // The address has been validated against memory maps
            unsafe {
                ptrace::write(
                    self.pid,
                    addr as *mut libc::c_void,
                    new_word as *mut libc::c_void,
                )?;
            }
        }

        Ok(())
    }

    /// Get the current CPU registers
    ///
    /// # Register Usage (System V AMD64 ABI)
    /// - RDI, RSI, RDX, RCX, R8, R9: Function arguments
    /// - RAX: Return value
    /// - RBP: Base pointer
    /// - RSP: Stack pointer
    /// - RIP: Instruction pointer
    pub fn get_registers(&self) -> Result<libc::user_regs_struct> {
        if !self.attached {
            return Err(InjectorError::AttachFailed {
                pid: self.pid.as_raw(),
                reason: "Not attached".to_string(),
            }
            .into());
        }

        // Use libc's ptrace directly for register access
        let mut regs: libc::user_regs_struct = unsafe { std::mem::zeroed() };

        unsafe {
            let result = libc::ptrace(
                libc::PTRACE_GETREGS,
                self.pid.as_raw(),
                std::ptr::null::<libc::c_void>(),
                &mut regs as *mut libc::user_regs_struct,
            );

            if result == -1 {
                return Err(InjectorError::PtraceError(
                    nix::Error::last(),
                ).into());
            }
        }

        Ok(regs)
    }

    /// Set CPU registers (unsafe - modifies process state)
    ///
    /// # Safety
    /// This is unsafe because:
    /// - Modifying RIP can cause the process to execute arbitrary code
    /// - Incorrect register values can crash the process
    /// - Stack manipulation can corrupt program state
    ///
    /// Always save original registers before modification!
    pub unsafe fn set_registers_raw(
        &self,
        regs: &libc::user_regs_struct,
    ) -> Result<()> {
        if !self.attached {
            return Err(InjectorError::AttachFailed {
                pid: self.pid.as_raw(),
                reason: "Not attached".to_string(),
            }
            .into());
        }

        let result = libc::ptrace(
            libc::PTRACE_SETREGS,
            self.pid.as_raw(),
            std::ptr::null::<libc::c_void>(),
            regs as *const libc::user_regs_struct,
        );

        if result == -1 {
            return Err(InjectorError::PtraceError(
                nix::Error::last(),
            ).into());
        }

        Ok(())
    }

    /// Save the current registers for later restoration
    pub fn save_registers(&mut self) -> Result<()> {
        let regs = self.get_registers()?;
        self.original_registers = Some(regs);
        Ok(())
    }

    /// Single-step the process (execute one instruction)
    ///
    /// This is fundamental to debugging:
    /// - PTRACE_SINGLESTEP executes one instruction then stops
    /// - We can examine state after each instruction
    /// - This is how "step" works in debuggers
    pub fn single_step(&self) -> Result<()> {
        if !self.attached {
            return Err(InjectorError::AttachFailed {
                pid: self.pid.as_raw(),
                reason: "Not attached".to_string(),
            }
            .into());
        }

        ptrace::step(self.pid, None)?;

        // Wait for the process to stop
        match waitpid(self.pid, Some(WaitPidFlag::WSTOPPED)) {
            Ok(WaitStatus::Stopped(_, Signal::SIGTRAP)) => {
                debug!("Single step completed");
                Ok(())
            }
            Ok(status) => {
                warn!("Unexpected status after single step: {:?}", status);
                Ok(())
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Continue process execution
    pub fn continue_execution(&self) -> Result<()> {
        if !self.attached {
            return Err(InjectorError::AttachFailed {
                pid: self.pid.as_raw(),
                reason: "Not attached".to_string(),
            }
            .into());
        }

        ptrace::cont(self.pid, None)?;
        Ok(())
    }

    /// Find executable memory regions (for code analysis)
    pub fn find_executable_regions(&self) -> Vec<&MemoryRegion> {
        self.memory_maps
            .iter()
            .filter(|r| r.is_executable())
            .collect()
    }

    /// Find the heap region
    pub fn find_heap(&self) -> Option<&MemoryRegion> {
        self.memory_maps
            .iter()
            .find(|r| r.pathname.as_ref().map_or(false, |p| {
                p.to_string_lossy().contains("[heap]")
            }))
    }

    /// Find the stack region
    pub fn find_stack(&self) -> Option<&MemoryRegion> {
        self.memory_maps
            .iter()
            .find(|r| r.pathname.as_ref().map_or(false, |p| {
                p.to_string_lossy().contains("[stack]")
            }))
    }

    /// Search for a byte pattern in process memory
    ///
    /// # Use Cases
    /// - Finding specific data structures
    /// - Locating strings
    /// - Pattern matching for signatures
    pub fn search_memory(&self, pattern: &[u8]) -> Result<Vec<u64>> {
        let mut matches = Vec::new();

        for region in &self.memory_maps {
            // Only search readable regions
            if !region.permissions.read {
                continue;
            }

            // Skip very large regions for performance
            if region.size() > 100 * 1024 * 1024 {
                debug!("Skipping large region: {:?}", region.pathname);
                continue;
            }

            // Read the region
            match self.read_memory(region.start, region.size() as usize) {
                Ok(data) => {
                    // Search for pattern
                    for (i, window) in data.windows(pattern.len()).enumerate() {
                        if window == pattern {
                            matches.push(region.start + i as u64);
                        }
                    }
                }
                Err(e) => {
                    debug!(
                        "Could not read region at {:#x}: {}",
                        region.start, e
                    );
                }
            }
        }

        Ok(matches)
    }

    /// Dump a memory region to a file
    pub fn dump_region(&self, region: &MemoryRegion, output_path: &Path) -> Result<()> {
        let data = self.read_memory(region.start, region.size() as usize)?;
        let mut file = File::create(output_path)?;
        file.write_all(&data)?;
        Ok(())
    }
}

impl Drop for ProcessAnalyzer {
    fn drop(&mut self) {
        if self.attached {
            if let Err(e) = self.detach() {
                error!("Failed to detach in drop: {}", e);
            }
        }
    }
}

/// Disassembly helpers (simplified)
///
/// # Note
/// Full disassembly would require a crate like capstone or iced-x86.
/// This provides basic instruction identification for educational purposes.
pub mod disasm {
    /// Common x86_64 instruction patterns
    pub const INT3: u8 = 0xCC;           // Breakpoint
    pub const NOP: u8 = 0x90;            // No operation
    pub const RET: u8 = 0xC3;            // Return
    pub const CALL_REL32: u8 = 0xE8;     // Relative call
    pub const JMP_REL32: u8 = 0xE9;      // Relative jump
    pub const JMP_REL8: u8 = 0xEB;       // Short jump

    /// Identify a basic instruction at the given bytes
    pub fn identify_instruction(bytes: &[u8]) -> &'static str {
        if bytes.is_empty() {
            return "???";
        }

        match bytes[0] {
            INT3 => "int3 (breakpoint)",
            NOP => "nop",
            RET => "ret",
            CALL_REL32 => "call (relative)",
            JMP_REL32 => "jmp (relative)",
            JMP_REL8 => "jmp (short)",
            0x55 => "push rbp",
            0x48 if bytes.get(1) == Some(&0x89) && bytes.get(2) == Some(&0xe5) => {
                "mov rbp, rsp"
            }
            0x48 if bytes.get(1) == Some(&0x83) && bytes.get(2) == Some(&0xec) => {
                "sub rsp, imm8"
            }
            _ => "unknown",
        }
    }
}

/// ELF parsing helpers
pub mod elf {
    /// ELF magic number
    pub const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];

    /// Check if data starts with ELF magic
    pub fn is_elf(data: &[u8]) -> bool {
        data.len() >= 4 && data[..4] == ELF_MAGIC
    }

    /// ELF class (32-bit or 64-bit)
    pub fn get_elf_class(data: &[u8]) -> Option<u8> {
        if data.len() > 4 && is_elf(data) {
            Some(data[4])
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_permissions_display() {
        let perms = Permissions {
            read: true,
            write: true,
            execute: false,
            shared: false,
        };
        assert_eq!(format!("{}", perms), "rw-p");

        let perms = Permissions {
            read: true,
            write: false,
            execute: true,
            shared: true,
        };
        assert_eq!(format!("{}", perms), "r-xs");
    }

    #[test]
    fn test_memory_region_contains() {
        let region = MemoryRegion {
            start: 0x1000,
            end: 0x2000,
            permissions: Permissions {
                read: true,
                write: false,
                execute: true,
                shared: false,
            },
            offset: 0,
            device: "00:00".to_string(),
            inode: 0,
            pathname: None,
        };

        assert!(region.contains(0x1000));
        assert!(region.contains(0x1500));
        assert!(region.contains(0x1FFF));
        assert!(!region.contains(0x2000));
        assert!(!region.contains(0x0FFF));
    }

    #[test]
    fn test_memory_region_size() {
        let region = MemoryRegion {
            start: 0x1000,
            end: 0x3000,
            permissions: Permissions {
                read: true,
                write: true,
                execute: false,
                shared: false,
            },
            offset: 0,
            device: "00:00".to_string(),
            inode: 0,
            pathname: None,
        };

        assert_eq!(region.size(), 0x2000);
    }

    #[test]
    fn test_elf_magic() {
        use elf::*;

        let elf_data = [0x7f, b'E', b'L', b'F', 2, 1, 1, 0];
        assert!(is_elf(&elf_data));
        assert_eq!(get_elf_class(&elf_data), Some(2));

        let not_elf = [0x00, 0x01, 0x02, 0x03];
        assert!(!is_elf(&not_elf));
    }

    #[test]
    fn test_disasm_identify() {
        use disasm::*;

        assert_eq!(identify_instruction(&[INT3]), "int3 (breakpoint)");
        assert_eq!(identify_instruction(&[NOP]), "nop");
        assert_eq!(identify_instruction(&[RET]), "ret");
        assert_eq!(identify_instruction(&[0x55]), "push rbp");
    }

    #[test]
    fn test_process_state_display() {
        assert_eq!(format!("{}", ProcessState::Running), "Running");
        assert_eq!(format!("{}", ProcessState::Stopped), "Stopped");
        assert_eq!(format!("{}", ProcessState::Zombie), "Zombie");
    }

    // Integration tests require a running target process
    // These would typically be run manually or with proper setup
    #[test]
    #[ignore]
    fn test_attach_self() {
        // Can't attach to self - would deadlock
        // This is a placeholder for integration tests
    }
}
