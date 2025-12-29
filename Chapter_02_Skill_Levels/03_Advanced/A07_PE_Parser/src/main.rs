//! # PE Parser - Windows Portable Executable Analyzer
//!
//! This tool parses and analyzes Windows PE (Portable Executable) files in detail.
//! PE files include .exe, .dll, .sys, .scr, and other Windows executable formats.
//!
//! ## PE File Format Overview
//!
//! The PE format evolved from COFF (Common Object File Format) and consists of:
//!
//! ```text
//! +---------------------------+
//! |     DOS Header (MZ)       |  <- Legacy DOS compatibility
//! +---------------------------+
//! |     DOS Stub              |  <- "This program cannot be run in DOS mode"
//! +---------------------------+
//! |     PE Signature          |  <- "PE\0\0" (0x50450000)
//! +---------------------------+
//! |     COFF File Header      |  <- Machine type, section count, timestamp
//! +---------------------------+
//! |     Optional Header       |  <- Entry point, image base, subsystem
//! +---------------------------+
//! |     Data Directories      |  <- Imports, exports, resources, etc.
//! +---------------------------+
//! |     Section Headers       |  <- .text, .data, .rdata, .rsrc, etc.
//! +---------------------------+
//! |     Section Data          |  <- Actual code and data
//! +---------------------------+
//! ```
//!
//! ## Security Relevance
//!
//! PE analysis is crucial for:
//! - Malware analysis and reverse engineering
//! - Detecting packers and protectors
//! - Analyzing imports for suspicious API usage
//! - Identifying code injection techniques
//! - Verifying digital signatures

use anyhow::{Context, Result};
use byteorder::{LittleEndian, ReadBytesExt};
use chrono::{DateTime, TimeZone, Utc};
use clap::{Parser, ValueEnum};
use colored::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::fs::File;
use std::io::{Cursor, Read, Seek, SeekFrom};
use std::path::PathBuf;
use thiserror::Error;

// ============================================================================
// ERROR HANDLING
// ============================================================================

/// PE parsing errors
#[derive(Error, Debug)]
pub enum PeError {
    #[error("Invalid DOS header - not a valid PE file")]
    InvalidDosHeader,

    #[error("Invalid PE signature at offset 0x{0:x}")]
    InvalidPeSignature(u32),

    #[error("Unsupported PE format: {0}")]
    UnsupportedFormat(String),

    #[error("Invalid section header at index {0}")]
    InvalidSection(usize),

    #[error("File read error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Invalid RVA: 0x{0:x}")]
    InvalidRva(u32),
}

// ============================================================================
// CLI INTERFACE
// ============================================================================

/// PE Parser - Analyze Windows Portable Executable files
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to PE file to analyze
    #[arg(short, long)]
    file: PathBuf,

    /// Output format
    #[arg(short, long, value_enum, default_value = "text")]
    output: OutputFormat,

    /// Show all imports
    #[arg(long)]
    imports: bool,

    /// Show all exports
    #[arg(long)]
    exports: bool,

    /// Show section hex dump
    #[arg(long)]
    hexdump: bool,

    /// Verbose output with security analysis
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum OutputFormat {
    Text,
    Json,
}

// ============================================================================
// PE STRUCTURES
// ============================================================================

/// DOS Header - First 64 bytes of every PE file
///
/// The DOS header maintains backward compatibility with MS-DOS.
/// Most fields are unused in modern Windows, except:
/// - e_magic: Must be 0x5A4D ("MZ")
/// - e_lfanew: Offset to PE signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DosHeader {
    /// Magic number - 0x5A4D ("MZ" for Mark Zbikowski)
    pub e_magic: u16,
    /// Bytes on last page of file
    pub e_cblp: u16,
    /// Pages in file
    pub e_cp: u16,
    /// Relocations
    pub e_crlc: u16,
    /// Size of header in paragraphs
    pub e_cparhdr: u16,
    /// Minimum extra paragraphs needed
    pub e_minalloc: u16,
    /// Maximum extra paragraphs needed
    pub e_maxalloc: u16,
    /// Initial (relative) SS value
    pub e_ss: u16,
    /// Initial SP value
    pub e_sp: u16,
    /// Checksum
    pub e_csum: u16,
    /// Initial IP value
    pub e_ip: u16,
    /// Initial (relative) CS value
    pub e_cs: u16,
    /// File address of relocation table
    pub e_lfarlc: u16,
    /// Overlay number
    pub e_ovno: u16,
    /// Reserved words (4)
    pub e_res: [u16; 4],
    /// OEM identifier
    pub e_oemid: u16,
    /// OEM information
    pub e_oeminfo: u16,
    /// Reserved words (10)
    pub e_res2: [u16; 10],
    /// File address of new exe header (PE signature)
    pub e_lfanew: i32,
}

/// COFF File Header - Describes the file type
///
/// This header contains essential information about the PE file:
/// - Target machine architecture
/// - Number of sections
/// - Compilation timestamp (often useful for malware analysis)
/// - Characteristics flags
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoffHeader {
    /// Target machine type
    pub machine: u16,
    /// Number of sections
    pub number_of_sections: u16,
    /// Unix timestamp of when the file was created
    pub time_date_stamp: u32,
    /// Pointer to symbol table (deprecated, usually 0)
    pub pointer_to_symbol_table: u32,
    /// Number of symbols (deprecated, usually 0)
    pub number_of_symbols: u32,
    /// Size of optional header
    pub size_of_optional_header: u16,
    /// Characteristics flags
    pub characteristics: u16,
}

/// Optional Header - Required for executables
///
/// Despite the name, this header is required for executable files.
/// It contains crucial information for the Windows loader:
/// - Entry point address
/// - Image base (preferred load address)
/// - Section alignment
/// - Subsystem (GUI, console, driver)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptionalHeader {
    /// Magic number: 0x10B (PE32) or 0x20B (PE32+)
    pub magic: u16,
    /// Linker major version
    pub major_linker_version: u8,
    /// Linker minor version
    pub minor_linker_version: u8,
    /// Size of code section
    pub size_of_code: u32,
    /// Size of initialized data
    pub size_of_initialized_data: u32,
    /// Size of uninitialized data
    pub size_of_uninitialized_data: u32,
    /// Entry point RVA
    pub address_of_entry_point: u32,
    /// Base of code section RVA
    pub base_of_code: u32,
    /// Base of data section RVA (PE32 only)
    pub base_of_data: Option<u32>,
    /// Preferred image base address
    pub image_base: u64,
    /// Section alignment in memory
    pub section_alignment: u32,
    /// File alignment on disk
    pub file_alignment: u32,
    /// Required OS major version
    pub major_operating_system_version: u16,
    /// Required OS minor version
    pub minor_operating_system_version: u16,
    /// Image major version
    pub major_image_version: u16,
    /// Image minor version
    pub minor_image_version: u16,
    /// Required subsystem major version
    pub major_subsystem_version: u16,
    /// Required subsystem minor version
    pub minor_subsystem_version: u16,
    /// Win32 version value (reserved, must be 0)
    pub win32_version_value: u32,
    /// Size of image in memory
    pub size_of_image: u32,
    /// Size of headers
    pub size_of_headers: u32,
    /// Checksum (validated for drivers)
    pub checksum: u32,
    /// Subsystem type
    pub subsystem: u16,
    /// DLL characteristics flags
    pub dll_characteristics: u16,
    /// Size of stack reserve
    pub size_of_stack_reserve: u64,
    /// Size of stack commit
    pub size_of_stack_commit: u64,
    /// Size of heap reserve
    pub size_of_heap_reserve: u64,
    /// Size of heap commit
    pub size_of_heap_commit: u64,
    /// Loader flags (reserved)
    pub loader_flags: u32,
    /// Number of data directory entries
    pub number_of_rva_and_sizes: u32,
    /// Is this a PE32+ (64-bit) file
    pub is_pe32_plus: bool,
}

/// Data Directory Entry
///
/// Data directories point to important tables in the PE file:
/// - Export table (DLL functions)
/// - Import table (required DLLs and functions)
/// - Resource table (icons, strings, dialogs)
/// - Security table (digital signatures)
/// - And many more...
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataDirectory {
    /// Relative Virtual Address
    pub virtual_address: u32,
    /// Size in bytes
    pub size: u32,
}

/// Section Header
///
/// Each section contains a specific type of data:
/// - .text: Executable code
/// - .data: Initialized global data
/// - .rdata: Read-only data (strings, constants)
/// - .bss: Uninitialized data
/// - .rsrc: Resources
/// - .reloc: Relocation information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionHeader {
    /// Section name (8 bytes, null-padded)
    pub name: String,
    /// Virtual size (size in memory)
    pub virtual_size: u32,
    /// Virtual address (RVA)
    pub virtual_address: u32,
    /// Size of raw data on disk
    pub size_of_raw_data: u32,
    /// Pointer to raw data on disk
    pub pointer_to_raw_data: u32,
    /// Pointer to relocations
    pub pointer_to_relocations: u32,
    /// Pointer to line numbers
    pub pointer_to_linenumbers: u32,
    /// Number of relocations
    pub number_of_relocations: u16,
    /// Number of line numbers
    pub number_of_linenumbers: u16,
    /// Section characteristics/flags
    pub characteristics: u32,
}

/// Import Directory Entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportDescriptor {
    /// DLL name
    pub name: String,
    /// Imported functions
    pub functions: Vec<ImportedFunction>,
}

/// Imported Function
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportedFunction {
    /// Function name (or ordinal if by_ordinal is true)
    pub name: String,
    /// Hint value
    pub hint: u16,
    /// Is imported by ordinal
    pub by_ordinal: bool,
    /// Ordinal value if by_ordinal
    pub ordinal: Option<u16>,
}

/// Export Directory
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportDirectory {
    /// DLL name
    pub name: String,
    /// Ordinal base
    pub ordinal_base: u32,
    /// Number of functions
    pub number_of_functions: u32,
    /// Number of names
    pub number_of_names: u32,
    /// Exported functions
    pub functions: Vec<ExportedFunction>,
}

/// Exported Function
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportedFunction {
    /// Function name
    pub name: String,
    /// Ordinal
    pub ordinal: u16,
    /// RVA of function
    pub rva: u32,
    /// Is a forwarder
    pub is_forwarder: bool,
    /// Forwarder string if applicable
    pub forwarder: Option<String>,
}

/// Complete PE File representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeFile {
    /// DOS header
    pub dos_header: DosHeader,
    /// COFF file header
    pub coff_header: CoffHeader,
    /// Optional header
    pub optional_header: OptionalHeader,
    /// Data directories
    pub data_directories: Vec<DataDirectory>,
    /// Section headers
    pub sections: Vec<SectionHeader>,
    /// Import descriptors
    pub imports: Vec<ImportDescriptor>,
    /// Export directory
    pub exports: Option<ExportDirectory>,
    /// Security analysis results
    pub security_info: SecurityInfo,
}

/// Security-relevant information
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SecurityInfo {
    /// Is the file packed/protected
    pub is_packed: bool,
    /// Packer/protector name if detected
    pub packer_name: Option<String>,
    /// Has digital signature
    pub has_signature: bool,
    /// Has ASLR enabled
    pub has_aslr: bool,
    /// Has DEP/NX enabled
    pub has_dep: bool,
    /// Has SEH protection
    pub has_seh: bool,
    /// Has CFG enabled
    pub has_cfg: bool,
    /// Suspicious imports detected
    pub suspicious_imports: Vec<String>,
    /// Anomalies detected
    pub anomalies: Vec<String>,
    /// Entry point in unusual section
    pub unusual_entry_point: bool,
    /// High entropy sections (possibly packed)
    pub high_entropy_sections: Vec<String>,
}

// ============================================================================
// CONSTANTS
// ============================================================================

/// DOS magic number "MZ"
const DOS_MAGIC: u16 = 0x5A4D;

/// PE signature "PE\0\0"
const PE_SIGNATURE: u32 = 0x00004550;

/// PE32 magic
const PE32_MAGIC: u16 = 0x10B;

/// PE32+ magic (64-bit)
const PE32PLUS_MAGIC: u16 = 0x20B;

/// Data directory indices
mod data_directory_index {
    pub const EXPORT: usize = 0;
    pub const IMPORT: usize = 1;
    pub const RESOURCE: usize = 2;
    pub const EXCEPTION: usize = 3;
    pub const SECURITY: usize = 4;
    pub const BASERELOC: usize = 5;
    pub const DEBUG: usize = 6;
    pub const ARCHITECTURE: usize = 7;
    pub const GLOBALPTR: usize = 8;
    pub const TLS: usize = 9;
    pub const LOAD_CONFIG: usize = 10;
    pub const BOUND_IMPORT: usize = 11;
    pub const IAT: usize = 12;
    pub const DELAY_IMPORT: usize = 13;
    pub const CLR_RUNTIME: usize = 14;
}

/// Machine types
fn machine_type_name(machine: u16) -> &'static str {
    match machine {
        0x0 => "Unknown",
        0x14c => "i386 (x86)",
        0x8664 => "AMD64 (x64)",
        0x1c0 => "ARM",
        0xaa64 => "ARM64",
        0x1c4 => "ARM Thumb-2",
        0xebc => "EFI Byte Code",
        0x5032 => "RISC-V 32-bit",
        0x5064 => "RISC-V 64-bit",
        _ => "Unknown",
    }
}

/// Subsystem types
fn subsystem_name(subsystem: u16) -> &'static str {
    match subsystem {
        0 => "Unknown",
        1 => "Native",
        2 => "Windows GUI",
        3 => "Windows Console",
        5 => "OS/2 Console",
        7 => "POSIX Console",
        9 => "Windows CE",
        10 => "EFI Application",
        11 => "EFI Boot Service Driver",
        12 => "EFI Runtime Driver",
        13 => "EFI ROM",
        14 => "Xbox",
        16 => "Windows Boot Application",
        _ => "Unknown",
    }
}

/// Section characteristics flags
fn section_characteristics_str(chars: u32) -> Vec<&'static str> {
    let mut flags = Vec::new();
    if chars & 0x00000020 != 0 { flags.push("CODE"); }
    if chars & 0x00000040 != 0 { flags.push("INITIALIZED_DATA"); }
    if chars & 0x00000080 != 0 { flags.push("UNINITIALIZED_DATA"); }
    if chars & 0x02000000 != 0 { flags.push("DISCARDABLE"); }
    if chars & 0x04000000 != 0 { flags.push("NOT_CACHED"); }
    if chars & 0x08000000 != 0 { flags.push("NOT_PAGED"); }
    if chars & 0x10000000 != 0 { flags.push("SHARED"); }
    if chars & 0x20000000 != 0 { flags.push("EXECUTE"); }
    if chars & 0x40000000 != 0 { flags.push("READ"); }
    if chars & 0x80000000 != 0 { flags.push("WRITE"); }
    flags
}

/// DLL characteristics flags
fn dll_characteristics_str(chars: u16) -> Vec<&'static str> {
    let mut flags = Vec::new();
    if chars & 0x0020 != 0 { flags.push("HIGH_ENTROPY_VA"); }
    if chars & 0x0040 != 0 { flags.push("DYNAMIC_BASE (ASLR)"); }
    if chars & 0x0080 != 0 { flags.push("FORCE_INTEGRITY"); }
    if chars & 0x0100 != 0 { flags.push("NX_COMPAT (DEP)"); }
    if chars & 0x0200 != 0 { flags.push("NO_ISOLATION"); }
    if chars & 0x0400 != 0 { flags.push("NO_SEH"); }
    if chars & 0x0800 != 0 { flags.push("NO_BIND"); }
    if chars & 0x1000 != 0 { flags.push("APPCONTAINER"); }
    if chars & 0x2000 != 0 { flags.push("WDM_DRIVER"); }
    if chars & 0x4000 != 0 { flags.push("GUARD_CF (CFG)"); }
    if chars & 0x8000 != 0 { flags.push("TERMINAL_SERVER_AWARE"); }
    flags
}

/// Suspicious API functions to detect
const SUSPICIOUS_APIS: &[&str] = &[
    // Process manipulation
    "CreateRemoteThread", "CreateRemoteThreadEx", "NtCreateThreadEx",
    "WriteProcessMemory", "ReadProcessMemory", "VirtualAllocEx",
    "NtWriteVirtualMemory", "NtReadVirtualMemory", "OpenProcess",

    // Code injection
    "SetWindowsHookEx", "SetWindowsHookExA", "SetWindowsHookExW",
    "QueueUserAPC", "NtQueueApcThread",

    // DLL injection
    "LoadLibrary", "LoadLibraryA", "LoadLibraryW", "LoadLibraryEx",
    "LdrLoadDll", "NtMapViewOfSection",

    // Anti-debugging
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess", "OutputDebugString",

    // Crypto/Ransomware
    "CryptEncrypt", "CryptDecrypt", "CryptGenKey",
    "CryptAcquireContext", "CryptImportKey",

    // Keylogging
    "GetAsyncKeyState", "GetKeyState", "SetWindowsHookEx",

    // Network
    "WSAStartup", "socket", "connect", "send", "recv",
    "InternetOpen", "InternetOpenUrl", "URLDownloadToFile",

    // Registry persistence
    "RegSetValueEx", "RegCreateKeyEx",

    // File system
    "CreateFile", "DeleteFile", "MoveFile",
];

// ============================================================================
// PE PARSER IMPLEMENTATION
// ============================================================================

/// PE Parser struct
pub struct PeParser<R: Read + Seek> {
    reader: R,
    file_size: u64,
}

impl<R: Read + Seek> PeParser<R> {
    /// Create a new PE parser
    pub fn new(mut reader: R) -> Result<Self, PeError> {
        // Get file size
        let file_size = reader.seek(SeekFrom::End(0))?;
        reader.seek(SeekFrom::Start(0))?;

        Ok(Self { reader, file_size })
    }

    /// Parse the PE file
    pub fn parse(&mut self) -> Result<PeFile, PeError> {
        // Parse DOS header
        let dos_header = self.parse_dos_header()?;

        // Seek to PE signature
        self.reader.seek(SeekFrom::Start(dos_header.e_lfanew as u64))?;

        // Verify PE signature
        let pe_sig = self.reader.read_u32::<LittleEndian>()?;
        if pe_sig != PE_SIGNATURE {
            return Err(PeError::InvalidPeSignature(dos_header.e_lfanew as u32));
        }

        // Parse COFF header
        let coff_header = self.parse_coff_header()?;

        // Parse Optional header
        let (optional_header, data_directories) = self.parse_optional_header()?;

        // Parse section headers
        let sections = self.parse_sections(coff_header.number_of_sections as usize)?;

        // Parse imports
        let imports = if data_directories.len() > data_directory_index::IMPORT {
            self.parse_imports(&data_directories[data_directory_index::IMPORT], &sections, optional_header.is_pe32_plus)?
        } else {
            Vec::new()
        };

        // Parse exports
        let exports = if data_directories.len() > data_directory_index::EXPORT {
            self.parse_exports(&data_directories[data_directory_index::EXPORT], &sections)?
        } else {
            None
        };

        // Perform security analysis
        let security_info = self.analyze_security(
            &optional_header,
            &data_directories,
            &sections,
            &imports,
        )?;

        Ok(PeFile {
            dos_header,
            coff_header,
            optional_header,
            data_directories,
            sections,
            imports,
            exports,
            security_info,
        })
    }

    /// Parse DOS header
    fn parse_dos_header(&mut self) -> Result<DosHeader, PeError> {
        self.reader.seek(SeekFrom::Start(0))?;

        let e_magic = self.reader.read_u16::<LittleEndian>()?;
        if e_magic != DOS_MAGIC {
            return Err(PeError::InvalidDosHeader);
        }

        Ok(DosHeader {
            e_magic,
            e_cblp: self.reader.read_u16::<LittleEndian>()?,
            e_cp: self.reader.read_u16::<LittleEndian>()?,
            e_crlc: self.reader.read_u16::<LittleEndian>()?,
            e_cparhdr: self.reader.read_u16::<LittleEndian>()?,
            e_minalloc: self.reader.read_u16::<LittleEndian>()?,
            e_maxalloc: self.reader.read_u16::<LittleEndian>()?,
            e_ss: self.reader.read_u16::<LittleEndian>()?,
            e_sp: self.reader.read_u16::<LittleEndian>()?,
            e_csum: self.reader.read_u16::<LittleEndian>()?,
            e_ip: self.reader.read_u16::<LittleEndian>()?,
            e_cs: self.reader.read_u16::<LittleEndian>()?,
            e_lfarlc: self.reader.read_u16::<LittleEndian>()?,
            e_ovno: self.reader.read_u16::<LittleEndian>()?,
            e_res: {
                let mut res = [0u16; 4];
                for r in &mut res {
                    *r = self.reader.read_u16::<LittleEndian>()?;
                }
                res
            },
            e_oemid: self.reader.read_u16::<LittleEndian>()?,
            e_oeminfo: self.reader.read_u16::<LittleEndian>()?,
            e_res2: {
                let mut res = [0u16; 10];
                for r in &mut res {
                    *r = self.reader.read_u16::<LittleEndian>()?;
                }
                res
            },
            e_lfanew: self.reader.read_i32::<LittleEndian>()?,
        })
    }

    /// Parse COFF header
    fn parse_coff_header(&mut self) -> Result<CoffHeader, PeError> {
        Ok(CoffHeader {
            machine: self.reader.read_u16::<LittleEndian>()?,
            number_of_sections: self.reader.read_u16::<LittleEndian>()?,
            time_date_stamp: self.reader.read_u32::<LittleEndian>()?,
            pointer_to_symbol_table: self.reader.read_u32::<LittleEndian>()?,
            number_of_symbols: self.reader.read_u32::<LittleEndian>()?,
            size_of_optional_header: self.reader.read_u16::<LittleEndian>()?,
            characteristics: self.reader.read_u16::<LittleEndian>()?,
        })
    }

    /// Parse optional header and data directories
    fn parse_optional_header(&mut self) -> Result<(OptionalHeader, Vec<DataDirectory>), PeError> {
        let magic = self.reader.read_u16::<LittleEndian>()?;
        let is_pe32_plus = match magic {
            PE32_MAGIC => false,
            PE32PLUS_MAGIC => true,
            _ => return Err(PeError::UnsupportedFormat(format!("Unknown magic: 0x{:x}", magic))),
        };

        let major_linker_version = self.reader.read_u8()?;
        let minor_linker_version = self.reader.read_u8()?;
        let size_of_code = self.reader.read_u32::<LittleEndian>()?;
        let size_of_initialized_data = self.reader.read_u32::<LittleEndian>()?;
        let size_of_uninitialized_data = self.reader.read_u32::<LittleEndian>()?;
        let address_of_entry_point = self.reader.read_u32::<LittleEndian>()?;
        let base_of_code = self.reader.read_u32::<LittleEndian>()?;

        let (base_of_data, image_base) = if is_pe32_plus {
            (None, self.reader.read_u64::<LittleEndian>()?)
        } else {
            (
                Some(self.reader.read_u32::<LittleEndian>()?),
                self.reader.read_u32::<LittleEndian>()? as u64,
            )
        };

        let section_alignment = self.reader.read_u32::<LittleEndian>()?;
        let file_alignment = self.reader.read_u32::<LittleEndian>()?;
        let major_operating_system_version = self.reader.read_u16::<LittleEndian>()?;
        let minor_operating_system_version = self.reader.read_u16::<LittleEndian>()?;
        let major_image_version = self.reader.read_u16::<LittleEndian>()?;
        let minor_image_version = self.reader.read_u16::<LittleEndian>()?;
        let major_subsystem_version = self.reader.read_u16::<LittleEndian>()?;
        let minor_subsystem_version = self.reader.read_u16::<LittleEndian>()?;
        let win32_version_value = self.reader.read_u32::<LittleEndian>()?;
        let size_of_image = self.reader.read_u32::<LittleEndian>()?;
        let size_of_headers = self.reader.read_u32::<LittleEndian>()?;
        let checksum = self.reader.read_u32::<LittleEndian>()?;
        let subsystem = self.reader.read_u16::<LittleEndian>()?;
        let dll_characteristics = self.reader.read_u16::<LittleEndian>()?;

        let (size_of_stack_reserve, size_of_stack_commit, size_of_heap_reserve, size_of_heap_commit) =
            if is_pe32_plus {
                (
                    self.reader.read_u64::<LittleEndian>()?,
                    self.reader.read_u64::<LittleEndian>()?,
                    self.reader.read_u64::<LittleEndian>()?,
                    self.reader.read_u64::<LittleEndian>()?,
                )
            } else {
                (
                    self.reader.read_u32::<LittleEndian>()? as u64,
                    self.reader.read_u32::<LittleEndian>()? as u64,
                    self.reader.read_u32::<LittleEndian>()? as u64,
                    self.reader.read_u32::<LittleEndian>()? as u64,
                )
            };

        let loader_flags = self.reader.read_u32::<LittleEndian>()?;
        let number_of_rva_and_sizes = self.reader.read_u32::<LittleEndian>()?;

        // Parse data directories
        let mut data_directories = Vec::new();
        for _ in 0..number_of_rva_and_sizes {
            data_directories.push(DataDirectory {
                virtual_address: self.reader.read_u32::<LittleEndian>()?,
                size: self.reader.read_u32::<LittleEndian>()?,
            });
        }

        Ok((
            OptionalHeader {
                magic,
                major_linker_version,
                minor_linker_version,
                size_of_code,
                size_of_initialized_data,
                size_of_uninitialized_data,
                address_of_entry_point,
                base_of_code,
                base_of_data,
                image_base,
                section_alignment,
                file_alignment,
                major_operating_system_version,
                minor_operating_system_version,
                major_image_version,
                minor_image_version,
                major_subsystem_version,
                minor_subsystem_version,
                win32_version_value,
                size_of_image,
                size_of_headers,
                checksum,
                subsystem,
                dll_characteristics,
                size_of_stack_reserve,
                size_of_stack_commit,
                size_of_heap_reserve,
                size_of_heap_commit,
                loader_flags,
                number_of_rva_and_sizes,
                is_pe32_plus,
            },
            data_directories,
        ))
    }

    /// Parse section headers
    fn parse_sections(&mut self, count: usize) -> Result<Vec<SectionHeader>, PeError> {
        let mut sections = Vec::with_capacity(count);

        for i in 0..count {
            let mut name_bytes = [0u8; 8];
            self.reader.read_exact(&mut name_bytes)?;
            let name = String::from_utf8_lossy(&name_bytes)
                .trim_end_matches('\0')
                .to_string();

            sections.push(SectionHeader {
                name,
                virtual_size: self.reader.read_u32::<LittleEndian>()?,
                virtual_address: self.reader.read_u32::<LittleEndian>()?,
                size_of_raw_data: self.reader.read_u32::<LittleEndian>()?,
                pointer_to_raw_data: self.reader.read_u32::<LittleEndian>()?,
                pointer_to_relocations: self.reader.read_u32::<LittleEndian>()?,
                pointer_to_linenumbers: self.reader.read_u32::<LittleEndian>()?,
                number_of_relocations: self.reader.read_u16::<LittleEndian>()?,
                number_of_linenumbers: self.reader.read_u16::<LittleEndian>()?,
                characteristics: self.reader.read_u32::<LittleEndian>()?,
            });
        }

        Ok(sections)
    }

    /// Convert RVA to file offset
    fn rva_to_offset(&self, rva: u32, sections: &[SectionHeader]) -> Option<u64> {
        for section in sections {
            if rva >= section.virtual_address
                && rva < section.virtual_address + section.virtual_size
            {
                let offset = rva - section.virtual_address + section.pointer_to_raw_data;
                return Some(offset as u64);
            }
        }
        None
    }

    /// Read null-terminated string at offset
    fn read_string_at(&mut self, offset: u64) -> Result<String, PeError> {
        self.reader.seek(SeekFrom::Start(offset))?;
        let mut bytes = Vec::new();
        loop {
            let byte = self.reader.read_u8()?;
            if byte == 0 {
                break;
            }
            bytes.push(byte);
            if bytes.len() > 256 {
                break; // Prevent runaway
            }
        }
        Ok(String::from_utf8_lossy(&bytes).to_string())
    }

    /// Parse import directory
    fn parse_imports(
        &mut self,
        import_dir: &DataDirectory,
        sections: &[SectionHeader],
        is_pe32_plus: bool,
    ) -> Result<Vec<ImportDescriptor>, PeError> {
        if import_dir.virtual_address == 0 || import_dir.size == 0 {
            return Ok(Vec::new());
        }

        let offset = match self.rva_to_offset(import_dir.virtual_address, sections) {
            Some(o) => o,
            None => return Ok(Vec::new()),
        };

        self.reader.seek(SeekFrom::Start(offset))?;

        let mut imports = Vec::new();

        loop {
            // Read import descriptor (20 bytes)
            let original_first_thunk = self.reader.read_u32::<LittleEndian>()?;
            let _time_date_stamp = self.reader.read_u32::<LittleEndian>()?;
            let _forwarder_chain = self.reader.read_u32::<LittleEndian>()?;
            let name_rva = self.reader.read_u32::<LittleEndian>()?;
            let first_thunk = self.reader.read_u32::<LittleEndian>()?;

            // End of import descriptors
            if original_first_thunk == 0 && name_rva == 0 && first_thunk == 0 {
                break;
            }

            // Get DLL name
            let dll_name = if let Some(name_offset) = self.rva_to_offset(name_rva, sections) {
                self.read_string_at(name_offset)?
            } else {
                continue;
            };

            // Parse imported functions
            let thunk_rva = if original_first_thunk != 0 {
                original_first_thunk
            } else {
                first_thunk
            };

            let functions = self.parse_import_thunks(thunk_rva, sections, is_pe32_plus)?;

            imports.push(ImportDescriptor {
                name: dll_name,
                functions,
            });

            // Save position for next descriptor
            let next_pos = offset + (imports.len() as u64 * 20);
            self.reader.seek(SeekFrom::Start(next_pos))?;
        }

        Ok(imports)
    }

    /// Parse import thunks (function entries)
    fn parse_import_thunks(
        &mut self,
        thunk_rva: u32,
        sections: &[SectionHeader],
        is_pe32_plus: bool,
    ) -> Result<Vec<ImportedFunction>, PeError> {
        let offset = match self.rva_to_offset(thunk_rva, sections) {
            Some(o) => o,
            None => return Ok(Vec::new()),
        };

        self.reader.seek(SeekFrom::Start(offset))?;

        let mut functions = Vec::new();
        let ordinal_flag: u64 = if is_pe32_plus { 0x8000000000000000 } else { 0x80000000 };

        loop {
            let thunk = if is_pe32_plus {
                self.reader.read_u64::<LittleEndian>()?
            } else {
                self.reader.read_u32::<LittleEndian>()? as u64
            };

            if thunk == 0 {
                break;
            }

            if thunk & ordinal_flag != 0 {
                // Import by ordinal
                let ordinal = (thunk & 0xFFFF) as u16;
                functions.push(ImportedFunction {
                    name: format!("Ordinal#{}", ordinal),
                    hint: 0,
                    by_ordinal: true,
                    ordinal: Some(ordinal),
                });
            } else {
                // Import by name
                let hint_name_rva = (thunk & 0x7FFFFFFF) as u32;
                if let Some(hn_offset) = self.rva_to_offset(hint_name_rva, sections) {
                    let current_pos = self.reader.stream_position()?;
                    self.reader.seek(SeekFrom::Start(hn_offset))?;
                    let hint = self.reader.read_u16::<LittleEndian>()?;
                    let name = self.read_string_at(hn_offset + 2)?;
                    self.reader.seek(SeekFrom::Start(current_pos))?;

                    functions.push(ImportedFunction {
                        name,
                        hint,
                        by_ordinal: false,
                        ordinal: None,
                    });
                }
            }
        }

        Ok(functions)
    }

    /// Parse export directory
    fn parse_exports(
        &mut self,
        export_dir: &DataDirectory,
        sections: &[SectionHeader],
    ) -> Result<Option<ExportDirectory>, PeError> {
        if export_dir.virtual_address == 0 || export_dir.size == 0 {
            return Ok(None);
        }

        let offset = match self.rva_to_offset(export_dir.virtual_address, sections) {
            Some(o) => o,
            None => return Ok(None),
        };

        self.reader.seek(SeekFrom::Start(offset))?;

        // Read export directory table
        let _characteristics = self.reader.read_u32::<LittleEndian>()?;
        let _time_date_stamp = self.reader.read_u32::<LittleEndian>()?;
        let _major_version = self.reader.read_u16::<LittleEndian>()?;
        let _minor_version = self.reader.read_u16::<LittleEndian>()?;
        let name_rva = self.reader.read_u32::<LittleEndian>()?;
        let ordinal_base = self.reader.read_u32::<LittleEndian>()?;
        let number_of_functions = self.reader.read_u32::<LittleEndian>()?;
        let number_of_names = self.reader.read_u32::<LittleEndian>()?;
        let address_of_functions = self.reader.read_u32::<LittleEndian>()?;
        let address_of_names = self.reader.read_u32::<LittleEndian>()?;
        let address_of_name_ordinals = self.reader.read_u32::<LittleEndian>()?;

        // Get DLL name
        let dll_name = if let Some(name_offset) = self.rva_to_offset(name_rva, sections) {
            self.read_string_at(name_offset)?
        } else {
            String::from("Unknown")
        };

        let mut functions = Vec::new();

        // Read function addresses
        if let Some(func_offset) = self.rva_to_offset(address_of_functions, sections) {
            self.reader.seek(SeekFrom::Start(func_offset))?;
            let mut func_rvas = Vec::new();
            for _ in 0..number_of_functions {
                func_rvas.push(self.reader.read_u32::<LittleEndian>()?);
            }

            // Read names
            let mut names: Vec<(u32, String)> = Vec::new();
            if let Some(names_offset) = self.rva_to_offset(address_of_names, sections) {
                self.reader.seek(SeekFrom::Start(names_offset))?;
                let mut name_rvas = Vec::new();
                for _ in 0..number_of_names {
                    name_rvas.push(self.reader.read_u32::<LittleEndian>()?);
                }

                // Read ordinals
                let mut ordinals = Vec::new();
                if let Some(ord_offset) = self.rva_to_offset(address_of_name_ordinals, sections) {
                    self.reader.seek(SeekFrom::Start(ord_offset))?;
                    for _ in 0..number_of_names {
                        ordinals.push(self.reader.read_u16::<LittleEndian>()?);
                    }
                }

                // Match names to ordinals
                for (i, name_rva) in name_rvas.iter().enumerate() {
                    if let Some(name_offset) = self.rva_to_offset(*name_rva, sections) {
                        let name = self.read_string_at(name_offset)?;
                        let ordinal = if i < ordinals.len() { ordinals[i] as u32 } else { i as u32 };
                        names.push((ordinal, name));
                    }
                }
            }

            // Build function list
            for (i, &rva) in func_rvas.iter().enumerate() {
                let ordinal = (ordinal_base + i as u32) as u16;
                let name = names.iter()
                    .find(|(ord, _)| *ord == i as u32)
                    .map(|(_, name)| name.clone())
                    .unwrap_or_else(|| format!("Ordinal#{}", ordinal));

                // Check if forwarder
                let is_forwarder = rva >= export_dir.virtual_address
                    && rva < export_dir.virtual_address + export_dir.size;

                let forwarder = if is_forwarder {
                    if let Some(fwd_offset) = self.rva_to_offset(rva, sections) {
                        Some(self.read_string_at(fwd_offset)?)
                    } else {
                        None
                    }
                } else {
                    None
                };

                functions.push(ExportedFunction {
                    name,
                    ordinal,
                    rva,
                    is_forwarder,
                    forwarder,
                });
            }
        }

        Ok(Some(ExportDirectory {
            name: dll_name,
            ordinal_base,
            number_of_functions,
            number_of_names,
            functions,
        }))
    }

    /// Analyze security properties
    fn analyze_security(
        &mut self,
        optional_header: &OptionalHeader,
        data_directories: &[DataDirectory],
        sections: &[SectionHeader],
        imports: &[ImportDescriptor],
    ) -> Result<SecurityInfo, PeError> {
        let mut info = SecurityInfo::default();

        // Check DLL characteristics for security features
        let dll_chars = optional_header.dll_characteristics;
        info.has_aslr = dll_chars & 0x0040 != 0; // DYNAMIC_BASE
        info.has_dep = dll_chars & 0x0100 != 0;  // NX_COMPAT
        info.has_seh = dll_chars & 0x0400 == 0;  // NO_SEH means no SEH
        info.has_cfg = dll_chars & 0x4000 != 0;  // GUARD_CF

        // Check for digital signature
        if data_directories.len() > data_directory_index::SECURITY {
            let sec_dir = &data_directories[data_directory_index::SECURITY];
            info.has_signature = sec_dir.virtual_address != 0 && sec_dir.size != 0;
        }

        // Check for suspicious imports
        for import in imports {
            for func in &import.functions {
                for &suspicious in SUSPICIOUS_APIS {
                    if func.name.contains(suspicious) {
                        info.suspicious_imports.push(format!("{}!{}", import.name, func.name));
                    }
                }
            }
        }

        // Check if entry point is in unusual section
        let entry_point = optional_header.address_of_entry_point;
        for section in sections {
            if entry_point >= section.virtual_address
                && entry_point < section.virtual_address + section.virtual_size
            {
                if !section.name.starts_with(".text") && !section.name.starts_with("CODE") {
                    info.unusual_entry_point = true;
                    info.anomalies.push(format!(
                        "Entry point in unusual section: {} at RVA 0x{:x}",
                        section.name, entry_point
                    ));
                }
                break;
            }
        }

        // Check section characteristics for anomalies
        for section in sections {
            let chars = section.characteristics;
            // Writable + Executable is suspicious
            if chars & 0x80000000 != 0 && chars & 0x20000000 != 0 {
                info.anomalies.push(format!(
                    "Section {} is both writable and executable",
                    section.name
                ));
            }
        }

        // Detect common packers by section names
        for section in sections {
            match section.name.as_str() {
                "UPX0" | "UPX1" | "UPX2" => {
                    info.is_packed = true;
                    info.packer_name = Some("UPX".to_string());
                }
                ".aspack" | ".adata" => {
                    info.is_packed = true;
                    info.packer_name = Some("ASPack".to_string());
                }
                ".nsp0" | ".nsp1" | ".nsp2" => {
                    info.is_packed = true;
                    info.packer_name = Some("NsPack".to_string());
                }
                "PEtite" | ".petite" => {
                    info.is_packed = true;
                    info.packer_name = Some("PEtite".to_string());
                }
                _ => {}
            }
        }

        Ok(info)
    }
}

// ============================================================================
// OUTPUT FORMATTING
// ============================================================================

fn print_text_output(pe: &PeFile, args: &Args) {
    println!("\n{}", "=".repeat(70).blue());
    println!("{}", "           PE FILE ANALYSIS REPORT".blue().bold());
    println!("{}", "=".repeat(70).blue());

    // DOS Header summary
    println!("\n{}", "[ DOS HEADER ]".cyan().bold());
    println!("  Magic:           0x{:04X} ({})",
             pe.dos_header.e_magic,
             if pe.dos_header.e_magic == 0x5A4D { "MZ" } else { "Invalid" });
    println!("  PE Header at:    0x{:08X}", pe.dos_header.e_lfanew);

    // COFF Header
    println!("\n{}", "[ COFF FILE HEADER ]".cyan().bold());
    println!("  Machine:         0x{:04X} ({})",
             pe.coff_header.machine,
             machine_type_name(pe.coff_header.machine));
    println!("  Sections:        {}", pe.coff_header.number_of_sections);
    let timestamp = Utc.timestamp_opt(pe.coff_header.time_date_stamp as i64, 0);
    if let chrono::LocalResult::Single(dt) = timestamp {
        println!("  Timestamp:       {} (0x{:08X})",
                 dt.format("%Y-%m-%d %H:%M:%S UTC"),
                 pe.coff_header.time_date_stamp);
    }
    println!("  Optional Hdr:    {} bytes", pe.coff_header.size_of_optional_header);

    // Optional Header
    println!("\n{}", "[ OPTIONAL HEADER ]".cyan().bold());
    println!("  Magic:           0x{:04X} ({})",
             pe.optional_header.magic,
             if pe.optional_header.is_pe32_plus { "PE32+ (64-bit)" } else { "PE32 (32-bit)" });
    println!("  Linker:          {}.{}",
             pe.optional_header.major_linker_version,
             pe.optional_header.minor_linker_version);
    println!("  Entry Point:     0x{:08X}", pe.optional_header.address_of_entry_point);
    println!("  Image Base:      0x{:016X}", pe.optional_header.image_base);
    println!("  Image Size:      0x{:08X} ({} bytes)",
             pe.optional_header.size_of_image,
             pe.optional_header.size_of_image);
    println!("  Section Align:   0x{:08X}", pe.optional_header.section_alignment);
    println!("  File Align:      0x{:08X}", pe.optional_header.file_alignment);
    println!("  Subsystem:       {} ({})",
             pe.optional_header.subsystem,
             subsystem_name(pe.optional_header.subsystem));
    println!("  Checksum:        0x{:08X}", pe.optional_header.checksum);

    // DLL Characteristics
    println!("\n  {}", "DLL Characteristics:".yellow());
    for flag in dll_characteristics_str(pe.optional_header.dll_characteristics) {
        println!("    - {}", flag);
    }

    // Sections
    println!("\n{}", "[ SECTIONS ]".cyan().bold());
    println!("  {:<10} {:>10} {:>10} {:>10} {:>10}  {}",
             "Name", "VirtAddr", "VirtSize", "RawAddr", "RawSize", "Characteristics");
    println!("  {}", "-".repeat(65));
    for section in &pe.sections {
        let chars_str = section_characteristics_str(section.characteristics).join(" | ");
        println!("  {:<10} 0x{:08X} 0x{:08X} 0x{:08X} 0x{:08X}",
                 section.name,
                 section.virtual_address,
                 section.virtual_size,
                 section.pointer_to_raw_data,
                 section.size_of_raw_data);
        if args.verbose {
            println!("              {}", chars_str.dimmed());
        }
    }

    // Imports
    if args.imports || args.verbose {
        println!("\n{}", "[ IMPORTS ]".cyan().bold());
        for import in &pe.imports {
            println!("\n  {} ({} functions)", import.name.yellow(), import.functions.len());
            if args.imports {
                for func in &import.functions {
                    if func.by_ordinal {
                        println!("    - {} (ordinal)", func.name);
                    } else {
                        println!("    - {} (hint: {})", func.name, func.hint);
                    }
                }
            }
        }
    } else {
        println!("\n{}", "[ IMPORTS SUMMARY ]".cyan().bold());
        println!("  {} DLLs imported", pe.imports.len());
        let total_funcs: usize = pe.imports.iter().map(|i| i.functions.len()).sum();
        println!("  {} functions imported", total_funcs);
        println!("  (use --imports for full list)");
    }

    // Exports
    if let Some(ref exports) = pe.exports {
        if args.exports || args.verbose {
            println!("\n{}", "[ EXPORTS ]".cyan().bold());
            println!("  DLL Name:      {}", exports.name);
            println!("  Ordinal Base:  {}", exports.ordinal_base);
            println!("  Functions:     {}", exports.number_of_functions);
            println!("  Names:         {}", exports.number_of_names);
            if args.exports {
                for func in &exports.functions {
                    if func.is_forwarder {
                        println!("    - {} (ordinal {}) -> {}",
                                 func.name, func.ordinal,
                                 func.forwarder.as_deref().unwrap_or("?"));
                    } else {
                        println!("    - {} (ordinal {}) @ 0x{:08X}",
                                 func.name, func.ordinal, func.rva);
                    }
                }
            }
        }
    }

    // Security Analysis
    println!("\n{}", "[ SECURITY ANALYSIS ]".cyan().bold());

    let print_status = |name: &str, enabled: bool| {
        if enabled {
            println!("  {} {}", name.green(), "[ENABLED]".green());
        } else {
            println!("  {} {}", name.red(), "[DISABLED]".red());
        }
    };

    print_status("ASLR (Address Space Layout Randomization):", pe.security_info.has_aslr);
    print_status("DEP/NX (Data Execution Prevention):       ", pe.security_info.has_dep);
    print_status("SEH (Structured Exception Handling):      ", pe.security_info.has_seh);
    print_status("CFG (Control Flow Guard):                 ", pe.security_info.has_cfg);
    print_status("Digital Signature:                        ", pe.security_info.has_signature);

    // Packer detection
    if pe.security_info.is_packed {
        println!("\n  {}", "PACKER DETECTED:".red().bold());
        if let Some(ref packer) = pe.security_info.packer_name {
            println!("    {}", packer.red());
        }
    }

    // Suspicious imports
    if !pe.security_info.suspicious_imports.is_empty() {
        println!("\n  {}", "SUSPICIOUS IMPORTS:".red().bold());
        for import in &pe.security_info.suspicious_imports {
            println!("    - {}", import.red());
        }
    }

    // Anomalies
    if !pe.security_info.anomalies.is_empty() {
        println!("\n  {}", "ANOMALIES DETECTED:".yellow().bold());
        for anomaly in &pe.security_info.anomalies {
            println!("    - {}", anomaly.yellow());
        }
    }

    println!("\n{}", "=".repeat(70).blue());
}

fn print_json_output(pe: &PeFile) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(pe)?);
    Ok(())
}

// ============================================================================
// MAIN
// ============================================================================

fn main() -> Result<()> {
    let args = Args::parse();

    // Open and parse PE file
    let file = File::open(&args.file)
        .context(format!("Failed to open file: {:?}", args.file))?;

    let mut parser = PeParser::new(file)?;
    let pe = parser.parse()
        .context("Failed to parse PE file")?;

    // Output results
    match args.output {
        OutputFormat::Text => print_text_output(&pe, &args),
        OutputFormat::Json => print_json_output(&pe)?,
    }

    Ok(())
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// Create a minimal valid PE file for testing
    fn create_minimal_pe() -> Vec<u8> {
        let mut pe = vec![0u8; 512];

        // DOS Header
        pe[0] = 0x4D; // 'M'
        pe[1] = 0x5A; // 'Z'
        pe[0x3C] = 0x80; // e_lfanew pointing to offset 0x80

        // PE Signature at 0x80
        pe[0x80] = 0x50; // 'P'
        pe[0x81] = 0x45; // 'E'
        pe[0x82] = 0x00;
        pe[0x83] = 0x00;

        // COFF Header (at 0x84)
        pe[0x84] = 0x4C; // Machine: i386 (0x014C)
        pe[0x85] = 0x01;
        pe[0x86] = 0x01; // NumberOfSections: 1
        pe[0x87] = 0x00;
        // TimeDateStamp (4 bytes)
        pe[0x88] = 0x00;
        pe[0x89] = 0x00;
        pe[0x8A] = 0x00;
        pe[0x8B] = 0x00;
        // PointerToSymbolTable (4 bytes)
        pe[0x8C] = 0x00;
        pe[0x8D] = 0x00;
        pe[0x8E] = 0x00;
        pe[0x8F] = 0x00;
        // NumberOfSymbols (4 bytes)
        pe[0x90] = 0x00;
        pe[0x91] = 0x00;
        pe[0x92] = 0x00;
        pe[0x93] = 0x00;
        // SizeOfOptionalHeader (2 bytes)
        pe[0x94] = 0x70; // 112 bytes for PE32
        pe[0x95] = 0x00;
        // Characteristics (2 bytes)
        pe[0x96] = 0x02; // EXECUTABLE_IMAGE
        pe[0x97] = 0x01;

        // Optional Header (at 0x98)
        pe[0x98] = 0x0B; // Magic: PE32 (0x010B)
        pe[0x99] = 0x01;
        // ... (rest can be zeros for minimal parsing)

        pe
    }

    #[test]
    fn test_dos_header_parsing() {
        let pe_data = create_minimal_pe();
        let cursor = Cursor::new(pe_data);
        let mut parser = PeParser::new(cursor).unwrap();
        let dos_header = parser.parse_dos_header().unwrap();

        assert_eq!(dos_header.e_magic, 0x5A4D);
        assert_eq!(dos_header.e_lfanew, 0x80);
    }

    #[test]
    fn test_invalid_dos_header() {
        let bad_data = vec![0x00u8; 64]; // No MZ signature
        let cursor = Cursor::new(bad_data);
        let mut parser = PeParser::new(cursor).unwrap();
        let result = parser.parse_dos_header();

        assert!(result.is_err());
    }

    #[test]
    fn test_machine_type_names() {
        assert_eq!(machine_type_name(0x14c), "i386 (x86)");
        assert_eq!(machine_type_name(0x8664), "AMD64 (x64)");
        assert_eq!(machine_type_name(0xaa64), "ARM64");
        assert_eq!(machine_type_name(0xFFFF), "Unknown");
    }

    #[test]
    fn test_subsystem_names() {
        assert_eq!(subsystem_name(2), "Windows GUI");
        assert_eq!(subsystem_name(3), "Windows Console");
        assert_eq!(subsystem_name(1), "Native");
    }

    #[test]
    fn test_section_characteristics() {
        let chars = 0x60000020; // CODE | EXECUTE | READ
        let flags = section_characteristics_str(chars);
        assert!(flags.contains(&"CODE"));
        assert!(flags.contains(&"EXECUTE"));
        assert!(flags.contains(&"READ"));
    }

    #[test]
    fn test_dll_characteristics() {
        let chars = 0x0140; // DYNAMIC_BASE | NX_COMPAT
        let flags = dll_characteristics_str(chars);
        assert!(flags.iter().any(|f| f.contains("ASLR")));
        assert!(flags.iter().any(|f| f.contains("DEP")));
    }
}
