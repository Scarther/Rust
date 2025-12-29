//! # ELF Parser - Linux Executable and Linkable Format Analyzer
//!
//! This tool parses and analyzes Linux ELF (Executable and Linkable Format) files in detail.
//! ELF is the standard binary format for Unix/Linux systems, used for:
//! - Executable files
//! - Shared libraries (.so)
//! - Object files (.o)
//! - Core dumps
//!
//! ## ELF File Format Overview
//!
//! The ELF format consists of:
//!
//! ```text
//! +---------------------------+
//! |       ELF Header          |  <- Identifies file, architecture, entry point
//! +---------------------------+
//! |    Program Headers        |  <- Describe segments for loading (runtime view)
//! |    (optional for .o)      |
//! +---------------------------+
//! |       Sections            |  <- Code, data, symbols, strings, etc.
//! +---------------------------+
//! |    Section Headers        |  <- Describe sections (linker view)
//! |    (optional for exec)    |
//! +---------------------------+
//! ```
//!
//! ## Key Concepts
//!
//! ### Segments vs Sections
//! - **Segments**: Runtime view - how to load the program into memory
//! - **Sections**: Linking view - logical divisions of code/data
//!
//! ### Security Relevance
//! - Detecting stripped binaries (harder to reverse engineer)
//! - Identifying RELRO, Stack Canary, NX, PIE protections
//! - Finding suspicious sections or symbols
//! - Analyzing dynamic linking for potential hijacking

use anyhow::{Context, Result};
use byteorder::{BigEndian, LittleEndian, ReadBytesExt};
use clap::{Parser, ValueEnum};
use colored::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;
use thiserror::Error;

// ============================================================================
// ERROR HANDLING
// ============================================================================

/// ELF parsing errors
#[derive(Error, Debug)]
pub enum ElfError {
    #[error("Invalid ELF magic - not a valid ELF file")]
    InvalidMagic,

    #[error("Unsupported ELF class: {0}")]
    UnsupportedClass(u8),

    #[error("Unsupported data encoding: {0}")]
    UnsupportedEncoding(u8),

    #[error("Invalid section at index {0}")]
    InvalidSection(usize),

    #[error("Invalid program header at index {0}")]
    InvalidProgramHeader(usize),

    #[error("File read error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("String table error: {0}")]
    StringTableError(String),
}

// ============================================================================
// CLI INTERFACE
// ============================================================================

/// ELF Parser - Analyze Linux ELF executable files
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to ELF file to analyze
    #[arg(short, long)]
    file: PathBuf,

    /// Output format
    #[arg(short, long, value_enum, default_value = "text")]
    output: OutputFormat,

    /// Show all symbols
    #[arg(long)]
    symbols: bool,

    /// Show dynamic section
    #[arg(long)]
    dynamic: bool,

    /// Show relocations
    #[arg(long)]
    relocs: bool,

    /// Show section hex dump
    #[arg(long)]
    hexdump: Option<String>,

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
// ELF STRUCTURES
// ============================================================================

/// ELF identification bytes (first 16 bytes of file)
///
/// The e_ident array contains magic bytes and file metadata:
/// - Bytes 0-3: Magic number (0x7F 'E' 'L' 'F')
/// - Byte 4: Class (32-bit or 64-bit)
/// - Byte 5: Data encoding (little or big endian)
/// - Byte 6: ELF version (always 1)
/// - Byte 7: OS/ABI identification
/// - Byte 8: ABI version
/// - Bytes 9-15: Padding (reserved)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElfIdent {
    /// Magic bytes (should be [0x7F, 'E', 'L', 'F'])
    pub magic: [u8; 4],
    /// Class: 1 = 32-bit, 2 = 64-bit
    pub class: u8,
    /// Data encoding: 1 = little endian, 2 = big endian
    pub data: u8,
    /// ELF version (should be 1)
    pub version: u8,
    /// OS/ABI identification
    pub osabi: u8,
    /// ABI version
    pub abiversion: u8,
}

/// ELF Header - Contains file metadata
///
/// This header identifies the file and provides offsets to other structures.
/// The exact size varies between ELF32 (52 bytes) and ELF64 (64 bytes).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElfHeader {
    /// Identification bytes
    pub ident: ElfIdent,
    /// Object file type
    pub e_type: u16,
    /// Target architecture
    pub e_machine: u16,
    /// ELF version (should be 1)
    pub e_version: u32,
    /// Entry point virtual address
    pub e_entry: u64,
    /// Program header table file offset
    pub e_phoff: u64,
    /// Section header table file offset
    pub e_shoff: u64,
    /// Processor-specific flags
    pub e_flags: u32,
    /// ELF header size
    pub e_ehsize: u16,
    /// Program header entry size
    pub e_phentsize: u16,
    /// Program header count
    pub e_phnum: u16,
    /// Section header entry size
    pub e_shentsize: u16,
    /// Section header count
    pub e_shnum: u16,
    /// Section name string table index
    pub e_shstrndx: u16,
    /// Is this a 64-bit ELF
    pub is_64bit: bool,
    /// Is this little endian
    pub is_little_endian: bool,
}

/// Program Header - Describes a segment for loading
///
/// Program headers define memory segments and how to load them.
/// Key segment types:
/// - PT_LOAD: Loadable segment
/// - PT_DYNAMIC: Dynamic linking info
/// - PT_INTERP: Path to interpreter (dynamic linker)
/// - PT_GNU_STACK: Stack permissions
/// - PT_GNU_RELRO: Read-only after relocation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramHeader {
    /// Segment type
    pub p_type: u32,
    /// Segment flags (PF_X, PF_W, PF_R)
    pub p_flags: u32,
    /// File offset
    pub p_offset: u64,
    /// Virtual address
    pub p_vaddr: u64,
    /// Physical address (usually same as vaddr)
    pub p_paddr: u64,
    /// Size in file
    pub p_filesz: u64,
    /// Size in memory
    pub p_memsz: u64,
    /// Alignment
    pub p_align: u64,
}

/// Section Header - Describes a section for linking
///
/// Sections contain code, data, symbols, and other information.
/// Key sections:
/// - .text: Executable code
/// - .data: Initialized data
/// - .rodata: Read-only data
/// - .bss: Uninitialized data
/// - .symtab: Symbol table
/// - .strtab: String table
/// - .dynsym: Dynamic symbols
/// - .dynstr: Dynamic strings
/// - .got: Global offset table
/// - .plt: Procedure linkage table
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionHeader {
    /// Section name (index into string table, resolved to string)
    pub name: String,
    /// Section name index (raw value)
    pub sh_name: u32,
    /// Section type
    pub sh_type: u32,
    /// Section flags
    pub sh_flags: u64,
    /// Virtual address
    pub sh_addr: u64,
    /// File offset
    pub sh_offset: u64,
    /// Size in bytes
    pub sh_size: u64,
    /// Link to another section
    pub sh_link: u32,
    /// Additional info
    pub sh_info: u32,
    /// Address alignment
    pub sh_addralign: u64,
    /// Entry size (for fixed-size entries)
    pub sh_entsize: u64,
}

/// Symbol table entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Symbol {
    /// Symbol name
    pub name: String,
    /// Symbol value (address or other)
    pub st_value: u64,
    /// Symbol size
    pub st_size: u64,
    /// Symbol type and binding
    pub st_info: u8,
    /// Symbol visibility
    pub st_other: u8,
    /// Section index
    pub st_shndx: u16,
    /// Parsed binding
    pub binding: String,
    /// Parsed type
    pub symbol_type: String,
}

/// Dynamic entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DynamicEntry {
    /// Tag type
    pub d_tag: i64,
    /// Tag name
    pub tag_name: String,
    /// Value/pointer
    pub d_val: u64,
}

/// Relocation entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Relocation {
    /// Offset to apply relocation
    pub r_offset: u64,
    /// Relocation type
    pub r_type: u32,
    /// Symbol index
    pub r_sym: u32,
    /// Addend (for RELA)
    pub r_addend: Option<i64>,
    /// Symbol name (if resolved)
    pub symbol_name: Option<String>,
}

/// Security analysis results
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SecurityInfo {
    /// Has RELRO (full or partial)
    pub relro: RelroType,
    /// Has stack canary
    pub has_canary: bool,
    /// Has NX (non-executable stack)
    pub has_nx: bool,
    /// Is Position Independent Executable
    pub is_pie: bool,
    /// Has FORTIFY_SOURCE
    pub has_fortify: bool,
    /// Has RUNPATH (can be hijacked)
    pub has_runpath: bool,
    /// Has RPATH (can be hijacked)
    pub has_rpath: bool,
    /// Is stripped (no symbols)
    pub is_stripped: bool,
    /// Path to interpreter
    pub interpreter: Option<String>,
    /// RUNPATH value
    pub runpath: Option<String>,
    /// RPATH value
    pub rpath: Option<String>,
    /// Detected anomalies
    pub anomalies: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub enum RelroType {
    #[default]
    None,
    Partial,
    Full,
}

/// Complete ELF file representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElfFile {
    /// ELF header
    pub header: ElfHeader,
    /// Program headers
    pub program_headers: Vec<ProgramHeader>,
    /// Section headers
    pub section_headers: Vec<SectionHeader>,
    /// Symbols
    pub symbols: Vec<Symbol>,
    /// Dynamic symbols
    pub dynamic_symbols: Vec<Symbol>,
    /// Dynamic entries
    pub dynamic_entries: Vec<DynamicEntry>,
    /// Relocations
    pub relocations: Vec<Relocation>,
    /// Security analysis
    pub security_info: SecurityInfo,
}

// ============================================================================
// CONSTANTS
// ============================================================================

/// ELF magic bytes
const ELF_MAGIC: [u8; 4] = [0x7F, b'E', b'L', b'F'];

/// ELF class values
mod elf_class {
    pub const ELFCLASS32: u8 = 1;
    pub const ELFCLASS64: u8 = 2;
}

/// ELF data encoding values
mod elf_data {
    pub const ELFDATA2LSB: u8 = 1; // Little endian
    pub const ELFDATA2MSB: u8 = 2; // Big endian
}

/// ELF file types
fn elf_type_name(e_type: u16) -> &'static str {
    match e_type {
        0 => "NONE (Unknown)",
        1 => "REL (Relocatable)",
        2 => "EXEC (Executable)",
        3 => "DYN (Shared Object)",
        4 => "CORE (Core Dump)",
        _ => "Unknown",
    }
}

/// Machine types
fn machine_name(machine: u16) -> &'static str {
    match machine {
        0 => "None",
        3 => "Intel 80386 (x86)",
        8 => "MIPS",
        20 => "PowerPC",
        21 => "PowerPC64",
        40 => "ARM",
        62 => "AMD x86-64",
        183 => "ARM64 (AArch64)",
        243 => "RISC-V",
        _ => "Unknown",
    }
}

/// OS/ABI names
fn osabi_name(osabi: u8) -> &'static str {
    match osabi {
        0 => "UNIX System V",
        1 => "HP-UX",
        2 => "NetBSD",
        3 => "Linux",
        6 => "Solaris",
        9 => "FreeBSD",
        12 => "OpenBSD",
        _ => "Unknown",
    }
}

/// Program header type names
fn phdr_type_name(p_type: u32) -> &'static str {
    match p_type {
        0 => "NULL",
        1 => "LOAD",
        2 => "DYNAMIC",
        3 => "INTERP",
        4 => "NOTE",
        5 => "SHLIB",
        6 => "PHDR",
        7 => "TLS",
        0x6474e550 => "GNU_EH_FRAME",
        0x6474e551 => "GNU_STACK",
        0x6474e552 => "GNU_RELRO",
        0x6474e553 => "GNU_PROPERTY",
        _ => "UNKNOWN",
    }
}

/// Section type names
fn shdr_type_name(sh_type: u32) -> &'static str {
    match sh_type {
        0 => "NULL",
        1 => "PROGBITS",
        2 => "SYMTAB",
        3 => "STRTAB",
        4 => "RELA",
        5 => "HASH",
        6 => "DYNAMIC",
        7 => "NOTE",
        8 => "NOBITS",
        9 => "REL",
        10 => "SHLIB",
        11 => "DYNSYM",
        14 => "INIT_ARRAY",
        15 => "FINI_ARRAY",
        16 => "PREINIT_ARRAY",
        17 => "GROUP",
        18 => "SYMTAB_SHNDX",
        0x6ffffff6 => "GNU_HASH",
        0x6ffffffe => "VERNEED",
        0x6fffffff => "VERSYM",
        _ => "UNKNOWN",
    }
}

/// Section flags to string
fn shdr_flags_str(flags: u64) -> String {
    let mut result = String::new();
    if flags & 0x1 != 0 { result.push('W'); } // WRITE
    if flags & 0x2 != 0 { result.push('A'); } // ALLOC
    if flags & 0x4 != 0 { result.push('X'); } // EXECINSTR
    if flags & 0x10 != 0 { result.push('M'); } // MERGE
    if flags & 0x20 != 0 { result.push('S'); } // STRINGS
    if flags & 0x40 != 0 { result.push('I'); } // INFO_LINK
    if flags & 0x80 != 0 { result.push('L'); } // LINK_ORDER
    if flags & 0x100 != 0 { result.push('O'); } // OS_NONCONFORMING
    if flags & 0x200 != 0 { result.push('G'); } // GROUP
    if flags & 0x400 != 0 { result.push('T'); } // TLS
    if result.is_empty() { result.push('-'); }
    result
}

/// Program header flags to string
fn phdr_flags_str(flags: u32) -> String {
    let mut result = String::new();
    if flags & 0x4 != 0 { result.push('R'); } // READ
    if flags & 0x2 != 0 { result.push('W'); } // WRITE
    if flags & 0x1 != 0 { result.push('X'); } // EXECUTE
    if result.is_empty() { result.push('-'); }
    result
}

/// Dynamic tag names
fn dynamic_tag_name(tag: i64) -> &'static str {
    match tag {
        0 => "NULL",
        1 => "NEEDED",
        2 => "PLTRELSZ",
        3 => "PLTGOT",
        4 => "HASH",
        5 => "STRTAB",
        6 => "SYMTAB",
        7 => "RELA",
        8 => "RELASZ",
        9 => "RELAENT",
        10 => "STRSZ",
        11 => "SYMENT",
        12 => "INIT",
        13 => "FINI",
        14 => "SONAME",
        15 => "RPATH",
        16 => "SYMBOLIC",
        17 => "REL",
        18 => "RELSZ",
        19 => "RELENT",
        20 => "PLTREL",
        21 => "DEBUG",
        22 => "TEXTREL",
        23 => "JMPREL",
        24 => "BIND_NOW",
        25 => "INIT_ARRAY",
        26 => "FINI_ARRAY",
        27 => "INIT_ARRAYSZ",
        28 => "FINI_ARRAYSZ",
        29 => "RUNPATH",
        30 => "FLAGS",
        32 => "PREINIT_ARRAY",
        33 => "PREINIT_ARRAYSZ",
        0x6ffffef5 => "GNU_HASH",
        0x6ffffffb => "FLAGS_1",
        0x6ffffffe => "VERNEED",
        0x6fffffff => "VERNEEDNUM",
        0x6ffffff0 => "VERSYM",
        0x6ffffff9 => "RELACOUNT",
        _ => "UNKNOWN",
    }
}

/// Symbol binding names
fn symbol_binding_name(info: u8) -> &'static str {
    match info >> 4 {
        0 => "LOCAL",
        1 => "GLOBAL",
        2 => "WEAK",
        10 => "LOOS",
        12 => "HIOS",
        13 => "LOPROC",
        15 => "HIPROC",
        _ => "UNKNOWN",
    }
}

/// Symbol type names
fn symbol_type_name(info: u8) -> &'static str {
    match info & 0xf {
        0 => "NOTYPE",
        1 => "OBJECT",
        2 => "FUNC",
        3 => "SECTION",
        4 => "FILE",
        5 => "COMMON",
        6 => "TLS",
        10 => "LOOS",
        12 => "HIOS",
        13 => "LOPROC",
        15 => "HIPROC",
        _ => "UNKNOWN",
    }
}

// ============================================================================
// ELF PARSER IMPLEMENTATION
// ============================================================================

/// ELF Parser struct
pub struct ElfParser<R: Read + Seek> {
    reader: R,
    is_64bit: bool,
    is_little_endian: bool,
}

impl<R: Read + Seek> ElfParser<R> {
    /// Create a new ELF parser
    pub fn new(reader: R) -> Self {
        Self {
            reader,
            is_64bit: true,
            is_little_endian: true,
        }
    }

    /// Read a u16 with correct endianness
    fn read_u16(&mut self) -> Result<u16, std::io::Error> {
        if self.is_little_endian {
            self.reader.read_u16::<LittleEndian>()
        } else {
            self.reader.read_u16::<BigEndian>()
        }
    }

    /// Read a u32 with correct endianness
    fn read_u32(&mut self) -> Result<u32, std::io::Error> {
        if self.is_little_endian {
            self.reader.read_u32::<LittleEndian>()
        } else {
            self.reader.read_u32::<BigEndian>()
        }
    }

    /// Read a u64 with correct endianness
    fn read_u64(&mut self) -> Result<u64, std::io::Error> {
        if self.is_little_endian {
            self.reader.read_u64::<LittleEndian>()
        } else {
            self.reader.read_u64::<BigEndian>()
        }
    }

    /// Read an address (32 or 64 bit based on class)
    fn read_addr(&mut self) -> Result<u64, std::io::Error> {
        if self.is_64bit {
            self.read_u64()
        } else {
            self.read_u32().map(|v| v as u64)
        }
    }

    /// Parse the ELF file
    pub fn parse(&mut self) -> Result<ElfFile, ElfError> {
        // Parse header first
        let header = self.parse_header()?;

        // Update parser state
        self.is_64bit = header.is_64bit;
        self.is_little_endian = header.is_little_endian;

        // Parse program headers
        let program_headers = self.parse_program_headers(&header)?;

        // Parse section headers
        let section_headers = self.parse_section_headers(&header)?;

        // Read string table for section names
        let strtab_data = if header.e_shstrndx < section_headers.len() as u16 {
            self.read_section_data(&section_headers[header.e_shstrndx as usize])?
        } else {
            Vec::new()
        };

        // Resolve section names
        let section_headers: Vec<SectionHeader> = section_headers.into_iter().map(|mut sh| {
            sh.name = self.read_string_from_data(&strtab_data, sh.sh_name as usize);
            sh
        }).collect();

        // Find and read symbol tables
        let (symbols, dynamic_symbols) = self.parse_symbols(&section_headers)?;

        // Parse dynamic section
        let dynamic_entries = self.parse_dynamic(&section_headers, &program_headers)?;

        // Parse relocations
        let relocations = self.parse_relocations(&section_headers, &symbols, &dynamic_symbols)?;

        // Security analysis
        let security_info = self.analyze_security(
            &header,
            &program_headers,
            &section_headers,
            &dynamic_entries,
            &symbols,
            &dynamic_symbols,
        )?;

        Ok(ElfFile {
            header,
            program_headers,
            section_headers,
            symbols,
            dynamic_symbols,
            dynamic_entries,
            relocations,
            security_info,
        })
    }

    /// Parse ELF header
    fn parse_header(&mut self) -> Result<ElfHeader, ElfError> {
        self.reader.seek(SeekFrom::Start(0))?;

        // Read identification bytes
        let mut magic = [0u8; 4];
        self.reader.read_exact(&mut magic)?;
        if magic != ELF_MAGIC {
            return Err(ElfError::InvalidMagic);
        }

        let class = self.reader.read_u8()?;
        let data = self.reader.read_u8()?;
        let version = self.reader.read_u8()?;
        let osabi = self.reader.read_u8()?;
        let abiversion = self.reader.read_u8()?;

        // Skip padding
        self.reader.seek(SeekFrom::Current(7))?;

        // Set endianness
        self.is_little_endian = match data {
            elf_data::ELFDATA2LSB => true,
            elf_data::ELFDATA2MSB => false,
            _ => return Err(ElfError::UnsupportedEncoding(data)),
        };

        // Set class
        self.is_64bit = match class {
            elf_class::ELFCLASS32 => false,
            elf_class::ELFCLASS64 => true,
            _ => return Err(ElfError::UnsupportedClass(class)),
        };

        let e_type = self.read_u16()?;
        let e_machine = self.read_u16()?;
        let e_version = self.read_u32()?;
        let e_entry = self.read_addr()?;
        let e_phoff = self.read_addr()?;
        let e_shoff = self.read_addr()?;
        let e_flags = self.read_u32()?;
        let e_ehsize = self.read_u16()?;
        let e_phentsize = self.read_u16()?;
        let e_phnum = self.read_u16()?;
        let e_shentsize = self.read_u16()?;
        let e_shnum = self.read_u16()?;
        let e_shstrndx = self.read_u16()?;

        Ok(ElfHeader {
            ident: ElfIdent {
                magic,
                class,
                data,
                version,
                osabi,
                abiversion,
            },
            e_type,
            e_machine,
            e_version,
            e_entry,
            e_phoff,
            e_shoff,
            e_flags,
            e_ehsize,
            e_phentsize,
            e_phnum,
            e_shentsize,
            e_shnum,
            e_shstrndx,
            is_64bit: self.is_64bit,
            is_little_endian: self.is_little_endian,
        })
    }

    /// Parse program headers
    fn parse_program_headers(&mut self, header: &ElfHeader) -> Result<Vec<ProgramHeader>, ElfError> {
        if header.e_phnum == 0 {
            return Ok(Vec::new());
        }

        self.reader.seek(SeekFrom::Start(header.e_phoff))?;

        let mut phdrs = Vec::with_capacity(header.e_phnum as usize);
        for _ in 0..header.e_phnum {
            let p_type = self.read_u32()?;

            let (p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align) = if self.is_64bit {
                let flags = self.read_u32()?;
                let offset = self.read_u64()?;
                let vaddr = self.read_u64()?;
                let paddr = self.read_u64()?;
                let filesz = self.read_u64()?;
                let memsz = self.read_u64()?;
                let align = self.read_u64()?;
                (flags, offset, vaddr, paddr, filesz, memsz, align)
            } else {
                let offset = self.read_u32()? as u64;
                let vaddr = self.read_u32()? as u64;
                let paddr = self.read_u32()? as u64;
                let filesz = self.read_u32()? as u64;
                let memsz = self.read_u32()? as u64;
                let flags = self.read_u32()?;
                let align = self.read_u32()? as u64;
                (flags, offset, vaddr, paddr, filesz, memsz, align)
            };

            phdrs.push(ProgramHeader {
                p_type,
                p_flags,
                p_offset,
                p_vaddr,
                p_paddr,
                p_filesz,
                p_memsz,
                p_align,
            });
        }

        Ok(phdrs)
    }

    /// Parse section headers
    fn parse_section_headers(&mut self, header: &ElfHeader) -> Result<Vec<SectionHeader>, ElfError> {
        if header.e_shnum == 0 {
            return Ok(Vec::new());
        }

        self.reader.seek(SeekFrom::Start(header.e_shoff))?;

        let mut shdrs = Vec::with_capacity(header.e_shnum as usize);
        for _ in 0..header.e_shnum {
            let sh_name = self.read_u32()?;
            let sh_type = self.read_u32()?;
            let sh_flags = self.read_addr()?;
            let sh_addr = self.read_addr()?;
            let sh_offset = self.read_addr()?;
            let sh_size = self.read_addr()?;
            let sh_link = self.read_u32()?;
            let sh_info = self.read_u32()?;
            let sh_addralign = self.read_addr()?;
            let sh_entsize = self.read_addr()?;

            shdrs.push(SectionHeader {
                name: String::new(), // Will be resolved later
                sh_name,
                sh_type,
                sh_flags,
                sh_addr,
                sh_offset,
                sh_size,
                sh_link,
                sh_info,
                sh_addralign,
                sh_entsize,
            });
        }

        Ok(shdrs)
    }

    /// Read section data
    fn read_section_data(&mut self, section: &SectionHeader) -> Result<Vec<u8>, ElfError> {
        if section.sh_type == 8 { // NOBITS
            return Ok(Vec::new());
        }

        let mut data = vec![0u8; section.sh_size as usize];
        self.reader.seek(SeekFrom::Start(section.sh_offset))?;
        self.reader.read_exact(&mut data)?;
        Ok(data)
    }

    /// Read null-terminated string from data at offset
    fn read_string_from_data(&self, data: &[u8], offset: usize) -> String {
        if offset >= data.len() {
            return String::new();
        }

        let end = data[offset..].iter()
            .position(|&b| b == 0)
            .map(|p| offset + p)
            .unwrap_or(data.len());

        String::from_utf8_lossy(&data[offset..end]).to_string()
    }

    /// Parse symbol tables
    fn parse_symbols(&mut self, sections: &[SectionHeader]) -> Result<(Vec<Symbol>, Vec<Symbol>), ElfError> {
        let mut symbols = Vec::new();
        let mut dynamic_symbols = Vec::new();

        for section in sections {
            if section.sh_type != 2 && section.sh_type != 11 {
                // Not SYMTAB or DYNSYM
                continue;
            }

            // Find the associated string table
            let strtab_idx = section.sh_link as usize;
            let strtab_data = if strtab_idx < sections.len() {
                self.read_section_data(&sections[strtab_idx])?
            } else {
                continue;
            };

            // Read symbol entries
            let sym_data = self.read_section_data(section)?;
            let entry_size = if self.is_64bit { 24 } else { 16 };
            let count = sym_data.len() / entry_size;

            for i in 0..count {
                let offset = i * entry_size;
                let sym = self.parse_symbol(&sym_data[offset..offset + entry_size], &strtab_data)?;

                if section.sh_type == 11 {
                    dynamic_symbols.push(sym);
                } else {
                    symbols.push(sym);
                }
            }
        }

        Ok((symbols, dynamic_symbols))
    }

    /// Parse a single symbol entry
    fn parse_symbol(&self, data: &[u8], strtab: &[u8]) -> Result<Symbol, ElfError> {
        use std::io::Cursor;
        let mut cursor = Cursor::new(data);

        let (st_name, st_value, st_size, st_info, st_other, st_shndx) = if self.is_64bit {
            let name = if self.is_little_endian {
                cursor.read_u32::<LittleEndian>()?
            } else {
                cursor.read_u32::<BigEndian>()?
            };
            let info = cursor.read_u8()?;
            let other = cursor.read_u8()?;
            let shndx = if self.is_little_endian {
                cursor.read_u16::<LittleEndian>()?
            } else {
                cursor.read_u16::<BigEndian>()?
            };
            let value = if self.is_little_endian {
                cursor.read_u64::<LittleEndian>()?
            } else {
                cursor.read_u64::<BigEndian>()?
            };
            let size = if self.is_little_endian {
                cursor.read_u64::<LittleEndian>()?
            } else {
                cursor.read_u64::<BigEndian>()?
            };
            (name, value, size, info, other, shndx)
        } else {
            let name = if self.is_little_endian {
                cursor.read_u32::<LittleEndian>()?
            } else {
                cursor.read_u32::<BigEndian>()?
            };
            let value = if self.is_little_endian {
                cursor.read_u32::<LittleEndian>()? as u64
            } else {
                cursor.read_u32::<BigEndian>()? as u64
            };
            let size = if self.is_little_endian {
                cursor.read_u32::<LittleEndian>()? as u64
            } else {
                cursor.read_u32::<BigEndian>()? as u64
            };
            let info = cursor.read_u8()?;
            let other = cursor.read_u8()?;
            let shndx = if self.is_little_endian {
                cursor.read_u16::<LittleEndian>()?
            } else {
                cursor.read_u16::<BigEndian>()?
            };
            (name, value, size, info, other, shndx)
        };

        let name = self.read_string_from_data(strtab, st_name as usize);

        Ok(Symbol {
            name,
            st_value,
            st_size,
            st_info,
            st_other,
            st_shndx,
            binding: symbol_binding_name(st_info).to_string(),
            symbol_type: symbol_type_name(st_info).to_string(),
        })
    }

    /// Parse dynamic section
    fn parse_dynamic(
        &mut self,
        sections: &[SectionHeader],
        program_headers: &[ProgramHeader],
    ) -> Result<Vec<DynamicEntry>, ElfError> {
        // Find .dynamic section or PT_DYNAMIC segment
        let dynamic_section = sections.iter().find(|s| s.sh_type == 6); // SHT_DYNAMIC

        let (offset, size) = if let Some(section) = dynamic_section {
            (section.sh_offset, section.sh_size)
        } else if let Some(phdr) = program_headers.iter().find(|p| p.p_type == 2) {
            (phdr.p_offset, phdr.p_filesz)
        } else {
            return Ok(Vec::new());
        };

        self.reader.seek(SeekFrom::Start(offset))?;

        let entry_size = if self.is_64bit { 16 } else { 8 };
        let count = size as usize / entry_size;
        let mut entries = Vec::new();

        for _ in 0..count {
            let d_tag = if self.is_64bit {
                self.read_u64()? as i64
            } else {
                self.read_u32()? as i64
            };

            let d_val = self.read_addr()?;

            if d_tag == 0 {
                break; // DT_NULL
            }

            entries.push(DynamicEntry {
                d_tag,
                tag_name: dynamic_tag_name(d_tag).to_string(),
                d_val,
            });
        }

        Ok(entries)
    }

    /// Parse relocations
    fn parse_relocations(
        &mut self,
        sections: &[SectionHeader],
        symbols: &[Symbol],
        dynamic_symbols: &[Symbol],
    ) -> Result<Vec<Relocation>, ElfError> {
        let mut relocs = Vec::new();

        for section in sections {
            // REL or RELA
            if section.sh_type != 4 && section.sh_type != 9 {
                continue;
            }

            let is_rela = section.sh_type == 4;
            let data = self.read_section_data(section)?;

            // Determine which symbol table to use
            let sym_table = if section.sh_link as usize < sections.len() {
                let link_section = &sections[section.sh_link as usize];
                if link_section.sh_type == 11 {
                    dynamic_symbols
                } else {
                    symbols
                }
            } else {
                symbols
            };

            let entry_size = if self.is_64bit {
                if is_rela { 24 } else { 16 }
            } else {
                if is_rela { 12 } else { 8 }
            };

            let count = data.len() / entry_size;

            for i in 0..count {
                let offset = i * entry_size;
                let reloc = self.parse_relocation(&data[offset..], is_rela, sym_table)?;
                relocs.push(reloc);
            }
        }

        Ok(relocs)
    }

    /// Parse a single relocation entry
    fn parse_relocation(
        &self,
        data: &[u8],
        is_rela: bool,
        symbols: &[Symbol],
    ) -> Result<Relocation, ElfError> {
        use std::io::Cursor;
        let mut cursor = Cursor::new(data);

        let (r_offset, r_info, r_addend) = if self.is_64bit {
            let offset = if self.is_little_endian {
                cursor.read_u64::<LittleEndian>()?
            } else {
                cursor.read_u64::<BigEndian>()?
            };
            let info = if self.is_little_endian {
                cursor.read_u64::<LittleEndian>()?
            } else {
                cursor.read_u64::<BigEndian>()?
            };
            let addend = if is_rela {
                Some(if self.is_little_endian {
                    cursor.read_i64::<LittleEndian>()?
                } else {
                    cursor.read_i64::<BigEndian>()?
                })
            } else {
                None
            };
            (offset, info, addend)
        } else {
            let offset = if self.is_little_endian {
                cursor.read_u32::<LittleEndian>()? as u64
            } else {
                cursor.read_u32::<BigEndian>()? as u64
            };
            let info = if self.is_little_endian {
                cursor.read_u32::<LittleEndian>()? as u64
            } else {
                cursor.read_u32::<BigEndian>()? as u64
            };
            let addend = if is_rela {
                Some(if self.is_little_endian {
                    cursor.read_i32::<LittleEndian>()? as i64
                } else {
                    cursor.read_i32::<BigEndian>()? as i64
                })
            } else {
                None
            };
            (offset, info, addend)
        };

        let (r_sym, r_type) = if self.is_64bit {
            ((r_info >> 32) as u32, (r_info & 0xFFFFFFFF) as u32)
        } else {
            ((r_info >> 8) as u32, (r_info & 0xFF) as u32)
        };

        let symbol_name = symbols.get(r_sym as usize).map(|s| s.name.clone());

        Ok(Relocation {
            r_offset,
            r_type,
            r_sym,
            r_addend,
            symbol_name,
        })
    }

    /// Analyze security properties
    fn analyze_security(
        &mut self,
        header: &ElfHeader,
        program_headers: &[ProgramHeader],
        sections: &[SectionHeader],
        dynamic: &[DynamicEntry],
        symbols: &[Symbol],
        dynamic_symbols: &[Symbol],
    ) -> Result<SecurityInfo, ElfError> {
        let mut info = SecurityInfo::default();

        // Check for RELRO
        let has_relro = program_headers.iter().any(|p| p.p_type == 0x6474e552); // GNU_RELRO
        let has_bind_now = dynamic.iter().any(|d| {
            d.d_tag == 24 || // DT_BIND_NOW
            (d.d_tag == 0x6ffffffb && d.d_val & 0x1 != 0) // DF_1_NOW
        });

        info.relro = if has_relro && has_bind_now {
            RelroType::Full
        } else if has_relro {
            RelroType::Partial
        } else {
            RelroType::None
        };

        // Check for NX (non-executable stack)
        if let Some(stack) = program_headers.iter().find(|p| p.p_type == 0x6474e551) {
            info.has_nx = stack.p_flags & 0x1 == 0; // No PF_X flag
        } else {
            // No GNU_STACK means executable stack by default
            info.has_nx = false;
        }

        // Check for PIE
        info.is_pie = header.e_type == 3; // ET_DYN with entry point

        // Check for stack canary
        let canary_funcs = ["__stack_chk_fail", "__stack_chk_guard"];
        info.has_canary = dynamic_symbols.iter()
            .any(|s| canary_funcs.contains(&s.name.as_str()));

        // Check for FORTIFY
        info.has_fortify = dynamic_symbols.iter()
            .any(|s| s.name.contains("__fortify") || s.name.ends_with("_chk"));

        // Check for RPATH/RUNPATH
        for entry in dynamic {
            match entry.d_tag {
                15 => { // DT_RPATH
                    info.has_rpath = true;
                    // Would need to resolve string from dynstr
                }
                29 => { // DT_RUNPATH
                    info.has_runpath = true;
                }
                _ => {}
            }
        }

        // Check if stripped
        info.is_stripped = symbols.is_empty() ||
            !sections.iter().any(|s| s.name == ".symtab");

        // Get interpreter
        if let Some(interp) = program_headers.iter().find(|p| p.p_type == 3) {
            let mut interp_data = vec![0u8; interp.p_filesz as usize];
            self.reader.seek(SeekFrom::Start(interp.p_offset))?;
            self.reader.read_exact(&mut interp_data)?;
            info.interpreter = Some(
                String::from_utf8_lossy(&interp_data)
                    .trim_end_matches('\0')
                    .to_string()
            );
        }

        // Check for anomalies
        // Writable and executable segment
        for (i, phdr) in program_headers.iter().enumerate() {
            if phdr.p_type == 1 && phdr.p_flags & 0x3 == 0x3 { // LOAD with W+X
                info.anomalies.push(format!(
                    "Segment {} is both writable and executable (W+X)",
                    i
                ));
            }
        }

        // Suspicious section characteristics
        for section in sections {
            if section.sh_flags & 0x5 == 0x5 { // WRITE + EXEC
                info.anomalies.push(format!(
                    "Section {} is both writable and executable",
                    section.name
                ));
            }
        }

        Ok(info)
    }
}

// ============================================================================
// OUTPUT FORMATTING
// ============================================================================

fn print_text_output(elf: &ElfFile, args: &Args) {
    println!("\n{}", "=".repeat(70).blue());
    println!("{}", "           ELF FILE ANALYSIS REPORT".blue().bold());
    println!("{}", "=".repeat(70).blue());

    // ELF Header
    println!("\n{}", "[ ELF HEADER ]".cyan().bold());
    println!("  Magic:           {:02X} {:02X} {:02X} {:02X}",
             elf.header.ident.magic[0], elf.header.ident.magic[1],
             elf.header.ident.magic[2], elf.header.ident.magic[3]);
    println!("  Class:           {} ({})",
             elf.header.ident.class,
             if elf.header.is_64bit { "64-bit" } else { "32-bit" });
    println!("  Data:            {} ({})",
             elf.header.ident.data,
             if elf.header.is_little_endian { "Little Endian" } else { "Big Endian" });
    println!("  OS/ABI:          {}", osabi_name(elf.header.ident.osabi));
    println!("  Type:            0x{:04X} ({})", elf.header.e_type, elf_type_name(elf.header.e_type));
    println!("  Machine:         0x{:04X} ({})", elf.header.e_machine, machine_name(elf.header.e_machine));
    println!("  Entry Point:     0x{:016X}", elf.header.e_entry);
    println!("  Program Headers: {} entries at offset 0x{:X}", elf.header.e_phnum, elf.header.e_phoff);
    println!("  Section Headers: {} entries at offset 0x{:X}", elf.header.e_shnum, elf.header.e_shoff);

    // Program Headers
    println!("\n{}", "[ PROGRAM HEADERS ]".cyan().bold());
    println!("  {:<14} {:<6} {:>18} {:>18} {:>10} {:>10}",
             "Type", "Flags", "Offset", "VirtAddr", "FileSize", "MemSize");
    println!("  {}", "-".repeat(76));
    for phdr in &elf.program_headers {
        println!("  {:<14} {:<6} 0x{:016X} 0x{:016X} 0x{:08X} 0x{:08X}",
                 phdr_type_name(phdr.p_type),
                 phdr_flags_str(phdr.p_flags),
                 phdr.p_offset,
                 phdr.p_vaddr,
                 phdr.p_filesz,
                 phdr.p_memsz);
    }

    // Section Headers
    println!("\n{}", "[ SECTION HEADERS ]".cyan().bold());
    println!("  {:>3} {:<20} {:<12} {:<6} {:>18} {:>10}",
             "Nr", "Name", "Type", "Flags", "Address", "Size");
    println!("  {}", "-".repeat(76));
    for (i, shdr) in elf.section_headers.iter().enumerate() {
        println!("  {:>3} {:<20} {:<12} {:<6} 0x{:016X} 0x{:08X}",
                 i,
                 if shdr.name.len() > 20 { &shdr.name[..20] } else { &shdr.name },
                 shdr_type_name(shdr.sh_type),
                 shdr_flags_str(shdr.sh_flags),
                 shdr.sh_addr,
                 shdr.sh_size);
    }

    // Dynamic Section
    if args.dynamic || args.verbose {
        println!("\n{}", "[ DYNAMIC SECTION ]".cyan().bold());
        for entry in &elf.dynamic_entries {
            println!("  {:<20} 0x{:016X}", entry.tag_name, entry.d_val);
        }
    }

    // Symbols
    if args.symbols {
        if !elf.symbols.is_empty() {
            println!("\n{}", "[ SYMBOL TABLE ]".cyan().bold());
            println!("  {:>6} {:>18} {:>8} {:<8} {:<8} {}",
                     "Num", "Value", "Size", "Type", "Bind", "Name");
            println!("  {}", "-".repeat(70));
            for (i, sym) in elf.symbols.iter().enumerate().take(100) {
                println!("  {:>6} 0x{:016X} {:>8} {:<8} {:<8} {}",
                         i, sym.st_value, sym.st_size,
                         sym.symbol_type, sym.binding, sym.name);
            }
            if elf.symbols.len() > 100 {
                println!("  ... and {} more symbols", elf.symbols.len() - 100);
            }
        }

        if !elf.dynamic_symbols.is_empty() {
            println!("\n{}", "[ DYNAMIC SYMBOLS ]".cyan().bold());
            for (i, sym) in elf.dynamic_symbols.iter().enumerate().take(50) {
                println!("  {:>4} {:<8} {:<8} {}",
                         i, sym.symbol_type, sym.binding, sym.name);
            }
        }
    } else {
        println!("\n{}", "[ SYMBOLS SUMMARY ]".cyan().bold());
        println!("  Static symbols:  {}", elf.symbols.len());
        println!("  Dynamic symbols: {}", elf.dynamic_symbols.len());
        println!("  (use --symbols for full list)");
    }

    // Relocations
    if args.relocs {
        println!("\n{}", "[ RELOCATIONS ]".cyan().bold());
        for (i, reloc) in elf.relocations.iter().enumerate().take(50) {
            println!("  0x{:016X}  type={:>3}  sym={:>4}  {}",
                     reloc.r_offset, reloc.r_type, reloc.r_sym,
                     reloc.symbol_name.as_deref().unwrap_or(""));
        }
        if elf.relocations.len() > 50 {
            println!("  ... and {} more relocations", elf.relocations.len() - 50);
        }
    }

    // Security Analysis
    println!("\n{}", "[ SECURITY ANALYSIS ]".cyan().bold());

    let print_status = |name: &str, good: bool, value: &str| {
        if good {
            println!("  {} {} [{}]", name, "[OK]".green(), value.green());
        } else {
            println!("  {} {} [{}]", name, "[!!]".red(), value.red());
        }
    };

    // RELRO
    let relro_str = match elf.security_info.relro {
        RelroType::Full => "Full RELRO",
        RelroType::Partial => "Partial RELRO",
        RelroType::None => "No RELRO",
    };
    print_status("RELRO:     ", elf.security_info.relro == RelroType::Full, relro_str);

    // Stack Canary
    print_status("Canary:    ",
                 elf.security_info.has_canary,
                 if elf.security_info.has_canary { "Found" } else { "Not Found" });

    // NX
    print_status("NX:        ",
                 elf.security_info.has_nx,
                 if elf.security_info.has_nx { "Enabled" } else { "Disabled" });

    // PIE
    print_status("PIE:       ",
                 elf.security_info.is_pie,
                 if elf.security_info.is_pie { "Enabled" } else { "Disabled" });

    // FORTIFY
    print_status("FORTIFY:   ",
                 elf.security_info.has_fortify,
                 if elf.security_info.has_fortify { "Found" } else { "Not Found" });

    // RPATH/RUNPATH (these are often security risks)
    if elf.security_info.has_rpath {
        println!("  {} {} [{}]", "RPATH:     ", "[!!]".yellow(), "Present (potential hijacking)".yellow());
    }
    if elf.security_info.has_runpath {
        println!("  {} {} [{}]", "RUNPATH:   ", "[!!]".yellow(), "Present (potential hijacking)".yellow());
    }

    // Stripped
    println!("  Stripped:    {}", if elf.security_info.is_stripped { "Yes" } else { "No" });

    // Interpreter
    if let Some(ref interp) = elf.security_info.interpreter {
        println!("  Interpreter: {}", interp);
    }

    // Anomalies
    if !elf.security_info.anomalies.is_empty() {
        println!("\n  {}", "ANOMALIES DETECTED:".red().bold());
        for anomaly in &elf.security_info.anomalies {
            println!("    - {}", anomaly.red());
        }
    }

    println!("\n{}", "=".repeat(70).blue());
}

fn print_json_output(elf: &ElfFile) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(elf)?);
    Ok(())
}

// ============================================================================
// MAIN
// ============================================================================

fn main() -> Result<()> {
    let args = Args::parse();

    // Open and parse ELF file
    let file = File::open(&args.file)
        .context(format!("Failed to open file: {:?}", args.file))?;

    let mut parser = ElfParser::new(file);
    let elf = parser.parse()
        .context("Failed to parse ELF file")?;

    // Output results
    match args.output {
        OutputFormat::Text => print_text_output(&elf, &args),
        OutputFormat::Json => print_json_output(&elf)?,
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

    /// Create a minimal valid ELF file for testing
    fn create_minimal_elf64() -> Vec<u8> {
        let mut elf = vec![0u8; 128];

        // ELF Magic
        elf[0] = 0x7F;
        elf[1] = b'E';
        elf[2] = b'L';
        elf[3] = b'F';

        // Class: 64-bit
        elf[4] = 2;
        // Data: Little endian
        elf[5] = 1;
        // Version
        elf[6] = 1;
        // OS/ABI: System V
        elf[7] = 0;

        // e_type: ET_EXEC (2)
        elf[16] = 2;
        elf[17] = 0;

        // e_machine: x86_64 (62 = 0x3E)
        elf[18] = 0x3E;
        elf[19] = 0;

        // e_version
        elf[20] = 1;

        // e_entry (8 bytes at offset 24)
        elf[24] = 0x00;
        elf[25] = 0x10;
        elf[26] = 0x40;
        elf[27] = 0x00;

        // e_phoff (8 bytes at offset 32) = 64
        elf[32] = 64;

        // e_shoff (8 bytes at offset 40) = 0
        elf[40] = 0;

        // e_flags (4 bytes at offset 48)
        elf[48] = 0;

        // e_ehsize (2 bytes at offset 52) = 64
        elf[52] = 64;

        // e_phentsize (2 bytes at offset 54) = 56
        elf[54] = 56;

        // e_phnum (2 bytes at offset 56) = 0
        elf[56] = 0;

        // e_shentsize (2 bytes at offset 58) = 64
        elf[58] = 64;

        // e_shnum (2 bytes at offset 60) = 0
        elf[60] = 0;

        // e_shstrndx (2 bytes at offset 62) = 0
        elf[62] = 0;

        elf
    }

    #[test]
    fn test_elf_magic_detection() {
        let elf_data = create_minimal_elf64();
        let cursor = Cursor::new(elf_data);
        let mut parser = ElfParser::new(cursor);
        let result = parser.parse();
        assert!(result.is_ok());
    }

    #[test]
    fn test_invalid_magic() {
        let bad_data = vec![0x00u8; 64];
        let cursor = Cursor::new(bad_data);
        let mut parser = ElfParser::new(cursor);
        let result = parser.parse();
        assert!(result.is_err());
    }

    #[test]
    fn test_type_names() {
        assert_eq!(elf_type_name(2), "EXEC (Executable)");
        assert_eq!(elf_type_name(3), "DYN (Shared Object)");
        assert_eq!(machine_name(62), "AMD x86-64");
        assert_eq!(machine_name(183), "ARM64 (AArch64)");
    }

    #[test]
    fn test_section_flags() {
        assert_eq!(shdr_flags_str(0x6), "AX");  // ALLOC + EXEC
        assert_eq!(shdr_flags_str(0x3), "WA");  // WRITE + ALLOC
        assert_eq!(shdr_flags_str(0x0), "-");
    }

    #[test]
    fn test_phdr_flags() {
        assert_eq!(phdr_flags_str(0x5), "RX");  // READ + EXEC
        assert_eq!(phdr_flags_str(0x6), "RW");  // READ + WRITE
        assert_eq!(phdr_flags_str(0x7), "RWX"); // All
    }

    #[test]
    fn test_symbol_info_parsing() {
        // GLOBAL + FUNC = (1 << 4) | 2 = 0x12
        assert_eq!(symbol_binding_name(0x12), "GLOBAL");
        assert_eq!(symbol_type_name(0x12), "FUNC");
    }

    #[test]
    fn test_header_parsing() {
        let elf_data = create_minimal_elf64();
        let cursor = Cursor::new(elf_data);
        let mut parser = ElfParser::new(cursor);
        let elf = parser.parse().unwrap();

        assert!(elf.header.is_64bit);
        assert!(elf.header.is_little_endian);
        assert_eq!(elf.header.e_type, 2); // ET_EXEC
        assert_eq!(elf.header.e_machine, 0x3E); // x86_64
    }
}
