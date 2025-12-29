//! # ELF File Parsing and Analysis
//!
//! This module provides comprehensive ELF file parsing:
//! - Headers (ELF header, program headers, section headers)
//! - Symbol tables
//! - Relocations
//! - Dynamic linking information
//! - Security features detection (NX, PIE, RELRO, etc.)

use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use goblin::elf::{Elf, header, program_header, section_header, sym};
use memmap2::Mmap;

use crate::error::{InstrumentError, InstrumentResult};
use crate::{Architecture, BinaryType};

/// Parsed ELF binary
pub struct ElfBinary {
    /// Raw bytes of the file
    data: Vec<u8>,
    /// Parsed ELF structure
    elf: Elf<'static>,
    /// Architecture
    pub arch: Architecture,
    /// Binary type
    pub binary_type: BinaryType,
    /// Entry point address
    pub entry_point: u64,
    /// Is position independent (PIE)
    pub is_pie: bool,
    /// Security features
    pub security: SecurityFeatures,
}

/// Security features detected in the binary
#[derive(Debug, Clone, Default)]
pub struct SecurityFeatures {
    /// Non-executable stack (NX)
    pub nx_enabled: bool,
    /// Full RELRO (GOT read-only)
    pub full_relro: bool,
    /// Partial RELRO
    pub partial_relro: bool,
    /// Stack canary detection
    pub stack_canary: bool,
    /// Position Independent Executable
    pub pie: bool,
    /// FORTIFY_SOURCE
    pub fortify: bool,
    /// RUNPATH set
    pub runpath: bool,
    /// RPATH set (deprecated, insecure)
    pub rpath: bool,
}

impl ElfBinary {
    /// Parse an ELF file from a path
    pub fn from_path<P: AsRef<Path>>(path: P) -> InstrumentResult<Self> {
        let mut file = File::open(path)?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)?;
        Self::from_bytes(data)
    }

    /// Parse an ELF file from bytes
    pub fn from_bytes(data: Vec<u8>) -> InstrumentResult<Self> {
        // Parse ELF - we need to leak the data to get a 'static lifetime
        // In a real implementation, we'd use a self-referential struct
        let data_ref: &'static [u8] = Box::leak(data.clone().into_boxed_slice());

        let elf = Elf::parse(data_ref).map_err(|e| {
            InstrumentError::ElfParse(e.to_string())
        })?;

        // Determine architecture
        let arch = match elf.header.e_machine {
            header::EM_386 => Architecture::X86,
            header::EM_X86_64 => Architecture::X86_64,
            header::EM_ARM => Architecture::Arm,
            header::EM_AARCH64 => Architecture::Aarch64,
            _ => Architecture::Unknown,
        };

        // Determine binary type
        let binary_type = match elf.header.e_type {
            header::ET_EXEC => BinaryType::Executable,
            header::ET_DYN => BinaryType::SharedObject,
            header::ET_REL => BinaryType::Relocatable,
            header::ET_CORE => BinaryType::Core,
            _ => BinaryType::Unknown,
        };

        // Check if PIE
        let is_pie = elf.header.e_type == header::ET_DYN
            && elf.program_headers.iter().any(|ph| {
                ph.p_type == program_header::PT_INTERP
            });

        // Detect security features
        let security = detect_security_features(&elf);

        Ok(Self {
            data,
            elf,
            arch,
            binary_type,
            entry_point: elf.header.e_entry,
            is_pie,
            security,
        })
    }

    /// Get raw bytes
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Get the ELF structure
    pub fn elf(&self) -> &Elf {
        &self.elf
    }

    /// Get all symbols
    pub fn symbols(&self) -> Vec<Symbol> {
        let mut symbols = Vec::new();

        // Dynamic symbols
        for sym in &self.elf.dynsyms {
            if let Some(name) = self.elf.dynstrtab.get_at(sym.st_name) {
                symbols.push(Symbol {
                    name: name.to_string(),
                    address: sym.st_value,
                    size: sym.st_size,
                    symbol_type: symbol_type_from_elf(sym.st_type()),
                    binding: symbol_binding_from_elf(sym.st_bind()),
                    section_index: sym.st_shndx as u32,
                    is_dynamic: true,
                });
            }
        }

        // Static symbols
        for sym in &self.elf.syms {
            if let Some(name) = self.elf.strtab.get_at(sym.st_name) {
                symbols.push(Symbol {
                    name: name.to_string(),
                    address: sym.st_value,
                    size: sym.st_size,
                    symbol_type: symbol_type_from_elf(sym.st_type()),
                    binding: symbol_binding_from_elf(sym.st_bind()),
                    section_index: sym.st_shndx as u32,
                    is_dynamic: false,
                });
            }
        }

        symbols
    }

    /// Get functions (symbols of type STT_FUNC)
    pub fn functions(&self) -> Vec<Symbol> {
        self.symbols()
            .into_iter()
            .filter(|s| s.symbol_type == SymbolType::Function && s.size > 0)
            .collect()
    }

    /// Get a symbol by name
    pub fn get_symbol(&self, name: &str) -> Option<Symbol> {
        self.symbols().into_iter().find(|s| s.name == name)
    }

    /// Get sections
    pub fn sections(&self) -> Vec<Section> {
        self.elf
            .section_headers
            .iter()
            .enumerate()
            .map(|(i, sh)| {
                let name = self.elf.shdr_strtab
                    .get_at(sh.sh_name)
                    .unwrap_or("")
                    .to_string();

                Section {
                    index: i,
                    name,
                    section_type: section_type_from_elf(sh.sh_type),
                    address: sh.sh_addr,
                    offset: sh.sh_offset,
                    size: sh.sh_size,
                    flags: SectionFlags::from_elf(sh.sh_flags),
                }
            })
            .collect()
    }

    /// Get a section by name
    pub fn get_section(&self, name: &str) -> Option<Section> {
        self.sections().into_iter().find(|s| s.name == name)
    }

    /// Get section data by name
    pub fn get_section_data(&self, name: &str) -> Option<&[u8]> {
        let section = self.get_section(name)?;
        let start = section.offset as usize;
        let end = start + section.size as usize;

        if end <= self.data.len() {
            Some(&self.data[start..end])
        } else {
            None
        }
    }

    /// Get program headers (segments)
    pub fn segments(&self) -> Vec<Segment> {
        self.elf
            .program_headers
            .iter()
            .map(|ph| Segment {
                segment_type: segment_type_from_elf(ph.p_type),
                flags: SegmentFlags::from_elf(ph.p_flags),
                offset: ph.p_offset,
                vaddr: ph.p_vaddr,
                paddr: ph.p_paddr,
                file_size: ph.p_filesz,
                mem_size: ph.p_memsz,
                align: ph.p_align,
            })
            .collect()
    }

    /// Get executable segments
    pub fn executable_segments(&self) -> Vec<Segment> {
        self.segments()
            .into_iter()
            .filter(|s| s.flags.execute)
            .collect()
    }

    /// Get relocations
    pub fn relocations(&self) -> Vec<Relocation> {
        let mut relocs = Vec::new();

        // PLT relocations
        for reloc in &self.elf.pltrelocs {
            let name = self.elf.dynsyms
                .get(reloc.r_sym)
                .and_then(|sym| self.elf.dynstrtab.get_at(sym.st_name))
                .unwrap_or("")
                .to_string();

            relocs.push(Relocation {
                offset: reloc.r_offset,
                reloc_type: reloc.r_type,
                symbol_index: reloc.r_sym,
                symbol_name: name,
                addend: reloc.r_addend.unwrap_or(0),
            });
        }

        // Dynamic relocations
        for reloc in &self.elf.dynrelas {
            let name = self.elf.dynsyms
                .get(reloc.r_sym)
                .and_then(|sym| self.elf.dynstrtab.get_at(sym.st_name))
                .unwrap_or("")
                .to_string();

            relocs.push(Relocation {
                offset: reloc.r_offset,
                reloc_type: reloc.r_type,
                symbol_index: reloc.r_sym,
                symbol_name: name,
                addend: reloc.r_addend.unwrap_or(0),
            });
        }

        relocs
    }

    /// Get imported libraries
    pub fn libraries(&self) -> Vec<String> {
        self.elf.libraries.iter().map(|s| s.to_string()).collect()
    }

    /// Get the GOT (Global Offset Table) entries
    pub fn got_entries(&self) -> Vec<GotEntry> {
        let mut entries = Vec::new();

        // Find .got and .got.plt sections
        for section in self.sections() {
            if section.name == ".got" || section.name == ".got.plt" {
                let data = self.get_section_data(&section.name);
                if let Some(data) = data {
                    let entry_size = self.arch.word_size();
                    for (i, chunk) in data.chunks(entry_size).enumerate() {
                        let value = if entry_size == 8 {
                            u64::from_le_bytes(chunk.try_into().unwrap_or([0; 8]))
                        } else {
                            u32::from_le_bytes(chunk.try_into().unwrap_or([0; 4])) as u64
                        };

                        entries.push(GotEntry {
                            address: section.address + (i * entry_size) as u64,
                            value,
                            symbol: None, // Would need relocation info to resolve
                        });
                    }
                }
            }
        }

        entries
    }

    /// Find all occurrences of a byte pattern
    pub fn find_pattern(&self, pattern: &[u8]) -> Vec<u64> {
        let mut matches = Vec::new();

        for segment in self.executable_segments() {
            let start = segment.offset as usize;
            let end = start + segment.file_size as usize;

            if end <= self.data.len() {
                let segment_data = &self.data[start..end];

                for i in 0..segment_data.len().saturating_sub(pattern.len()) {
                    if &segment_data[i..i + pattern.len()] == pattern {
                        // Convert file offset to virtual address
                        let vaddr = segment.vaddr + i as u64;
                        matches.push(vaddr);
                    }
                }
            }
        }

        matches
    }

    /// Get file offset for a virtual address
    pub fn vaddr_to_offset(&self, vaddr: u64) -> Option<u64> {
        for segment in self.segments() {
            if vaddr >= segment.vaddr && vaddr < segment.vaddr + segment.mem_size {
                let offset_in_segment = vaddr - segment.vaddr;
                if offset_in_segment < segment.file_size {
                    return Some(segment.offset + offset_in_segment);
                }
            }
        }
        None
    }

    /// Get bytes at a virtual address
    pub fn read_bytes(&self, vaddr: u64, size: usize) -> Option<&[u8]> {
        let offset = self.vaddr_to_offset(vaddr)? as usize;
        if offset + size <= self.data.len() {
            Some(&self.data[offset..offset + size])
        } else {
            None
        }
    }
}

/// Detect security features in the binary
fn detect_security_features(elf: &Elf) -> SecurityFeatures {
    let mut features = SecurityFeatures::default();

    // Check for NX (non-executable stack)
    for ph in &elf.program_headers {
        if ph.p_type == program_header::PT_GNU_STACK {
            features.nx_enabled = (ph.p_flags & program_header::PF_X) == 0;
        }
        if ph.p_type == program_header::PT_GNU_RELRO {
            features.partial_relro = true;
        }
    }

    // Check for PIE
    features.pie = elf.header.e_type == header::ET_DYN;

    // Check dynamic section for BIND_NOW (full RELRO)
    if let Some(ref dynamic) = elf.dynamic {
        for dyn_entry in &dynamic.dyns {
            match dyn_entry.d_tag {
                goblin::elf::dynamic::DT_FLAGS => {
                    if dyn_entry.d_val & 0x8 != 0 {
                        // DF_BIND_NOW
                        features.full_relro = features.partial_relro;
                    }
                }
                goblin::elf::dynamic::DT_FLAGS_1 => {
                    if dyn_entry.d_val & 0x1 != 0 {
                        // DF_1_NOW
                        features.full_relro = features.partial_relro;
                    }
                }
                goblin::elf::dynamic::DT_RPATH => {
                    features.rpath = true;
                }
                goblin::elf::dynamic::DT_RUNPATH => {
                    features.runpath = true;
                }
                _ => {}
            }
        }
    }

    // Check for stack canary (__stack_chk_fail)
    for sym in &elf.dynsyms {
        if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
            if name == "__stack_chk_fail" {
                features.stack_canary = true;
            }
            if name.starts_with("__fortify") {
                features.fortify = true;
            }
        }
    }

    features
}

/// Symbol information
#[derive(Debug, Clone)]
pub struct Symbol {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub symbol_type: SymbolType,
    pub binding: SymbolBinding,
    pub section_index: u32,
    pub is_dynamic: bool,
}

/// Symbol types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolType {
    None,
    Object,
    Function,
    Section,
    File,
    Common,
    Tls,
    Unknown(u8),
}

fn symbol_type_from_elf(st_type: u8) -> SymbolType {
    match st_type {
        sym::STT_NOTYPE => SymbolType::None,
        sym::STT_OBJECT => SymbolType::Object,
        sym::STT_FUNC => SymbolType::Function,
        sym::STT_SECTION => SymbolType::Section,
        sym::STT_FILE => SymbolType::File,
        sym::STT_COMMON => SymbolType::Common,
        sym::STT_TLS => SymbolType::Tls,
        other => SymbolType::Unknown(other),
    }
}

/// Symbol bindings
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolBinding {
    Local,
    Global,
    Weak,
    Unknown(u8),
}

fn symbol_binding_from_elf(st_bind: u8) -> SymbolBinding {
    match st_bind {
        sym::STB_LOCAL => SymbolBinding::Local,
        sym::STB_GLOBAL => SymbolBinding::Global,
        sym::STB_WEAK => SymbolBinding::Weak,
        other => SymbolBinding::Unknown(other),
    }
}

/// Section information
#[derive(Debug, Clone)]
pub struct Section {
    pub index: usize,
    pub name: String,
    pub section_type: SectionType,
    pub address: u64,
    pub offset: u64,
    pub size: u64,
    pub flags: SectionFlags,
}

/// Section types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SectionType {
    Null,
    Progbits,
    Symtab,
    Strtab,
    Rela,
    Hash,
    Dynamic,
    Note,
    Nobits,
    Rel,
    Dynsym,
    InitArray,
    FiniArray,
    Unknown(u32),
}

fn section_type_from_elf(sh_type: u32) -> SectionType {
    match sh_type {
        section_header::SHT_NULL => SectionType::Null,
        section_header::SHT_PROGBITS => SectionType::Progbits,
        section_header::SHT_SYMTAB => SectionType::Symtab,
        section_header::SHT_STRTAB => SectionType::Strtab,
        section_header::SHT_RELA => SectionType::Rela,
        section_header::SHT_HASH => SectionType::Hash,
        section_header::SHT_DYNAMIC => SectionType::Dynamic,
        section_header::SHT_NOTE => SectionType::Note,
        section_header::SHT_NOBITS => SectionType::Nobits,
        section_header::SHT_REL => SectionType::Rel,
        section_header::SHT_DYNSYM => SectionType::Dynsym,
        section_header::SHT_INIT_ARRAY => SectionType::InitArray,
        section_header::SHT_FINI_ARRAY => SectionType::FiniArray,
        other => SectionType::Unknown(other),
    }
}

/// Section flags
#[derive(Debug, Clone, Copy, Default)]
pub struct SectionFlags {
    pub write: bool,
    pub alloc: bool,
    pub exec: bool,
}

impl SectionFlags {
    fn from_elf(flags: u64) -> Self {
        Self {
            write: (flags & section_header::SHF_WRITE as u64) != 0,
            alloc: (flags & section_header::SHF_ALLOC as u64) != 0,
            exec: (flags & section_header::SHF_EXECINSTR as u64) != 0,
        }
    }
}

/// Segment (program header) information
#[derive(Debug, Clone)]
pub struct Segment {
    pub segment_type: SegmentType,
    pub flags: SegmentFlags,
    pub offset: u64,
    pub vaddr: u64,
    pub paddr: u64,
    pub file_size: u64,
    pub mem_size: u64,
    pub align: u64,
}

/// Segment types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SegmentType {
    Null,
    Load,
    Dynamic,
    Interp,
    Note,
    Phdr,
    Tls,
    GnuStack,
    GnuRelro,
    Unknown(u32),
}

fn segment_type_from_elf(p_type: u32) -> SegmentType {
    match p_type {
        program_header::PT_NULL => SegmentType::Null,
        program_header::PT_LOAD => SegmentType::Load,
        program_header::PT_DYNAMIC => SegmentType::Dynamic,
        program_header::PT_INTERP => SegmentType::Interp,
        program_header::PT_NOTE => SegmentType::Note,
        program_header::PT_PHDR => SegmentType::Phdr,
        program_header::PT_TLS => SegmentType::Tls,
        program_header::PT_GNU_STACK => SegmentType::GnuStack,
        program_header::PT_GNU_RELRO => SegmentType::GnuRelro,
        other => SegmentType::Unknown(other),
    }
}

/// Segment flags
#[derive(Debug, Clone, Copy, Default)]
pub struct SegmentFlags {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

impl SegmentFlags {
    fn from_elf(flags: u32) -> Self {
        Self {
            read: (flags & program_header::PF_R) != 0,
            write: (flags & program_header::PF_W) != 0,
            execute: (flags & program_header::PF_X) != 0,
        }
    }
}

/// Relocation entry
#[derive(Debug, Clone)]
pub struct Relocation {
    pub offset: u64,
    pub reloc_type: u32,
    pub symbol_index: usize,
    pub symbol_name: String,
    pub addend: i64,
}

/// GOT entry
#[derive(Debug, Clone)]
pub struct GotEntry {
    pub address: u64,
    pub value: u64,
    pub symbol: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_features_default() {
        let features = SecurityFeatures::default();
        assert!(!features.nx_enabled);
        assert!(!features.pie);
        assert!(!features.stack_canary);
    }

    #[test]
    fn test_section_flags() {
        let flags = SectionFlags::from_elf(
            (section_header::SHF_WRITE | section_header::SHF_ALLOC) as u64
        );
        assert!(flags.write);
        assert!(flags.alloc);
        assert!(!flags.exec);
    }
}
