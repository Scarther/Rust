//! # Binary Instrumentation Library
//!
//! This crate provides tools for binary analysis and instrumentation:
//! - ELF file parsing and analysis
//! - Disassembly using iced-x86
//! - Process memory manipulation
//! - Ptrace-based debugging
//! - Function hooking (conceptual)
//!
//! ## Architecture
//!
//! ```text
//! +------------------+
//! |   ELF Parser     |  Parse binary structure
//! +------------------+
//!          |
//! +------------------+
//! |   Disassembler   |  Decode instructions
//! +------------------+
//!          |
//! +------------------+
//! |   Analyzer       |  Find patterns, functions
//! +------------------+
//!          |
//! +------------------+
//! |   Instrumenter   |  Apply modifications
//! +------------------+
//! ```
//!
//! ## Security Note
//!
//! This library is for educational purposes. Binary instrumentation
//! should only be performed on binaries you own or have permission to analyze.

pub mod elf;
pub mod disasm;
pub mod ptrace;
pub mod memory;
pub mod analysis;
pub mod error;

pub use elf::*;
pub use disasm::*;
pub use ptrace::*;
pub use memory::*;
pub use analysis::*;
pub use error::*;

/// Supported architectures
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Architecture {
    X86,
    X86_64,
    Arm,
    Aarch64,
    Unknown,
}

impl Architecture {
    /// Get the word size in bytes
    pub fn word_size(&self) -> usize {
        match self {
            Architecture::X86 | Architecture::Arm => 4,
            Architecture::X86_64 | Architecture::Aarch64 => 8,
            Architecture::Unknown => 8,
        }
    }

    /// Check if this is a 64-bit architecture
    pub fn is_64bit(&self) -> bool {
        matches!(self, Architecture::X86_64 | Architecture::Aarch64)
    }
}

/// Binary type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryType {
    Executable,
    SharedObject,
    Relocatable,
    Core,
    Unknown,
}

/// Common patterns to search for in binaries
pub mod patterns {
    /// x86_64 function prologue
    pub const X86_64_PROLOGUE: &[u8] = &[0x55, 0x48, 0x89, 0xe5]; // push rbp; mov rbp, rsp

    /// x86 function prologue
    pub const X86_PROLOGUE: &[u8] = &[0x55, 0x89, 0xe5]; // push ebp; mov ebp, esp

    /// NOP sled patterns
    pub const NOP_SLED: &[u8] = &[0x90, 0x90, 0x90, 0x90];

    /// INT 3 breakpoint
    pub const INT3: u8 = 0xCC;

    /// System call (syscall instruction)
    pub const SYSCALL: &[u8] = &[0x0f, 0x05];

    /// Return instruction
    pub const RET: u8 = 0xC3;

    /// Call instruction (relative)
    pub const CALL_REL: u8 = 0xE8;

    /// Jump instruction (relative)
    pub const JMP_REL: u8 = 0xE9;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_architecture() {
        assert_eq!(Architecture::X86_64.word_size(), 8);
        assert_eq!(Architecture::X86.word_size(), 4);
        assert!(Architecture::X86_64.is_64bit());
        assert!(!Architecture::X86.is_64bit());
    }
}
