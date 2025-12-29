//! # Error Types for Binary Instrumentation

use thiserror::Error;

/// Main error type
#[derive(Error, Debug)]
pub enum InstrumentError {
    /// Failed to parse ELF file
    #[error("ELF parsing error: {0}")]
    ElfParse(String),

    /// Invalid ELF structure
    #[error("Invalid ELF: {0}")]
    InvalidElf(String),

    /// Disassembly error
    #[error("Disassembly error: {0}")]
    Disassembly(String),

    /// Ptrace operation failed
    #[error("Ptrace error: {0}")]
    Ptrace(String),

    /// Memory operation failed
    #[error("Memory error: {0}")]
    Memory(String),

    /// Process not found
    #[error("Process not found: {0}")]
    ProcessNotFound(i32),

    /// Permission denied
    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    /// Invalid address
    #[error("Invalid address: 0x{0:x}")]
    InvalidAddress(u64),

    /// Pattern not found
    #[error("Pattern not found: {0}")]
    PatternNotFound(String),

    /// Architecture not supported
    #[error("Architecture not supported: {0:?}")]
    UnsupportedArchitecture(crate::Architecture),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Nix error
    #[error("System error: {0}")]
    Nix(#[from] nix::Error),

    /// Goblin error
    #[error("Goblin error: {0}")]
    Goblin(#[from] goblin::error::Error),

    /// Hook installation failed
    #[error("Hook installation failed: {0}")]
    HookFailed(String),

    /// Analysis failed
    #[error("Analysis failed: {0}")]
    AnalysisFailed(String),
}

/// Result type alias
pub type InstrumentResult<T> = Result<T, InstrumentError>;
