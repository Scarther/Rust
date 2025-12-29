//! # Protocol Error Types
//!
//! Comprehensive error handling for the custom protocol.

use thiserror::Error;

/// Main error type for protocol operations
#[derive(Error, Debug)]
pub enum ProtocolError {
    /// Invalid protocol magic bytes
    #[error("Invalid protocol magic: expected {expected:?}, got {actual:?}")]
    InvalidMagic {
        expected: [u8; 4],
        actual: [u8; 4],
    },

    /// Unsupported protocol version
    #[error("Unsupported protocol version: {0}")]
    UnsupportedVersion(u8),

    /// Message too large
    #[error("Message exceeds maximum size: {size} > {max}")]
    MessageTooLarge {
        size: usize,
        max: usize,
    },

    /// Cryptographic operation failed
    #[error("Cryptographic error: {0}")]
    CryptoError(String),

    /// Key exchange failed
    #[error("Key exchange failed: {0}")]
    KeyExchangeError(String),

    /// Authentication failed
    #[error("Authentication failed: {0}")]
    AuthenticationError(String),

    /// Frame parsing error
    #[error("Frame parsing error: {0}")]
    FrameError(String),

    /// Handshake failed
    #[error("Handshake failed: {0}")]
    HandshakeError(String),

    /// Session error
    #[error("Session error: {0}")]
    SessionError(String),

    /// Replay attack detected
    #[error("Replay attack detected: nonce {0} already used")]
    ReplayDetected(u64),

    /// Connection closed
    #[error("Connection closed unexpectedly")]
    ConnectionClosed,

    /// Timeout
    #[error("Operation timed out after {0} seconds")]
    Timeout(u64),

    /// IO error
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// CRC mismatch
    #[error("CRC mismatch: expected {expected:08x}, got {actual:08x}")]
    CrcMismatch {
        expected: u32,
        actual: u32,
    },

    /// Invalid state transition
    #[error("Invalid state transition: {from} -> {to}")]
    InvalidStateTransition {
        from: String,
        to: String,
    },
}

/// Result type alias for protocol operations
pub type ProtocolResult<T> = Result<T, ProtocolError>;

impl From<bincode::Error> for ProtocolError {
    fn from(e: bincode::Error) -> Self {
        ProtocolError::SerializationError(e.to_string())
    }
}

/// Error context for enhanced debugging
#[derive(Debug)]
pub struct ErrorContext {
    pub operation: String,
    pub details: String,
    pub source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl ErrorContext {
    pub fn new(operation: impl Into<String>, details: impl Into<String>) -> Self {
        Self {
            operation: operation.into(),
            details: details.into(),
            source: None,
        }
    }

    pub fn with_source(mut self, source: impl std::error::Error + Send + Sync + 'static) -> Self {
        self.source = Some(Box::new(source));
        self
    }
}

impl std::fmt::Display for ErrorContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.operation, self.details)?;
        if let Some(ref source) = self.source {
            write!(f, " (caused by: {})", source)?;
        }
        Ok(())
    }
}
