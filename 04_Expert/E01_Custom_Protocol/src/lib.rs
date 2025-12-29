//! # Custom Encrypted Network Protocol
//!
//! This crate implements a custom network protocol with:
//! - X25519 Diffie-Hellman key exchange
//! - AES-256-GCM authenticated encryption
//! - HKDF key derivation
//! - Custom message framing with integrity checks
//! - Replay protection via nonce management
//!
//! ## Protocol Overview
//!
//! ```text
//! Client                              Server
//!   |                                    |
//!   |------- ClientHello (pubkey) ------>|
//!   |                                    |
//!   |<------ ServerHello (pubkey) -------|
//!   |                                    |
//!   |  [Both derive shared secret]       |
//!   |                                    |
//!   |------- Encrypted Messages -------->|
//!   |<------ Encrypted Messages ---------|
//!   |                                    |
//! ```
//!
//! ## Security Properties
//!
//! - Perfect Forward Secrecy (ephemeral keys)
//! - Authenticated Encryption (AES-GCM)
//! - Protection against replay attacks
//! - Constant-time comparisons for secrets

pub mod crypto;
pub mod frame;
pub mod handshake;
pub mod session;
pub mod transport;
pub mod error;

pub use crypto::*;
pub use frame::*;
pub use handshake::*;
pub use session::*;
pub use transport::*;
pub use error::*;

/// Protocol version identifier
pub const PROTOCOL_VERSION: u8 = 1;

/// Maximum message size (1 MB)
pub const MAX_MESSAGE_SIZE: usize = 1024 * 1024;

/// Header magic bytes for protocol identification
pub const PROTOCOL_MAGIC: [u8; 4] = [0x53, 0x45, 0x43, 0x50]; // "SECP"

/// Nonce size for AES-GCM (96 bits)
pub const NONCE_SIZE: usize = 12;

/// Tag size for AES-GCM authentication
pub const TAG_SIZE: usize = 16;

/// Key size for AES-256
pub const KEY_SIZE: usize = 32;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_constants() {
        assert_eq!(PROTOCOL_MAGIC, [0x53, 0x45, 0x43, 0x50]);
        assert_eq!(NONCE_SIZE, 12);
        assert_eq!(KEY_SIZE, 32);
    }
}
