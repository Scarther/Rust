//! # Crypto Tool - Advanced Encryption/Decryption Utility
//!
//! This tool provides cryptographic operations including:
//! - Symmetric encryption (AES-128, AES-256 in CBC, CTR, GCM modes)
//! - Asymmetric encryption (RSA with OAEP padding)
//! - Hashing (SHA-256, SHA-512, SHA3, BLAKE2, MD5)
//! - Key derivation (PBKDF2, Argon2)
//! - HMAC authentication
//!
//! ## Cryptographic Concepts
//!
//! ### Symmetric vs Asymmetric Encryption
//!
//! **Symmetric (AES)**:
//! - Same key for encryption and decryption
//! - Fast, efficient for large data
//! - Challenge: Secure key exchange
//!
//! **Asymmetric (RSA)**:
//! - Public key encrypts, private key decrypts
//! - Slower, but solves key exchange problem
//! - Often used to encrypt symmetric keys
//!
//! ### Block Cipher Modes
//!
//! - **CBC (Cipher Block Chaining)**: Each block XORed with previous ciphertext
//! - **CTR (Counter)**: Turns block cipher into stream cipher
//! - **GCM (Galois/Counter Mode)**: CTR + authentication tag
//!
//! ### Key Derivation Functions (KDFs)
//!
//! Convert passwords to cryptographic keys:
//! - PBKDF2: Widely supported, uses many iterations
//! - Argon2: Memory-hard, resists GPU/ASIC attacks
//!
//! ## Security Considerations
//!
//! - Never reuse IVs/nonces with the same key
//! - Use authenticated encryption (GCM) when possible
//! - Store passwords with Argon2, not plain hashes
//! - RSA key size: minimum 2048 bits, prefer 4096

use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce as GcmNonce,
};
use anyhow::{Context, Result};
use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
use blake2::{Blake2b512, Blake2s256};
use clap::{Parser, Subcommand, ValueEnum};
use colored::*;
use hmac::{Hmac, Mac};
use md5::Md5;
use pbkdf2::pbkdf2_hmac;
use rand::{rngs::OsRng, RngCore};
use rsa::{
    pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey, EncodeRsaPrivateKey, EncodeRsaPublicKey},
    Oaep, RsaPrivateKey, RsaPublicKey,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use sha3::{Sha3_256, Sha3_512};
use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;
use thiserror::Error;

// Type aliases for HMAC
type HmacSha256 = Hmac<Sha256>;
type HmacSha512 = Hmac<Sha512>;

// Type aliases for AES-CBC
type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

// ============================================================================
// ERROR HANDLING
// ============================================================================

/// Cryptographic operation errors
#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Invalid key length: expected {expected}, got {got}")]
    InvalidKeyLength { expected: usize, got: usize },

    #[error("Invalid IV/nonce length: expected {expected}, got {got}")]
    InvalidIvLength { expected: usize, got: usize },

    #[error("Encryption failed: {0}")]
    EncryptionError(String),

    #[error("Decryption failed: {0}")]
    DecryptionError(String),

    #[error("Authentication failed")]
    AuthenticationError,

    #[error("Key generation failed: {0}")]
    KeyGenError(String),

    #[error("Invalid padding")]
    PaddingError,

    #[error("RSA operation failed: {0}")]
    RsaError(String),

    #[error("Hash error: {0}")]
    HashError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

// ============================================================================
// CLI INTERFACE
// ============================================================================

/// Crypto Tool - Encryption, Decryption, and Hashing Utility
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Commands,

    /// Output format
    #[arg(short, long, value_enum, default_value = "hex")]
    format: OutputFormat,

    /// Verbose output with explanations
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Encrypt data using symmetric encryption
    Encrypt {
        /// Algorithm to use
        #[arg(short, long, value_enum, default_value = "aes-256-gcm")]
        algorithm: SymmetricAlgorithm,

        /// Input data (string or @file for file input)
        #[arg(short, long)]
        input: String,

        /// Encryption key (hex encoded) or @file for key file
        #[arg(short, long)]
        key: String,

        /// IV/Nonce (hex encoded, auto-generated if not provided)
        #[arg(long)]
        iv: Option<String>,

        /// Output file (optional)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Decrypt data using symmetric encryption
    Decrypt {
        /// Algorithm to use
        #[arg(short, long, value_enum, default_value = "aes-256-gcm")]
        algorithm: SymmetricAlgorithm,

        /// Input data (hex encoded) or @file for file input
        #[arg(short, long)]
        input: String,

        /// Decryption key (hex encoded) or @file for key file
        #[arg(short, long)]
        key: String,

        /// IV/Nonce (hex encoded)
        #[arg(long)]
        iv: String,

        /// Output file (optional)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Generate RSA key pair
    RsaKeygen {
        /// Key size in bits
        #[arg(short, long, default_value = "2048")]
        bits: usize,

        /// Output file prefix
        #[arg(short, long)]
        output: PathBuf,
    },

    /// Encrypt with RSA public key
    RsaEncrypt {
        /// Public key file (PEM format)
        #[arg(short, long)]
        pubkey: PathBuf,

        /// Input data
        #[arg(short, long)]
        input: String,
    },

    /// Decrypt with RSA private key
    RsaDecrypt {
        /// Private key file (PEM format)
        #[arg(short, long)]
        privkey: PathBuf,

        /// Input data (hex or base64 encoded)
        #[arg(short, long)]
        input: String,
    },

    /// Compute hash of data
    Hash {
        /// Hash algorithm
        #[arg(short, long, value_enum, default_value = "sha256")]
        algorithm: HashAlgorithm,

        /// Input data or @file for file input
        #[arg(short, long)]
        input: String,
    },

    /// Compute HMAC
    Hmac {
        /// Hash algorithm for HMAC
        #[arg(short, long, value_enum, default_value = "sha256")]
        algorithm: HashAlgorithm,

        /// Input data
        #[arg(short, long)]
        input: String,

        /// HMAC key (hex encoded)
        #[arg(short, long)]
        key: String,
    },

    /// Derive key from password
    Kdf {
        /// Key derivation function
        #[arg(short, long, value_enum, default_value = "argon2")]
        algorithm: KdfAlgorithm,

        /// Password
        #[arg(short, long)]
        password: String,

        /// Salt (hex encoded, auto-generated if not provided)
        #[arg(short, long)]
        salt: Option<String>,

        /// Output key length in bytes
        #[arg(short, long, default_value = "32")]
        length: usize,

        /// Iterations (for PBKDF2)
        #[arg(long, default_value = "100000")]
        iterations: u32,
    },

    /// Generate random key/IV
    Generate {
        /// Number of random bytes
        #[arg(short, long, default_value = "32")]
        bytes: usize,
    },
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum SymmetricAlgorithm {
    /// AES-128 in CBC mode
    Aes128Cbc,
    /// AES-256 in CBC mode
    Aes256Cbc,
    /// AES-256 in GCM mode (authenticated)
    Aes256Gcm,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum HashAlgorithm {
    Md5,
    Sha256,
    Sha512,
    Sha3_256,
    Sha3_512,
    Blake2s,
    Blake2b,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum KdfAlgorithm {
    Pbkdf2,
    Argon2,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum OutputFormat {
    Hex,
    Base64,
    Raw,
}

// ============================================================================
// CRYPTOGRAPHIC OPERATIONS
// ============================================================================

/// AES Encryption/Decryption Module
///
/// ## AES (Advanced Encryption Standard)
///
/// AES is a symmetric block cipher with:
/// - Block size: 128 bits (16 bytes)
/// - Key sizes: 128, 192, or 256 bits
///
/// ### Mode Selection
///
/// **CBC (Cipher Block Chaining)**:
/// ```text
/// Plaintext:  P1  P2  P3  ...
///              |   |   |
///       IV -> XOR  |   |
///              |   v   |
///              v  XOR  v
///            E(K) E(K) E(K)
///              |   |   |
///              v   v   v
/// Ciphertext: C1  C2  C3  ...
/// ```
/// - Requires padding (PKCS7)
/// - IV must be random and unique
/// - Sequential encryption (can't parallelize)
///
/// **GCM (Galois/Counter Mode)**:
/// - Provides authentication (integrity check)
/// - Parallelizable
/// - No padding needed
/// - Produces 16-byte authentication tag
pub mod aes_ops {
    use super::*;

    /// Encrypt data using AES-CBC with PKCS7 padding
    ///
    /// # Arguments
    /// * `data` - Plaintext to encrypt
    /// * `key` - AES key (16 or 32 bytes)
    /// * `iv` - Initialization vector (16 bytes)
    ///
    /// # Security Notes
    /// - IV must be unique for each encryption with the same key
    /// - Consider using GCM mode for authenticated encryption
    pub fn encrypt_aes_cbc(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if iv.len() != 16 {
            return Err(CryptoError::InvalidIvLength {
                expected: 16,
                got: iv.len(),
            });
        }

        // Calculate padded length (PKCS7)
        let block_size = 16;
        let padding_len = block_size - (data.len() % block_size);
        let padded_len = data.len() + padding_len;

        // Create padded buffer
        let mut buffer = vec![padding_len as u8; padded_len];
        buffer[..data.len()].copy_from_slice(data);

        match key.len() {
            16 => {
                let cipher = Aes128CbcEnc::new_from_slices(key, iv)
                    .map_err(|e| CryptoError::EncryptionError(e.to_string()))?;
                cipher.encrypt_padded_mut::<block_padding::NoPadding>(&mut buffer, data.len())
                    .map_err(|e| CryptoError::EncryptionError(e.to_string()))?;
            }
            32 => {
                let cipher = Aes256CbcEnc::new_from_slices(key, iv)
                    .map_err(|e| CryptoError::EncryptionError(e.to_string()))?;
                cipher.encrypt_padded_mut::<block_padding::NoPadding>(&mut buffer, data.len())
                    .map_err(|e| CryptoError::EncryptionError(e.to_string()))?;
            }
            _ => {
                return Err(CryptoError::InvalidKeyLength {
                    expected: 32,
                    got: key.len(),
                });
            }
        }

        Ok(buffer)
    }

    /// Decrypt AES-CBC encrypted data
    pub fn decrypt_aes_cbc(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if iv.len() != 16 {
            return Err(CryptoError::InvalidIvLength {
                expected: 16,
                got: iv.len(),
            });
        }

        if data.len() % 16 != 0 {
            return Err(CryptoError::DecryptionError(
                "Ciphertext length must be multiple of block size".to_string(),
            ));
        }

        let mut buffer = data.to_vec();

        match key.len() {
            16 => {
                let cipher = Aes128CbcDec::new_from_slices(key, iv)
                    .map_err(|e| CryptoError::DecryptionError(e.to_string()))?;
                cipher.decrypt_padded_mut::<block_padding::NoPadding>(&mut buffer)
                    .map_err(|e| CryptoError::DecryptionError(e.to_string()))?;
            }
            32 => {
                let cipher = Aes256CbcDec::new_from_slices(key, iv)
                    .map_err(|e| CryptoError::DecryptionError(e.to_string()))?;
                cipher.decrypt_padded_mut::<block_padding::NoPadding>(&mut buffer)
                    .map_err(|e| CryptoError::DecryptionError(e.to_string()))?;
            }
            _ => {
                return Err(CryptoError::InvalidKeyLength {
                    expected: 32,
                    got: key.len(),
                });
            }
        }

        // Remove PKCS7 padding
        if let Some(&padding_len) = buffer.last() {
            if padding_len as usize <= 16 && padding_len > 0 {
                let new_len = buffer.len() - padding_len as usize;
                buffer.truncate(new_len);
            }
        }

        Ok(buffer)
    }

    /// Encrypt using AES-256-GCM (authenticated encryption)
    ///
    /// ## GCM Mode
    ///
    /// GCM provides both confidentiality and integrity:
    /// - Encryption: AES in counter mode
    /// - Authentication: GHASH over ciphertext
    /// - Output: ciphertext || 16-byte tag
    ///
    /// # Security Notes
    /// - Nonce MUST be unique for each encryption with same key
    /// - Nonce reuse completely breaks security
    /// - Tag provides tamper detection
    pub fn encrypt_aes_gcm(data: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if key.len() != 32 {
            return Err(CryptoError::InvalidKeyLength {
                expected: 32,
                got: key.len(),
            });
        }

        if nonce.len() != 12 {
            return Err(CryptoError::InvalidIvLength {
                expected: 12,
                got: nonce.len(),
            });
        }

        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| CryptoError::EncryptionError(e.to_string()))?;

        let nonce = GcmNonce::from_slice(nonce);

        cipher
            .encrypt(nonce, data)
            .map_err(|e| CryptoError::EncryptionError(e.to_string()))
    }

    /// Decrypt AES-256-GCM
    pub fn decrypt_aes_gcm(data: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if key.len() != 32 {
            return Err(CryptoError::InvalidKeyLength {
                expected: 32,
                got: key.len(),
            });
        }

        if nonce.len() != 12 {
            return Err(CryptoError::InvalidIvLength {
                expected: 12,
                got: nonce.len(),
            });
        }

        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| CryptoError::DecryptionError(e.to_string()))?;

        let nonce = GcmNonce::from_slice(nonce);

        cipher
            .decrypt(nonce, data)
            .map_err(|_| CryptoError::AuthenticationError)
    }
}

/// RSA Operations Module
///
/// ## RSA Encryption
///
/// RSA is based on the mathematical difficulty of factoring large primes:
/// - Key generation: Choose primes p, q; compute n = p*q
/// - Public key: (n, e) where e is typically 65537
/// - Private key: d where e*d ≡ 1 (mod φ(n))
///
/// ### OAEP Padding
///
/// Optimal Asymmetric Encryption Padding prevents various attacks:
/// - Prevents chosen ciphertext attacks
/// - Provides semantic security (same plaintext → different ciphertexts)
/// - Maximum message size: key_size - 2*hash_size - 2
///
/// For 2048-bit RSA with SHA-256: 2048/8 - 2*32 - 2 = 190 bytes max
///
/// ### Security Notes
/// - Key size: Minimum 2048 bits, prefer 4096 for long-term security
/// - RSA is slow; typically used to encrypt symmetric keys only
/// - Always use padding (never "textbook RSA")
pub mod rsa_ops {
    use super::*;

    /// Generate RSA key pair
    ///
    /// # Arguments
    /// * `bits` - Key size (2048, 3072, or 4096 recommended)
    ///
    /// # Returns
    /// Tuple of (private_key, public_key) in PEM format
    pub fn generate_keypair(bits: usize) -> Result<(String, String), CryptoError> {
        let mut rng = OsRng;

        // Generate private key
        let private_key = RsaPrivateKey::new(&mut rng, bits)
            .map_err(|e| CryptoError::KeyGenError(e.to_string()))?;

        // Derive public key
        let public_key = RsaPublicKey::from(&private_key);

        // Encode to PEM
        let private_pem = private_key
            .to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
            .map_err(|e| CryptoError::KeyGenError(e.to_string()))?
            .to_string();

        let public_pem = public_key
            .to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
            .map_err(|e| CryptoError::KeyGenError(e.to_string()))?;

        Ok((private_pem, public_pem))
    }

    /// Encrypt data with RSA public key using OAEP padding
    pub fn encrypt(public_key_pem: &str, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let public_key = RsaPublicKey::from_pkcs1_pem(public_key_pem)
            .map_err(|e| CryptoError::RsaError(e.to_string()))?;

        let mut rng = OsRng;
        let padding = Oaep::new::<Sha256>();

        public_key
            .encrypt(&mut rng, padding, data)
            .map_err(|e| CryptoError::RsaError(e.to_string()))
    }

    /// Decrypt data with RSA private key
    pub fn decrypt(private_key_pem: &str, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let private_key = RsaPrivateKey::from_pkcs1_pem(private_key_pem)
            .map_err(|e| CryptoError::RsaError(e.to_string()))?;

        let padding = Oaep::new::<Sha256>();

        private_key
            .decrypt(padding, data)
            .map_err(|e| CryptoError::RsaError(e.to_string()))
    }
}

/// Hashing Operations Module
///
/// ## Cryptographic Hash Functions
///
/// Properties:
/// 1. **Deterministic**: Same input → same output
/// 2. **Quick to compute**: Efficient for any input size
/// 3. **Pre-image resistant**: Hard to find input from hash
/// 4. **Collision resistant**: Hard to find two inputs with same hash
/// 5. **Avalanche effect**: Small input change → large output change
///
/// ### Algorithm Comparison
///
/// | Algorithm | Output Size | Speed    | Security  |
/// |-----------|-------------|----------|-----------|
/// | MD5       | 128 bits    | Fast     | BROKEN    |
/// | SHA-256   | 256 bits    | Medium   | Strong    |
/// | SHA-512   | 512 bits    | Medium   | Strong    |
/// | SHA3-256  | 256 bits    | Medium   | Strong    |
/// | BLAKE2b   | 512 bits    | Fast     | Strong    |
/// | BLAKE2s   | 256 bits    | Fast     | Strong    |
///
/// ### When to Use Each
/// - **MD5**: NEVER for security (only for checksums, legacy)
/// - **SHA-256**: Digital signatures, certificates, general use
/// - **SHA-512**: When 256-bit security margin isn't enough
/// - **SHA-3**: Post-quantum considerations, diversity
/// - **BLAKE2**: Performance-critical applications
pub mod hash_ops {
    use super::*;

    /// Compute hash of data using specified algorithm
    pub fn hash(data: &[u8], algorithm: HashAlgorithm) -> Vec<u8> {
        match algorithm {
            HashAlgorithm::Md5 => {
                let mut hasher = Md5::new();
                hasher.update(data);
                hasher.finalize().to_vec()
            }
            HashAlgorithm::Sha256 => {
                let mut hasher = Sha256::new();
                hasher.update(data);
                hasher.finalize().to_vec()
            }
            HashAlgorithm::Sha512 => {
                let mut hasher = Sha512::new();
                hasher.update(data);
                hasher.finalize().to_vec()
            }
            HashAlgorithm::Sha3_256 => {
                let mut hasher = Sha3_256::new();
                hasher.update(data);
                hasher.finalize().to_vec()
            }
            HashAlgorithm::Sha3_512 => {
                let mut hasher = Sha3_512::new();
                hasher.update(data);
                hasher.finalize().to_vec()
            }
            HashAlgorithm::Blake2s => {
                let mut hasher = Blake2s256::new();
                hasher.update(data);
                hasher.finalize().to_vec()
            }
            HashAlgorithm::Blake2b => {
                let mut hasher = Blake2b512::new();
                hasher.update(data);
                hasher.finalize().to_vec()
            }
        }
    }

    /// Compute HMAC using specified algorithm
    ///
    /// ## HMAC (Hash-based Message Authentication Code)
    ///
    /// HMAC provides:
    /// - Message integrity: Detect tampering
    /// - Message authenticity: Verify sender has the key
    ///
    /// Construction: HMAC(K, M) = H((K ⊕ opad) || H((K ⊕ ipad) || M))
    ///
    /// Unlike plain hashes, HMACs require a secret key, preventing
    /// an attacker from computing valid MACs.
    pub fn hmac(data: &[u8], key: &[u8], algorithm: HashAlgorithm) -> Result<Vec<u8>, CryptoError> {
        match algorithm {
            HashAlgorithm::Sha256 => {
                let mut mac = HmacSha256::new_from_slice(key)
                    .map_err(|e| CryptoError::HashError(e.to_string()))?;
                mac.update(data);
                Ok(mac.finalize().into_bytes().to_vec())
            }
            HashAlgorithm::Sha512 => {
                let mut mac = HmacSha512::new_from_slice(key)
                    .map_err(|e| CryptoError::HashError(e.to_string()))?;
                mac.update(data);
                Ok(mac.finalize().into_bytes().to_vec())
            }
            _ => Err(CryptoError::HashError(
                "HMAC only supports SHA-256 and SHA-512".to_string(),
            )),
        }
    }
}

/// Key Derivation Functions Module
///
/// ## Purpose of KDFs
///
/// KDFs convert passwords (low entropy) to cryptographic keys (high entropy):
/// - Add computational cost to slow brute-force attacks
/// - Use salt to prevent rainbow table attacks
/// - Produce fixed-size output regardless of password length
///
/// ### PBKDF2 (Password-Based Key Derivation Function 2)
///
/// - Applies HMAC repeatedly (iterations)
/// - Widely supported in standards and libraries
/// - Recommended: 100,000+ iterations for SHA-256
///
/// ### Argon2 (Winner of Password Hashing Competition 2015)
///
/// Three variants:
/// - **Argon2d**: Data-dependent, GPU-resistant (non-side-channel safe)
/// - **Argon2i**: Data-independent, side-channel safe
/// - **Argon2id**: Hybrid (recommended for passwords)
///
/// Parameters:
/// - Memory: Amount of RAM used (resists GPU attacks)
/// - Iterations: Time cost
/// - Parallelism: Number of threads
///
/// Recommended for passwords: Argon2id with 64MB memory, 3 iterations
pub mod kdf_ops {
    use super::*;

    /// Derive key using PBKDF2
    ///
    /// # Arguments
    /// * `password` - User password
    /// * `salt` - Random salt (should be unique per password)
    /// * `iterations` - Number of iterations (higher = slower/more secure)
    /// * `key_length` - Desired output length in bytes
    pub fn pbkdf2_derive(
        password: &[u8],
        salt: &[u8],
        iterations: u32,
        key_length: usize,
    ) -> Vec<u8> {
        let mut key = vec![0u8; key_length];
        pbkdf2_hmac::<Sha256>(password, salt, iterations, &mut key);
        key
    }

    /// Derive key using Argon2id
    ///
    /// # Arguments
    /// * `password` - User password
    /// * `salt` - Random salt (16+ bytes recommended)
    /// * `key_length` - Desired output length in bytes
    ///
    /// Uses recommended defaults:
    /// - Memory: 64 MB (65536 KB)
    /// - Iterations: 3
    /// - Parallelism: 4
    pub fn argon2_derive(
        password: &[u8],
        salt: &[u8],
    ) -> Result<String, CryptoError> {
        let salt = SaltString::encode_b64(salt)
            .map_err(|e| CryptoError::HashError(e.to_string()))?;

        let argon2 = Argon2::default();

        let hash = argon2
            .hash_password(password, &salt)
            .map_err(|e| CryptoError::HashError(e.to_string()))?;

        Ok(hash.to_string())
    }
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/// Parse input that may be a file reference (@filename) or direct data
fn parse_input(input: &str) -> Result<Vec<u8>> {
    if let Some(path) = input.strip_prefix('@') {
        fs::read(path).context(format!("Failed to read file: {}", path))
    } else {
        Ok(input.as_bytes().to_vec())
    }
}

/// Parse hex key that may be from file
fn parse_key(key: &str) -> Result<Vec<u8>> {
    if let Some(path) = key.strip_prefix('@') {
        let content = fs::read_to_string(path)
            .context(format!("Failed to read key file: {}", path))?;
        hex::decode(content.trim())
            .context("Failed to decode key as hex")
    } else {
        hex::decode(key).context("Failed to decode key as hex")
    }
}

/// Generate random bytes
fn generate_random_bytes(len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

/// Format output based on requested format
fn format_output(data: &[u8], format: OutputFormat) -> String {
    match format {
        OutputFormat::Hex => hex::encode(data),
        OutputFormat::Base64 => base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            data,
        ),
        OutputFormat::Raw => String::from_utf8_lossy(data).to_string(),
    }
}

// ============================================================================
// MAIN COMMAND HANDLERS
// ============================================================================

fn handle_encrypt(
    algorithm: SymmetricAlgorithm,
    input: &str,
    key: &str,
    iv: Option<String>,
    output: Option<PathBuf>,
    format: OutputFormat,
    verbose: bool,
) -> Result<()> {
    let data = parse_input(input)?;
    let key_bytes = parse_key(key)?;

    let (iv_bytes, iv_generated) = match iv {
        Some(iv_str) => (hex::decode(&iv_str)?, false),
        None => {
            let len = match algorithm {
                SymmetricAlgorithm::Aes256Gcm => 12,
                _ => 16,
            };
            (generate_random_bytes(len), true)
        }
    };

    if verbose {
        println!("\n{}", "[ ENCRYPTION OPERATION ]".cyan().bold());
        println!("  Algorithm:    {:?}", algorithm);
        println!("  Key length:   {} bytes", key_bytes.len());
        println!("  IV/Nonce:     {} bytes {}", iv_bytes.len(),
                 if iv_generated { "(auto-generated)" } else { "(provided)" });
        println!("  Input size:   {} bytes", data.len());
    }

    let ciphertext = match algorithm {
        SymmetricAlgorithm::Aes128Cbc | SymmetricAlgorithm::Aes256Cbc => {
            aes_ops::encrypt_aes_cbc(&data, &key_bytes, &iv_bytes)?
        }
        SymmetricAlgorithm::Aes256Gcm => {
            aes_ops::encrypt_aes_gcm(&data, &key_bytes, &iv_bytes)?
        }
    };

    if verbose {
        println!("  Output size:  {} bytes", ciphertext.len());
        if algorithm == SymmetricAlgorithm::Aes256Gcm {
            println!("  {} Authenticated encryption with 16-byte tag", "[*]".green());
        }
    }

    // Output results
    match output {
        Some(path) => {
            fs::write(&path, &ciphertext)?;
            println!("\n{}", "OUTPUT".green().bold());
            println!("  Ciphertext written to: {:?}", path);
        }
        None => {
            println!("\n{}", "OUTPUT".green().bold());
        }
    }

    println!("  Ciphertext: {}", format_output(&ciphertext, format));
    println!("  IV/Nonce:   {}", hex::encode(&iv_bytes));

    Ok(())
}

fn handle_decrypt(
    algorithm: SymmetricAlgorithm,
    input: &str,
    key: &str,
    iv: &str,
    output: Option<PathBuf>,
    format: OutputFormat,
    verbose: bool,
) -> Result<()> {
    let ciphertext = if input.starts_with('@') {
        fs::read(&input[1..])?
    } else {
        hex::decode(input)?
    };

    let key_bytes = parse_key(key)?;
    let iv_bytes = hex::decode(iv)?;

    if verbose {
        println!("\n{}", "[ DECRYPTION OPERATION ]".cyan().bold());
        println!("  Algorithm:   {:?}", algorithm);
        println!("  Key length:  {} bytes", key_bytes.len());
        println!("  IV/Nonce:    {} bytes", iv_bytes.len());
        println!("  Input size:  {} bytes", ciphertext.len());
    }

    let plaintext = match algorithm {
        SymmetricAlgorithm::Aes128Cbc | SymmetricAlgorithm::Aes256Cbc => {
            aes_ops::decrypt_aes_cbc(&ciphertext, &key_bytes, &iv_bytes)?
        }
        SymmetricAlgorithm::Aes256Gcm => {
            aes_ops::decrypt_aes_gcm(&ciphertext, &key_bytes, &iv_bytes)?
        }
    };

    if verbose {
        println!("  Output size: {} bytes", plaintext.len());
        if algorithm == SymmetricAlgorithm::Aes256Gcm {
            println!("  {} Authentication tag verified", "[+]".green());
        }
    }

    // Output results
    match output {
        Some(path) => {
            fs::write(&path, &plaintext)?;
            println!("\n{}", "OUTPUT".green().bold());
            println!("  Plaintext written to: {:?}", path);
        }
        None => {
            println!("\n{}", "OUTPUT".green().bold());
            println!("  Plaintext: {}", format_output(&plaintext, format));
        }
    }

    Ok(())
}

fn handle_rsa_keygen(bits: usize, output: PathBuf, verbose: bool) -> Result<()> {
    if verbose {
        println!("\n{}", "[ RSA KEY GENERATION ]".cyan().bold());
        println!("  Key size: {} bits", bits);
        println!("  Generating... (this may take a moment)");
    }

    let (private_pem, public_pem) = rsa_ops::generate_keypair(bits)?;

    let private_path = output.with_extension("key");
    let public_path = output.with_extension("pub");

    fs::write(&private_path, &private_pem)?;
    fs::write(&public_path, &public_pem)?;

    println!("\n{}", "OUTPUT".green().bold());
    println!("  Private key: {:?}", private_path);
    println!("  Public key:  {:?}", public_path);

    if verbose {
        println!("\n{}", "[ SECURITY REMINDER ]".yellow());
        println!("  - Keep the private key SECRET");
        println!("  - Set restrictive file permissions (chmod 600)");
        println!("  - Consider encrypting the private key");
    }

    Ok(())
}

fn handle_rsa_encrypt(pubkey: PathBuf, input: &str, format: OutputFormat, verbose: bool) -> Result<()> {
    let public_pem = fs::read_to_string(&pubkey)?;
    let data = parse_input(input)?;

    if verbose {
        println!("\n{}", "[ RSA ENCRYPTION ]".cyan().bold());
        println!("  Public key:  {:?}", pubkey);
        println!("  Input size:  {} bytes", data.len());
    }

    let ciphertext = rsa_ops::encrypt(&public_pem, &data)?;

    if verbose {
        println!("  Output size: {} bytes", ciphertext.len());
    }

    println!("\n{}", "OUTPUT".green().bold());
    println!("  Ciphertext: {}", format_output(&ciphertext, format));

    Ok(())
}

fn handle_rsa_decrypt(privkey: PathBuf, input: &str, format: OutputFormat, verbose: bool) -> Result<()> {
    let private_pem = fs::read_to_string(&privkey)?;
    let ciphertext = hex::decode(input)?;

    if verbose {
        println!("\n{}", "[ RSA DECRYPTION ]".cyan().bold());
        println!("  Private key: {:?}", privkey);
        println!("  Input size:  {} bytes", ciphertext.len());
    }

    let plaintext = rsa_ops::decrypt(&private_pem, &ciphertext)?;

    if verbose {
        println!("  Output size: {} bytes", plaintext.len());
    }

    println!("\n{}", "OUTPUT".green().bold());
    println!("  Plaintext: {}", format_output(&plaintext, format));

    Ok(())
}

fn handle_hash(algorithm: HashAlgorithm, input: &str, format: OutputFormat, verbose: bool) -> Result<()> {
    let data = parse_input(input)?;

    if verbose {
        println!("\n{}", "[ HASH OPERATION ]".cyan().bold());
        println!("  Algorithm:  {:?}", algorithm);
        println!("  Input size: {} bytes", data.len());

        // Security warning for MD5
        if algorithm == HashAlgorithm::Md5 {
            println!("\n  {}", "WARNING: MD5 is cryptographically broken!".red());
            println!("  Do not use for security-critical applications.");
        }
    }

    let hash = hash_ops::hash(&data, algorithm);

    println!("\n{}", "OUTPUT".green().bold());
    println!("  Hash: {}", format_output(&hash, format));
    println!("  Size: {} bits", hash.len() * 8);

    Ok(())
}

fn handle_hmac(algorithm: HashAlgorithm, input: &str, key: &str, format: OutputFormat, verbose: bool) -> Result<()> {
    let data = parse_input(input)?;
    let key_bytes = parse_key(key)?;

    if verbose {
        println!("\n{}", "[ HMAC OPERATION ]".cyan().bold());
        println!("  Algorithm:  HMAC-{:?}", algorithm);
        println!("  Key size:   {} bytes", key_bytes.len());
        println!("  Input size: {} bytes", data.len());
    }

    let mac = hash_ops::hmac(&data, &key_bytes, algorithm)?;

    println!("\n{}", "OUTPUT".green().bold());
    println!("  HMAC: {}", format_output(&mac, format));

    Ok(())
}

fn handle_kdf(
    algorithm: KdfAlgorithm,
    password: &str,
    salt: Option<String>,
    length: usize,
    iterations: u32,
    format: OutputFormat,
    verbose: bool,
) -> Result<()> {
    let salt_bytes = match salt {
        Some(s) => hex::decode(&s)?,
        None => generate_random_bytes(16),
    };

    if verbose {
        println!("\n{}", "[ KEY DERIVATION ]".cyan().bold());
        println!("  Algorithm:  {:?}", algorithm);
        println!("  Salt:       {} bytes", salt_bytes.len());
        if algorithm == KdfAlgorithm::Pbkdf2 {
            println!("  Iterations: {}", iterations);
        }
        println!("  Output:     {} bytes", length);
    }

    match algorithm {
        KdfAlgorithm::Pbkdf2 => {
            let key = kdf_ops::pbkdf2_derive(password.as_bytes(), &salt_bytes, iterations, length);
            println!("\n{}", "OUTPUT".green().bold());
            println!("  Key:  {}", format_output(&key, format));
            println!("  Salt: {}", hex::encode(&salt_bytes));
        }
        KdfAlgorithm::Argon2 => {
            let hash = kdf_ops::argon2_derive(password.as_bytes(), &salt_bytes)?;
            println!("\n{}", "OUTPUT".green().bold());
            println!("  Hash: {}", hash);
        }
    }

    Ok(())
}

fn handle_generate(bytes: usize, format: OutputFormat, verbose: bool) -> Result<()> {
    let random_bytes = generate_random_bytes(bytes);

    if verbose {
        println!("\n{}", "[ RANDOM GENERATION ]".cyan().bold());
        println!("  Source: Operating system CSPRNG");
        println!("  Size:   {} bytes ({} bits)", bytes, bytes * 8);
    }

    println!("\n{}", "OUTPUT".green().bold());
    println!("  Random: {}", format_output(&random_bytes, format));

    Ok(())
}

// ============================================================================
// MAIN
// ============================================================================

fn main() -> Result<()> {
    let args = Args::parse();

    match args.command {
        Commands::Encrypt { algorithm, input, key, iv, output } => {
            handle_encrypt(algorithm, &input, &key, iv, output, args.format, args.verbose)?;
        }
        Commands::Decrypt { algorithm, input, key, iv, output } => {
            handle_decrypt(algorithm, &input, &key, &iv, output, args.format, args.verbose)?;
        }
        Commands::RsaKeygen { bits, output } => {
            handle_rsa_keygen(bits, output, args.verbose)?;
        }
        Commands::RsaEncrypt { pubkey, input } => {
            handle_rsa_encrypt(pubkey, &input, args.format, args.verbose)?;
        }
        Commands::RsaDecrypt { privkey, input } => {
            handle_rsa_decrypt(privkey, &input, args.format, args.verbose)?;
        }
        Commands::Hash { algorithm, input } => {
            handle_hash(algorithm, &input, args.format, args.verbose)?;
        }
        Commands::Hmac { algorithm, input, key } => {
            handle_hmac(algorithm, &input, &key, args.format, args.verbose)?;
        }
        Commands::Kdf { algorithm, password, salt, length, iterations } => {
            handle_kdf(algorithm, &password, salt, length, iterations, args.format, args.verbose)?;
        }
        Commands::Generate { bytes } => {
            handle_generate(bytes, args.format, args.verbose)?;
        }
    }

    Ok(())
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_cbc_roundtrip() {
        let plaintext = b"Hello, World! This is a test message for AES-CBC.";
        let key = generate_random_bytes(32);
        let iv = generate_random_bytes(16);

        let ciphertext = aes_ops::encrypt_aes_cbc(plaintext, &key, &iv).unwrap();
        let decrypted = aes_ops::decrypt_aes_cbc(&ciphertext, &key, &iv).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_aes_gcm_roundtrip() {
        let plaintext = b"Secret message for GCM test";
        let key = generate_random_bytes(32);
        let nonce = generate_random_bytes(12);

        let ciphertext = aes_ops::encrypt_aes_gcm(plaintext, &key, &nonce).unwrap();
        let decrypted = aes_ops::decrypt_aes_gcm(&ciphertext, &key, &nonce).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_aes_gcm_authentication() {
        let plaintext = b"Test message";
        let key = generate_random_bytes(32);
        let nonce = generate_random_bytes(12);

        let mut ciphertext = aes_ops::encrypt_aes_gcm(plaintext, &key, &nonce).unwrap();

        // Tamper with ciphertext
        if !ciphertext.is_empty() {
            ciphertext[0] ^= 0xFF;
        }

        // Decryption should fail due to authentication
        let result = aes_ops::decrypt_aes_gcm(&ciphertext, &key, &nonce);
        assert!(result.is_err());
    }

    #[test]
    fn test_hash_consistency() {
        let data = b"test data";

        // Same input should produce same hash
        let hash1 = hash_ops::hash(data, HashAlgorithm::Sha256);
        let hash2 = hash_ops::hash(data, HashAlgorithm::Sha256);
        assert_eq!(hash1, hash2);

        // Different input should produce different hash
        let hash3 = hash_ops::hash(b"different data", HashAlgorithm::Sha256);
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_hash_sizes() {
        let data = b"test";

        assert_eq!(hash_ops::hash(data, HashAlgorithm::Md5).len(), 16);      // 128 bits
        assert_eq!(hash_ops::hash(data, HashAlgorithm::Sha256).len(), 32);   // 256 bits
        assert_eq!(hash_ops::hash(data, HashAlgorithm::Sha512).len(), 64);   // 512 bits
        assert_eq!(hash_ops::hash(data, HashAlgorithm::Sha3_256).len(), 32); // 256 bits
        assert_eq!(hash_ops::hash(data, HashAlgorithm::Blake2b).len(), 64);  // 512 bits
    }

    #[test]
    fn test_hmac() {
        let data = b"message";
        let key = b"secret_key";

        let hmac = hash_ops::hmac(data, key, HashAlgorithm::Sha256).unwrap();
        assert_eq!(hmac.len(), 32);

        // Same inputs should produce same HMAC
        let hmac2 = hash_ops::hmac(data, key, HashAlgorithm::Sha256).unwrap();
        assert_eq!(hmac, hmac2);

        // Different key should produce different HMAC
        let hmac3 = hash_ops::hmac(data, b"other_key", HashAlgorithm::Sha256).unwrap();
        assert_ne!(hmac, hmac3);
    }

    #[test]
    fn test_pbkdf2() {
        let password = b"password123";
        let salt = b"randomsalt";

        let key1 = kdf_ops::pbkdf2_derive(password, salt, 1000, 32);
        let key2 = kdf_ops::pbkdf2_derive(password, salt, 1000, 32);

        // Same inputs should produce same key
        assert_eq!(key1, key2);
        assert_eq!(key1.len(), 32);

        // Different iterations should produce different key
        let key3 = kdf_ops::pbkdf2_derive(password, salt, 2000, 32);
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_random_generation() {
        let random1 = generate_random_bytes(32);
        let random2 = generate_random_bytes(32);

        // Should be different (with overwhelming probability)
        assert_ne!(random1, random2);
        assert_eq!(random1.len(), 32);
    }

    #[test]
    fn test_invalid_key_lengths() {
        let plaintext = b"test";
        let bad_key = vec![0u8; 15]; // Invalid length
        let iv = generate_random_bytes(16);

        let result = aes_ops::encrypt_aes_cbc(plaintext, &bad_key, &iv);
        assert!(result.is_err());
    }
}
