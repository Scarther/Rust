//! # Cryptographic Primitives
//!
//! This module provides the cryptographic foundation:
//! - X25519 key exchange
//! - AES-256-GCM encryption/decryption
//! - HKDF key derivation
//! - Secure random generation
//!
//! ## Security Considerations
//!
//! - All secret keys are zeroized on drop
//! - Constant-time operations where possible
//! - Proper nonce management to prevent reuse

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{ProtocolError, ProtocolResult};
use crate::{KEY_SIZE, NONCE_SIZE};

/// Ephemeral keypair for key exchange
///
/// Uses X25519 elliptic curve Diffie-Hellman.
/// The private key is automatically zeroized on drop.
pub struct KeyPair {
    /// The secret key (zeroized on drop)
    secret: Option<EphemeralSecret>,
    /// The public key for sharing
    pub public: PublicKey,
}

impl KeyPair {
    /// Generate a new random keypair
    ///
    /// Uses OS-provided cryptographically secure random numbers.
    pub fn generate() -> Self {
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self {
            secret: Some(secret),
            public,
        }
    }

    /// Perform Diffie-Hellman key exchange
    ///
    /// Consumes the secret key to prevent reuse.
    ///
    /// # Arguments
    /// * `peer_public` - The peer's public key
    ///
    /// # Returns
    /// The shared secret, which should be processed through HKDF
    pub fn exchange(mut self, peer_public: &PublicKey) -> ProtocolResult<SharedSecret> {
        let secret = self.secret.take().ok_or_else(|| {
            ProtocolError::KeyExchangeError("Secret key already consumed".to_string())
        })?;
        Ok(secret.diffie_hellman(peer_public))
    }

    /// Get the public key bytes for transmission
    pub fn public_bytes(&self) -> [u8; 32] {
        self.public.to_bytes()
    }
}

/// Derived session keys after key exchange
///
/// Contains separate keys for encryption and authentication.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SessionKeys {
    /// Key for client-to-server encryption
    pub client_write_key: [u8; KEY_SIZE],
    /// Key for server-to-client encryption
    pub server_write_key: [u8; KEY_SIZE],
    /// Key for client-to-server MAC
    pub client_mac_key: [u8; KEY_SIZE],
    /// Key for server-to-client MAC
    pub server_mac_key: [u8; KEY_SIZE],
}

impl SessionKeys {
    /// Derive session keys from shared secret using HKDF
    ///
    /// # Arguments
    /// * `shared_secret` - The DH shared secret
    /// * `client_random` - Random bytes from client hello
    /// * `server_random` - Random bytes from server hello
    ///
    /// # Security
    /// Uses HKDF-SHA256 with proper info strings for domain separation.
    pub fn derive(
        shared_secret: &[u8],
        client_random: &[u8; 32],
        server_random: &[u8; 32],
    ) -> ProtocolResult<Self> {
        // Construct the salt from randoms
        let mut salt = [0u8; 64];
        salt[..32].copy_from_slice(client_random);
        salt[32..].copy_from_slice(server_random);

        let hk = Hkdf::<Sha256>::new(Some(&salt), shared_secret);

        let mut client_write_key = [0u8; KEY_SIZE];
        let mut server_write_key = [0u8; KEY_SIZE];
        let mut client_mac_key = [0u8; KEY_SIZE];
        let mut server_mac_key = [0u8; KEY_SIZE];

        // Derive each key with different info strings
        hk.expand(b"client_write_key", &mut client_write_key)
            .map_err(|e| ProtocolError::CryptoError(format!("HKDF expand failed: {}", e)))?;
        hk.expand(b"server_write_key", &mut server_write_key)
            .map_err(|e| ProtocolError::CryptoError(format!("HKDF expand failed: {}", e)))?;
        hk.expand(b"client_mac_key", &mut client_mac_key)
            .map_err(|e| ProtocolError::CryptoError(format!("HKDF expand failed: {}", e)))?;
        hk.expand(b"server_mac_key", &mut server_mac_key)
            .map_err(|e| ProtocolError::CryptoError(format!("HKDF expand failed: {}", e)))?;

        // Zeroize the salt
        salt.zeroize();

        Ok(Self {
            client_write_key,
            server_write_key,
            client_mac_key,
            server_mac_key,
        })
    }
}

/// AES-256-GCM cipher context
///
/// Handles encryption and decryption with authenticated additional data.
pub struct CipherContext {
    /// The AES-GCM cipher instance
    cipher: Aes256Gcm,
    /// Counter for nonce generation (incremented per message)
    nonce_counter: u64,
    /// Base nonce derived from session
    nonce_base: [u8; 4],
}

impl CipherContext {
    /// Create a new cipher context
    ///
    /// # Arguments
    /// * `key` - 256-bit encryption key
    /// * `nonce_base` - 4-byte base for nonce construction
    pub fn new(key: &[u8; KEY_SIZE], nonce_base: [u8; 4]) -> ProtocolResult<Self> {
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| ProtocolError::CryptoError(format!("Failed to create cipher: {}", e)))?;

        Ok(Self {
            cipher,
            nonce_counter: 0,
            nonce_base,
        })
    }

    /// Generate the next nonce
    ///
    /// Nonce structure: [4 bytes base][8 bytes counter]
    /// This ensures unique nonces while preventing reuse.
    fn next_nonce(&mut self) -> [u8; NONCE_SIZE] {
        let mut nonce = [0u8; NONCE_SIZE];
        nonce[..4].copy_from_slice(&self.nonce_base);
        nonce[4..].copy_from_slice(&self.nonce_counter.to_be_bytes());
        self.nonce_counter = self.nonce_counter.wrapping_add(1);
        nonce
    }

    /// Construct a nonce for a specific counter value
    fn nonce_for_counter(&self, counter: u64) -> [u8; NONCE_SIZE] {
        let mut nonce = [0u8; NONCE_SIZE];
        nonce[..4].copy_from_slice(&self.nonce_base);
        nonce[4..].copy_from_slice(&counter.to_be_bytes());
        nonce
    }

    /// Encrypt plaintext with authenticated additional data
    ///
    /// # Arguments
    /// * `plaintext` - Data to encrypt
    /// * `aad` - Additional authenticated data (not encrypted, but authenticated)
    ///
    /// # Returns
    /// Tuple of (ciphertext_with_tag, nonce_counter)
    pub fn encrypt(&mut self, plaintext: &[u8], aad: &[u8]) -> ProtocolResult<(Vec<u8>, u64)> {
        let nonce_counter = self.nonce_counter;
        let nonce_bytes = self.next_nonce();
        let nonce = Nonce::from_slice(&nonce_bytes);

        let payload = Payload {
            msg: plaintext,
            aad,
        };

        let ciphertext = self.cipher.encrypt(nonce, payload).map_err(|e| {
            ProtocolError::CryptoError(format!("Encryption failed: {}", e))
        })?;

        Ok((ciphertext, nonce_counter))
    }

    /// Decrypt ciphertext with authenticated additional data
    ///
    /// # Arguments
    /// * `ciphertext` - Encrypted data with authentication tag
    /// * `aad` - Additional authenticated data
    /// * `nonce_counter` - The counter value used during encryption
    ///
    /// # Security
    /// Verifies the authentication tag before returning plaintext.
    pub fn decrypt(
        &self,
        ciphertext: &[u8],
        aad: &[u8],
        nonce_counter: u64,
    ) -> ProtocolResult<Vec<u8>> {
        let nonce_bytes = self.nonce_for_counter(nonce_counter);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let payload = Payload {
            msg: ciphertext,
            aad,
        };

        self.cipher.decrypt(nonce, payload).map_err(|e| {
            ProtocolError::AuthenticationError(format!("Decryption/authentication failed: {}", e))
        })
    }

    /// Get the current nonce counter
    pub fn current_counter(&self) -> u64 {
        self.nonce_counter
    }
}

/// HMAC-SHA256 for message authentication
pub struct MacContext {
    key: [u8; KEY_SIZE],
}

impl MacContext {
    /// Create a new MAC context
    pub fn new(key: &[u8; KEY_SIZE]) -> Self {
        Self { key: *key }
    }

    /// Compute HMAC over data
    pub fn compute(&self, data: &[u8]) -> [u8; 32] {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.key)
            .expect("HMAC can take key of any size");
        mac.update(data);
        mac.finalize().into_bytes().into()
    }

    /// Verify HMAC in constant time
    pub fn verify(&self, data: &[u8], expected: &[u8; 32]) -> bool {
        let computed = self.compute(data);
        constant_time_eq::constant_time_eq_32(&computed, expected)
    }
}

impl Drop for MacContext {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

/// Generate cryptographically secure random bytes
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

/// Generate a random u64
pub fn random_u64() -> u64 {
    OsRng.next_u64()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let kp1 = KeyPair::generate();
        let kp2 = KeyPair::generate();

        // Public keys should be different
        assert_ne!(kp1.public_bytes(), kp2.public_bytes());
    }

    #[test]
    fn test_key_exchange() {
        let alice = KeyPair::generate();
        let bob = KeyPair::generate();

        let alice_public = alice.public;
        let bob_public = bob.public;

        let alice_shared = alice.exchange(&bob_public).unwrap();
        let bob_shared = bob.exchange(&alice_public).unwrap();

        // Shared secrets should be identical
        assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
    }

    #[test]
    fn test_session_keys_derivation() {
        let shared_secret = random_bytes::<32>();
        let client_random = random_bytes::<32>();
        let server_random = random_bytes::<32>();

        let keys = SessionKeys::derive(&shared_secret, &client_random, &server_random).unwrap();

        // All keys should be different
        assert_ne!(keys.client_write_key, keys.server_write_key);
        assert_ne!(keys.client_mac_key, keys.server_mac_key);
    }

    #[test]
    fn test_encryption_decryption() {
        let key = random_bytes::<KEY_SIZE>();
        let nonce_base = random_bytes::<4>();

        let mut cipher = CipherContext::new(&key, nonce_base).unwrap();
        let plaintext = b"Hello, secure world!";
        let aad = b"additional data";

        let (ciphertext, counter) = cipher.encrypt(plaintext, aad).unwrap();

        // Create new context for decryption (simulates receiver)
        let cipher2 = CipherContext::new(&key, nonce_base).unwrap();
        let decrypted = cipher2.decrypt(&ciphertext, aad, counter).unwrap();

        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_mac() {
        let key = random_bytes::<KEY_SIZE>();
        let mac_ctx = MacContext::new(&key);

        let data = b"message to authenticate";
        let tag = mac_ctx.compute(data);

        assert!(mac_ctx.verify(data, &tag));

        // Tampered data should fail
        let mut tampered = *data;
        tampered[0] ^= 1;
        assert!(!mac_ctx.verify(&tampered, &tag));
    }
}
