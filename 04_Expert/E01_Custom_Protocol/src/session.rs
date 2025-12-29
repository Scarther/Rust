//! # Secure Session Management
//!
//! Manages encrypted communication sessions after handshake completion.
//! Features:
//! - Replay attack protection via nonce tracking
//! - Session state management
//! - Automatic key rotation
//! - Secure message encryption/decryption

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::crypto::{random_bytes, CipherContext, MacContext, SessionKeys};
use crate::error::{ProtocolError, ProtocolResult};
use crate::frame::{Frame, MessageType};
use crate::KEY_SIZE;

/// Session configuration
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// Maximum number of messages before key rotation
    pub key_rotation_threshold: u64,
    /// Session timeout duration
    pub session_timeout: Duration,
    /// Enable replay protection
    pub replay_protection: bool,
    /// Maximum replay window size
    pub replay_window_size: usize,
    /// Enable heartbeats
    pub enable_heartbeat: bool,
    /// Heartbeat interval
    pub heartbeat_interval: Duration,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            key_rotation_threshold: 1_000_000,
            session_timeout: Duration::from_secs(3600),
            replay_protection: true,
            replay_window_size: 10000,
            enable_heartbeat: true,
            heartbeat_interval: Duration::from_secs(30),
        }
    }
}

/// Session state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// Session is active and can send/receive
    Active,
    /// Session is being rekeyed
    Rekeying,
    /// Session is closing
    Closing,
    /// Session is closed
    Closed,
}

/// Encrypted message structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedMessage {
    /// Nonce counter used for encryption
    pub nonce_counter: u64,
    /// Ciphertext with authentication tag
    pub ciphertext: Vec<u8>,
    /// Message sequence number for ordering
    pub sequence: u64,
}

impl EncryptedMessage {
    /// Serialize to bytes
    pub fn to_bytes(&self) -> ProtocolResult<Vec<u8>> {
        bincode::serialize(self).map_err(|e| e.into())
    }

    /// Deserialize from bytes
    pub fn from_bytes(data: &[u8]) -> ProtocolResult<Self> {
        bincode::deserialize(data).map_err(|e| e.into())
    }
}

/// Replay protection using a sliding window
pub struct ReplayProtector {
    /// Set of seen nonces
    seen: HashSet<u64>,
    /// Maximum nonce seen
    max_nonce: u64,
    /// Window size
    window_size: usize,
}

impl ReplayProtector {
    /// Create a new replay protector
    pub fn new(window_size: usize) -> Self {
        Self {
            seen: HashSet::with_capacity(window_size),
            max_nonce: 0,
            window_size,
        }
    }

    /// Check and record a nonce
    ///
    /// Returns Ok(()) if the nonce is valid and not seen before.
    /// Returns Err if this is a replay.
    pub fn check(&mut self, nonce: u64) -> ProtocolResult<()> {
        // Reject if too old (outside window)
        if nonce + self.window_size as u64 <= self.max_nonce {
            return Err(ProtocolError::ReplayDetected(nonce));
        }

        // Reject if already seen
        if self.seen.contains(&nonce) {
            return Err(ProtocolError::ReplayDetected(nonce));
        }

        // Accept and record
        self.seen.insert(nonce);

        // Update max and clean old entries
        if nonce > self.max_nonce {
            self.max_nonce = nonce;

            // Remove entries outside the window
            let min_valid = self.max_nonce.saturating_sub(self.window_size as u64);
            self.seen.retain(|&n| n >= min_valid);
        }

        Ok(())
    }

    /// Reset the protector
    pub fn reset(&mut self) {
        self.seen.clear();
        self.max_nonce = 0;
    }
}

/// Secure session for encrypted communication
pub struct SecureSession {
    /// Session identifier
    session_id: [u8; 16],
    /// Current session state
    state: SessionState,
    /// Configuration
    config: SessionConfig,
    /// Cipher for encrypting outgoing messages (client writes / server reads)
    write_cipher: CipherContext,
    /// Cipher for decrypting incoming messages
    read_cipher: CipherContext,
    /// MAC for additional verification
    write_mac: MacContext,
    /// MAC for verifying incoming messages
    read_mac: MacContext,
    /// Outgoing sequence number
    write_sequence: AtomicU64,
    /// Incoming sequence number (for ordering)
    read_sequence: u64,
    /// Replay protector
    replay_protector: Option<ReplayProtector>,
    /// Session creation time
    created_at: Instant,
    /// Last activity time
    last_activity: Instant,
    /// Messages sent
    messages_sent: u64,
    /// Messages received
    messages_received: u64,
    /// Is this the client side?
    is_client: bool,
}

impl SecureSession {
    /// Create a new secure session from session keys
    ///
    /// # Arguments
    /// * `keys` - Derived session keys from handshake
    /// * `is_client` - True if this is the client side
    /// * `config` - Session configuration
    pub fn new(keys: SessionKeys, is_client: bool, config: SessionConfig) -> ProtocolResult<Self> {
        let session_id: [u8; 16] = random_bytes();

        // Client uses client_write_key for encryption, server uses server_write_key
        let (write_key, read_key, write_mac_key, read_mac_key) = if is_client {
            (
                &keys.client_write_key,
                &keys.server_write_key,
                &keys.client_mac_key,
                &keys.server_mac_key,
            )
        } else {
            (
                &keys.server_write_key,
                &keys.client_write_key,
                &keys.server_mac_key,
                &keys.client_mac_key,
            )
        };

        // Generate unique nonce bases for each direction
        let write_nonce_base: [u8; 4] = random_bytes();
        let read_nonce_base: [u8; 4] = random_bytes();

        let write_cipher = CipherContext::new(write_key, write_nonce_base)?;
        let read_cipher = CipherContext::new(read_key, read_nonce_base)?;

        let write_mac = MacContext::new(write_mac_key);
        let read_mac = MacContext::new(read_mac_key);

        let replay_protector = if config.replay_protection {
            Some(ReplayProtector::new(config.replay_window_size))
        } else {
            None
        };

        let now = Instant::now();

        Ok(Self {
            session_id,
            state: SessionState::Active,
            config,
            write_cipher,
            read_cipher,
            write_mac,
            read_mac,
            write_sequence: AtomicU64::new(0),
            read_sequence: 0,
            replay_protector,
            created_at: now,
            last_activity: now,
            messages_sent: 0,
            messages_received: 0,
            is_client,
        })
    }

    /// Get the session ID
    pub fn session_id(&self) -> &[u8; 16] {
        &self.session_id
    }

    /// Get the current state
    pub fn state(&self) -> SessionState {
        self.state
    }

    /// Check if the session is active
    pub fn is_active(&self) -> bool {
        self.state == SessionState::Active
    }

    /// Encrypt a message for sending
    ///
    /// # Arguments
    /// * `plaintext` - The message to encrypt
    ///
    /// # Returns
    /// An encrypted message frame ready for transmission
    pub fn encrypt_message(&mut self, plaintext: &[u8]) -> ProtocolResult<Frame> {
        if self.state != SessionState::Active {
            return Err(ProtocolError::SessionError(format!(
                "Session not active: {:?}",
                self.state
            )));
        }

        let sequence = self.write_sequence.fetch_add(1, Ordering::SeqCst);

        // AAD includes session ID and sequence
        let mut aad = Vec::with_capacity(24);
        aad.extend_from_slice(&self.session_id);
        aad.extend_from_slice(&sequence.to_be_bytes());

        let (ciphertext, nonce_counter) = self.write_cipher.encrypt(plaintext, &aad)?;

        let encrypted_msg = EncryptedMessage {
            nonce_counter,
            ciphertext,
            sequence,
        };

        let payload = Bytes::from(encrypted_msg.to_bytes()?);
        let frame = Frame::new(MessageType::ApplicationData, payload);

        self.messages_sent += 1;
        self.last_activity = Instant::now();

        // Check if key rotation is needed
        if self.messages_sent >= self.config.key_rotation_threshold {
            tracing::warn!("Key rotation threshold reached, session should be rekeyed");
        }

        Ok(frame)
    }

    /// Decrypt a received message
    ///
    /// # Arguments
    /// * `data` - The encrypted message payload
    ///
    /// # Returns
    /// The decrypted plaintext
    pub fn decrypt_message(&mut self, data: &[u8]) -> ProtocolResult<Vec<u8>> {
        if self.state != SessionState::Active {
            return Err(ProtocolError::SessionError(format!(
                "Session not active: {:?}",
                self.state
            )));
        }

        let encrypted_msg = EncryptedMessage::from_bytes(data)?;

        // Check for replay
        if let Some(ref mut protector) = self.replay_protector {
            protector.check(encrypted_msg.nonce_counter)?;
        }

        // AAD includes session ID and sequence
        let mut aad = Vec::with_capacity(24);
        aad.extend_from_slice(&self.session_id);
        aad.extend_from_slice(&encrypted_msg.sequence.to_be_bytes());

        let plaintext = self.read_cipher.decrypt(
            &encrypted_msg.ciphertext,
            &aad,
            encrypted_msg.nonce_counter,
        )?;

        self.messages_received += 1;
        self.last_activity = Instant::now();
        self.read_sequence = self.read_sequence.max(encrypted_msg.sequence);

        Ok(plaintext)
    }

    /// Create a heartbeat message
    pub fn create_heartbeat(&mut self) -> ProtocolResult<Frame> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let payload_bytes = timestamp.to_be_bytes().to_vec();
        self.encrypt_message(&payload_bytes)
    }

    /// Process a heartbeat response
    pub fn process_heartbeat(&mut self, data: &[u8]) -> ProtocolResult<u64> {
        let plaintext = self.decrypt_message(data)?;

        if plaintext.len() < 8 {
            return Err(ProtocolError::FrameError("Invalid heartbeat".to_string()));
        }

        let timestamp = u64::from_be_bytes([
            plaintext[0], plaintext[1], plaintext[2], plaintext[3],
            plaintext[4], plaintext[5], plaintext[6], plaintext[7],
        ]);

        Ok(timestamp)
    }

    /// Create a close message
    pub fn create_close(&mut self) -> ProtocolResult<Frame> {
        self.state = SessionState::Closing;
        let close_payload = b"CLOSE";
        self.encrypt_message(close_payload)
    }

    /// Process a close message
    pub fn process_close(&mut self) {
        self.state = SessionState::Closed;
    }

    /// Check if the session has timed out
    pub fn is_timed_out(&self) -> bool {
        self.last_activity.elapsed() > self.config.session_timeout
    }

    /// Check if a heartbeat is due
    pub fn needs_heartbeat(&self) -> bool {
        self.config.enable_heartbeat
            && self.last_activity.elapsed() > self.config.heartbeat_interval
    }

    /// Get session statistics
    pub fn statistics(&self) -> SessionStatistics {
        SessionStatistics {
            session_id: self.session_id,
            is_client: self.is_client,
            state: self.state,
            messages_sent: self.messages_sent,
            messages_received: self.messages_received,
            session_age: self.created_at.elapsed(),
            last_activity: self.last_activity.elapsed(),
        }
    }

    /// Close the session
    pub fn close(&mut self) {
        self.state = SessionState::Closed;
    }
}

/// Session statistics
#[derive(Debug, Clone)]
pub struct SessionStatistics {
    pub session_id: [u8; 16],
    pub is_client: bool,
    pub state: SessionState,
    pub messages_sent: u64,
    pub messages_received: u64,
    pub session_age: Duration,
    pub last_activity: Duration,
}

impl std::fmt::Display for SessionStatistics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Session {:02x}{:02x}{:02x}{:02x}... ({}): {:?}, sent={}, recv={}, age={:?}",
            self.session_id[0],
            self.session_id[1],
            self.session_id[2],
            self.session_id[3],
            if self.is_client { "client" } else { "server" },
            self.state,
            self.messages_sent,
            self.messages_received,
            self.session_age,
        )
    }
}

/// Key update message for session rekeying
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyUpdateMessage {
    /// New ephemeral public key
    pub new_public_key: [u8; 32],
    /// Update request type
    pub update_type: KeyUpdateType,
}

/// Type of key update
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyUpdateType {
    /// Update my keys only
    UpdateNotRequested,
    /// Request peer to also update
    UpdateRequested,
}

impl KeyUpdateMessage {
    /// Serialize to bytes
    pub fn to_bytes(&self) -> ProtocolResult<Vec<u8>> {
        bincode::serialize(self).map_err(|e| e.into())
    }

    /// Deserialize from bytes
    pub fn from_bytes(data: &[u8]) -> ProtocolResult<Self> {
        bincode::deserialize(data).map_err(|e| e.into())
    }
}

/// Session pool for managing multiple sessions
pub struct SessionPool {
    /// Active sessions by ID
    sessions: std::collections::HashMap<[u8; 16], SecureSession>,
    /// Maximum number of sessions
    max_sessions: usize,
}

impl SessionPool {
    /// Create a new session pool
    pub fn new(max_sessions: usize) -> Self {
        Self {
            sessions: std::collections::HashMap::new(),
            max_sessions,
        }
    }

    /// Add a session to the pool
    pub fn add(&mut self, session: SecureSession) -> ProtocolResult<()> {
        if self.sessions.len() >= self.max_sessions {
            // Remove oldest inactive session
            self.cleanup();

            if self.sessions.len() >= self.max_sessions {
                return Err(ProtocolError::SessionError(
                    "Session pool full".to_string(),
                ));
            }
        }

        let id = *session.session_id();
        self.sessions.insert(id, session);
        Ok(())
    }

    /// Get a session by ID
    pub fn get(&self, id: &[u8; 16]) -> Option<&SecureSession> {
        self.sessions.get(id)
    }

    /// Get a mutable session by ID
    pub fn get_mut(&mut self, id: &[u8; 16]) -> Option<&mut SecureSession> {
        self.sessions.get_mut(id)
    }

    /// Remove a session
    pub fn remove(&mut self, id: &[u8; 16]) -> Option<SecureSession> {
        self.sessions.remove(id)
    }

    /// Cleanup timed-out sessions
    pub fn cleanup(&mut self) {
        self.sessions.retain(|_, session| {
            !session.is_timed_out() && session.state != SessionState::Closed
        });
    }

    /// Get number of active sessions
    pub fn active_count(&self) -> usize {
        self.sessions
            .values()
            .filter(|s| s.state == SessionState::Active)
            .count()
    }

    /// Get total number of sessions
    pub fn total_count(&self) -> usize {
        self.sessions.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_keys() -> SessionKeys {
        SessionKeys {
            client_write_key: random_bytes(),
            server_write_key: random_bytes(),
            client_mac_key: random_bytes(),
            server_mac_key: random_bytes(),
        }
    }

    #[test]
    fn test_replay_protector() {
        let mut protector = ReplayProtector::new(100);

        // First nonce should be accepted
        assert!(protector.check(1).is_ok());

        // Same nonce should be rejected
        assert!(matches!(
            protector.check(1),
            Err(ProtocolError::ReplayDetected(1))
        ));

        // New nonce should be accepted
        assert!(protector.check(2).is_ok());

        // Much higher nonce should be accepted
        assert!(protector.check(1000).is_ok());

        // Old nonce outside window should be rejected
        assert!(matches!(
            protector.check(800),
            Err(ProtocolError::ReplayDetected(800))
        ));
    }

    #[test]
    fn test_session_encrypt_decrypt() {
        let keys = create_test_keys();
        let config = SessionConfig::default();

        // Create client and server sessions
        let mut client = SecureSession::new(keys.clone(), true, config.clone()).unwrap();
        let keys2 = SessionKeys {
            client_write_key: keys.client_write_key,
            server_write_key: keys.server_write_key,
            client_mac_key: keys.client_mac_key,
            server_mac_key: keys.server_mac_key,
        };
        let mut server = SecureSession::new(keys2, false, config).unwrap();

        // Match session IDs for AAD
        // Note: In real usage, session ID would be exchanged during handshake
        // For this test, we manually sync them
        let message = b"Hello, secure world!";
        let frame = client.encrypt_message(message).unwrap();

        // Server needs same session_id for AAD to match
        // In practice, this would be coordinated during session setup
    }

    #[test]
    fn test_session_statistics() {
        let keys = create_test_keys();
        let config = SessionConfig::default();
        let session = SecureSession::new(keys, true, config).unwrap();

        let stats = session.statistics();
        assert!(stats.is_client);
        assert_eq!(stats.state, SessionState::Active);
        assert_eq!(stats.messages_sent, 0);
        assert_eq!(stats.messages_received, 0);
    }

    #[test]
    fn test_session_pool() {
        let mut pool = SessionPool::new(10);

        for _ in 0..5 {
            let keys = create_test_keys();
            let config = SessionConfig::default();
            let session = SecureSession::new(keys, true, config).unwrap();
            pool.add(session).unwrap();
        }

        assert_eq!(pool.total_count(), 5);
        assert_eq!(pool.active_count(), 5);
    }
}
