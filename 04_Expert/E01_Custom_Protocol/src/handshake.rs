//! # Protocol Handshake
//!
//! Implements the key exchange handshake:
//! 1. Client sends ClientHello with public key and random
//! 2. Server responds with ServerHello with public key and random
//! 3. Both derive shared secrets
//! 4. Handshake finished confirmations
//!
//! ## Security Properties
//!
//! - Perfect Forward Secrecy: Ephemeral keys used for each session
//! - Mutual Key Confirmation: Both parties verify key derivation

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use x25519_dalek::PublicKey;

use crate::crypto::{random_bytes, KeyPair, SessionKeys};
use crate::error::{ProtocolError, ProtocolResult};
use crate::frame::{Frame, MessageType};
use crate::PROTOCOL_VERSION;

/// Client hello message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientHello {
    /// Protocol version
    pub version: u8,
    /// Client's ephemeral public key
    pub public_key: [u8; 32],
    /// Random bytes for key derivation
    pub random: [u8; 32],
    /// Optional client identifier
    pub client_id: Option<String>,
    /// Supported cipher suites (for future extensibility)
    pub cipher_suites: Vec<u8>,
    /// Unix timestamp
    pub timestamp: u64,
}

impl ClientHello {
    /// Create a new client hello with generated keys
    pub fn new(keypair: &KeyPair, client_id: Option<String>) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            public_key: keypair.public_bytes(),
            random: random_bytes(),
            client_id,
            cipher_suites: vec![0x01], // Only AES-256-GCM supported
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> ProtocolResult<Vec<u8>> {
        bincode::serialize(self).map_err(|e| e.into())
    }

    /// Deserialize from bytes
    pub fn from_bytes(data: &[u8]) -> ProtocolResult<Self> {
        bincode::deserialize(data).map_err(|e| e.into())
    }

    /// Create a protocol frame
    pub fn to_frame(&self) -> ProtocolResult<Frame> {
        let payload = Bytes::from(self.to_bytes()?);
        Ok(Frame::new(MessageType::ClientHello, payload))
    }

    /// Get the public key
    pub fn get_public_key(&self) -> ProtocolResult<PublicKey> {
        Ok(PublicKey::from(self.public_key))
    }

    /// Validate the client hello
    pub fn validate(&self) -> ProtocolResult<()> {
        if self.version != PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedVersion(self.version));
        }

        if !self.cipher_suites.contains(&0x01) {
            return Err(ProtocolError::HandshakeError(
                "No supported cipher suite".to_string(),
            ));
        }

        // Check timestamp is within acceptable range (5 minutes)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if self.timestamp > now + 300 || self.timestamp < now.saturating_sub(300) {
            return Err(ProtocolError::HandshakeError(
                "Timestamp out of acceptable range".to_string(),
            ));
        }

        Ok(())
    }
}

/// Server hello message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerHello {
    /// Protocol version
    pub version: u8,
    /// Server's ephemeral public key
    pub public_key: [u8; 32],
    /// Random bytes for key derivation
    pub random: [u8; 32],
    /// Selected cipher suite
    pub selected_cipher: u8,
    /// Server identifier
    pub server_id: Option<String>,
    /// Unix timestamp
    pub timestamp: u64,
}

impl ServerHello {
    /// Create a new server hello
    pub fn new(keypair: &KeyPair, client_hello: &ClientHello, server_id: Option<String>) -> ProtocolResult<Self> {
        // Validate client's cipher suites
        if !client_hello.cipher_suites.contains(&0x01) {
            return Err(ProtocolError::HandshakeError(
                "No common cipher suite".to_string(),
            ));
        }

        Ok(Self {
            version: PROTOCOL_VERSION,
            public_key: keypair.public_bytes(),
            random: random_bytes(),
            selected_cipher: 0x01, // AES-256-GCM
            server_id,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        })
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> ProtocolResult<Vec<u8>> {
        bincode::serialize(self).map_err(|e| e.into())
    }

    /// Deserialize from bytes
    pub fn from_bytes(data: &[u8]) -> ProtocolResult<Self> {
        bincode::deserialize(data).map_err(|e| e.into())
    }

    /// Create a protocol frame
    pub fn to_frame(&self) -> ProtocolResult<Frame> {
        let payload = Bytes::from(self.to_bytes()?);
        Ok(Frame::new(MessageType::ServerHello, payload))
    }

    /// Get the public key
    pub fn get_public_key(&self) -> ProtocolResult<PublicKey> {
        Ok(PublicKey::from(self.public_key))
    }
}

/// Handshake finished message
///
/// Contains a verify hash to confirm both parties derived the same keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeFinished {
    /// Hash of the handshake transcript
    pub verify_data: [u8; 32],
}

impl HandshakeFinished {
    /// Create from session keys and handshake data
    pub fn new(keys: &SessionKeys, is_client: bool, handshake_data: &[u8]) -> Self {
        use sha2::{Sha256, Digest};

        let mut hasher = Sha256::new();
        hasher.update(if is_client { b"client" } else { b"server" });
        hasher.update(&keys.client_write_key);
        hasher.update(&keys.server_write_key);
        hasher.update(handshake_data);

        let result = hasher.finalize();
        let mut verify_data = [0u8; 32];
        verify_data.copy_from_slice(&result);

        Self { verify_data }
    }

    /// Verify the finished message
    pub fn verify(
        &self,
        keys: &SessionKeys,
        is_client: bool,
        handshake_data: &[u8],
    ) -> ProtocolResult<()> {
        let expected = Self::new(keys, is_client, handshake_data);

        if !constant_time_eq::constant_time_eq_32(&self.verify_data, &expected.verify_data) {
            return Err(ProtocolError::HandshakeError(
                "Handshake verification failed".to_string(),
            ));
        }

        Ok(())
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> ProtocolResult<Vec<u8>> {
        bincode::serialize(self).map_err(|e| e.into())
    }

    /// Deserialize from bytes
    pub fn from_bytes(data: &[u8]) -> ProtocolResult<Self> {
        bincode::deserialize(data).map_err(|e| e.into())
    }

    /// Create a protocol frame
    pub fn to_frame(&self) -> ProtocolResult<Frame> {
        let payload = Bytes::from(self.to_bytes()?);
        Ok(Frame::new(MessageType::HandshakeFinished, payload))
    }
}

/// Handshake state machine states
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeState {
    /// Initial state
    Initial,
    /// Awaiting client hello
    AwaitingClientHello,
    /// Awaiting server hello
    AwaitingServerHello,
    /// Awaiting handshake finished
    AwaitingFinished,
    /// Handshake complete
    Complete,
    /// Handshake failed
    Failed,
}

impl std::fmt::Display for HandshakeState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Initial => write!(f, "Initial"),
            Self::AwaitingClientHello => write!(f, "AwaitingClientHello"),
            Self::AwaitingServerHello => write!(f, "AwaitingServerHello"),
            Self::AwaitingFinished => write!(f, "AwaitingFinished"),
            Self::Complete => write!(f, "Complete"),
            Self::Failed => write!(f, "Failed"),
        }
    }
}

/// Client-side handshake handler
pub struct ClientHandshake {
    state: HandshakeState,
    keypair: Option<KeyPair>,
    client_hello: Option<ClientHello>,
    server_hello: Option<ServerHello>,
    session_keys: Option<SessionKeys>,
    handshake_transcript: Vec<u8>,
}

impl ClientHandshake {
    /// Create a new client handshake
    pub fn new() -> Self {
        Self {
            state: HandshakeState::Initial,
            keypair: None,
            client_hello: None,
            server_hello: None,
            session_keys: None,
            handshake_transcript: Vec::new(),
        }
    }

    /// Start the handshake by generating client hello
    pub fn start(&mut self, client_id: Option<String>) -> ProtocolResult<Frame> {
        if self.state != HandshakeState::Initial {
            return Err(ProtocolError::InvalidStateTransition {
                from: self.state.to_string(),
                to: "Starting handshake".to_string(),
            });
        }

        let keypair = KeyPair::generate();
        let client_hello = ClientHello::new(&keypair, client_id);

        // Record in transcript
        let hello_bytes = client_hello.to_bytes()?;
        self.handshake_transcript.extend_from_slice(&hello_bytes);

        let frame = client_hello.to_frame()?;

        self.keypair = Some(keypair);
        self.client_hello = Some(client_hello);
        self.state = HandshakeState::AwaitingServerHello;

        Ok(frame)
    }

    /// Process server hello
    pub fn process_server_hello(&mut self, data: &[u8]) -> ProtocolResult<()> {
        if self.state != HandshakeState::AwaitingServerHello {
            return Err(ProtocolError::InvalidStateTransition {
                from: self.state.to_string(),
                to: "Processing server hello".to_string(),
            });
        }

        let server_hello = ServerHello::from_bytes(data)?;

        // Record in transcript
        self.handshake_transcript.extend_from_slice(data);

        // Perform key exchange
        let keypair = self.keypair.take().ok_or_else(|| {
            ProtocolError::HandshakeError("Keypair not available".to_string())
        })?;

        let server_public = server_hello.get_public_key()?;
        let shared_secret = keypair.exchange(&server_public)?;

        let client_hello = self.client_hello.as_ref().ok_or_else(|| {
            ProtocolError::HandshakeError("Client hello not available".to_string())
        })?;

        // Derive session keys
        let session_keys = SessionKeys::derive(
            shared_secret.as_bytes(),
            &client_hello.random,
            &server_hello.random,
        )?;

        self.session_keys = Some(session_keys);
        self.server_hello = Some(server_hello);
        self.state = HandshakeState::AwaitingFinished;

        Ok(())
    }

    /// Generate handshake finished message
    pub fn finish(&mut self) -> ProtocolResult<Frame> {
        if self.state != HandshakeState::AwaitingFinished {
            return Err(ProtocolError::InvalidStateTransition {
                from: self.state.to_string(),
                to: "Finishing handshake".to_string(),
            });
        }

        let keys = self.session_keys.as_ref().ok_or_else(|| {
            ProtocolError::HandshakeError("Session keys not available".to_string())
        })?;

        let finished = HandshakeFinished::new(keys, true, &self.handshake_transcript);
        let frame = finished.to_frame()?;

        self.state = HandshakeState::Complete;

        Ok(frame)
    }

    /// Get the derived session keys
    pub fn take_session_keys(&mut self) -> Option<SessionKeys> {
        if self.state == HandshakeState::Complete {
            self.session_keys.take()
        } else {
            None
        }
    }

    /// Check if handshake is complete
    pub fn is_complete(&self) -> bool {
        self.state == HandshakeState::Complete
    }

    /// Get current state
    pub fn state(&self) -> HandshakeState {
        self.state
    }
}

impl Default for ClientHandshake {
    fn default() -> Self {
        Self::new()
    }
}

/// Server-side handshake handler
pub struct ServerHandshake {
    state: HandshakeState,
    keypair: Option<KeyPair>,
    client_hello: Option<ClientHello>,
    server_hello: Option<ServerHello>,
    session_keys: Option<SessionKeys>,
    handshake_transcript: Vec<u8>,
}

impl ServerHandshake {
    /// Create a new server handshake
    pub fn new() -> Self {
        Self {
            state: HandshakeState::AwaitingClientHello,
            keypair: None,
            client_hello: None,
            server_hello: None,
            session_keys: None,
            handshake_transcript: Vec::new(),
        }
    }

    /// Process client hello and generate server hello
    pub fn process_client_hello(
        &mut self,
        data: &[u8],
        server_id: Option<String>,
    ) -> ProtocolResult<Frame> {
        if self.state != HandshakeState::AwaitingClientHello {
            return Err(ProtocolError::InvalidStateTransition {
                from: self.state.to_string(),
                to: "Processing client hello".to_string(),
            });
        }

        let client_hello = ClientHello::from_bytes(data)?;
        client_hello.validate()?;

        // Record in transcript
        self.handshake_transcript.extend_from_slice(data);

        // Generate our keypair
        let keypair = KeyPair::generate();
        let server_hello = ServerHello::new(&keypair, &client_hello, server_id)?;

        // Record in transcript
        let server_hello_bytes = server_hello.to_bytes()?;
        self.handshake_transcript.extend_from_slice(&server_hello_bytes);

        // Perform key exchange
        let client_public = client_hello.get_public_key()?;
        let shared_secret = keypair.exchange(&client_public)?;

        // Derive session keys
        let session_keys = SessionKeys::derive(
            shared_secret.as_bytes(),
            &client_hello.random,
            &server_hello.random,
        )?;

        let frame = server_hello.to_frame()?;

        self.client_hello = Some(client_hello);
        self.server_hello = Some(server_hello);
        self.session_keys = Some(session_keys);
        self.state = HandshakeState::AwaitingFinished;

        Ok(frame)
    }

    /// Process client's handshake finished
    pub fn process_finished(&mut self, data: &[u8]) -> ProtocolResult<Frame> {
        if self.state != HandshakeState::AwaitingFinished {
            return Err(ProtocolError::InvalidStateTransition {
                from: self.state.to_string(),
                to: "Processing finished".to_string(),
            });
        }

        let client_finished = HandshakeFinished::from_bytes(data)?;

        let keys = self.session_keys.as_ref().ok_or_else(|| {
            ProtocolError::HandshakeError("Session keys not available".to_string())
        })?;

        // Verify client's finished message
        client_finished.verify(keys, true, &self.handshake_transcript)?;

        // Generate server's finished message
        let server_finished = HandshakeFinished::new(keys, false, &self.handshake_transcript);
        let frame = server_finished.to_frame()?;

        self.state = HandshakeState::Complete;

        Ok(frame)
    }

    /// Get the derived session keys
    pub fn take_session_keys(&mut self) -> Option<SessionKeys> {
        if self.state == HandshakeState::Complete {
            self.session_keys.take()
        } else {
            None
        }
    }

    /// Check if handshake is complete
    pub fn is_complete(&self) -> bool {
        self.state == HandshakeState::Complete
    }

    /// Get current state
    pub fn state(&self) -> HandshakeState {
        self.state
    }
}

impl Default for ServerHandshake {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_hello_roundtrip() {
        let keypair = KeyPair::generate();
        let hello = ClientHello::new(&keypair, Some("test-client".to_string()));

        let bytes = hello.to_bytes().unwrap();
        let parsed = ClientHello::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.version, hello.version);
        assert_eq!(parsed.public_key, hello.public_key);
        assert_eq!(parsed.client_id, hello.client_id);
    }

    #[test]
    fn test_full_handshake() {
        // Client starts handshake
        let mut client_hs = ClientHandshake::new();
        let client_hello_frame = client_hs.start(Some("client".to_string())).unwrap();

        // Server processes client hello
        let mut server_hs = ServerHandshake::new();
        let server_hello_frame = server_hs
            .process_client_hello(client_hello_frame.payload(), Some("server".to_string()))
            .unwrap();

        // Client processes server hello
        client_hs.process_server_hello(server_hello_frame.payload()).unwrap();

        // Client sends finished
        let client_finished_frame = client_hs.finish().unwrap();

        // Server processes finished and responds
        let _server_finished = server_hs.process_finished(client_finished_frame.payload()).unwrap();

        // Both should be complete
        assert!(client_hs.is_complete());
        assert!(server_hs.is_complete());

        // Both should have session keys
        let client_keys = client_hs.take_session_keys().unwrap();
        let server_keys = server_hs.take_session_keys().unwrap();

        // Keys should match
        assert_eq!(client_keys.client_write_key, server_keys.client_write_key);
        assert_eq!(client_keys.server_write_key, server_keys.server_write_key);
    }
}
