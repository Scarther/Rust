//! # Message Framing
//!
//! This module handles the wire format for protocol messages:
//! - Frame header with magic, version, and length
//! - CRC32 integrity checking
//! - Message type identification
//!
//! ## Frame Format
//!
//! ```text
//! +--------+--------+--------+----------+----------+--------+
//! | Magic  | Version| Type   | Length   | Payload  | CRC32  |
//! | 4 bytes| 1 byte | 1 byte | 4 bytes  | variable | 4 bytes|
//! +--------+--------+--------+----------+----------+--------+
//! ```

use bytes::{Buf, BufMut, Bytes, BytesMut};
use serde::{Deserialize, Serialize};

use crate::error::{ProtocolError, ProtocolResult};
use crate::{MAX_MESSAGE_SIZE, PROTOCOL_MAGIC, PROTOCOL_VERSION};

/// Frame header size in bytes
pub const FRAME_HEADER_SIZE: usize = 10; // magic(4) + version(1) + type(1) + length(4)

/// CRC trailer size
pub const FRAME_CRC_SIZE: usize = 4;

/// Minimum frame size
pub const MIN_FRAME_SIZE: usize = FRAME_HEADER_SIZE + FRAME_CRC_SIZE;

/// Message types in the protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum MessageType {
    /// Client hello during handshake
    ClientHello = 0x01,
    /// Server hello response
    ServerHello = 0x02,
    /// Handshake finished confirmation
    HandshakeFinished = 0x03,
    /// Encrypted application data
    ApplicationData = 0x10,
    /// Alert/error notification
    Alert = 0x20,
    /// Connection close
    Close = 0x30,
    /// Heartbeat/keepalive
    Heartbeat = 0x40,
    /// Key update request
    KeyUpdate = 0x50,
}

impl TryFrom<u8> for MessageType {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(MessageType::ClientHello),
            0x02 => Ok(MessageType::ServerHello),
            0x03 => Ok(MessageType::HandshakeFinished),
            0x10 => Ok(MessageType::ApplicationData),
            0x20 => Ok(MessageType::Alert),
            0x30 => Ok(MessageType::Close),
            0x40 => Ok(MessageType::Heartbeat),
            0x50 => Ok(MessageType::KeyUpdate),
            _ => Err(ProtocolError::FrameError(format!(
                "Unknown message type: 0x{:02x}",
                value
            ))),
        }
    }
}

/// Frame header structure
#[derive(Debug, Clone)]
pub struct FrameHeader {
    /// Protocol magic bytes
    pub magic: [u8; 4],
    /// Protocol version
    pub version: u8,
    /// Message type
    pub message_type: MessageType,
    /// Payload length (not including header or CRC)
    pub length: u32,
}

impl FrameHeader {
    /// Create a new frame header
    pub fn new(message_type: MessageType, length: u32) -> Self {
        Self {
            magic: PROTOCOL_MAGIC,
            version: PROTOCOL_VERSION,
            message_type,
            length,
        }
    }

    /// Serialize the header to bytes
    pub fn to_bytes(&self) -> [u8; FRAME_HEADER_SIZE] {
        let mut buf = [0u8; FRAME_HEADER_SIZE];
        buf[0..4].copy_from_slice(&self.magic);
        buf[4] = self.version;
        buf[5] = self.message_type as u8;
        buf[6..10].copy_from_slice(&self.length.to_be_bytes());
        buf
    }

    /// Parse a header from bytes
    pub fn from_bytes(data: &[u8]) -> ProtocolResult<Self> {
        if data.len() < FRAME_HEADER_SIZE {
            return Err(ProtocolError::FrameError(format!(
                "Header too short: {} < {}",
                data.len(),
                FRAME_HEADER_SIZE
            )));
        }

        let mut magic = [0u8; 4];
        magic.copy_from_slice(&data[0..4]);

        if magic != PROTOCOL_MAGIC {
            return Err(ProtocolError::InvalidMagic {
                expected: PROTOCOL_MAGIC,
                actual: magic,
            });
        }

        let version = data[4];
        if version != PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedVersion(version));
        }

        let message_type = MessageType::try_from(data[5])?;

        let length = u32::from_be_bytes([data[6], data[7], data[8], data[9]]);

        if length as usize > MAX_MESSAGE_SIZE {
            return Err(ProtocolError::MessageTooLarge {
                size: length as usize,
                max: MAX_MESSAGE_SIZE,
            });
        }

        Ok(Self {
            magic,
            version,
            message_type,
            length,
        })
    }
}

/// Complete protocol frame
#[derive(Debug, Clone)]
pub struct Frame {
    /// Frame header
    pub header: FrameHeader,
    /// Payload data
    pub payload: Bytes,
    /// CRC32 checksum
    pub crc: u32,
}

impl Frame {
    /// Create a new frame with automatic CRC calculation
    pub fn new(message_type: MessageType, payload: Bytes) -> Self {
        let header = FrameHeader::new(message_type, payload.len() as u32);
        let crc = Self::calculate_crc(&header, &payload);

        Self {
            header,
            payload,
            crc,
        }
    }

    /// Calculate CRC32 over header and payload
    fn calculate_crc(header: &FrameHeader, payload: &[u8]) -> u32 {
        let mut hasher = crc32fast::Hasher::new();
        hasher.update(&header.to_bytes());
        hasher.update(payload);
        hasher.finalize()
    }

    /// Serialize the complete frame to bytes
    pub fn to_bytes(&self) -> BytesMut {
        let total_len = FRAME_HEADER_SIZE + self.payload.len() + FRAME_CRC_SIZE;
        let mut buf = BytesMut::with_capacity(total_len);

        buf.put_slice(&self.header.to_bytes());
        buf.put_slice(&self.payload);
        buf.put_u32(self.crc);

        buf
    }

    /// Parse a frame from a byte buffer
    ///
    /// Returns the frame and number of bytes consumed, or None if incomplete.
    pub fn parse(data: &mut BytesMut) -> ProtocolResult<Option<Self>> {
        // Check if we have enough for the header
        if data.len() < FRAME_HEADER_SIZE {
            return Ok(None);
        }

        // Parse header without consuming
        let header = FrameHeader::from_bytes(data)?;

        // Check if we have the complete frame
        let frame_len = FRAME_HEADER_SIZE + header.length as usize + FRAME_CRC_SIZE;
        if data.len() < frame_len {
            return Ok(None);
        }

        // Consume the header
        data.advance(FRAME_HEADER_SIZE);

        // Extract payload
        let payload = data.split_to(header.length as usize).freeze();

        // Extract CRC
        let crc = data.get_u32();

        // Verify CRC
        let expected_crc = Self::calculate_crc(&header, &payload);
        if crc != expected_crc {
            return Err(ProtocolError::CrcMismatch {
                expected: expected_crc,
                actual: crc,
            });
        }

        Ok(Some(Self {
            header,
            payload,
            crc,
        }))
    }

    /// Get the message type
    pub fn message_type(&self) -> MessageType {
        self.header.message_type
    }

    /// Get the payload
    pub fn payload(&self) -> &Bytes {
        &self.payload
    }

    /// Total frame size
    pub fn total_size(&self) -> usize {
        FRAME_HEADER_SIZE + self.payload.len() + FRAME_CRC_SIZE
    }
}

/// Frame encoder for streaming writes
pub struct FrameEncoder {
    buffer: BytesMut,
}

impl FrameEncoder {
    /// Create a new encoder with specified capacity
    pub fn new(capacity: usize) -> Self {
        Self {
            buffer: BytesMut::with_capacity(capacity),
        }
    }

    /// Encode a frame
    pub fn encode(&mut self, frame: &Frame) -> &[u8] {
        self.buffer.clear();
        let bytes = frame.to_bytes();
        self.buffer.extend_from_slice(&bytes);
        &self.buffer
    }
}

/// Frame decoder for streaming reads
pub struct FrameDecoder {
    buffer: BytesMut,
}

impl FrameDecoder {
    /// Create a new decoder
    pub fn new() -> Self {
        Self {
            buffer: BytesMut::with_capacity(MAX_MESSAGE_SIZE),
        }
    }

    /// Add data to the buffer
    pub fn push(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    /// Try to decode the next frame
    pub fn decode(&mut self) -> ProtocolResult<Option<Frame>> {
        Frame::parse(&mut self.buffer)
    }

    /// Get remaining buffered data length
    pub fn buffered(&self) -> usize {
        self.buffer.len()
    }

    /// Clear the buffer
    pub fn clear(&mut self) {
        self.buffer.clear();
    }
}

impl Default for FrameDecoder {
    fn default() -> Self {
        Self::new()
    }
}

/// Alert severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum AlertLevel {
    Warning = 1,
    Fatal = 2,
}

/// Alert codes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum AlertCode {
    CloseNotify = 0,
    UnexpectedMessage = 10,
    BadRecordMac = 20,
    DecryptionFailed = 21,
    RecordOverflow = 22,
    HandshakeFailure = 40,
    BadCertificate = 42,
    CertificateExpired = 45,
    InternalError = 80,
    UserCanceled = 90,
    ProtocolVersion = 70,
}

/// Alert message payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertPayload {
    pub level: AlertLevel,
    pub code: AlertCode,
    pub description: String,
}

impl AlertPayload {
    pub fn new(level: AlertLevel, code: AlertCode, description: impl Into<String>) -> Self {
        Self {
            level,
            code,
            description: description.into(),
        }
    }

    pub fn fatal(code: AlertCode, description: impl Into<String>) -> Self {
        Self::new(AlertLevel::Fatal, code, description)
    }

    pub fn warning(code: AlertCode, description: impl Into<String>) -> Self {
        Self::new(AlertLevel::Warning, code, description)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_roundtrip() {
        let payload = Bytes::from_static(b"Test payload data");
        let frame = Frame::new(MessageType::ApplicationData, payload.clone());

        let bytes = frame.to_bytes();
        let mut buf = BytesMut::from(&bytes[..]);

        let parsed = Frame::parse(&mut buf).unwrap().unwrap();

        assert_eq!(parsed.message_type(), MessageType::ApplicationData);
        assert_eq!(parsed.payload(), &payload);
    }

    #[test]
    fn test_crc_verification() {
        let payload = Bytes::from_static(b"Test payload");
        let frame = Frame::new(MessageType::ApplicationData, payload);

        let mut bytes = frame.to_bytes();

        // Corrupt a byte
        bytes[FRAME_HEADER_SIZE] ^= 0xFF;

        let result = Frame::parse(&mut bytes);
        assert!(matches!(result, Err(ProtocolError::CrcMismatch { .. })));
    }

    #[test]
    fn test_incomplete_frame() {
        let payload = Bytes::from_static(b"Test");
        let frame = Frame::new(MessageType::ApplicationData, payload);

        let bytes = frame.to_bytes();

        // Only provide partial data
        let mut partial = BytesMut::from(&bytes[..5]);

        let result = Frame::parse(&mut partial).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_frame_decoder_streaming() {
        let payload1 = Bytes::from_static(b"First message");
        let payload2 = Bytes::from_static(b"Second message");

        let frame1 = Frame::new(MessageType::ApplicationData, payload1);
        let frame2 = Frame::new(MessageType::ApplicationData, payload2);

        let mut bytes = frame1.to_bytes();
        bytes.extend_from_slice(&frame2.to_bytes());

        let mut decoder = FrameDecoder::new();

        // Push bytes in chunks
        decoder.push(&bytes[..10]);
        assert!(decoder.decode().unwrap().is_none());

        decoder.push(&bytes[10..]);

        let decoded1 = decoder.decode().unwrap().unwrap();
        assert_eq!(decoded1.payload(), b"First message".as_ref());

        let decoded2 = decoder.decode().unwrap().unwrap();
        assert_eq!(decoded2.payload(), b"Second message".as_ref());
    }
}
