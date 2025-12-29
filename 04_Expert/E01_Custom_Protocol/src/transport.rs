//! # Transport Layer
//!
//! Async TCP transport with frame reading/writing.
//! Provides the network interface for the protocol.

use std::io::ErrorKind;
use std::net::SocketAddr;

use bytes::BytesMut;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{timeout, Duration};

use crate::error::{ProtocolError, ProtocolResult};
use crate::frame::{Frame, FrameDecoder, FRAME_HEADER_SIZE, MAX_MESSAGE_SIZE};

/// Default read buffer size
const READ_BUFFER_SIZE: usize = 8192;

/// Connection timeout
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);

/// Read timeout
const READ_TIMEOUT: Duration = Duration::from_secs(60);

/// Write timeout
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// Transport connection wrapping a TCP stream
pub struct Transport {
    /// The underlying TCP stream
    stream: TcpStream,
    /// Frame decoder for reading
    decoder: FrameDecoder,
    /// Read buffer
    read_buffer: Vec<u8>,
    /// Peer address
    peer_addr: SocketAddr,
    /// Local address
    local_addr: SocketAddr,
    /// Bytes sent
    bytes_sent: u64,
    /// Bytes received
    bytes_received: u64,
}

impl Transport {
    /// Create a transport from an existing TCP stream
    pub fn new(stream: TcpStream) -> ProtocolResult<Self> {
        let peer_addr = stream.peer_addr()?;
        let local_addr = stream.local_addr()?;

        Ok(Self {
            stream,
            decoder: FrameDecoder::new(),
            read_buffer: vec![0u8; READ_BUFFER_SIZE],
            peer_addr,
            local_addr,
            bytes_sent: 0,
            bytes_received: 0,
        })
    }

    /// Connect to a remote address
    pub async fn connect(addr: SocketAddr) -> ProtocolResult<Self> {
        let stream = timeout(CONNECTION_TIMEOUT, TcpStream::connect(addr))
            .await
            .map_err(|_| ProtocolError::Timeout(CONNECTION_TIMEOUT.as_secs()))?
            .map_err(ProtocolError::IoError)?;

        // Set TCP options
        stream.set_nodelay(true)?;

        Self::new(stream)
    }

    /// Get the peer address
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    /// Get the local address
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Get bytes sent
    pub fn bytes_sent(&self) -> u64 {
        self.bytes_sent
    }

    /// Get bytes received
    pub fn bytes_received(&self) -> u64 {
        self.bytes_received
    }

    /// Send a frame
    pub async fn send_frame(&mut self, frame: &Frame) -> ProtocolResult<()> {
        let bytes = frame.to_bytes();

        timeout(WRITE_TIMEOUT, self.stream.write_all(&bytes))
            .await
            .map_err(|_| ProtocolError::Timeout(WRITE_TIMEOUT.as_secs()))?
            .map_err(ProtocolError::IoError)?;

        self.bytes_sent += bytes.len() as u64;

        Ok(())
    }

    /// Receive a frame
    pub async fn recv_frame(&mut self) -> ProtocolResult<Frame> {
        loop {
            // Try to decode from buffered data first
            if let Some(frame) = self.decoder.decode()? {
                return Ok(frame);
            }

            // Read more data
            let n = timeout(READ_TIMEOUT, self.stream.read(&mut self.read_buffer))
                .await
                .map_err(|_| ProtocolError::Timeout(READ_TIMEOUT.as_secs()))?
                .map_err(ProtocolError::IoError)?;

            if n == 0 {
                return Err(ProtocolError::ConnectionClosed);
            }

            self.bytes_received += n as u64;
            self.decoder.push(&self.read_buffer[..n]);
        }
    }

    /// Try to receive a frame without blocking
    pub async fn try_recv_frame(&mut self) -> ProtocolResult<Option<Frame>> {
        // Try to decode from buffered data first
        if let Some(frame) = self.decoder.decode()? {
            return Ok(Some(frame));
        }

        // Try a non-blocking read
        match self.stream.try_read(&mut self.read_buffer) {
            Ok(0) => Err(ProtocolError::ConnectionClosed),
            Ok(n) => {
                self.bytes_received += n as u64;
                self.decoder.push(&self.read_buffer[..n]);
                self.decoder.decode()
            }
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(ProtocolError::IoError(e)),
        }
    }

    /// Flush the write buffer
    pub async fn flush(&mut self) -> ProtocolResult<()> {
        self.stream.flush().await.map_err(ProtocolError::IoError)
    }

    /// Shutdown the connection
    pub async fn shutdown(&mut self) -> ProtocolResult<()> {
        self.stream
            .shutdown()
            .await
            .map_err(ProtocolError::IoError)
    }

    /// Get a reference to the underlying stream (for advanced usage)
    pub fn stream(&self) -> &TcpStream {
        &self.stream
    }

    /// Get a mutable reference to the underlying stream
    pub fn stream_mut(&mut self) -> &mut TcpStream {
        &mut self.stream
    }

    /// Split into read and write halves
    pub fn into_split(self) -> (TransportReader, TransportWriter) {
        let (read_half, write_half) = self.stream.into_split();
        (
            TransportReader {
                stream: read_half,
                decoder: self.decoder,
                read_buffer: self.read_buffer,
                bytes_received: self.bytes_received,
            },
            TransportWriter {
                stream: write_half,
                bytes_sent: self.bytes_sent,
            },
        )
    }
}

/// Read half of a split transport
pub struct TransportReader {
    stream: tokio::net::tcp::OwnedReadHalf,
    decoder: FrameDecoder,
    read_buffer: Vec<u8>,
    bytes_received: u64,
}

impl TransportReader {
    /// Receive a frame
    pub async fn recv_frame(&mut self) -> ProtocolResult<Frame> {
        loop {
            if let Some(frame) = self.decoder.decode()? {
                return Ok(frame);
            }

            let n = timeout(READ_TIMEOUT, self.stream.read(&mut self.read_buffer))
                .await
                .map_err(|_| ProtocolError::Timeout(READ_TIMEOUT.as_secs()))?
                .map_err(ProtocolError::IoError)?;

            if n == 0 {
                return Err(ProtocolError::ConnectionClosed);
            }

            self.bytes_received += n as u64;
            self.decoder.push(&self.read_buffer[..n]);
        }
    }

    /// Get bytes received
    pub fn bytes_received(&self) -> u64 {
        self.bytes_received
    }
}

/// Write half of a split transport
pub struct TransportWriter {
    stream: tokio::net::tcp::OwnedWriteHalf,
    bytes_sent: u64,
}

impl TransportWriter {
    /// Send a frame
    pub async fn send_frame(&mut self, frame: &Frame) -> ProtocolResult<()> {
        let bytes = frame.to_bytes();

        timeout(WRITE_TIMEOUT, self.stream.write_all(&bytes))
            .await
            .map_err(|_| ProtocolError::Timeout(WRITE_TIMEOUT.as_secs()))?
            .map_err(ProtocolError::IoError)?;

        self.bytes_sent += bytes.len() as u64;

        Ok(())
    }

    /// Get bytes sent
    pub fn bytes_sent(&self) -> u64 {
        self.bytes_sent
    }
}

/// TCP listener wrapper
pub struct TransportListener {
    listener: TcpListener,
    local_addr: SocketAddr,
}

impl TransportListener {
    /// Bind to an address
    pub async fn bind(addr: SocketAddr) -> ProtocolResult<Self> {
        let listener = TcpListener::bind(addr).await?;
        let local_addr = listener.local_addr()?;

        Ok(Self {
            listener,
            local_addr,
        })
    }

    /// Get the local address
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Accept a new connection
    pub async fn accept(&self) -> ProtocolResult<(Transport, SocketAddr)> {
        let (stream, addr) = self.listener.accept().await?;
        stream.set_nodelay(true)?;
        let transport = Transport::new(stream)?;
        Ok((transport, addr))
    }
}

/// Transport statistics
#[derive(Debug, Clone)]
pub struct TransportStats {
    pub peer_addr: SocketAddr,
    pub local_addr: SocketAddr,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

impl std::fmt::Display for TransportStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} -> {}: sent={} bytes, recv={} bytes",
            self.local_addr, self.peer_addr, self.bytes_sent, self.bytes_received
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::MessageType;

    #[tokio::test]
    async fn test_transport_echo() {
        // Create a listener
        let listener = TransportListener::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let addr = listener.local_addr();

        // Spawn server
        let server_handle = tokio::spawn(async move {
            let (mut transport, _) = listener.accept().await.unwrap();
            let frame = transport.recv_frame().await.unwrap();
            transport.send_frame(&frame).await.unwrap();
        });

        // Connect client
        let mut client = Transport::connect(addr).await.unwrap();

        // Send and receive
        let test_frame = Frame::new(
            MessageType::ApplicationData,
            bytes::Bytes::from_static(b"test"),
        );
        client.send_frame(&test_frame).await.unwrap();

        let echo_frame = client.recv_frame().await.unwrap();
        assert_eq!(echo_frame.payload(), test_frame.payload());

        server_handle.await.unwrap();
    }
}
