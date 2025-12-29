//! # Protocol Server Binary
//!
//! Standalone server for the custom encrypted protocol.

use std::net::SocketAddr;

use custom_protocol::{
    MessageType, ProtocolResult, SecureSession, ServerHandshake,
    SessionConfig, Transport, TransportListener,
};
use tracing::{error, info, Level};
use tracing_subscriber::FmtSubscriber;

async fn handle_client(mut transport: Transport) -> ProtocolResult<()> {
    let peer = transport.peer_addr();
    info!("Handling client: {}", peer);

    // Handshake
    let mut handshake = ServerHandshake::new();

    let client_hello = transport.recv_frame().await?;
    let server_hello = handshake.process_client_hello(
        client_hello.payload(),
        Some("secure-server".to_string()),
    )?;
    transport.send_frame(&server_hello).await?;

    let finished = transport.recv_frame().await?;
    let server_finished = handshake.process_finished(finished.payload())?;
    transport.send_frame(&server_finished).await?;

    let keys = handshake.take_session_keys().unwrap();
    let mut session = SecureSession::new(keys, false, SessionConfig::default())?;
    info!("Session established with {}", peer);

    loop {
        let frame = transport.recv_frame().await?;

        match frame.message_type() {
            MessageType::ApplicationData => {
                let plaintext = session.decrypt_message(frame.payload())?;
                info!("[{}] Received {} bytes", peer, plaintext.len());

                let response = session.encrypt_message(&plaintext)?;
                transport.send_frame(&response).await?;
            }
            MessageType::Close => {
                info!("[{}] Closing connection", peer);
                break;
            }
            _ => {}
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> ProtocolResult<()> {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();

    let addr: SocketAddr = std::env::args()
        .nth(1)
        .map(|s| s.parse().expect("Invalid address"))
        .unwrap_or_else(|| "0.0.0.0:9000".parse().unwrap());

    let listener = TransportListener::bind(addr).await?;
    info!("Server listening on {}", listener.local_addr());

    loop {
        match listener.accept().await {
            Ok((transport, peer)) => {
                info!("Connection from {}", peer);
                tokio::spawn(async move {
                    if let Err(e) = handle_client(transport).await {
                        error!("Error: {}", e);
                    }
                });
            }
            Err(e) => {
                error!("Accept error: {}", e);
            }
        }
    }
}
