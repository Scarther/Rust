//! # Custom Protocol Demo
//!
//! Demonstrates the complete protocol with handshake and encrypted messaging.

use std::net::SocketAddr;

use bytes::Bytes;
use custom_protocol::{
    ClientHandshake, Frame, MessageType, ProtocolResult, SecureSession,
    ServerHandshake, SessionConfig, Transport, TransportListener,
};
use tracing::{error, info, Level};
use tracing_subscriber::FmtSubscriber;

/// Run a demo server
async fn run_server(addr: SocketAddr) -> ProtocolResult<()> {
    let listener = TransportListener::bind(addr).await?;
    info!("Server listening on {}", listener.local_addr());

    loop {
        let (mut transport, peer) = listener.accept().await?;
        info!("New connection from {}", peer);

        tokio::spawn(async move {
            if let Err(e) = handle_client(&mut transport).await {
                error!("Client handler error: {}", e);
            }
        });
    }
}

/// Handle a single client connection
async fn handle_client(transport: &mut Transport) -> ProtocolResult<()> {
    // Perform handshake
    let mut handshake = ServerHandshake::new();

    // Receive ClientHello
    let client_hello_frame = transport.recv_frame().await?;
    if client_hello_frame.message_type() != MessageType::ClientHello {
        return Err(custom_protocol::ProtocolError::HandshakeError(
            "Expected ClientHello".to_string(),
        ));
    }

    info!("Received ClientHello");

    // Send ServerHello
    let server_hello = handshake.process_client_hello(
        client_hello_frame.payload(),
        Some("demo-server".to_string()),
    )?;
    transport.send_frame(&server_hello).await?;
    info!("Sent ServerHello");

    // Receive client finished
    let finished_frame = transport.recv_frame().await?;
    if finished_frame.message_type() != MessageType::HandshakeFinished {
        return Err(custom_protocol::ProtocolError::HandshakeError(
            "Expected HandshakeFinished".to_string(),
        ));
    }

    // Send server finished
    let server_finished = handshake.process_finished(finished_frame.payload())?;
    transport.send_frame(&server_finished).await?;
    info!("Handshake complete");

    // Get session keys and create secure session
    let keys = handshake.take_session_keys().unwrap();
    let mut session = SecureSession::new(keys, false, SessionConfig::default())?;

    // Message loop
    loop {
        let frame = transport.recv_frame().await?;

        match frame.message_type() {
            MessageType::ApplicationData => {
                let plaintext = session.decrypt_message(frame.payload())?;
                let message = String::from_utf8_lossy(&plaintext);
                info!("Received: {}", message);

                // Echo back with modification
                let response = format!("Server received: {}", message);
                let response_frame = session.encrypt_message(response.as_bytes())?;
                transport.send_frame(&response_frame).await?;
            }
            MessageType::Close => {
                info!("Client requested close");
                session.process_close();
                break;
            }
            _ => {
                info!("Ignoring message type: {:?}", frame.message_type());
            }
        }
    }

    Ok(())
}

/// Run a demo client
async fn run_client(server_addr: SocketAddr) -> ProtocolResult<()> {
    info!("Connecting to {}", server_addr);
    let mut transport = Transport::connect(server_addr).await?;
    info!("Connected to server");

    // Perform handshake
    let mut handshake = ClientHandshake::new();

    // Send ClientHello
    let client_hello = handshake.start(Some("demo-client".to_string()))?;
    transport.send_frame(&client_hello).await?;
    info!("Sent ClientHello");

    // Receive ServerHello
    let server_hello_frame = transport.recv_frame().await?;
    if server_hello_frame.message_type() != MessageType::ServerHello {
        return Err(custom_protocol::ProtocolError::HandshakeError(
            "Expected ServerHello".to_string(),
        ));
    }
    handshake.process_server_hello(server_hello_frame.payload())?;
    info!("Received ServerHello");

    // Send finished
    let finished = handshake.finish()?;
    transport.send_frame(&finished).await?;

    // Receive server finished
    let server_finished_frame = transport.recv_frame().await?;
    if server_finished_frame.message_type() != MessageType::HandshakeFinished {
        return Err(custom_protocol::ProtocolError::HandshakeError(
            "Expected HandshakeFinished".to_string(),
        ));
    }
    info!("Handshake complete");

    // Get session keys and create secure session
    let keys = handshake.take_session_keys().unwrap();
    let mut session = SecureSession::new(keys, true, SessionConfig::default())?;

    // Send some messages
    let messages = [
        "Hello, secure server!",
        "This message is encrypted",
        "Testing custom protocol",
    ];

    for msg in messages {
        let frame = session.encrypt_message(msg.as_bytes())?;
        transport.send_frame(&frame).await?;
        info!("Sent: {}", msg);

        let response_frame = transport.recv_frame().await?;
        let response = session.decrypt_message(response_frame.payload())?;
        info!("Response: {}", String::from_utf8_lossy(&response));
    }

    // Send close
    let close_frame = session.create_close()?;
    transport.send_frame(&close_frame).await?;
    info!("Connection closed");

    Ok(())
}

#[tokio::main]
async fn main() -> ProtocolResult<()> {
    // Initialize tracing
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    let args: Vec<String> = std::env::args().collect();

    match args.get(1).map(|s| s.as_str()) {
        Some("server") => {
            let addr = args
                .get(2)
                .map(|s| s.parse().expect("Invalid address"))
                .unwrap_or_else(|| "127.0.0.1:9000".parse().unwrap());
            run_server(addr).await
        }
        Some("client") => {
            let addr = args
                .get(2)
                .map(|s| s.parse().expect("Invalid address"))
                .unwrap_or_else(|| "127.0.0.1:9000".parse().unwrap());
            run_client(addr).await
        }
        Some("demo") => {
            // Run integrated demo
            info!("Running integrated demo");

            let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
            let listener = TransportListener::bind(addr).await?;
            let server_addr = listener.local_addr();
            info!("Demo server on {}", server_addr);

            // Spawn server task
            let server_handle = tokio::spawn(async move {
                let (mut transport, _) = listener.accept().await.unwrap();
                handle_client(&mut transport).await
            });

            // Give server time to start
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

            // Run client
            run_client(server_addr).await?;

            // Wait for server
            server_handle.await.unwrap()?;

            info!("Demo complete!");
            Ok(())
        }
        _ => {
            println!("Custom Encrypted Protocol Demo");
            println!();
            println!("Usage:");
            println!("  {} server [addr]   - Run server (default: 127.0.0.1:9000)", args[0]);
            println!("  {} client [addr]   - Connect to server", args[0]);
            println!("  {} demo            - Run integrated demo", args[0]);
            println!();
            println!("Protocol Features:");
            println!("  - X25519 key exchange");
            println!("  - AES-256-GCM encryption");
            println!("  - HKDF key derivation");
            println!("  - CRC32 frame integrity");
            println!("  - Replay protection");
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_full_protocol() {
        // This tests the complete protocol flow
        let listener = TransportListener::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let addr = listener.local_addr();

        let server_handle = tokio::spawn(async move {
            let (mut transport, _) = listener.accept().await.unwrap();
            handle_client(&mut transport).await.unwrap();
        });

        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        run_client(addr).await.unwrap();

        server_handle.await.unwrap();
    }
}
