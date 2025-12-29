//! # Protocol Client Binary
//!
//! Standalone client for the custom encrypted protocol.

use std::net::SocketAddr;

use custom_protocol::{
    ClientHandshake, MessageType, ProtocolResult, SecureSession,
    SessionConfig, Transport,
};
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

#[tokio::main]
async fn main() -> ProtocolResult<()> {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();

    let addr: SocketAddr = std::env::args()
        .nth(1)
        .map(|s| s.parse().expect("Invalid address"))
        .unwrap_or_else(|| "127.0.0.1:9000".parse().unwrap());

    info!("Connecting to {}", addr);
    let mut transport = Transport::connect(addr).await?;

    // Handshake
    let mut handshake = ClientHandshake::new();

    let client_hello = handshake.start(Some("secure-client".to_string()))?;
    transport.send_frame(&client_hello).await?;

    let server_hello = transport.recv_frame().await?;
    handshake.process_server_hello(server_hello.payload())?;

    let finished = handshake.finish()?;
    transport.send_frame(&finished).await?;

    let _server_finished = transport.recv_frame().await?;

    let keys = handshake.take_session_keys().unwrap();
    let mut session = SecureSession::new(keys, true, SessionConfig::default())?;
    info!("Session established");

    // Interactive mode
    println!("Enter messages (Ctrl+C to exit):");
    let stdin = tokio::io::stdin();
    let mut reader = tokio::io::BufReader::new(stdin);

    loop {
        let mut line = String::new();
        use tokio::io::AsyncBufReadExt;
        if reader.read_line(&mut line).await? == 0 {
            break;
        }

        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        if line == "/quit" {
            let close = session.create_close()?;
            transport.send_frame(&close).await?;
            break;
        }

        let frame = session.encrypt_message(line.as_bytes())?;
        transport.send_frame(&frame).await?;

        let response_frame = transport.recv_frame().await?;
        let response = session.decrypt_message(response_frame.payload())?;
        println!("< {}", String::from_utf8_lossy(&response));
    }

    info!("Disconnected");
    Ok(())
}
