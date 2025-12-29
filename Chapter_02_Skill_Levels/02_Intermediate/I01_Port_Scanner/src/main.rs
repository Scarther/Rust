//! # I01: Multi-threaded Port Scanner
//!
//! A fast, multi-threaded TCP port scanner with banner grabbing.
//!
//! ## Usage
//! ```bash
//! cargo run -- -t 127.0.0.1 -p 1-1024
//! cargo run -- -t scanme.nmap.org -p 22,80,443 --banner
//! ```

use clap::Parser;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Parser, Debug)]
#[command(name = "portscan")]
#[command(version = "1.0.0")]
#[command(about = "Fast multi-threaded port scanner")]
struct Args {
    #[arg(short, long)]
    target: String,

    #[arg(short, long, default_value = "1-1000")]
    ports: String,

    #[arg(long, default_value_t = 100)]
    threads: usize,

    #[arg(short = 'T', long, default_value_t = 1000)]
    timeout: u64,

    #[arg(short, long)]
    banner: bool,

    #[arg(short, long)]
    verbose: bool,
}

#[derive(Debug, Clone)]
struct ScanResult {
    port: u16,
    service: Option<String>,
    banner: Option<String>,
    response_time: Duration,
}

fn get_service_name(port: u16) -> Option<&'static str> {
    let services: HashMap<u16, &'static str> = [
        (21, "ftp"), (22, "ssh"), (23, "telnet"), (25, "smtp"),
        (53, "dns"), (80, "http"), (110, "pop3"), (143, "imap"),
        (443, "https"), (445, "smb"), (3306, "mysql"), (3389, "rdp"),
        (5432, "postgresql"), (6379, "redis"), (8080, "http-proxy"),
    ].iter().cloned().collect();
    services.get(&port).copied()
}

fn parse_ports(spec: &str) -> Result<Vec<u16>, String> {
    let mut ports = Vec::new();
    for part in spec.split(',') {
        let part = part.trim();
        if part.contains('-') {
            let range: Vec<&str> = part.split('-').collect();
            if range.len() != 2 {
                return Err(format!("Invalid range: {}", part));
            }
            let start: u16 = range[0].parse().map_err(|_| "Invalid port")?;
            let end: u16 = range[1].parse().map_err(|_| "Invalid port")?;
            ports.extend(start..=end);
        } else {
            let port: u16 = part.parse().map_err(|_| "Invalid port")?;
            ports.push(port);
        }
    }
    Ok(ports)
}

fn grab_banner(stream: &mut TcpStream, port: u16) -> Option<String> {
    stream.set_read_timeout(Some(Duration::from_millis(500))).ok()?;

    if port == 80 || port == 8080 {
        stream.write_all(b"HEAD / HTTP/1.0\r\n\r\n").ok()?;
    }

    let mut buffer = [0u8; 512];
    match stream.read(&mut buffer) {
        Ok(n) if n > 0 => {
            Some(String::from_utf8_lossy(&buffer[..n])
                .lines().next().unwrap_or("").trim().to_string())
        }
        _ => None,
    }
}

fn scan_port(addr: SocketAddr, timeout: Duration, grab_banners: bool) -> Option<ScanResult> {
    let start = Instant::now();

    match TcpStream::connect_timeout(&addr, timeout) {
        Ok(mut stream) => {
            let response_time = start.elapsed();
            let banner = if grab_banners { grab_banner(&mut stream, addr.port()) } else { None };
            let _ = stream.shutdown(Shutdown::Both);

            Some(ScanResult {
                port: addr.port(),
                service: get_service_name(addr.port()).map(String::from),
                banner,
                response_time,
            })
        }
        Err(_) => None,
    }
}

fn resolve_target(target: &str) -> Result<IpAddr, String> {
    if let Ok(ip) = target.parse::<IpAddr>() {
        return Ok(ip);
    }
    format!("{}:0", target)
        .to_socket_addrs()
        .map_err(|e| format!("DNS failed: {}", e))?
        .next()
        .map(|addr| addr.ip())
        .ok_or_else(|| "No IP found".to_string())
}

fn main() {
    let args = Args::parse();

    println!("╔════════════════════════════════════════╗");
    println!("║        PORT SCANNER v1.0.0             ║");
    println!("╚════════════════════════════════════════╝\n");

    let ip = match resolve_target(&args.target) {
        Ok(ip) => { println!("[*] Target: {} ({})", args.target, ip); ip }
        Err(e) => { eprintln!("[-] Error: {}", e); return; }
    };

    let ports = match parse_ports(&args.ports) {
        Ok(p) => { println!("[*] Ports: {}", p.len()); p }
        Err(e) => { eprintln!("[-] Error: {}", e); return; }
    };

    let start_time = Instant::now();
    let timeout = Duration::from_millis(args.timeout);
    let results = Arc::new(Mutex::new(Vec::new()));

    let chunk_size = (ports.len() / args.threads).max(1);
    let mut handles = vec![];

    for chunk in ports.chunks(chunk_size) {
        let chunk = chunk.to_vec();
        let results = Arc::clone(&results);
        let grab_banners = args.banner;

        handles.push(thread::spawn(move || {
            for port in chunk {
                let addr = SocketAddr::new(ip, port);
                if let Some(result) = scan_port(addr, timeout, grab_banners) {
                    results.lock().unwrap().push(result);
                }
            }
        }));
    }

    for handle in handles { handle.join().unwrap(); }

    let mut results = results.lock().unwrap();
    results.sort_by_key(|r| r.port);

    println!("\nPORT      STATE  SERVICE    BANNER");
    println!("────────────────────────────────────────");

    for r in results.iter() {
        println!("{:<9} open   {:<10} {}",
            format!("{}/tcp", r.port),
            r.service.as_deref().unwrap_or("?"),
            r.banner.as_deref().unwrap_or("")
        );
    }

    println!("\n[+] {} open ports in {:.2}s", results.len(), start_time.elapsed().as_secs_f64());
}
