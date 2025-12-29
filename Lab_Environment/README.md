# Rust Security Lab Environment

## Overview

Docker-based lab environment for developing and testing Rust security tools in an isolated network.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                     LAB NETWORK (172.30.0.0/24)                     │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐          │
│  │  Rust Dev    │    │ Target Linux │    │  Vuln Web    │          │
│  │ 172.30.0.10  │    │ 172.30.0.20  │    │ 172.30.0.30  │          │
│  │ SSH: 2222    │    │ SSH: 2223    │    │ HTTP: 8082   │          │
│  └──────────────┘    └──────────────┘    └──────────────┘          │
│                                                                      │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐          │
│  │  Services    │    │  Database    │    │    Redis     │          │
│  │ 172.30.0.40  │    │ 172.30.0.50  │    │ 172.30.0.51  │          │
│  │ Multi-port   │    │ Port: 5432   │    │ Port: 6379   │          │
│  └──────────────┘    └──────────────┘    └──────────────┘          │
│                                                                      │
│  ┌──────────────┐                                                   │
│  │ Log Collector│                                                   │
│  │ 172.30.0.60  │                                                   │
│  │ Web: 8084    │                                                   │
│  └──────────────┘                                                   │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites

- Docker Engine 20.10+
- Docker Compose 2.0+
- 8GB RAM minimum
- 10GB free disk space

### Start the Lab

```bash
cd Lab_Environment

# Start all services
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f
```

### Access Services

| Service | Access | Credentials |
|---------|--------|-------------|
| Rust Dev SSH | `ssh root@localhost -p 2222` | root:rustlab |
| Target Linux | `ssh root@localhost -p 2223` | root:targetpass |
| Vuln Web App | http://localhost:8082 | N/A |
| Services Target | Ports 2121, 2525, 8083 | Various |
| PostgreSQL | localhost:5432 | rustlab:labpassword |
| Redis | localhost:6379 | N/A |
| Log Collector | http://localhost:8084 | N/A |

### Stop the Lab

```bash
# Stop services
docker-compose down

# Stop and remove volumes
docker-compose down -v
```

---

## Services

### Rust Dev (172.30.0.10)

Complete Rust development environment with:

- Rust 1.75 with cargo, clippy, rustfmt
- Cross-compilation targets (Linux musl, Windows, ARM)
- Network tools (nmap, tcpdump, netcat)
- Development tools (git, vim, tmux, gdb)

**Key Directories:**
- `/workspace` - Mounted repository root
- `/root/.cargo` - Cargo cache (persisted)

**Usage:**
```bash
# SSH into development container
ssh root@localhost -p 2222

# Build a project
cd /workspace/Chapter_02_Skill_Levels/02_Intermediate/I01_Port_Scanner
cargo build --release

# Run against lab targets
./target/release/portscan -t 172.30.0.20 -p 1-1000
```

### Target Linux (172.30.0.20)

Ubuntu server with simulated sensitive data:

- SSH server with test user
- Nginx web server
- Fake credentials and SSH keys
- Document files

**Test Files:**
- `/home/testuser/.ssh/id_rsa` - Fake SSH key
- `/home/testuser/.credentials` - Fake credentials
- `/home/testuser/Documents/budget.txt` - Fake document

### Vuln Web (172.30.0.30)

Intentionally vulnerable Flask application:

| Endpoint | Vulnerability |
|----------|---------------|
| `/search?q=` | SQL Injection |
| `/hello?name=` | XSS |
| `/cmd?ip=` | Command Injection |
| `/admin` | Hidden admin panel |
| `/.git/config` | Exposed git config |

### Services Target (172.30.0.40)

Multiple services for scanning practice:

| Port | Service | Banner |
|------|---------|--------|
| 21 | FTP | Welcome to Lab FTP Server |
| 22 | SSH | OpenSSH_8.9 |
| 80 | HTTP | TestServer/1.0 |
| 7777 | Custom | CustomService/1.0 |
| 8888 | Custom | TestDaemon/2.1 |
| 9999 | Custom | LabService/3.0 |

---

## Lab Exercises

### Exercise 1: Port Scanner

Test your port scanner against the services target:

```bash
# From rust-dev container
cd /workspace/Chapter_02_Skill_Levels/02_Intermediate/I01_Port_Scanner
cargo run -- -t 172.30.0.40 -p 1-10000 --banner
```

Expected output:
- Port 21 (FTP)
- Port 22 (SSH)
- Port 80 (HTTP)
- Ports 7777, 8888, 9999 (custom services)

### Exercise 2: Web Scanner

Test web security tools against the vulnerable app:

```bash
# Scan for common paths
cargo run -- -t http://172.30.0.30 --wordlist /usr/share/wordlists/common.txt

# Test SQL injection
curl "http://172.30.0.30/search?q=' OR 1=1--"
```

### Exercise 3: Network Enumeration

Practice network discovery:

```bash
# From rust-dev container
nmap -sn 172.30.0.0/24

# Test your own enumeration tool
cd /workspace/Chapter_02_Skill_Levels/02_Intermediate/I02_Network_Enum
cargo run -- -n 172.30.0.0/24
```

### Exercise 4: Log Collection

Send logs from your Rust tools:

```rust
// In your Rust tool
async fn log_to_collector(message: &str) {
    let client = reqwest::Client::new();
    client.post("http://172.30.0.60:8080/api/log")
        .json(&serde_json::json!({
            "source": "my-tool",
            "level": "INFO",
            "message": message
        }))
        .send()
        .await
        .ok();
}
```

View logs at: http://localhost:8084

---

## Development Workflow

### 1. Start Lab
```bash
docker-compose up -d
```

### 2. Connect to Dev Container
```bash
ssh root@localhost -p 2222
# Or use docker exec
docker exec -it rust_dev bash
```

### 3. Develop and Test
```bash
cd /workspace/your-project
cargo build
cargo run -- [args]
```

### 4. Build for Release
```bash
# Static Linux binary
cargo build --release --target x86_64-unknown-linux-musl

# Windows executable
cargo build --release --target x86_64-pc-windows-gnu
```

---

## Customization

### Adding More Targets

Edit `docker-compose.yml`:

```yaml
  custom-target:
    image: ubuntu:22.04
    networks:
      rust_lab:
        ipv4_address: 172.30.0.100
    command: ["/bin/bash", "-c", "apt update && apt install -y openssh-server && service ssh start && tail -f /dev/null"]
```

### Persisting Data

Volumes are used for:
- `cargo-cache` - Cargo registry cache
- `rust-target` - Build artifacts
- `postgres-data` - Database data
- `logs-data` - Collected logs

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Container won't start | Check Docker: `systemctl status docker` |
| Port already in use | Change port mapping in docker-compose.yml |
| Can't reach containers | Verify network: `docker network inspect rust_lab` |
| Slow builds | Increase Docker memory allocation |
| Permission denied | Check volume mounts and user permissions |

---

## Security Notice

```
⚠️ FOR TRAINING USE ONLY ⚠️

- Never expose lab services to the internet
- Don't use real credentials in the lab
- The vulnerable app has real vulnerabilities
- Clean up containers after training

Use responsibly and ethically.
```

---

[← Back to Main](../README.md)
