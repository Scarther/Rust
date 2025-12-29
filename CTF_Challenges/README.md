# CTF-Style Rust Challenges

## Overview

Capture-the-flag style challenges to practice Rust security programming skills. Each challenge has a hidden flag in the format `FLAG{...}`.

---

## Challenge Categories

### 🔰 Beginner Challenges

#### Challenge B01: The Hasher
**Objective:** Compute the SHA-256 hash of "RustSecurityBible2024"

```rust
// Complete this function to find the flag
use sha2::{Sha256, Digest};

fn find_flag() -> String {
    // Hash the string "RustSecurityBible2024"
    // The flag is FLAG{first_8_chars_of_hash}
    todo!()
}
```

<details>
<summary>Hint</summary>
Use `Sha256::digest()` and format the output as hex.
</details>

---

#### Challenge B02: Port Detective
**Objective:** Scan localhost and find the service running on port 7777

Setup:
```bash
# Start the challenge server
cd Lab_Environment && docker-compose up -d
```

Challenge:
```rust
// Write a port scanner that connects to 172.30.0.40:7777
// and reads the banner. The flag is in the response.
```

<details>
<summary>Hint</summary>
Use TcpStream::connect() and read the response.
</details>

---

#### Challenge B03: Base64 Decoder
**Objective:** Decode this string to find the flag

```
RkxBR3tiYXNlNjRfaXNfbm90X2VuY3J5cHRpb259
```

```rust
// Decode the base64 string to find the flag
use base64::{Engine as _, engine::general_purpose};

fn decode_flag(encoded: &str) -> String {
    todo!()
}
```

---

### 🔷 Intermediate Challenges

#### Challenge I01: The Crawler
**Objective:** Find the hidden admin page on the vulnerable web app

Target: `http://172.30.0.30`

```rust
// Write a web crawler that discovers all pages
// One page contains the flag
use reqwest;

async fn find_hidden_page(base_url: &str) -> Option<String> {
    // Hint: Check common paths like /admin, /secret, /hidden
    todo!()
}
```

<details>
<summary>Hint</summary>
The admin page at /admin contains the flag.
</details>

---

#### Challenge I02: SQL Injection Detective
**Objective:** Extract the admin password from the vulnerable search endpoint

Target: `http://172.30.0.30/search?q=`

```rust
// Write code that exploits the SQL injection
// to extract the admin user's password from the database
// The flag is FLAG{password_value}
```

<details>
<summary>Hint</summary>
Try: `' UNION SELECT id, username, password FROM users--`
</details>

---

#### Challenge I03: Network Discovery
**Objective:** Find all live hosts on 172.30.0.0/24 and identify which one runs PostgreSQL

```rust
// 1. Scan the subnet for live hosts
// 2. Find which host has port 5432 open
// 3. The flag is FLAG{host_ip_address}
```

---

### 🔶 Advanced Challenges

#### Challenge A01: Encrypted Message
**Objective:** Decrypt this AES-256-GCM encrypted message

```
Key (hex): 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
Nonce (hex): 000102030405060708090a0b
Ciphertext (hex): 8b1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f
```

```rust
// Decrypt the message to find the flag
use aes_gcm::{Aes256Gcm, Key, Nonce, aead::{Aead, KeyInit}};

fn decrypt_flag(key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> String {
    todo!()
}
```

---

#### Challenge A02: Binary Analysis
**Objective:** Parse the provided ELF binary and find the flag in the .rodata section

```rust
// Use goblin to parse the binary
// Find the FLAG{...} string in read-only data
use goblin::Object;

fn find_flag_in_binary(path: &str) -> Option<String> {
    todo!()
}
```

---

#### Challenge A03: Protocol Reverse Engineering
**Objective:** The service on port 9999 speaks a custom protocol. Decode it.

Protocol spec:
```
[1 byte: message type][2 bytes: length][N bytes: data]
Message type 0x01 returns the flag
```

```rust
// Connect to 172.30.0.40:9999
// Send the correct message to receive the flag
```

---

### 🔴 Expert Challenges

#### Challenge E01: Memory Forensics
**Objective:** Analyze the provided memory dump and find credentials

```rust
// Search the memory dump for patterns matching:
// - Email addresses
// - Password patterns
// - The flag format FLAG{...}
```

---

#### Challenge E02: Malware Config Extractor
**Objective:** Extract the C2 configuration from the simulated malware sample

The "malware" has XOR-encoded config at offset 0x1000 with key 0x42.

```rust
// Parse the binary
// Find config at offset 0x1000
// XOR with 0x42 to decode
// Extract the flag from decoded config
```

---

#### Challenge E03: Custom IDS Rule
**Objective:** Write a detection rule that catches the attack pattern

Pattern to detect:
- HTTP POST to /api/upload
- Body contains "eval(" or "exec("
- Response includes base64-encoded data

```rust
// Implement a packet inspection function
// that returns true when the attack pattern is detected
fn detect_attack(request: &[u8], response: &[u8]) -> bool {
    todo!()
}
```

---

## Scoring

| Challenge Level | Points |
|-----------------|--------|
| Beginner | 100 pts |
| Intermediate | 250 pts |
| Advanced | 500 pts |
| Expert | 1000 pts |

## Flag Submission

Each flag follows the format: `FLAG{secret_value}`

To verify your flags, use the provided verification tool:
```bash
cargo run --bin flag-checker -- "FLAG{your_answer}"
```

---

## Setting Up Challenges

```bash
# Start the lab environment
cd Lab_Environment
docker-compose up -d

# Verify services are running
docker-compose ps

# Access the challenge targets
curl http://localhost:8082  # Vulnerable web app
nc localhost 7777           # Custom services
```

---

## Tips

1. **Read error messages** - Rust's compiler gives helpful hints
2. **Use the docs** - `cargo doc --open` for local documentation
3. **Test incrementally** - Build and test small pieces
4. **Check the lab** - Many challenges require the Docker environment

---

[← Back to Main](../README.md)
