# Chapter 03: Red Team Rust - Assessment Quiz

## Instructions
- Choose the best answer for each question
- Answers are provided at the end
- Passing score: 70% (14/20 correct)

---

## Section A: Reconnaissance (5 questions)

### Q1. Which crate is best for async HTTP requests in Rust?
- A) hyper
- B) reqwest
- C) curl
- D) http

### Q2. What does this code do?
```rust
let addrs = format!("{}:0", hostname)
    .to_socket_addrs()?
    .map(|addr| addr.ip())
    .collect::<Vec<_>>();
```
- A) Creates a socket connection
- B) Performs DNS resolution
- C) Scans ports
- D) Validates IP address

### Q3. Which scan type requires raw sockets?
- A) TCP Connect scan
- B) SYN scan
- C) Full connect with banner grab
- D) HTTP enumeration

### Q4. What crate provides raw packet manipulation?
- A) tokio
- B) pnet
- C) socket2
- D) net2

### Q5. How do you implement connection timeout in Rust?
- A) `TcpStream::connect_timeout()`
- B) `TcpStream::connect().timeout()`
- C) `timeout(Duration::from_secs(5), TcpStream::connect()).await`
- D) Both A and C

---

## Section B: Exploitation Concepts (5 questions)

### Q6. Which library is commonly used for AES encryption in Rust?
- A) openssl
- B) aes-gcm
- C) ring
- D) All of the above

### Q7. How do you safely handle cryptographic secrets in Rust?
```rust
// Which approach is safest?
```
- A) Use `String` type
- B) Use `zeroize` crate to clear memory
- C) Use `Box<[u8]>`
- D) Store in environment variable

### Q8. What is the purpose of base64 encoding in payloads?
- A) Encryption
- B) Compression
- C) Encoding binary data as ASCII-safe text
- D) Authentication

### Q9. Which crate is used for regex pattern matching?
- A) pcre
- B) regex
- C) re
- D) pattern

### Q10. How do you execute a system command in Rust?
- A) `std::process::Command::new("cmd").arg("-c").arg("ls").output()`
- B) `std::os::system("ls")`
- C) `exec("ls")`
- D) `shell::run("ls")`

---

## Section C: Network Operations (5 questions)

### Q11. What does `TcpStream::connect()` return?
- A) `TcpStream`
- B) `Result<TcpStream, io::Error>`
- C) `Option<TcpStream>`
- D) `&TcpStream`

### Q12. How do you implement multi-threaded port scanning?
- A) Use `std::thread::spawn()` with channels
- B) Use `tokio::spawn()` for async
- C) Use `rayon` for parallel iteration
- D) All of the above

### Q13. What is the correct way to read from a TCP socket?
```rust
let mut stream = TcpStream::connect("127.0.0.1:80")?;
```
- A) `stream.read_string()`
- B) `stream.read(&mut buffer)?`
- C) `stream.get_data()`
- D) `buffer.read_from(&stream)`

### Q14. Which protocol uses UDP?
- A) HTTP
- B) SSH
- C) DNS
- D) HTTPS

### Q15. How do you implement rate limiting in async Rust?
- A) `thread::sleep()`
- B) `tokio::time::sleep().await`
- C) `Semaphore` for concurrent limits
- D) Both B and C

---

## Section D: Payload Development (5 questions)

### Q16. Which build profile produces optimized binaries?
- A) `cargo build`
- B) `cargo build --release`
- C) `cargo build --optimized`
- D) `cargo build --fast`

### Q17. How do you compile a static binary on Linux?
- A) `cargo build --static`
- B) `cargo build --target x86_64-unknown-linux-musl`
- C) `cargo build --no-dynamic`
- D) `STATIC=1 cargo build`

### Q18. What does `#[cfg(target_os = "windows")]` do?
- A) Enables Windows API
- B) Conditionally compiles code for Windows
- C) Imports Windows crate
- D) Sets Windows as target

### Q19. How do you minimize binary size?
```toml
[profile.release]
# Which settings help?
```
- A) `opt-level = "z"`
- B) `lto = true`
- C) `strip = true`
- D) All of the above

### Q20. What is the MITRE ATT&CK technique for port scanning?
- A) T1046 - Network Service Discovery
- B) T1018 - Remote System Discovery
- C) T1016 - System Network Configuration
- D) T1040 - Network Sniffing

---

## Answer Key

<details>
<summary>Click to reveal answers</summary>

| Question | Answer | Explanation |
|----------|--------|-------------|
| Q1 | B | reqwest is the most popular high-level HTTP client |
| Q2 | B | to_socket_addrs() performs DNS resolution |
| Q3 | B | SYN scans require raw socket access |
| Q4 | B | pnet provides packet crafting and capture |
| Q5 | D | Both sync and async have timeout options |
| Q6 | D | All are valid crypto libraries |
| Q7 | B | zeroize clears sensitive data from memory |
| Q8 | C | Base64 encodes binary as printable ASCII |
| Q9 | B | regex crate for Rust regex |
| Q10 | A | std::process::Command for subprocess |
| Q11 | B | Returns Result for error handling |
| Q12 | D | All approaches work for parallel scanning |
| Q13 | B | Read trait method with buffer |
| Q14 | C | DNS primarily uses UDP |
| Q15 | D | Both sleep and semaphore for rate limiting |
| Q16 | B | --release enables optimizations |
| Q17 | B | musl target for static binaries |
| Q18 | B | Conditional compilation attribute |
| Q19 | D | All settings reduce binary size |
| Q20 | A | T1046 Network Service Discovery |

**Passing Score: 14/20 (70%)**

</details>

---

## Practical Exercise

After completing this quiz, test your knowledge by building:

1. A multi-threaded port scanner targeting the lab environment
2. A simple HTTP directory enumerator
3. A network host discovery tool

Use the lab at `172.30.0.0/24` for testing.

---

[← Chapter 02 Quiz](./Chapter_02_Skills_Quiz.md) | [Back to Assessments](./README.md) | [Chapter 04 Quiz →](./Chapter_04_BlueTeam_Quiz.md)
