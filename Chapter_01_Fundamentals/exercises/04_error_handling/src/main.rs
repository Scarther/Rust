//! # Error Handling Exercises
//!
//! Rust uses Result<T, E> and Option<T> for error handling instead of exceptions.
//! This approach makes error handling explicit and catches errors at compile time.
//!
//! Run with: cargo run
//! Check solutions in: src/solutions.rs

#![allow(unused_variables, dead_code)]

mod solutions;

fn main() {
    println!("=== Rust Error Handling Exercises ===\n");

    println!("Exercise 1: Option Basics");
    exercise_1();

    println!("\nExercise 2: Result Basics");
    exercise_2();

    println!("\nExercise 3: The ? Operator");
    exercise_3();

    println!("\nExercise 4: Custom Error Types");
    exercise_4();

    println!("\nExercise 5: Error Conversion");
    exercise_5();

    println!("\nExercise 6: Option Combinators");
    exercise_6();

    println!("\nExercise 7: Result Combinators");
    exercise_7();

    println!("\nExercise 8: Authentication Errors");
    exercise_8();

    println!("\nExercise 9: File Security Scanner");
    exercise_9();

    println!("\nExercise 10: Challenge - Crypto Operation Pipeline");
    exercise_10();

    println!("\n=== All exercises completed! ===");
}

// =============================================================================
// EXERCISE 1: Option Basics
// =============================================================================
//
// Option<T> represents a value that might or might not exist.
// Use Some(value) when there's a value, None when there isn't.
//
// YOUR TASK: Work with Option values safely.
//
fn exercise_1() {
    fn find_user(id: u32) -> Option<String> {
        match id {
            1 => Some(String::from("alice")),
            2 => Some(String::from("bob")),
            3 => Some(String::from("charlie")),
            _ => None,
        }
    }

    fn get_user_role(username: &str) -> Option<String> {
        match username {
            "alice" => Some(String::from("admin")),
            "bob" => Some(String::from("user")),
            _ => None,
        }
    }

    // Using match
    match find_user(1) {
        Some(name) => println!("  Found user: {}", name),
        None => println!("  User not found"),
    }

    // Using if let
    if let Some(name) = find_user(2) {
        println!("  User 2 is: {}", name);
    }

    // Using unwrap_or
    let user = find_user(99).unwrap_or(String::from("guest"));
    println!("  User 99 or default: {}", user);

    // Using unwrap_or_else (lazy evaluation)
    let user = find_user(99).unwrap_or_else(|| String::from("anonymous"));
    println!("  User with lazy default: {}", user);

    // Chaining Options
    let role = find_user(1).and_then(|name| get_user_role(&name));
    println!("  User 1's role: {:?}", role);

    solutions::solution_1();
}

// =============================================================================
// EXERCISE 2: Result Basics
// =============================================================================
//
// Result<T, E> represents either success (Ok(T)) or failure (Err(E)).
// This is used for operations that can fail.
//
// YOUR TASK: Handle Result values properly.
//
fn exercise_2() {
    fn parse_port(s: &str) -> Result<u16, String> {
        match s.parse::<u16>() {
            Ok(port) if port > 0 => Ok(port),
            Ok(_) => Err(String::from("Port must be greater than 0")),
            Err(_) => Err(format!("Invalid port number: {}", s)),
        }
    }

    fn validate_ip(ip: &str) -> Result<String, String> {
        let parts: Vec<&str> = ip.split('.').collect();
        if parts.len() != 4 {
            return Err(String::from("IP must have 4 octets"));
        }

        for part in &parts {
            match part.parse::<u8>() {
                Ok(_) => continue,
                Err(_) => return Err(format!("Invalid octet: {}", part)),
            }
        }

        Ok(ip.to_string())
    }

    // Using match
    match parse_port("8080") {
        Ok(port) => println!("  Valid port: {}", port),
        Err(e) => println!("  Error: {}", e),
    }

    // Using if let
    if let Ok(port) = parse_port("443") {
        println!("  HTTPS port: {}", port);
    }

    // Using is_ok() and is_err()
    let result = validate_ip("192.168.1.1");
    println!("  IP valid: {}", result.is_ok());

    // Using unwrap_or
    let port = parse_port("invalid").unwrap_or(80);
    println!("  Port with default: {}", port);

    // Collecting results
    let ports = vec!["80", "443", "invalid", "8080"];
    let valid_ports: Vec<u16> = ports
        .iter()
        .filter_map(|p| parse_port(p).ok())
        .collect();
    println!("  Valid ports: {:?}", valid_ports);

    solutions::solution_2();
}

// =============================================================================
// EXERCISE 3: The ? Operator
// =============================================================================
//
// The ? operator provides a shorthand for propagating errors.
// It returns early with Err if the Result is Err, otherwise unwraps Ok.
//
// YOUR TASK: Use the ? operator for clean error propagation.
//
fn exercise_3() {
    #[derive(Debug)]
    struct Config {
        host: String,
        port: u16,
        timeout: u32,
    }

    fn parse_config(input: &str) -> Result<Config, String> {
        let lines: Vec<&str> = input.lines().collect();

        let host = lines
            .get(0)
            .ok_or("Missing host")?
            .trim()
            .to_string();

        let port: u16 = lines
            .get(1)
            .ok_or("Missing port")?
            .trim()
            .parse()
            .map_err(|_| "Invalid port")?;

        let timeout: u32 = lines
            .get(2)
            .ok_or("Missing timeout")?
            .trim()
            .parse()
            .map_err(|_| "Invalid timeout")?;

        Ok(Config { host, port, timeout })
    }

    let valid_config = "localhost\n8080\n30";
    match parse_config(valid_config) {
        Ok(config) => println!("  Config: {:?}", config),
        Err(e) => println!("  Error: {}", e),
    }

    let invalid_config = "localhost\ninvalid\n30";
    match parse_config(invalid_config) {
        Ok(config) => println!("  Config: {:?}", config),
        Err(e) => println!("  Error: {}", e),
    }

    solutions::solution_3();
}

// =============================================================================
// EXERCISE 4: Custom Error Types
// =============================================================================
//
// For complex applications, define custom error types that provide
// detailed error information.
//
// YOUR TASK: Create and use custom error types.
//
fn exercise_4() {
    #[derive(Debug)]
    enum AuthError {
        InvalidCredentials,
        AccountLocked { attempts: u32 },
        SessionExpired { expired_at: u64 },
        PermissionDenied { required_role: String },
        NetworkError(String),
    }

    impl std::fmt::Display for AuthError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                AuthError::InvalidCredentials => write!(f, "Invalid username or password"),
                AuthError::AccountLocked { attempts } => {
                    write!(f, "Account locked after {} failed attempts", attempts)
                }
                AuthError::SessionExpired { expired_at } => {
                    write!(f, "Session expired at timestamp {}", expired_at)
                }
                AuthError::PermissionDenied { required_role } => {
                    write!(f, "Permission denied. Required role: {}", required_role)
                }
                AuthError::NetworkError(msg) => write!(f, "Network error: {}", msg),
            }
        }
    }

    fn authenticate(username: &str, password: &str) -> Result<String, AuthError> {
        if username == "locked" {
            return Err(AuthError::AccountLocked { attempts: 5 });
        }
        if username != "admin" || password != "secret" {
            return Err(AuthError::InvalidCredentials);
        }
        Ok(String::from("session_token_12345"))
    }

    fn access_resource(token: &str, resource: &str) -> Result<String, AuthError> {
        if token.is_empty() {
            return Err(AuthError::SessionExpired { expired_at: 1704067200 });
        }
        if resource == "/admin" {
            return Err(AuthError::PermissionDenied {
                required_role: String::from("admin"),
            });
        }
        Ok(format!("Data from {}", resource))
    }

    // Test various error conditions
    for (user, pass) in [("admin", "secret"), ("admin", "wrong"), ("locked", "pass")] {
        match authenticate(user, pass) {
            Ok(token) => println!("  Auth success: token length {}", token.len()),
            Err(e) => println!("  Auth failed: {}", e),
        }
    }

    solutions::solution_4();
}

// =============================================================================
// EXERCISE 5: Error Conversion
// =============================================================================
//
// Use From trait to convert between error types, enabling the ?
// operator across different error types.
//
// YOUR TASK: Implement error conversion for unified error handling.
//
fn exercise_5() {
    use std::num::ParseIntError;

    #[derive(Debug)]
    enum ConfigError {
        ParseError(String),
        ValidationError(String),
        MissingField(String),
    }

    impl From<ParseIntError> for ConfigError {
        fn from(err: ParseIntError) -> Self {
            ConfigError::ParseError(err.to_string())
        }
    }

    impl std::fmt::Display for ConfigError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                ConfigError::ParseError(msg) => write!(f, "Parse error: {}", msg),
                ConfigError::ValidationError(msg) => write!(f, "Validation error: {}", msg),
                ConfigError::MissingField(field) => write!(f, "Missing field: {}", field),
            }
        }
    }

    fn parse_security_config(input: &str) -> Result<(u16, u32, bool), ConfigError> {
        let mut port: Option<u16> = None;
        let mut timeout: Option<u32> = None;
        let mut tls_enabled: Option<bool> = None;

        for line in input.lines() {
            let parts: Vec<&str> = line.splitn(2, '=').collect();
            if parts.len() != 2 {
                continue;
            }

            let key = parts[0].trim();
            let value = parts[1].trim();

            match key {
                "port" => port = Some(value.parse()?), // ? converts ParseIntError
                "timeout" => timeout = Some(value.parse()?),
                "tls" => {
                    tls_enabled = Some(match value {
                        "true" | "1" | "yes" => true,
                        "false" | "0" | "no" => false,
                        _ => return Err(ConfigError::ValidationError(
                            format!("Invalid boolean: {}", value)
                        )),
                    });
                }
                _ => {}
            }
        }

        Ok((
            port.ok_or(ConfigError::MissingField("port".to_string()))?,
            timeout.ok_or(ConfigError::MissingField("timeout".to_string()))?,
            tls_enabled.ok_or(ConfigError::MissingField("tls".to_string()))?,
        ))
    }

    let config = "port=8443\ntimeout=30\ntls=true";
    match parse_security_config(config) {
        Ok((port, timeout, tls)) => {
            println!("  Port: {}, Timeout: {}s, TLS: {}", port, timeout, tls);
        }
        Err(e) => println!("  Error: {}", e),
    }

    let bad_config = "port=invalid\ntimeout=30\ntls=true";
    match parse_security_config(bad_config) {
        Ok(_) => println!("  Unexpected success"),
        Err(e) => println!("  Expected error: {}", e),
    }

    solutions::solution_5();
}

// =============================================================================
// EXERCISE 6: Option Combinators
// =============================================================================
//
// Option has many combinator methods for transforming and chaining operations.
//
// YOUR TASK: Use Option combinators effectively.
//
fn exercise_6() {
    fn get_config_value(key: &str) -> Option<String> {
        match key {
            "api_key" => Some(String::from("secret123")),
            "timeout" => Some(String::from("30")),
            "port" => Some(String::from("8080")),
            _ => None,
        }
    }

    // map: Transform the inner value
    let timeout: Option<u32> = get_config_value("timeout")
        .map(|s| s.parse::<u32>().unwrap_or(0));
    println!("  Timeout: {:?}", timeout);

    // and_then (flatMap): Chain Option-returning functions
    let port: Option<u16> = get_config_value("port")
        .and_then(|s| s.parse().ok());
    println!("  Port: {:?}", port);

    // filter: Keep value only if predicate is true
    let large_port = port.filter(|&p| p > 1024);
    println!("  Large port (>1024): {:?}", large_port);

    // or_else: Provide alternative if None
    let missing = get_config_value("missing")
        .or_else(|| Some(String::from("default_value")));
    println!("  Missing with fallback: {:?}", missing);

    // zip: Combine two Options
    let api_key = get_config_value("api_key");
    let timeout = get_config_value("timeout");
    let combined = api_key.zip(timeout);
    println!("  Combined: {:?}", combined);

    // take: Take ownership and leave None
    let mut value = Some(String::from("sensitive"));
    let taken = value.take();
    println!("  Taken: {:?}, Original now: {:?}", taken, value);

    // replace: Replace value and return old
    let mut config = Some(String::from("old_value"));
    let old = config.replace(String::from("new_value"));
    println!("  Old: {:?}, New: {:?}", old, config);

    solutions::solution_6();
}

// =============================================================================
// EXERCISE 7: Result Combinators
// =============================================================================
//
// Result also has powerful combinators for error handling pipelines.
//
// YOUR TASK: Use Result combinators for clean error handling.
//
fn exercise_7() {
    fn fetch_data(url: &str) -> Result<String, String> {
        if url.starts_with("https://") {
            Ok(format!("Data from {}", url))
        } else {
            Err(String::from("Insecure protocol"))
        }
    }

    fn validate_data(data: &str) -> Result<String, String> {
        if data.len() > 10 {
            Ok(data.to_uppercase())
        } else {
            Err(String::from("Data too short"))
        }
    }

    fn process_data(data: String) -> Result<usize, String> {
        Ok(data.len())
    }

    // map: Transform Ok value
    let result: Result<usize, String> = fetch_data("https://example.com")
        .map(|data| data.len());
    println!("  Mapped result: {:?}", result);

    // map_err: Transform Err value
    let result: Result<String, (String, u32)> = fetch_data("http://insecure.com")
        .map_err(|e| (e, 400));
    println!("  Mapped error: {:?}", result);

    // and_then: Chain Result-returning functions
    let result = fetch_data("https://example.com")
        .and_then(|data| validate_data(&data))
        .and_then(process_data);
    println!("  Chained result: {:?}", result);

    // or_else: Handle error and potentially recover
    let result = fetch_data("http://insecure.com")
        .or_else(|_| fetch_data("https://fallback.com"));
    println!("  With fallback: {:?}", result);

    // unwrap_or_else: Get value or compute default from error
    let data = fetch_data("http://bad.com")
        .unwrap_or_else(|err| format!("Error occurred: {}", err));
    println!("  With error handler: {}", data);

    solutions::solution_7();
}

// =============================================================================
// EXERCISE 8: Authentication Errors
// =============================================================================
//
// Build a complete authentication system with proper error handling.
//
// YOUR TASK: Implement comprehensive auth error handling.
//
fn exercise_8() {
    use std::collections::HashMap;

    #[derive(Debug)]
    enum AuthError {
        UserNotFound,
        InvalidPassword,
        AccountLocked,
        TokenExpired,
        InsufficientPermissions,
    }

    struct AuthService {
        users: HashMap<String, String>, // username -> password_hash
        locked: Vec<String>,
        sessions: HashMap<String, String>, // token -> username
    }

    impl AuthService {
        fn new() -> Self {
            let mut users = HashMap::new();
            users.insert("admin".to_string(), "hashed_password".to_string());
            users.insert("user".to_string(), "hashed_password".to_string());

            let mut sessions = HashMap::new();
            sessions.insert("valid_token".to_string(), "admin".to_string());

            AuthService {
                users,
                locked: vec!["blocked".to_string()],
                sessions,
            }
        }

        fn login(&self, username: &str, password_hash: &str) -> Result<String, AuthError> {
            if self.locked.contains(&username.to_string()) {
                return Err(AuthError::AccountLocked);
            }

            let stored_hash = self.users
                .get(username)
                .ok_or(AuthError::UserNotFound)?;

            if stored_hash != password_hash {
                return Err(AuthError::InvalidPassword);
            }

            Ok(format!("token_{}", username))
        }

        fn validate_token(&self, token: &str) -> Result<&str, AuthError> {
            self.sessions
                .get(token)
                .map(|s| s.as_str())
                .ok_or(AuthError::TokenExpired)
        }

        fn authorize(&self, token: &str, required_role: &str) -> Result<(), AuthError> {
            let username = self.validate_token(token)?;

            // Simple role check
            if required_role == "admin" && username != "admin" {
                return Err(AuthError::InsufficientPermissions);
            }

            Ok(())
        }
    }

    let auth = AuthService::new();

    // Test login scenarios
    let test_cases = vec![
        ("admin", "hashed_password"),
        ("admin", "wrong_password"),
        ("unknown", "password"),
        ("blocked", "password"),
    ];

    for (user, pass) in test_cases {
        match auth.login(user, pass) {
            Ok(token) => println!("  {} logged in: {}", user, token),
            Err(e) => println!("  {} failed: {:?}", user, e),
        }
    }

    // Test authorization
    match auth.authorize("valid_token", "admin") {
        Ok(()) => println!("  Authorization successful"),
        Err(e) => println!("  Authorization failed: {:?}", e),
    }

    solutions::solution_8();
}

// =============================================================================
// EXERCISE 9: File Security Scanner
// =============================================================================
//
// Build a security scanner that handles various file operation errors.
//
// YOUR TASK: Implement robust error handling for file operations.
//
fn exercise_9() {
    #[derive(Debug)]
    enum ScanError {
        FileNotFound(String),
        PermissionDenied(String),
        InvalidFormat(String),
        SuspiciousContent { file: String, reason: String },
    }

    impl std::fmt::Display for ScanError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                ScanError::FileNotFound(path) => write!(f, "File not found: {}", path),
                ScanError::PermissionDenied(path) => write!(f, "Permission denied: {}", path),
                ScanError::InvalidFormat(msg) => write!(f, "Invalid format: {}", msg),
                ScanError::SuspiciousContent { file, reason } => {
                    write!(f, "Suspicious content in {}: {}", file, reason)
                }
            }
        }
    }

    struct FileScanner {
        suspicious_patterns: Vec<&'static str>,
    }

    impl FileScanner {
        fn new() -> Self {
            FileScanner {
                suspicious_patterns: vec![
                    "eval(", "exec(", "system(", "<script>", "DROP TABLE",
                ],
            }
        }

        fn scan_content(&self, filename: &str, content: &str) -> Result<(), ScanError> {
            for pattern in &self.suspicious_patterns {
                if content.contains(pattern) {
                    return Err(ScanError::SuspiciousContent {
                        file: filename.to_string(),
                        reason: format!("Contains pattern: {}", pattern),
                    });
                }
            }
            Ok(())
        }

        fn scan_file(&self, path: &str) -> Result<ScanResult, ScanError> {
            // Simulate file reading
            let content = match path {
                "/safe/file.txt" => "This is safe content",
                "/malicious/script.js" => "eval(dangerous_code)",
                "/restricted/data.txt" => return Err(ScanError::PermissionDenied(path.to_string())),
                _ => return Err(ScanError::FileNotFound(path.to_string())),
            };

            self.scan_content(path, content)?;

            Ok(ScanResult {
                path: path.to_string(),
                size: content.len(),
                clean: true,
            })
        }

        fn scan_multiple(&self, paths: &[&str]) -> Vec<Result<ScanResult, ScanError>> {
            paths.iter().map(|p| self.scan_file(p)).collect()
        }
    }

    #[derive(Debug)]
    struct ScanResult {
        path: String,
        size: usize,
        clean: bool,
    }

    let scanner = FileScanner::new();

    let files = vec![
        "/safe/file.txt",
        "/malicious/script.js",
        "/restricted/data.txt",
        "/nonexistent/file.txt",
    ];

    println!("  Scan results:");
    for result in scanner.scan_multiple(&files) {
        match result {
            Ok(scan) => println!("    [CLEAN] {} ({} bytes)", scan.path, scan.size),
            Err(e) => println!("    [ERROR] {}", e),
        }
    }

    solutions::solution_9();
}

// =============================================================================
// EXERCISE 10: Challenge - Crypto Operation Pipeline
// =============================================================================
//
// Build a cryptographic operation pipeline with comprehensive error handling.
// Chain multiple operations where any step can fail.
//
// YOUR TASK: Implement a robust crypto pipeline.
//
fn exercise_10() {
    #[derive(Debug)]
    enum CryptoError {
        InvalidKey { expected: usize, got: usize },
        InvalidData(String),
        EncryptionFailed(String),
        DecryptionFailed(String),
        HashMismatch,
        SignatureInvalid,
    }

    impl std::fmt::Display for CryptoError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                CryptoError::InvalidKey { expected, got } => {
                    write!(f, "Invalid key size: expected {} bytes, got {}", expected, got)
                }
                CryptoError::InvalidData(msg) => write!(f, "Invalid data: {}", msg),
                CryptoError::EncryptionFailed(msg) => write!(f, "Encryption failed: {}", msg),
                CryptoError::DecryptionFailed(msg) => write!(f, "Decryption failed: {}", msg),
                CryptoError::HashMismatch => write!(f, "Hash verification failed"),
                CryptoError::SignatureInvalid => write!(f, "Invalid signature"),
            }
        }
    }

    struct CryptoOps;

    impl CryptoOps {
        fn validate_key(key: &[u8]) -> Result<(), CryptoError> {
            if key.len() != 32 {
                return Err(CryptoError::InvalidKey {
                    expected: 32,
                    got: key.len(),
                });
            }
            Ok(())
        }

        fn encrypt(data: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
            Self::validate_key(key)?;

            if data.is_empty() {
                return Err(CryptoError::InvalidData("Empty data".to_string()));
            }

            // Simulated encryption (XOR for demo)
            let encrypted: Vec<u8> = data
                .iter()
                .zip(key.iter().cycle())
                .map(|(d, k)| d ^ k)
                .collect();

            Ok(encrypted)
        }

        fn decrypt(data: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
            Self::validate_key(key)?;

            if data.is_empty() {
                return Err(CryptoError::DecryptionFailed("Empty ciphertext".to_string()));
            }

            // XOR is symmetric
            let decrypted: Vec<u8> = data
                .iter()
                .zip(key.iter().cycle())
                .map(|(d, k)| d ^ k)
                .collect();

            Ok(decrypted)
        }

        fn hash(data: &[u8]) -> Vec<u8> {
            // Simple hash for demo (sum of bytes)
            let sum: u64 = data.iter().map(|&b| b as u64).sum();
            sum.to_le_bytes().to_vec()
        }

        fn verify_hash(data: &[u8], expected_hash: &[u8]) -> Result<(), CryptoError> {
            let computed = Self::hash(data);
            if computed != expected_hash {
                return Err(CryptoError::HashMismatch);
            }
            Ok(())
        }

        fn sign(data: &[u8], private_key: &[u8]) -> Result<Vec<u8>, CryptoError> {
            Self::validate_key(private_key)?;
            // Simplified: signature is hash XOR with key bytes
            let hash = Self::hash(data);
            let signature: Vec<u8> = hash
                .iter()
                .zip(private_key.iter())
                .map(|(h, k)| h ^ k)
                .collect();
            Ok(signature)
        }

        fn verify_signature(
            data: &[u8],
            signature: &[u8],
            public_key: &[u8],
        ) -> Result<(), CryptoError> {
            Self::validate_key(public_key)?;
            let expected = Self::sign(data, public_key)?;
            if signature != expected {
                return Err(CryptoError::SignatureInvalid);
            }
            Ok(())
        }
    }

    fn secure_transmit(
        plaintext: &[u8],
        encryption_key: &[u8],
        signing_key: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), CryptoError> {
        // 1. Hash the plaintext
        let hash = CryptoOps::hash(plaintext);

        // 2. Sign the hash
        let signature = CryptoOps::sign(&hash, signing_key)?;

        // 3. Encrypt the plaintext
        let ciphertext = CryptoOps::encrypt(plaintext, encryption_key)?;

        Ok((ciphertext, hash, signature))
    }

    fn secure_receive(
        ciphertext: &[u8],
        hash: &[u8],
        signature: &[u8],
        encryption_key: &[u8],
        verification_key: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        // 1. Verify signature
        CryptoOps::verify_signature(hash, signature, verification_key)?;

        // 2. Decrypt
        let plaintext = CryptoOps::decrypt(ciphertext, encryption_key)?;

        // 3. Verify hash
        CryptoOps::verify_hash(&plaintext, hash)?;

        Ok(plaintext)
    }

    // Test the pipeline
    let key = [0u8; 32]; // 32-byte key
    let message = b"Secret message for secure transmission";

    println!("  Original message: {:?}", String::from_utf8_lossy(message));

    match secure_transmit(message, &key, &key) {
        Ok((ciphertext, hash, signature)) => {
            println!("  Encrypted: {} bytes", ciphertext.len());
            println!("  Hash: {} bytes", hash.len());
            println!("  Signature: {} bytes", signature.len());

            match secure_receive(&ciphertext, &hash, &signature, &key, &key) {
                Ok(decrypted) => {
                    println!("  Decrypted: {:?}", String::from_utf8_lossy(&decrypted));
                }
                Err(e) => println!("  Receive error: {}", e),
            }
        }
        Err(e) => println!("  Transmit error: {}", e),
    }

    // Test error cases
    let short_key = [0u8; 16];
    match CryptoOps::encrypt(message, &short_key) {
        Ok(_) => println!("  Unexpected success"),
        Err(e) => println!("  Expected error: {}", e),
    }

    solutions::solution_10();
}
