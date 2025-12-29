//! # Solutions for Error Handling Exercises
//!
//! Reference solutions demonstrating proper error handling patterns.

/// Solution 1: Option patterns
pub fn solution_1() {
    println!("  [Solution 1]:");

    fn safe_divide(a: i32, b: i32) -> Option<i32> {
        if b == 0 { None } else { Some(a / b) }
    }

    fn get_nested_value(data: &[Vec<i32>], row: usize, col: usize) -> Option<i32> {
        data.get(row)?.get(col).copied()
    }

    // Pattern: Use ? with Option in Option-returning function
    fn complex_lookup(id: Option<u32>) -> Option<String> {
        let id = id?; // Early return if None
        if id > 100 { None } else { Some(format!("User_{}", id)) }
    }

    println!("    10 / 2 = {:?}", safe_divide(10, 2));
    println!("    10 / 0 = {:?}", safe_divide(10, 0));

    let matrix = vec![vec![1, 2, 3], vec![4, 5, 6]];
    println!("    matrix[1][2] = {:?}", get_nested_value(&matrix, 1, 2));
    println!("    matrix[5][0] = {:?}", get_nested_value(&matrix, 5, 0));

    println!("    lookup(50) = {:?}", complex_lookup(Some(50)));
    println!("    lookup(None) = {:?}", complex_lookup(None));
}

/// Solution 2: Result patterns
pub fn solution_2() {
    println!("  [Solution 2]:");

    #[derive(Debug)]
    enum ValidationError {
        TooShort(usize),
        TooLong(usize),
        InvalidCharacter(char),
        Reserved(String),
    }

    fn validate_username(username: &str) -> Result<(), ValidationError> {
        if username.len() < 3 {
            return Err(ValidationError::TooShort(username.len()));
        }
        if username.len() > 20 {
            return Err(ValidationError::TooLong(username.len()));
        }
        for c in username.chars() {
            if !c.is_alphanumeric() && c != '_' {
                return Err(ValidationError::InvalidCharacter(c));
            }
        }
        let reserved = ["admin", "root", "system"];
        if reserved.contains(&username.to_lowercase().as_str()) {
            return Err(ValidationError::Reserved(username.to_string()));
        }
        Ok(())
    }

    let usernames = vec!["ab", "valid_user", "admin", "test@user", "a".repeat(25).as_str()];
    for name in usernames {
        match validate_username(name) {
            Ok(()) => println!("    '{}' is valid", name),
            Err(e) => println!("    '{}' error: {:?}", name, e),
        }
    }
}

/// Solution 3: The ? operator in detail
pub fn solution_3() {
    println!("  [Solution 3]:");

    #[derive(Debug)]
    struct ServerConfig {
        host: String,
        port: u16,
        workers: u32,
        tls: bool,
    }

    #[derive(Debug)]
    enum ConfigError {
        MissingField(String),
        InvalidValue { field: String, value: String },
    }

    impl std::fmt::Display for ConfigError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                ConfigError::MissingField(field) => write!(f, "Missing field: {}", field),
                ConfigError::InvalidValue { field, value } => {
                    write!(f, "Invalid value '{}' for field '{}'", value, field)
                }
            }
        }
    }

    fn parse_config(input: &str) -> Result<ServerConfig, ConfigError> {
        use std::collections::HashMap;

        let mut map: HashMap<&str, &str> = HashMap::new();
        for line in input.lines() {
            if let Some(eq_pos) = line.find('=') {
                let key = line[..eq_pos].trim();
                let value = line[eq_pos + 1..].trim();
                map.insert(key, value);
            }
        }

        let host = map
            .get("host")
            .ok_or_else(|| ConfigError::MissingField("host".into()))?
            .to_string();

        let port_str = *map
            .get("port")
            .ok_or_else(|| ConfigError::MissingField("port".into()))?;
        let port: u16 = port_str.parse().map_err(|_| ConfigError::InvalidValue {
            field: "port".into(),
            value: port_str.into(),
        })?;

        let workers_str = *map
            .get("workers")
            .ok_or_else(|| ConfigError::MissingField("workers".into()))?;
        let workers: u32 = workers_str.parse().map_err(|_| ConfigError::InvalidValue {
            field: "workers".into(),
            value: workers_str.into(),
        })?;

        let tls = map.get("tls").map(|&v| v == "true").unwrap_or(false);

        Ok(ServerConfig { host, port, workers, tls })
    }

    let config = "host = 127.0.0.1\nport = 8080\nworkers = 4\ntls = true";
    match parse_config(config) {
        Ok(cfg) => println!("    Parsed: {:?}", cfg),
        Err(e) => println!("    Error: {}", e),
    }
}

/// Solution 4: Custom error types
pub fn solution_4() {
    println!("  [Solution 4]:");

    use std::error::Error;

    #[derive(Debug)]
    struct SecurityError {
        kind: SecurityErrorKind,
        context: Option<String>,
        source: Option<Box<dyn Error>>,
    }

    #[derive(Debug)]
    enum SecurityErrorKind {
        Authentication,
        Authorization,
        Encryption,
        Network,
        Configuration,
    }

    impl SecurityError {
        fn new(kind: SecurityErrorKind) -> Self {
            SecurityError {
                kind,
                context: None,
                source: None,
            }
        }

        fn with_context(mut self, context: impl Into<String>) -> Self {
            self.context = Some(context.into());
            self
        }

        fn with_source(mut self, source: impl Error + 'static) -> Self {
            self.source = Some(Box::new(source));
            self
        }
    }

    impl std::fmt::Display for SecurityError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{:?}", self.kind)?;
            if let Some(ref ctx) = self.context {
                write!(f, ": {}", ctx)?;
            }
            Ok(())
        }
    }

    impl Error for SecurityError {
        fn source(&self) -> Option<&(dyn Error + 'static)> {
            self.source.as_ref().map(|s| s.as_ref())
        }
    }

    fn authenticate(token: &str) -> Result<String, SecurityError> {
        if token.is_empty() {
            return Err(SecurityError::new(SecurityErrorKind::Authentication)
                .with_context("Empty token provided"));
        }
        if !token.starts_with("Bearer ") {
            return Err(SecurityError::new(SecurityErrorKind::Authentication)
                .with_context("Invalid token format"));
        }
        Ok(String::from("authenticated_user"))
    }

    match authenticate("Bearer valid_token") {
        Ok(user) => println!("    Authenticated: {}", user),
        Err(e) => println!("    Error: {}", e),
    }

    match authenticate("invalid") {
        Ok(_) => println!("    Unexpected success"),
        Err(e) => println!("    Expected error: {}", e),
    }
}

/// Solution 5: Error conversion
pub fn solution_5() {
    println!("  [Solution 5]:");

    use std::num::ParseIntError;

    #[derive(Debug)]
    enum AppError {
        Parse(ParseIntError),
        Io(String),
        Security(String),
    }

    impl From<ParseIntError> for AppError {
        fn from(err: ParseIntError) -> Self {
            AppError::Parse(err)
        }
    }

    impl std::fmt::Display for AppError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                AppError::Parse(e) => write!(f, "Parse error: {}", e),
                AppError::Io(msg) => write!(f, "IO error: {}", msg),
                AppError::Security(msg) => write!(f, "Security error: {}", msg),
            }
        }
    }

    // Now ? works across different error types
    fn process_input(input: &str) -> Result<u32, AppError> {
        let value: u32 = input.parse()?; // ParseIntError -> AppError

        if value == 0 {
            return Err(AppError::Security("Zero not allowed".into()));
        }

        Ok(value * 2)
    }

    println!("    process('42') = {:?}", process_input("42"));
    println!("    process('0') = {:?}", process_input("0"));
    println!("    process('abc') = {:?}", process_input("abc"));
}

/// Solution 6: Option combinators
pub fn solution_6() {
    println!("  [Solution 6]:");

    struct User {
        name: String,
        email: Option<String>,
        age: Option<u32>,
    }

    let users = vec![
        User {
            name: "Alice".into(),
            email: Some("alice@example.com".into()),
            age: Some(30),
        },
        User {
            name: "Bob".into(),
            email: None,
            age: Some(25),
        },
        User {
            name: "Charlie".into(),
            email: Some("charlie@example.com".into()),
            age: None,
        },
    ];

    // Filter and map
    let emails: Vec<&str> = users
        .iter()
        .filter_map(|u| u.email.as_ref().map(|e| e.as_str()))
        .collect();
    println!("    Emails: {:?}", emails);

    // Combine options
    for user in &users {
        let info = user.email.as_ref().zip(user.age.as_ref());
        match info {
            Some((email, age)) => println!("    {} ({}) - age {}", user.name, email, age),
            None => println!("    {} - incomplete profile", user.name),
        }
    }

    // Default values with computation
    fn get_age_category(age: Option<u32>) -> &'static str {
        age.map(|a| if a < 18 { "minor" } else { "adult" })
            .unwrap_or("unknown")
    }

    for user in &users {
        println!("    {} is {}", user.name, get_age_category(user.age));
    }
}

/// Solution 7: Result combinators
pub fn solution_7() {
    println!("  [Solution 7]:");

    fn validate(input: &str) -> Result<&str, &'static str> {
        if input.is_empty() {
            Err("Empty input")
        } else if input.len() > 100 {
            Err("Input too long")
        } else {
            Ok(input)
        }
    }

    fn sanitize(input: &str) -> Result<String, &'static str> {
        let sanitized = input.trim().to_lowercase();
        if sanitized.contains('<') || sanitized.contains('>') {
            Err("HTML tags not allowed")
        } else {
            Ok(sanitized)
        }
    }

    fn process(input: &str) -> Result<String, &'static str> {
        Ok(format!("Processed: {}", input))
    }

    // Full pipeline
    fn full_pipeline(input: &str) -> Result<String, &'static str> {
        validate(input)
            .and_then(|v| sanitize(v))
            .and_then(|s| process(&s))
    }

    let inputs = vec!["  HELLO World  ", "<script>alert('xss')</script>", "", "Valid Input"];

    for input in inputs {
        match full_pipeline(input) {
            Ok(result) => println!("    '{}' -> {}", input, result),
            Err(e) => println!("    '{}' -> Error: {}", input, e),
        }
    }
}

/// Solution 8: Authentication system
pub fn solution_8() {
    println!("  [Solution 8]:");

    use std::collections::HashMap;
    use std::time::{Duration, Instant};

    #[derive(Debug)]
    enum AuthError {
        UserNotFound,
        InvalidPassword,
        AccountLocked(Duration),
        TokenExpired,
        RateLimited(Duration),
    }

    impl std::fmt::Display for AuthError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                AuthError::UserNotFound => write!(f, "User not found"),
                AuthError::InvalidPassword => write!(f, "Invalid password"),
                AuthError::AccountLocked(d) => write!(f, "Account locked for {:?}", d),
                AuthError::TokenExpired => write!(f, "Session expired"),
                AuthError::RateLimited(d) => write!(f, "Rate limited, retry in {:?}", d),
            }
        }
    }

    struct AuthManager {
        users: HashMap<String, String>,
        failed_attempts: HashMap<String, u32>,
        sessions: HashMap<String, (String, Instant)>,
    }

    impl AuthManager {
        fn new() -> Self {
            let mut users = HashMap::new();
            users.insert("admin".into(), "secret_hash".into());
            AuthManager {
                users,
                failed_attempts: HashMap::new(),
                sessions: HashMap::new(),
            }
        }

        fn login(&mut self, username: &str, password_hash: &str) -> Result<String, AuthError> {
            // Check lockout
            if let Some(&attempts) = self.failed_attempts.get(username) {
                if attempts >= 5 {
                    return Err(AuthError::AccountLocked(Duration::from_secs(300)));
                }
            }

            let stored = self.users.get(username).ok_or(AuthError::UserNotFound)?;

            if stored != password_hash {
                *self.failed_attempts.entry(username.into()).or_insert(0) += 1;
                return Err(AuthError::InvalidPassword);
            }

            // Clear failed attempts on success
            self.failed_attempts.remove(username);

            let token = format!("token_{}_{}", username, rand_id());
            self.sessions.insert(token.clone(), (username.into(), Instant::now()));

            Ok(token)
        }

        fn validate(&self, token: &str) -> Result<&str, AuthError> {
            let (username, created) = self.sessions.get(token).ok_or(AuthError::TokenExpired)?;

            if created.elapsed() > Duration::from_secs(3600) {
                return Err(AuthError::TokenExpired);
            }

            Ok(username)
        }
    }

    fn rand_id() -> u32 {
        42 // Simplified
    }

    let mut auth = AuthManager::new();

    match auth.login("admin", "secret_hash") {
        Ok(token) => {
            println!("    Login success: {}", token);
            match auth.validate(&token) {
                Ok(user) => println!("    Token valid for: {}", user),
                Err(e) => println!("    Token error: {}", e),
            }
        }
        Err(e) => println!("    Login failed: {}", e),
    }
}

/// Solution 9: File scanner
pub fn solution_9() {
    println!("  [Solution 9]:");

    #[derive(Debug)]
    enum ScanError {
        NotFound(String),
        AccessDenied(String),
        Malformed(String),
        ThreatDetected { path: String, threat: String, severity: u8 },
    }

    #[derive(Debug)]
    struct ScanReport {
        path: String,
        size: usize,
        hash: String,
        threats: Vec<String>,
    }

    struct Scanner {
        signatures: Vec<(&'static str, &'static str, u8)>, // pattern, name, severity
    }

    impl Scanner {
        fn new() -> Self {
            Scanner {
                signatures: vec![
                    ("EICAR", "EICAR Test", 1),
                    ("eval(", "Code Injection", 7),
                    ("rm -rf", "Dangerous Command", 9),
                    ("DROP TABLE", "SQL Injection", 8),
                ],
            }
        }

        fn scan(&self, path: &str, content: &str) -> Result<ScanReport, ScanError> {
            let mut threats = Vec::new();

            for (pattern, name, severity) in &self.signatures {
                if content.contains(pattern) {
                    if *severity >= 8 {
                        return Err(ScanError::ThreatDetected {
                            path: path.into(),
                            threat: name.to_string(),
                            severity: *severity,
                        });
                    }
                    threats.push(format!("{} (severity: {})", name, severity));
                }
            }

            Ok(ScanReport {
                path: path.into(),
                size: content.len(),
                hash: format!("{:x}", content.len() * 31337),
                threats,
            })
        }
    }

    let scanner = Scanner::new();

    let files = vec![
        ("/clean.txt", "This is a clean file"),
        ("/suspicious.js", "let x = eval(input)"),
        ("/dangerous.sh", "rm -rf / --no-preserve-root"),
    ];

    for (path, content) in files {
        match scanner.scan(path, content) {
            Ok(report) => {
                if report.threats.is_empty() {
                    println!("    {} - Clean", report.path);
                } else {
                    println!("    {} - Warnings: {:?}", report.path, report.threats);
                }
            }
            Err(e) => println!("    BLOCKED: {:?}", e),
        }
    }
}

/// Solution 10: Crypto pipeline
pub fn solution_10() {
    println!("  [Solution 10]:");

    use std::fmt;

    #[derive(Debug)]
    enum CryptoError {
        KeyError(String),
        DataError(String),
        IntegrityError(String),
    }

    impl fmt::Display for CryptoError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                CryptoError::KeyError(msg) => write!(f, "Key error: {}", msg),
                CryptoError::DataError(msg) => write!(f, "Data error: {}", msg),
                CryptoError::IntegrityError(msg) => write!(f, "Integrity error: {}", msg),
            }
        }
    }

    struct SecureChannel {
        key: [u8; 32],
    }

    impl SecureChannel {
        fn new(key: [u8; 32]) -> Self {
            SecureChannel { key }
        }

        fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
            if plaintext.is_empty() {
                return Err(CryptoError::DataError("Empty plaintext".into()));
            }

            // Compute checksum
            let checksum: u8 = plaintext.iter().fold(0u8, |a, b| a.wrapping_add(*b));

            // "Encrypt" (XOR for demo)
            let mut sealed: Vec<u8> = plaintext
                .iter()
                .zip(self.key.iter().cycle())
                .map(|(p, k)| p ^ k)
                .collect();

            // Append checksum
            sealed.push(checksum ^ self.key[0]);

            Ok(sealed)
        }

        fn open(&self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
            if ciphertext.len() < 2 {
                return Err(CryptoError::DataError("Ciphertext too short".into()));
            }

            // Extract checksum
            let encrypted_checksum = ciphertext[ciphertext.len() - 1];
            let stored_checksum = encrypted_checksum ^ self.key[0];

            // "Decrypt"
            let plaintext: Vec<u8> = ciphertext[..ciphertext.len() - 1]
                .iter()
                .zip(self.key.iter().cycle())
                .map(|(c, k)| c ^ k)
                .collect();

            // Verify checksum
            let computed_checksum: u8 = plaintext.iter().fold(0u8, |a, b| a.wrapping_add(*b));

            if computed_checksum != stored_checksum {
                return Err(CryptoError::IntegrityError("Checksum mismatch".into()));
            }

            Ok(plaintext)
        }
    }

    let key = [0x42u8; 32];
    let channel = SecureChannel::new(key);

    let message = b"Confidential data";
    println!("    Original: {:?}", String::from_utf8_lossy(message));

    match channel.seal(message) {
        Ok(sealed) => {
            println!("    Sealed: {} bytes", sealed.len());

            match channel.open(&sealed) {
                Ok(opened) => {
                    println!("    Opened: {:?}", String::from_utf8_lossy(&opened));
                }
                Err(e) => println!("    Open error: {}", e),
            }

            // Test tampering
            let mut tampered = sealed.clone();
            tampered[0] ^= 0xFF;
            match channel.open(&tampered) {
                Ok(_) => println!("    Tamper not detected!"),
                Err(e) => println!("    Tamper detected: {}", e),
            }
        }
        Err(e) => println!("    Seal error: {}", e),
    }
}
