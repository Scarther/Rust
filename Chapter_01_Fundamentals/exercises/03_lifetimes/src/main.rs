//! # Lifetime Annotation Exercises
//!
//! Lifetimes ensure references remain valid for as long as they're used.
//! This is crucial for memory safety and preventing dangling pointers.
//!
//! Run with: cargo run
//! Check solutions in: src/solutions.rs

#![allow(unused_variables, dead_code)]

mod solutions;

fn main() {
    println!("=== Rust Lifetime Exercises ===\n");

    println!("Exercise 1: Basic Lifetime Annotations");
    exercise_1();

    println!("\nExercise 2: Multiple Lifetimes");
    exercise_2();

    println!("\nExercise 3: Struct Lifetimes");
    exercise_3();

    println!("\nExercise 4: Method Lifetimes");
    exercise_4();

    println!("\nExercise 5: Static Lifetime");
    exercise_5();

    println!("\nExercise 6: Lifetime Bounds");
    exercise_6();

    println!("\nExercise 7: Security Token Validation");
    exercise_7();

    println!("\nExercise 8: Log Parser");
    exercise_8();

    println!("\nExercise 9: Configuration Reader");
    exercise_9();

    println!("\nExercise 10: Challenge - Zero-Copy Parser");
    exercise_10();

    println!("\n=== All exercises completed! ===");
}

// =============================================================================
// EXERCISE 1: Basic Lifetime Annotations
// =============================================================================
//
// When a function returns a reference, Rust needs to know how long that
// reference is valid. Lifetime annotations tell Rust how references relate.
//
// YOUR TASK: Add lifetime annotations to make the function compile.
//
fn exercise_1() {
    // This function returns a reference to the longer string
    // The lifetime annotation 'a means "the returned reference lives as long
    // as both input references"
    fn longest<'a>(x: &'a str, y: &'a str) -> &'a str {
        if x.len() > y.len() {
            x
        } else {
            y
        }
    }

    let string1 = String::from("long string is long");
    let result;
    {
        let string2 = String::from("xyz");
        result = longest(string1.as_str(), string2.as_str());
        println!("  Longest in inner scope: {}", result);
    }
    // Note: result is used inside the inner scope where string2 is valid

    // This works because string1 outlives the usage of result
    let string3 = String::from("short");
    let result2 = longest(string1.as_str(), string3.as_str());
    println!("  Longest: {}", result2);

    solutions::solution_1();
}

// =============================================================================
// EXERCISE 2: Multiple Lifetimes
// =============================================================================
//
// Sometimes different references have different lifetimes and you need
// to annotate them separately.
//
// YOUR TASK: Understand how multiple lifetime parameters work.
//
fn exercise_2() {
    // Two different lifetimes - 'a for the first parameter, 'b for context
    // Return lifetime is tied to 'a (the data), not 'b (the context)
    fn extract_with_context<'a, 'b>(data: &'a str, context: &'b str) -> &'a str {
        println!("  Context: {}", context);
        data
    }

    // Here the return lifetime only depends on the first parameter
    fn first_word<'a>(s: &'a str) -> &'a str {
        match s.find(' ') {
            Some(pos) => &s[..pos],
            None => s,
        }
    }

    let data = String::from("sensitive_data_here");
    let extracted;
    {
        let context = String::from("extraction context");
        extracted = extract_with_context(&data, &context);
        // context goes out of scope, but extracted is still valid
        // because it's tied to data's lifetime, not context's
    }
    println!("  Extracted: {}", extracted);

    let sentence = "Hello world from Rust";
    let first = first_word(sentence);
    println!("  First word: {}", first);

    solutions::solution_2();
}

// =============================================================================
// EXERCISE 3: Struct Lifetimes
// =============================================================================
//
// When a struct holds references, it needs lifetime annotations to ensure
// the references remain valid for the struct's lifetime.
//
// YOUR TASK: Add lifetime annotations to the struct.
//
fn exercise_3() {
    // This struct holds a reference, so it needs a lifetime parameter
    struct SecurityEvent<'a> {
        timestamp: u64,
        event_type: &'a str,
        details: &'a str,
    }

    impl<'a> SecurityEvent<'a> {
        fn new(timestamp: u64, event_type: &'a str, details: &'a str) -> Self {
            SecurityEvent {
                timestamp,
                event_type,
                details,
            }
        }

        fn summary(&self) -> String {
            format!("[{}] {}: {}", self.timestamp, self.event_type, self.details)
        }
    }

    let event_type = "LOGIN_ATTEMPT";
    let details = "User admin from 192.168.1.1";

    let event = SecurityEvent::new(1704067200, event_type, details);
    println!("  Event: {}", event.summary());

    solutions::solution_3();
}

// =============================================================================
// EXERCISE 4: Method Lifetimes
// =============================================================================
//
// Methods can have their own lifetime parameters in addition to the
// struct's lifetime parameters.
//
// YOUR TASK: Implement methods with proper lifetime annotations.
//
fn exercise_4() {
    struct Parser<'a> {
        input: &'a str,
        position: usize,
    }

    impl<'a> Parser<'a> {
        fn new(input: &'a str) -> Self {
            Parser { input, position: 0 }
        }

        // Returns a reference with the same lifetime as the input
        fn remaining(&self) -> &'a str {
            &self.input[self.position..]
        }

        // Returns a slice of the input
        fn take(&mut self, n: usize) -> &'a str {
            let start = self.position;
            let end = (start + n).min(self.input.len());
            self.position = end;
            &self.input[start..end]
        }

        // Peek at next n characters without consuming
        fn peek(&self, n: usize) -> &'a str {
            let end = (self.position + n).min(self.input.len());
            &self.input[self.position..end]
        }
    }

    let input = "GET /api/users HTTP/1.1";
    let mut parser = Parser::new(input);

    let method = parser.take(3);
    println!("  Method: {}", method);

    parser.take(1); // Skip space

    let path = parser.take(10);
    println!("  Path: {}", path);

    println!("  Remaining: {}", parser.remaining());

    solutions::solution_4();
}

// =============================================================================
// EXERCISE 5: Static Lifetime
// =============================================================================
//
// The 'static lifetime means the reference can live for the entire
// duration of the program. String literals have 'static lifetime.
//
// YOUR TASK: Understand when and how to use 'static.
//
fn exercise_5() {
    // String literals are 'static
    let static_str: &'static str = "I live forever";

    // Function that returns a static string based on error code
    fn error_message(code: u32) -> &'static str {
        match code {
            401 => "Unauthorized",
            403 => "Forbidden",
            404 => "Not Found",
            500 => "Internal Server Error",
            _ => "Unknown Error",
        }
    }

    // Constants are also 'static
    const SECRET_KEY: &str = "default_secret_key";

    // Static items
    static ERROR_PREFIX: &str = "[ERROR]";

    fn format_error(code: u32) -> String {
        format!("{} {} (code: {})", ERROR_PREFIX, error_message(code), code)
    }

    println!("  Static string: {}", static_str);
    println!("  Error 401: {}", error_message(401));
    println!("  Formatted: {}", format_error(403));

    solutions::solution_5();
}

// =============================================================================
// EXERCISE 6: Lifetime Bounds
// =============================================================================
//
// Generic types can have lifetime bounds that specify minimum lifetime
// requirements for the type parameter.
//
// YOUR TASK: Add lifetime bounds to generic types.
//
fn exercise_6() {
    // T: 'a means T must live at least as long as 'a
    struct Wrapper<'a, T: 'a> {
        value: &'a T,
    }

    impl<'a, T: 'a> Wrapper<'a, T> {
        fn new(value: &'a T) -> Self {
            Wrapper { value }
        }

        fn get(&self) -> &T {
            self.value
        }
    }

    // Multiple bounds: T must implement Debug and live at least as long as 'a
    fn debug_wrapper<'a, T: std::fmt::Debug + 'a>(wrapper: &Wrapper<'a, T>) {
        println!("  Wrapped value: {:?}", wrapper.get());
    }

    let data = vec![1, 2, 3, 4, 5];
    let wrapper = Wrapper::new(&data);
    debug_wrapper(&wrapper);

    let text = String::from("Hello, Rust!");
    let text_wrapper = Wrapper::new(&text);
    println!("  Text wrapper: {}", text_wrapper.get());

    solutions::solution_6();
}

// =============================================================================
// EXERCISE 7: Security Token Validation
// =============================================================================
//
// Build a token validator that uses references efficiently with proper
// lifetime management.
//
// YOUR TASK: Implement the TokenValidator with correct lifetimes.
//
fn exercise_7() {
    #[derive(Debug)]
    struct Token<'a> {
        header: &'a str,
        payload: &'a str,
        signature: &'a str,
    }

    struct TokenValidator<'a> {
        secret_key: &'a str,
    }

    impl<'a> TokenValidator<'a> {
        fn new(secret_key: &'a str) -> Self {
            TokenValidator { secret_key }
        }

        // Parse a token string into Token struct
        // The Token references parts of the original string
        fn parse<'b>(&self, token_str: &'b str) -> Option<Token<'b>> {
            let parts: Vec<&str> = token_str.split('.').collect();
            if parts.len() == 3 {
                Some(Token {
                    header: parts[0],
                    payload: parts[1],
                    signature: parts[2],
                })
            } else {
                None
            }
        }

        fn validate(&self, token: &Token) -> bool {
            // Simple validation: signature should be header + payload + secret
            let expected = format!(
                "{}.{}.{}",
                token.header,
                token.payload,
                self.secret_key.len()
            );
            token.signature == format!("{}", self.secret_key.len())
        }
    }

    let secret = "my_secret_key";
    let validator = TokenValidator::new(secret);

    let token_string = "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.13";
    if let Some(token) = validator.parse(token_string) {
        println!("  Token header: {}", token.header);
        println!("  Token payload: {}", token.payload);
        println!("  Valid: {}", validator.validate(&token));
    }

    solutions::solution_7();
}

// =============================================================================
// EXERCISE 8: Log Parser
// =============================================================================
//
// Create a log parser that returns references to parts of the original
// log line without copying data.
//
// YOUR TASK: Implement zero-copy log parsing with lifetimes.
//
fn exercise_8() {
    #[derive(Debug)]
    struct LogEntry<'a> {
        timestamp: &'a str,
        level: &'a str,
        source: &'a str,
        message: &'a str,
    }

    fn parse_log_entry(line: &str) -> Option<LogEntry> {
        // Format: "2024-01-01T12:00:00 [INFO] source: message"
        let parts: Vec<&str> = line.splitn(2, ' ').collect();
        if parts.len() != 2 {
            return None;
        }

        let timestamp = parts[0];
        let rest = parts[1];

        // Extract level [INFO], [ERROR], etc.
        if !rest.starts_with('[') {
            return None;
        }
        let level_end = rest.find(']')?;
        let level = &rest[1..level_end];

        let after_level = &rest[level_end + 2..]; // Skip "] "

        // Extract source and message
        let colon_pos = after_level.find(':')?;
        let source = &after_level[..colon_pos];
        let message = after_level[colon_pos + 1..].trim();

        Some(LogEntry {
            timestamp,
            level,
            source,
            message,
        })
    }

    fn filter_by_level<'a, 'b>(entries: &'a [LogEntry<'b>], level: &str) -> Vec<&'a LogEntry<'b>> {
        entries.iter().filter(|e| e.level == level).collect()
    }

    let log_lines = vec![
        "2024-01-01T12:00:00 [INFO] auth: User logged in",
        "2024-01-01T12:00:01 [ERROR] db: Connection failed",
        "2024-01-01T12:00:02 [INFO] api: Request processed",
        "2024-01-01T12:00:03 [WARN] security: Suspicious activity",
    ];

    let entries: Vec<LogEntry> = log_lines
        .iter()
        .filter_map(|line| parse_log_entry(line))
        .collect();

    println!("  Parsed {} entries", entries.len());

    let errors = filter_by_level(&entries, "ERROR");
    println!("  Errors: {}", errors.len());

    for entry in &entries {
        println!("  [{}] {} - {}", entry.level, entry.source, entry.message);
    }

    solutions::solution_8();
}

// =============================================================================
// EXERCISE 9: Configuration Reader
// =============================================================================
//
// Implement a configuration reader that holds references to the original
// configuration data for efficient access.
//
// YOUR TASK: Build ConfigReader with proper lifetime management.
//
fn exercise_9() {
    use std::collections::HashMap;

    struct ConfigReader<'a> {
        raw_config: &'a str,
        values: HashMap<&'a str, &'a str>,
    }

    impl<'a> ConfigReader<'a> {
        fn parse(config: &'a str) -> Self {
            let mut values = HashMap::new();

            for line in config.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }

                if let Some(eq_pos) = line.find('=') {
                    let key = line[..eq_pos].trim();
                    let value = line[eq_pos + 1..].trim();
                    values.insert(key, value);
                }
            }

            ConfigReader {
                raw_config: config,
                values,
            }
        }

        fn get(&self, key: &str) -> Option<&'a str> {
            self.values.get(key).copied()
        }

        fn get_or_default(&self, key: &str, default: &'static str) -> &str {
            self.values.get(key).copied().unwrap_or(default)
        }

        fn keys(&self) -> Vec<&'a str> {
            self.values.keys().copied().collect()
        }
    }

    let config_data = r#"
        # Security Configuration
        api_key = secret_api_key_12345
        max_attempts = 3
        timeout = 30
        enable_logging = true
        # End of config
    "#;

    let config = ConfigReader::parse(config_data);

    println!("  API Key: {:?}", config.get("api_key"));
    println!("  Max Attempts: {:?}", config.get("max_attempts"));
    println!("  Missing Key: {:?}", config.get("nonexistent"));
    println!("  With Default: {}", config.get_or_default("missing", "default_value"));
    println!("  All keys: {:?}", config.keys());

    solutions::solution_9();
}

// =============================================================================
// EXERCISE 10: Challenge - Zero-Copy Parser
// =============================================================================
//
// Build a HTTP request parser that parses headers without copying any data.
// All parsed values should be references into the original request string.
//
// YOUR TASK: Implement zero-copy HTTP parsing.
//
fn exercise_10() {
    use std::collections::HashMap;

    #[derive(Debug)]
    struct HttpRequest<'a> {
        method: &'a str,
        path: &'a str,
        version: &'a str,
        headers: HashMap<&'a str, &'a str>,
        body: Option<&'a str>,
    }

    fn parse_http_request(raw: &str) -> Option<HttpRequest> {
        let mut lines = raw.lines();

        // Parse request line: GET /path HTTP/1.1
        let request_line = lines.next()?;
        let mut parts = request_line.split_whitespace();
        let method = parts.next()?;
        let path = parts.next()?;
        let version = parts.next()?;

        // Parse headers
        let mut headers = HashMap::new();
        let mut body_start = None;

        for line in lines {
            if line.is_empty() {
                // Empty line indicates start of body
                body_start = Some(line);
                break;
            }

            if let Some(colon_pos) = line.find(':') {
                let key = line[..colon_pos].trim();
                let value = line[colon_pos + 1..].trim();
                headers.insert(key, value);
            }
        }

        // For body, we'd need the position in the original string
        // This simplified version doesn't handle body properly
        let body = None;

        Some(HttpRequest {
            method,
            path,
            version,
            headers,
            body,
        })
    }

    fn get_header<'a>(request: &'a HttpRequest, name: &str) -> Option<&'a str> {
        request.headers.get(name).copied()
    }

    fn is_secure(request: &HttpRequest) -> bool {
        // Check for security-related headers
        let has_auth = request.headers.contains_key("Authorization");
        let has_csrf = request.headers.contains_key("X-CSRF-Token");
        has_auth || has_csrf
    }

    let raw_request = "\
GET /api/users HTTP/1.1
Host: example.com
Authorization: Bearer token123
Content-Type: application/json
X-CSRF-Token: abc123
User-Agent: SecurityClient/1.0

";

    if let Some(request) = parse_http_request(raw_request) {
        println!("  Method: {}", request.method);
        println!("  Path: {}", request.path);
        println!("  Version: {}", request.version);
        println!("  Host: {:?}", get_header(&request, "Host"));
        println!("  Auth: {:?}", get_header(&request, "Authorization"));
        println!("  Is Secure: {}", is_secure(&request));
        println!("  Header count: {}", request.headers.len());
    }

    solutions::solution_10();
}
