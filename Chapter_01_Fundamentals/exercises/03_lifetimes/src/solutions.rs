//! # Solutions for Lifetime Exercises
//!
//! Reference solutions demonstrating proper lifetime usage.

/// Solution 1: Basic lifetime annotations
pub fn solution_1() {
    println!("  [Solution 1]:");

    // The lifetime 'a means: the returned reference is valid for the shorter
    // of the two input lifetimes
    fn longest<'a>(x: &'a str, y: &'a str) -> &'a str {
        if x.len() > y.len() { x } else { y }
    }

    // When one reference definitely outlives the other, we can use different lifetimes
    fn longest_with_announcement<'a, 'b>(x: &'a str, y: &'a str, ann: &'b str) -> &'a str {
        println!("    Announcement: {}", ann);
        if x.len() > y.len() { x } else { y }
    }

    let s1 = String::from("security");
    let s2 = String::from("vulnerability");
    let result = longest(&s1, &s2);
    println!("    Longest: {}", result);

    let ann = String::from("Finding longest...");
    let result2 = longest_with_announcement(&s1, &s2, &ann);
    println!("    Result: {}", result2);
}

/// Solution 2: Multiple lifetime parameters
pub fn solution_2() {
    println!("  [Solution 2]:");

    // Different lifetimes for independent references
    fn combine_with_prefix<'a, 'b>(data: &'a str, prefix: &'b str) -> String {
        // Returns owned String, so no lifetime needed on return
        format!("{}: {}", prefix, data)
    }

    // Return depends only on one parameter
    fn extract_domain<'a>(email: &'a str) -> Option<&'a str> {
        email.find('@').map(|pos| &email[pos + 1..])
    }

    // Multiple returns with different lifetimes - must use owned types
    fn split_at_delimiter<'a>(s: &'a str, delimiter: char) -> (&'a str, &'a str) {
        match s.find(delimiter) {
            Some(pos) => (&s[..pos], &s[pos + 1..]),
            None => (s, ""),
        }
    }

    let email = "admin@security.com";
    println!("    Domain: {:?}", extract_domain(email));

    let kv = "key=value";
    let (key, value) = split_at_delimiter(kv, '=');
    println!("    Key: {}, Value: {}", key, value);
}

/// Solution 3: Struct lifetime annotations
pub fn solution_3() {
    println!("  [Solution 3]:");

    #[derive(Debug)]
    struct Credential<'a> {
        username: &'a str,
        password_hash: &'a str,
        roles: Vec<&'a str>,
    }

    impl<'a> Credential<'a> {
        fn new(username: &'a str, password_hash: &'a str) -> Self {
            Credential {
                username,
                password_hash,
                roles: Vec::new(),
            }
        }

        fn add_role(&mut self, role: &'a str) {
            self.roles.push(role);
        }

        fn has_role(&self, role: &str) -> bool {
            self.roles.contains(&role)
        }

        fn display(&self) -> String {
            format!("User: {} with roles: {:?}", self.username, self.roles)
        }
    }

    let username = "admin";
    let hash = "5f4dcc3b5aa765d61d8327deb882cf99";
    let role1 = "administrator";
    let role2 = "auditor";

    let mut cred = Credential::new(username, hash);
    cred.add_role(role1);
    cred.add_role(role2);

    println!("    {}", cred.display());
    println!("    Has admin role: {}", cred.has_role("administrator"));
}

/// Solution 4: Method lifetime annotations
pub fn solution_4() {
    println!("  [Solution 4]:");

    struct Scanner<'a> {
        input: &'a str,
        pos: usize,
    }

    impl<'a> Scanner<'a> {
        fn new(input: &'a str) -> Self {
            Scanner { input, pos: 0 }
        }

        fn remaining(&self) -> &'a str {
            &self.input[self.pos..]
        }

        fn is_empty(&self) -> bool {
            self.pos >= self.input.len()
        }

        fn peek(&self) -> Option<char> {
            self.input[self.pos..].chars().next()
        }

        fn advance(&mut self) -> Option<char> {
            let c = self.peek()?;
            self.pos += c.len_utf8();
            Some(c)
        }

        fn take_while<F>(&mut self, predicate: F) -> &'a str
        where
            F: Fn(char) -> bool,
        {
            let start = self.pos;
            while let Some(c) = self.peek() {
                if !predicate(c) {
                    break;
                }
                self.advance();
            }
            &self.input[start..self.pos]
        }

        fn skip_whitespace(&mut self) {
            self.take_while(|c| c.is_whitespace());
        }

        fn take_identifier(&mut self) -> &'a str {
            self.take_while(|c| c.is_alphanumeric() || c == '_')
        }
    }

    let input = "  hello_world  123  rust";
    let mut scanner = Scanner::new(input);

    scanner.skip_whitespace();
    let id1 = scanner.take_identifier();
    println!("    First identifier: {}", id1);

    scanner.skip_whitespace();
    let num = scanner.take_while(|c| c.is_ascii_digit());
    println!("    Number: {}", num);

    scanner.skip_whitespace();
    let id2 = scanner.take_identifier();
    println!("    Second identifier: {}", id2);
}

/// Solution 5: Static lifetime usage
pub fn solution_5() {
    println!("  [Solution 5]:");

    // Error codes with static messages
    #[derive(Debug)]
    struct SecurityError {
        code: u32,
        message: &'static str,
    }

    impl SecurityError {
        fn new(code: u32) -> Self {
            let message = match code {
                1001 => "Authentication failed",
                1002 => "Session expired",
                1003 => "Invalid token",
                1004 => "Permission denied",
                1005 => "Rate limit exceeded",
                _ => "Unknown security error",
            };
            SecurityError { code, message }
        }
    }

    // Static configuration
    static SECURITY_HEADERS: &[(&str, &str)] = &[
        ("X-Content-Type-Options", "nosniff"),
        ("X-Frame-Options", "DENY"),
        ("X-XSS-Protection", "1; mode=block"),
        ("Strict-Transport-Security", "max-age=31536000"),
    ];

    fn get_security_headers() -> &'static [(&'static str, &'static str)] {
        SECURITY_HEADERS
    }

    let error = SecurityError::new(1003);
    println!("    Error {}: {}", error.code, error.message);

    println!("    Security headers:");
    for (name, value) in get_security_headers() {
        println!("      {}: {}", name, value);
    }
}

/// Solution 6: Lifetime bounds with generics
pub fn solution_6() {
    println!("  [Solution 6]:");

    use std::fmt::Debug;

    // Generic container with lifetime bound
    struct Container<'a, T: 'a + Debug> {
        items: Vec<&'a T>,
        label: &'a str,
    }

    impl<'a, T: 'a + Debug> Container<'a, T> {
        fn new(label: &'a str) -> Self {
            Container {
                items: Vec::new(),
                label,
            }
        }

        fn add(&mut self, item: &'a T) {
            self.items.push(item);
        }

        fn get(&self, index: usize) -> Option<&T> {
            self.items.get(index).copied()
        }

        fn iter(&self) -> impl Iterator<Item = &&'a T> {
            self.items.iter()
        }

        fn display(&self) {
            println!("    Container '{}' contents:", self.label);
            for (i, item) in self.items.iter().enumerate() {
                println!("      [{}]: {:?}", i, item);
            }
        }
    }

    let label = "Security Events";
    let event1 = String::from("Login attempt");
    let event2 = String::from("Access denied");
    let event3 = String::from("Session created");

    let mut container = Container::new(label);
    container.add(&event1);
    container.add(&event2);
    container.add(&event3);

    container.display();
}

/// Solution 7: Token validation with lifetimes
pub fn solution_7() {
    println!("  [Solution 7]:");

    use std::collections::HashMap;

    #[derive(Debug)]
    struct JWTToken<'a> {
        header: &'a str,
        payload: &'a str,
        signature: &'a str,
    }

    impl<'a> JWTToken<'a> {
        fn parse(token: &'a str) -> Option<Self> {
            let parts: Vec<&str> = token.split('.').collect();
            if parts.len() == 3 {
                Some(JWTToken {
                    header: parts[0],
                    payload: parts[1],
                    signature: parts[2],
                })
            } else {
                None
            }
        }

        fn decode_payload(&self) -> HashMap<&'a str, &'a str> {
            // Simplified: just split by comma for demo
            let mut claims = HashMap::new();
            for pair in self.payload.split(',') {
                if let Some(eq_pos) = pair.find('=') {
                    claims.insert(&pair[..eq_pos], &pair[eq_pos + 1..]);
                }
            }
            claims
        }
    }

    struct TokenValidator<'a> {
        secret: &'a str,
        issuer: &'a str,
    }

    impl<'a> TokenValidator<'a> {
        fn new(secret: &'a str, issuer: &'a str) -> Self {
            TokenValidator { secret, issuer }
        }

        fn validate(&self, token: &JWTToken) -> Result<(), &'static str> {
            // Simplified validation
            if token.header.is_empty() {
                return Err("Empty header");
            }
            if token.payload.is_empty() {
                return Err("Empty payload");
            }
            if token.signature.len() < 5 {
                return Err("Signature too short");
            }
            Ok(())
        }
    }

    let secret = "super_secret_key";
    let issuer = "security.example.com";
    let validator = TokenValidator::new(secret, issuer);

    let token_str = "eyJhbGc.sub=admin,role=user.signature123";
    if let Some(token) = JWTToken::parse(token_str) {
        match validator.validate(&token) {
            Ok(()) => {
                println!("    Token valid");
                let claims = token.decode_payload();
                for (k, v) in claims {
                    println!("      {}: {}", k, v);
                }
            }
            Err(e) => println!("    Validation failed: {}", e),
        }
    }
}

/// Solution 8: Log parsing with zero-copy
pub fn solution_8() {
    println!("  [Solution 8]:");

    #[derive(Debug)]
    struct ParsedLog<'a> {
        timestamp: &'a str,
        level: &'a str,
        component: &'a str,
        message: &'a str,
        metadata: Vec<(&'a str, &'a str)>,
    }

    fn parse_log<'a>(line: &'a str) -> Option<ParsedLog<'a>> {
        // Format: timestamp [LEVEL] component: message key=value key=value
        let mut parts = line.splitn(2, ' ');
        let timestamp = parts.next()?;
        let rest = parts.next()?;

        // Extract level
        if !rest.starts_with('[') {
            return None;
        }
        let level_end = rest.find(']')?;
        let level = &rest[1..level_end];

        let after_level = rest[level_end + 2..].trim();

        // Extract component
        let colon_pos = after_level.find(':')?;
        let component = &after_level[..colon_pos];

        let message_and_meta = after_level[colon_pos + 1..].trim();

        // Split message and metadata
        let (message, metadata) = if let Some(meta_start) = message_and_meta.find(" [") {
            let msg = &message_and_meta[..meta_start];
            let meta_str = &message_and_meta[meta_start + 2..message_and_meta.len() - 1];

            let metadata: Vec<(&str, &str)> = meta_str
                .split(' ')
                .filter_map(|pair| {
                    let eq = pair.find('=')?;
                    Some((&pair[..eq], &pair[eq + 1..]))
                })
                .collect();

            (msg, metadata)
        } else {
            (message_and_meta, Vec::new())
        };

        Some(ParsedLog {
            timestamp,
            level,
            component,
            message,
            metadata,
        })
    }

    let logs = vec![
        "2024-01-01T10:00:00Z [INFO] auth: User login successful [user=admin ip=192.168.1.1]",
        "2024-01-01T10:00:01Z [ERROR] db: Connection timeout [retries=3 host=db.local]",
        "2024-01-01T10:00:02Z [WARN] security: Rate limit approached [requests=95 limit=100]",
    ];

    for log_line in logs {
        if let Some(parsed) = parse_log(log_line) {
            println!("    {} [{}] {}", parsed.timestamp, parsed.level, parsed.component);
            println!("      Message: {}", parsed.message);
            if !parsed.metadata.is_empty() {
                println!("      Metadata: {:?}", parsed.metadata);
            }
        }
    }
}

/// Solution 9: Configuration with lifetimes
pub fn solution_9() {
    println!("  [Solution 9]:");

    use std::collections::HashMap;

    struct Config<'a> {
        source: &'a str,
        values: HashMap<&'a str, &'a str>,
        sections: HashMap<&'a str, HashMap<&'a str, &'a str>>,
    }

    impl<'a> Config<'a> {
        fn parse(source: &'a str) -> Self {
            let mut values = HashMap::new();
            let mut sections: HashMap<&str, HashMap<&str, &str>> = HashMap::new();
            let mut current_section: Option<&str> = None;

            for line in source.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                    continue;
                }

                // Section header [section]
                if line.starts_with('[') && line.ends_with(']') {
                    let section_name = &line[1..line.len() - 1];
                    sections.entry(section_name).or_insert_with(HashMap::new);
                    current_section = Some(section_name);
                    continue;
                }

                // Key-value pair
                if let Some(eq_pos) = line.find('=') {
                    let key = line[..eq_pos].trim();
                    let value = line[eq_pos + 1..].trim();

                    if let Some(section) = current_section {
                        sections.get_mut(section).unwrap().insert(key, value);
                    } else {
                        values.insert(key, value);
                    }
                }
            }

            Config {
                source,
                values,
                sections,
            }
        }

        fn get(&self, key: &str) -> Option<&'a str> {
            self.values.get(key).copied()
        }

        fn get_section(&self, section: &str, key: &str) -> Option<&'a str> {
            self.sections.get(section)?.get(key).copied()
        }

        fn section_keys(&self, section: &str) -> Option<Vec<&'a str>> {
            self.sections.get(section).map(|s| s.keys().copied().collect())
        }
    }

    let config_str = r#"
# Global settings
app_name = SecurityApp
version = 1.0

[database]
host = localhost
port = 5432
name = security_db

[auth]
token_expiry = 3600
max_attempts = 5
lockout_duration = 900
"#;

    let config = Config::parse(config_str);

    println!("    App: {:?}", config.get("app_name"));
    println!("    DB Host: {:?}", config.get_section("database", "host"));
    println!("    Token Expiry: {:?}", config.get_section("auth", "token_expiry"));
    println!("    Auth keys: {:?}", config.section_keys("auth"));
}

/// Solution 10: Zero-copy HTTP parser
pub fn solution_10() {
    println!("  [Solution 10]:");

    use std::collections::HashMap;

    #[derive(Debug)]
    struct Request<'a> {
        method: &'a str,
        uri: &'a str,
        version: &'a str,
        headers: HashMap<&'a str, &'a str>,
        body: Option<&'a str>,
    }

    impl<'a> Request<'a> {
        fn parse(raw: &'a str) -> Option<Self> {
            // Find the header/body boundary
            let (header_section, body) = match raw.find("\r\n\r\n") {
                Some(pos) => {
                    let body = &raw[pos + 4..];
                    let body = if body.is_empty() { None } else { Some(body) };
                    (&raw[..pos], body)
                }
                None => match raw.find("\n\n") {
                    Some(pos) => {
                        let body = &raw[pos + 2..];
                        let body = if body.is_empty() { None } else { Some(body) };
                        (&raw[..pos], body)
                    }
                    None => (raw, None),
                },
            };

            let mut lines = header_section.lines();

            // Parse request line
            let request_line = lines.next()?;
            let mut parts = request_line.split_whitespace();
            let method = parts.next()?;
            let uri = parts.next()?;
            let version = parts.next()?;

            // Parse headers
            let mut headers = HashMap::new();
            for line in lines {
                if line.is_empty() {
                    break;
                }
                if let Some(colon) = line.find(':') {
                    let name = line[..colon].trim();
                    let value = line[colon + 1..].trim();
                    headers.insert(name, value);
                }
            }

            Some(Request {
                method,
                uri,
                version,
                headers,
                body,
            })
        }

        fn get_header(&self, name: &str) -> Option<&'a str> {
            // Case-insensitive lookup
            for (k, v) in &self.headers {
                if k.eq_ignore_ascii_case(name) {
                    return Some(*v);
                }
            }
            None
        }

        fn has_header(&self, name: &str) -> bool {
            self.get_header(name).is_some()
        }

        fn content_length(&self) -> Option<usize> {
            self.get_header("Content-Length")?.parse().ok()
        }

        fn is_secure_request(&self) -> bool {
            // Check for security-related headers
            self.has_header("Authorization")
                || self.has_header("X-API-Key")
                || self.has_header("X-CSRF-Token")
        }

        fn parse_query_params(&self) -> HashMap<&'a str, &'a str> {
            let mut params = HashMap::new();
            if let Some(query_start) = self.uri.find('?') {
                let query = &self.uri[query_start + 1..];
                for pair in query.split('&') {
                    if let Some(eq) = pair.find('=') {
                        params.insert(&pair[..eq], &pair[eq + 1..]);
                    }
                }
            }
            params
        }
    }

    let raw = "POST /api/login?redirect=/dashboard HTTP/1.1\r\n\
Host: example.com\r\n\
Content-Type: application/json\r\n\
Content-Length: 42\r\n\
Authorization: Bearer abc123\r\n\
X-Request-ID: req-12345\r\n\
\r\n\
{\"username\":\"admin\",\"password\":\"secret\"}";

    if let Some(request) = Request::parse(raw) {
        println!("    {} {} {}", request.method, request.uri, request.version);
        println!("    Host: {:?}", request.get_header("Host"));
        println!("    Content-Length: {:?}", request.content_length());
        println!("    Is Secure: {}", request.is_secure_request());
        println!("    Query Params: {:?}", request.parse_query_params());
        println!("    Body: {:?}", request.body);
    }
}
