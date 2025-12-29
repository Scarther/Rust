//! # Solutions for Borrowing Exercises
//!
//! Reference solutions demonstrating proper borrowing patterns.

/// Solution 1: Multiple immutable borrows for analysis
pub fn solution_1() {
    println!("  [Solution 1]:");

    fn analyze_all(s: &str) -> (usize, usize, usize, bool) {
        let length = s.len();
        let alpha_count = s.chars().filter(|c| c.is_alphabetic()).count();
        let digit_count = s.chars().filter(|c| c.is_ascii_digit()).count();
        let has_special = s.chars().any(|c| !c.is_alphanumeric());
        (length, alpha_count, digit_count, has_special)
    }

    let password = String::from("Secure@123!");
    let (len, alpha, digits, special) = analyze_all(&password);

    println!("    Length: {}, Alpha: {}, Digits: {}, Special: {}",
             len, alpha, digits, special);
    println!("    Original preserved: '{}'", password);
}

/// Solution 2: Mutable references for in-place modification
pub fn solution_2() {
    println!("  [Solution 2]:");

    fn sanitize_input(input: &mut String) {
        // Remove leading/trailing whitespace
        let trimmed = input.trim().to_string();
        // Replace newlines, tabs with single space
        let cleaned = trimmed
            .chars()
            .map(|c| if c.is_whitespace() { ' ' } else { c })
            .collect::<String>();
        // Collapse multiple spaces
        let mut prev_space = false;
        let collapsed: String = cleaned
            .chars()
            .filter(|&c| {
                if c == ' ' {
                    if prev_space {
                        return false;
                    }
                    prev_space = true;
                } else {
                    prev_space = false;
                }
                true
            })
            .collect();
        *input = collapsed;
    }

    fn mask_sensitive(data: &mut String, visible_chars: usize) {
        let len = data.len();
        if len > visible_chars {
            let masked = "*".repeat(len - visible_chars);
            let visible = &data[len - visible_chars..];
            *data = format!("{}{}", masked, visible);
        } else {
            *data = "*".repeat(len);
        }
    }

    let mut input = String::from("  hello\n\t  world  test  ");
    sanitize_input(&mut input);
    println!("    Sanitized: '{}'", input);

    let mut credit_card = String::from("4532015112830366");
    mask_sensitive(&mut credit_card, 4);
    println!("    Masked CC: '{}'", credit_card);
}

/// Solution 3: Proper borrow scoping
pub fn solution_3() {
    println!("  [Solution 3]:");

    let mut data = vec![1, 2, 3, 4, 5];

    // Pattern 1: Complete immutable work before mutating
    let sum: i32 = data.iter().sum();
    let avg = sum as f64 / data.len() as f64;
    println!("    Sum: {}, Avg: {:.2}", sum, avg);

    // Now we can mutate
    data.push(6);
    data.push(7);
    println!("    After pushes: {:?}", data);

    // Pattern 2: Use indices when you need to read and write
    let mut i = 0;
    while i < data.len() {
        if data[i] % 2 == 0 {
            data[i] *= 2;
        }
        i += 1;
    }
    println!("    After doubling evens: {:?}", data);

    // Pattern 3: Collect into new structure, then replace
    let squared: Vec<i32> = data.iter().map(|x| x * x).collect();
    data = squared;
    println!("    After squaring: {:?}", data);
}

/// Solution 4: Struct methods with proper self references
pub fn solution_4() {
    println!("  [Solution 4]:");

    struct SecurityLog {
        entries: Vec<(u64, String, String)>, // timestamp, level, message
        max_entries: usize,
    }

    impl SecurityLog {
        fn new(max: usize) -> Self {
            SecurityLog {
                entries: Vec::new(),
                max_entries: max,
            }
        }

        fn log(&mut self, level: &str, message: &str) {
            let timestamp = self.entries.len() as u64 + 1;
            if self.entries.len() >= self.max_entries {
                self.entries.remove(0);
            }
            self.entries.push((timestamp, level.to_string(), message.to_string()));
        }

        fn filter_by_level(&self, level: &str) -> Vec<&(u64, String, String)> {
            self.entries.iter().filter(|(_, l, _)| l == level).collect()
        }

        fn search(&self, keyword: &str) -> Vec<&(u64, String, String)> {
            self.entries
                .iter()
                .filter(|(_, _, msg)| msg.contains(keyword))
                .collect()
        }

        fn summary(&self) -> (usize, usize, usize) {
            let info = self.entries.iter().filter(|(_, l, _)| l == "INFO").count();
            let warn = self.entries.iter().filter(|(_, l, _)| l == "WARN").count();
            let error = self.entries.iter().filter(|(_, l, _)| l == "ERROR").count();
            (info, warn, error)
        }
    }

    let mut log = SecurityLog::new(100);
    log.log("INFO", "Service started");
    log.log("WARN", "High memory usage detected");
    log.log("ERROR", "Authentication failed for user admin");
    log.log("INFO", "User admin logged in successfully");
    log.log("ERROR", "Database connection timeout");

    let errors = log.filter_by_level("ERROR");
    println!("    Errors: {}", errors.len());

    let admin_events = log.search("admin");
    println!("    Admin-related events: {}", admin_events.len());

    let (info, warn, error) = log.summary();
    println!("    Summary: INFO={}, WARN={}, ERROR={}", info, warn, error);
}

/// Solution 5: Multiple simultaneous immutable borrows
pub fn solution_5() {
    println!("  [Solution 5]:");

    /// Constant-time string comparison to prevent timing attacks
    fn secure_compare(a: &str, b: &str) -> bool {
        if a.len() != b.len() {
            return false;
        }

        let mut result = 0u8;
        for (byte_a, byte_b) in a.bytes().zip(b.bytes()) {
            result |= byte_a ^ byte_b;
        }

        result == 0
    }

    /// Check multiple conditions borrowing from multiple sources
    fn validate_credentials(
        username: &str,
        password: &str,
        stored_hash: &str,
        forbidden_list: &[&str],
    ) -> Result<(), Vec<&'static str>> {
        let mut errors = Vec::new();

        // Borrow username for length check
        if username.len() < 3 {
            errors.push("Username too short");
        }

        // Borrow password for multiple checks
        if password.len() < 8 {
            errors.push("Password too short");
        }

        if password.to_lowercase() == username.to_lowercase() {
            errors.push("Password cannot match username");
        }

        // Borrow forbidden_list
        for &word in forbidden_list {
            if password.to_lowercase().contains(word) {
                errors.push("Password contains forbidden word");
                break;
            }
        }

        // Borrow stored_hash for comparison
        let computed_hash = format!("{:x}", password.len() * 12345); // Fake hash
        if !secure_compare(&computed_hash, stored_hash) {
            // This would be the actual hash check in real code
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    let forbidden = vec!["password", "123456", "admin"];
    match validate_credentials("alice", "SecureP@ss1", "abc123", &forbidden) {
        Ok(()) => println!("    Credentials valid"),
        Err(errors) => println!("    Errors: {:?}", errors),
    }
}

/// Solution 6: Efficient iteration patterns
pub fn solution_6() {
    println!("  [Solution 6]:");

    let mut logs = vec![
        String::from("2024-01-01 INFO: Application started"),
        String::from("2024-01-01 WARN: Memory usage high"),
        String::from("2024-01-01 ERROR: Connection refused"),
        String::from("2024-01-02 INFO: User login"),
        String::from("2024-01-02 ERROR: Invalid token"),
    ];

    // Pattern 1: Count without mutation
    let error_count = logs.iter().filter(|l| l.contains("ERROR")).count();
    println!("    Error count: {}", error_count);

    // Pattern 2: Collect references for further analysis
    let errors: Vec<&String> = logs.iter().filter(|l| l.contains("ERROR")).collect();
    for error in &errors {
        println!("    Error entry: {}", error);
    }

    // Pattern 3: Transform in place using indices
    for i in 0..logs.len() {
        if logs[i].contains("ERROR") {
            logs[i] = format!("[ALERT] {}", logs[i]);
        }
    }

    // Pattern 4: Map and collect into new structure
    let anonymized: Vec<String> = logs
        .iter()
        .map(|log| log.replace("User", "[REDACTED]"))
        .collect();

    println!("    First anonymized: {}", anonymized.first().unwrap_or(&String::new()));
}

/// Solution 7: Comprehensive audit trail with borrowing
pub fn solution_7() {
    println!("  [Solution 7]:");

    use std::collections::HashMap;

    #[derive(Debug, Clone)]
    struct AuditEvent {
        id: u64,
        timestamp: u64,
        actor: String,
        action: String,
        resource: String,
        success: bool,
    }

    struct AuditTrail {
        events: Vec<AuditEvent>,
        next_id: u64,
    }

    impl AuditTrail {
        fn new() -> Self {
            AuditTrail {
                events: Vec::new(),
                next_id: 1,
            }
        }

        fn record(&mut self, actor: &str, action: &str, resource: &str, success: bool) {
            self.events.push(AuditEvent {
                id: self.next_id,
                timestamp: self.next_id * 1000, // Simulated timestamp
                actor: actor.to_string(),
                action: action.to_string(),
                resource: resource.to_string(),
                success,
            });
            self.next_id += 1;
        }

        fn query_by_actor(&self, actor: &str) -> impl Iterator<Item = &AuditEvent> {
            self.events.iter().filter(move |e| e.actor == actor)
        }

        fn get_failed_attempts(&self) -> Vec<&AuditEvent> {
            self.events.iter().filter(|e| !e.success).collect()
        }

        fn get_statistics(&self) -> HashMap<&str, (usize, usize)> {
            let mut stats: HashMap<&str, (usize, usize)> = HashMap::new();

            for event in &self.events {
                let entry = stats.entry(&event.action).or_insert((0, 0));
                if event.success {
                    entry.0 += 1;
                } else {
                    entry.1 += 1;
                }
            }

            stats
        }
    }

    let mut trail = AuditTrail::new();
    trail.record("alice", "login", "/auth", true);
    trail.record("bob", "login", "/auth", false);
    trail.record("alice", "read", "/secrets", true);
    trail.record("bob", "login", "/auth", true);
    trail.record("charlie", "write", "/config", false);

    println!("    Alice's actions: {}", trail.query_by_actor("alice").count());
    println!("    Failed attempts: {}", trail.get_failed_attempts().len());

    let stats = trail.get_statistics();
    for (action, (success, failed)) in stats {
        println!("    {}: {} success, {} failed", action, success, failed);
    }
}

/// Solution 8: Complete password validator
pub fn solution_8() {
    println!("  [Solution 8]:");

    struct PasswordPolicy {
        min_length: usize,
        max_length: usize,
        min_uppercase: usize,
        min_lowercase: usize,
        min_digits: usize,
        min_special: usize,
        special_chars: &'static str,
        forbidden_patterns: Vec<&'static str>,
    }

    impl Default for PasswordPolicy {
        fn default() -> Self {
            PasswordPolicy {
                min_length: 12,
                max_length: 128,
                min_uppercase: 1,
                min_lowercase: 1,
                min_digits: 1,
                min_special: 1,
                special_chars: "!@#$%^&*()_+-=[]{}|;:,.<>?",
                forbidden_patterns: vec!["password", "123456", "qwerty", "admin"],
            }
        }
    }

    fn validate(password: &str, policy: &PasswordPolicy) -> Vec<String> {
        let mut errors = Vec::new();

        // Length checks
        if password.len() < policy.min_length {
            errors.push(format!("Must be at least {} characters", policy.min_length));
        }
        if password.len() > policy.max_length {
            errors.push(format!("Must be at most {} characters", policy.max_length));
        }

        // Character class checks
        let uppercase = password.chars().filter(|c| c.is_uppercase()).count();
        let lowercase = password.chars().filter(|c| c.is_lowercase()).count();
        let digits = password.chars().filter(|c| c.is_ascii_digit()).count();
        let special = password
            .chars()
            .filter(|c| policy.special_chars.contains(*c))
            .count();

        if uppercase < policy.min_uppercase {
            errors.push(format!("Need {} uppercase letter(s)", policy.min_uppercase));
        }
        if lowercase < policy.min_lowercase {
            errors.push(format!("Need {} lowercase letter(s)", policy.min_lowercase));
        }
        if digits < policy.min_digits {
            errors.push(format!("Need {} digit(s)", policy.min_digits));
        }
        if special < policy.min_special {
            errors.push(format!("Need {} special character(s)", policy.min_special));
        }

        // Forbidden patterns
        let lower_password = password.to_lowercase();
        for pattern in &policy.forbidden_patterns {
            if lower_password.contains(pattern) {
                errors.push(format!("Contains forbidden pattern: '{}'", pattern));
            }
        }

        errors
    }

    let policy = PasswordPolicy::default();
    let passwords = vec![
        "short",
        "NoSpecialChar123",
        "Str0ng!P@ssw0rd#",
        "password123!ABC",
    ];

    for pwd in passwords {
        let errors = validate(pwd, &policy);
        if errors.is_empty() {
            println!("    '{}' - VALID", pwd);
        } else {
            println!("    '{}' - {} error(s)", pwd, errors.len());
        }
    }
}

/// Solution 9: Network packet inspection
pub fn solution_9() {
    println!("  [Solution 9]:");

    struct Packet {
        source: [u8; 4],
        destination: [u8; 4],
        protocol: u8,
        flags: u8,
        payload: Vec<u8>,
    }

    struct PacketInspector;

    impl PacketInspector {
        fn analyze<'a>(packet: &'a Packet) -> PacketAnalysis<'a> {
            let suspicious_patterns = vec![
                (&b"\x00\x00\x00\x00"[..], "Null bytes sequence"),
                (b"<script", "Potential XSS"),
                (b"SELECT", "Potential SQL injection"),
                (b"/etc/passwd", "Path traversal attempt"),
            ];

            let mut threats = Vec::new();
            for (pattern, description) in suspicious_patterns {
                if Self::contains_pattern(&packet.payload, pattern) {
                    threats.push(description);
                }
            }

            PacketAnalysis {
                packet,
                payload_size: packet.payload.len(),
                is_suspicious: !threats.is_empty(),
                detected_threats: threats,
            }
        }

        fn contains_pattern(data: &[u8], pattern: &[u8]) -> bool {
            data.windows(pattern.len()).any(|w| w == pattern)
        }

        fn extract_strings(payload: &[u8], min_length: usize) -> Vec<String> {
            let mut strings = Vec::new();
            let mut current = String::new();

            for &byte in payload {
                if byte.is_ascii_graphic() || byte == b' ' {
                    current.push(byte as char);
                } else {
                    if current.len() >= min_length {
                        strings.push(current.clone());
                    }
                    current.clear();
                }
            }

            if current.len() >= min_length {
                strings.push(current);
            }

            strings
        }
    }

    struct PacketAnalysis<'a> {
        packet: &'a Packet,
        payload_size: usize,
        is_suspicious: bool,
        detected_threats: Vec<&'static str>,
    }

    let packet = Packet {
        source: [192, 168, 1, 100],
        destination: [10, 0, 0, 1],
        protocol: 6,
        flags: 0x02,
        payload: b"GET /api?id=1 UNION SELECT * FROM users".to_vec(),
    };

    let analysis = PacketInspector::analyze(&packet);
    println!("    Payload size: {} bytes", analysis.payload_size);
    println!("    Suspicious: {}", analysis.is_suspicious);
    println!("    Threats: {:?}", analysis.detected_threats);

    let strings = PacketInspector::extract_strings(&packet.payload, 3);
    println!("    Extracted strings: {:?}", strings);
}

/// Solution 10: Complete access control system
pub fn solution_10() {
    println!("  [Solution 10]:");

    use std::collections::HashSet;

    #[derive(Debug)]
    struct User {
        id: u32,
        name: String,
        roles: HashSet<String>,
        active: bool,
    }

    #[derive(Debug)]
    struct Resource {
        id: u32,
        path: String,
        allowed_roles: HashSet<String>,
        public: bool,
    }

    #[derive(Debug)]
    struct AccessResult {
        allowed: bool,
        reason: String,
        matching_role: Option<String>,
    }

    struct AccessControl {
        users: Vec<User>,
        resources: Vec<Resource>,
    }

    impl AccessControl {
        fn new() -> Self {
            AccessControl {
                users: Vec::new(),
                resources: Vec::new(),
            }
        }

        fn add_user(&mut self, id: u32, name: &str, roles: &[&str]) {
            self.users.push(User {
                id,
                name: name.to_string(),
                roles: roles.iter().map(|s| s.to_string()).collect(),
                active: true,
            });
        }

        fn add_resource(&mut self, id: u32, path: &str, roles: &[&str], public: bool) {
            self.resources.push(Resource {
                id,
                path: path.to_string(),
                allowed_roles: roles.iter().map(|s| s.to_string()).collect(),
                public,
            });
        }

        fn get_user(&self, id: u32) -> Option<&User> {
            self.users.iter().find(|u| u.id == id)
        }

        fn get_resource_by_path(&self, path: &str) -> Option<&Resource> {
            self.resources.iter().find(|r| r.path == path)
        }

        fn check_access(&self, user_id: u32, resource_path: &str) -> AccessResult {
            let resource = match self.get_resource_by_path(resource_path) {
                Some(r) => r,
                None => {
                    return AccessResult {
                        allowed: false,
                        reason: "Resource not found".to_string(),
                        matching_role: None,
                    }
                }
            };

            if resource.public {
                return AccessResult {
                    allowed: true,
                    reason: "Public resource".to_string(),
                    matching_role: None,
                };
            }

            let user = match self.get_user(user_id) {
                Some(u) => u,
                None => {
                    return AccessResult {
                        allowed: false,
                        reason: "User not found".to_string(),
                        matching_role: None,
                    }
                }
            };

            if !user.active {
                return AccessResult {
                    allowed: false,
                    reason: "User account inactive".to_string(),
                    matching_role: None,
                };
            }

            // Check role intersection
            for role in &user.roles {
                if resource.allowed_roles.contains(role) {
                    return AccessResult {
                        allowed: true,
                        reason: "Role match".to_string(),
                        matching_role: Some(role.clone()),
                    };
                }
            }

            AccessResult {
                allowed: false,
                reason: "No matching role".to_string(),
                matching_role: None,
            }
        }

        fn get_user_resources(&self, user_id: u32) -> Vec<&Resource> {
            let user = match self.get_user(user_id) {
                Some(u) if u.active => u,
                _ => return Vec::new(),
            };

            self.resources
                .iter()
                .filter(|r| {
                    r.public || r.allowed_roles.iter().any(|role| user.roles.contains(role))
                })
                .collect()
        }
    }

    let mut ac = AccessControl::new();

    ac.add_user(1, "alice", &["admin", "user"]);
    ac.add_user(2, "bob", &["user"]);
    ac.add_user(3, "charlie", &["guest"]);

    ac.add_resource(1, "/public/info", &[], true);
    ac.add_resource(2, "/user/profile", &["user", "admin"], false);
    ac.add_resource(3, "/admin/settings", &["admin"], false);
    ac.add_resource(4, "/secrets/keys", &["admin"], false);

    // Test access
    let test_cases = vec![
        (1, "/admin/settings"),
        (2, "/admin/settings"),
        (1, "/public/info"),
        (3, "/user/profile"),
    ];

    for (user_id, path) in test_cases {
        let result = ac.check_access(user_id, path);
        println!(
            "    User {} -> {}: {} ({})",
            user_id, path, result.allowed, result.reason
        );
    }

    // List accessible resources
    println!("    Alice can access {} resources", ac.get_user_resources(1).len());
    println!("    Bob can access {} resources", ac.get_user_resources(2).len());
}
