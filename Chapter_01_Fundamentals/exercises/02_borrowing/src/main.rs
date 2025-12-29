//! # Borrowing and References Exercises
//!
//! These exercises teach Rust's borrowing rules, which allow you to access
//! data without taking ownership. This is crucial for efficient and safe
//! security programming.
//!
//! Run with: cargo run
//! Check solutions in: src/solutions.rs

#![allow(unused_variables, dead_code)]

mod solutions;

fn main() {
    println!("=== Rust Borrowing Exercises ===\n");

    println!("Exercise 1: Immutable References");
    exercise_1();

    println!("\nExercise 2: Mutable References");
    exercise_2();

    println!("\nExercise 3: Reference Rules");
    exercise_3();

    println!("\nExercise 4: References in Functions");
    exercise_4();

    println!("\nExercise 5: Multiple Immutable Borrows");
    exercise_5();

    println!("\nExercise 6: Borrowing in Loops");
    exercise_6();

    println!("\nExercise 7: Security Audit Trail");
    exercise_7();

    println!("\nExercise 8: Password Validator");
    exercise_8();

    println!("\nExercise 9: Network Packet Inspector");
    exercise_9();

    println!("\nExercise 10: Challenge - Access Control System");
    exercise_10();

    println!("\n=== All exercises completed! ===");
}

// =============================================================================
// EXERCISE 1: Immutable References
// =============================================================================
//
// Immutable references (&T) allow reading data without taking ownership.
// Multiple immutable references can exist simultaneously.
//
// YOUR TASK: Create functions that borrow data immutably to inspect it.
//
fn exercise_1() {
    fn get_length(s: &String) -> usize {
        s.len()
    }

    fn get_first_char(s: &String) -> Option<char> {
        s.chars().next()
    }

    fn contains_digit(s: &String) -> bool {
        s.chars().any(|c| c.is_ascii_digit())
    }

    let password = String::from("secure123");

    // All these functions borrow immutably - password remains valid
    let length = get_length(&password);
    let first = get_first_char(&password);
    let has_digit = contains_digit(&password);

    println!("  Password analysis:");
    println!("    Length: {}", length);
    println!("    First char: {:?}", first);
    println!("    Has digit: {}", has_digit);
    println!("    Original still valid: '{}'", password);

    solutions::solution_1();
}

// =============================================================================
// EXERCISE 2: Mutable References
// =============================================================================
//
// Mutable references (&mut T) allow modifying data without taking ownership.
// Only ONE mutable reference can exist at a time.
//
// YOUR TASK: Use mutable references to modify data in place.
//
fn exercise_2() {
    fn sanitize_input(input: &mut String) {
        // TODO: Remove leading/trailing whitespace
        // TODO: Replace any newlines with spaces
        *input = input.trim().replace('\n', " ");
    }

    fn mask_password(password: &mut String) {
        // TODO: Replace all characters except last 4 with '*'
        let len = password.len();
        if len > 4 {
            let masked = "*".repeat(len - 4);
            let visible = &password[len - 4..];
            *password = format!("{}{}", masked, visible);
        }
    }

    let mut input = String::from("  hello\nworld  ");
    sanitize_input(&mut input);
    println!("  Sanitized: '{}'", input);

    let mut password = String::from("mysecretpassword");
    mask_password(&mut password);
    println!("  Masked: '{}'", password);

    solutions::solution_2();
}

// =============================================================================
// EXERCISE 3: Reference Rules
// =============================================================================
//
// Rust enforces these borrowing rules at compile time:
// 1. At any time, you can have EITHER one mutable reference OR any number of immutable references
// 2. References must always be valid (no dangling references)
//
// YOUR TASK: Fix the code to comply with borrowing rules.
//
fn exercise_3() {
    let mut data = vec![1, 2, 3, 4, 5];

    // This pattern is correct - immutable borrow ends before mutable borrow
    let sum: i32 = data.iter().sum();
    data.push(6);

    // For simultaneous access, we need to be careful
    // This works because we're done with immutable borrow before mutating
    println!("  Sum before push: {}", sum);
    println!("  After push: {:?}", data);

    solutions::solution_3();
}

// =============================================================================
// EXERCISE 4: References in Functions
// =============================================================================
//
// Functions can take references to avoid ownership transfer.
// This is especially useful for large data structures.
//
// YOUR TASK: Implement functions that work with references.
//
fn exercise_4() {
    struct SecurityLog {
        entries: Vec<String>,
        max_size: usize,
    }

    impl SecurityLog {
        fn new(max_size: usize) -> Self {
            SecurityLog {
                entries: Vec::new(),
                max_size,
            }
        }

        // Takes &mut self to modify the log
        fn add_entry(&mut self, entry: String) {
            if self.entries.len() >= self.max_size {
                self.entries.remove(0); // Remove oldest
            }
            self.entries.push(entry);
        }

        // Takes &self for read-only access
        fn get_last(&self) -> Option<&String> {
            self.entries.last()
        }

        // Takes &self and returns count
        fn count(&self) -> usize {
            self.entries.len()
        }

        // Takes &self to search
        fn contains(&self, keyword: &str) -> bool {
            self.entries.iter().any(|e| e.contains(keyword))
        }
    }

    let mut log = SecurityLog::new(5);
    log.add_entry(String::from("Login attempt from 192.168.1.1"));
    log.add_entry(String::from("Failed auth for user admin"));
    log.add_entry(String::from("Suspicious activity detected"));

    println!("  Log entries: {}", log.count());
    println!("  Last entry: {:?}", log.get_last());
    println!("  Contains 'admin': {}", log.contains("admin"));

    solutions::solution_4();
}

// =============================================================================
// EXERCISE 5: Multiple Immutable Borrows
// =============================================================================
//
// Multiple parts of code can borrow data immutably at the same time.
// This is safe because no one is modifying the data.
//
// YOUR TASK: Create a function that borrows from multiple sources.
//
fn exercise_5() {
    fn compare_hashes(hash1: &str, hash2: &str) -> bool {
        // Constant-time comparison to prevent timing attacks
        if hash1.len() != hash2.len() {
            return false;
        }

        let mut result = 0u8;
        for (b1, b2) in hash1.bytes().zip(hash2.bytes()) {
            result |= b1 ^ b2;
        }
        result == 0
    }

    fn analyze_credentials(username: &str, password: &str) -> (bool, bool, bool) {
        let valid_length = password.len() >= 8;
        let has_upper = password.chars().any(|c| c.is_uppercase());
        let no_username = !password.to_lowercase().contains(&username.to_lowercase());
        (valid_length, has_upper, no_username)
    }

    let stored_hash = "5e884898da28047d9106420e9e5a65baf424";
    let provided_hash = "5e884898da28047d9106420e9e5a65baf424";

    println!("  Hash match: {}", compare_hashes(stored_hash, provided_hash));

    let username = "admin";
    let password = "SecurePass123";
    let (valid_len, has_upper, no_user) = analyze_credentials(username, password);
    println!("  Password check: len={}, upper={}, no_user={}", valid_len, has_upper, no_user);

    solutions::solution_5();
}

// =============================================================================
// EXERCISE 6: Borrowing in Loops
// =============================================================================
//
// When borrowing in loops, be careful about mutable vs immutable access
// within the same iteration scope.
//
// YOUR TASK: Implement a log analyzer that iterates and potentially modifies.
//
fn exercise_6() {
    let logs = vec![
        "INFO: System started",
        "WARN: High memory usage",
        "ERROR: Connection failed",
        "INFO: User logged in",
        "ERROR: File not found",
    ];

    // Immutable iteration - safe and common
    let error_count = logs.iter().filter(|l| l.starts_with("ERROR")).count();
    println!("  Error count: {}", error_count);

    // Collecting results while iterating
    let warnings: Vec<&str> = logs
        .iter()
        .filter(|l| l.starts_with("WARN"))
        .copied()
        .collect();
    println!("  Warnings: {:?}", warnings);

    // For mutable modification, we often need indices or collect first
    let mut mutable_logs: Vec<String> = logs.iter().map(|s| s.to_string()).collect();
    for log in &mut mutable_logs {
        if log.starts_with("ERROR") {
            *log = format!("[CRITICAL] {}", log);
        }
    }
    println!("  Modified first error: {}", mutable_logs.get(2).unwrap_or(&String::new()));

    solutions::solution_6();
}

// =============================================================================
// EXERCISE 7: Security Audit Trail
// =============================================================================
//
// Build an audit system that uses borrowing efficiently to track
// security events without unnecessary copying.
//
// YOUR TASK: Implement the AuditTrail with proper borrowing.
//
fn exercise_7() {
    #[derive(Debug)]
    struct AuditEvent {
        timestamp: u64,
        actor: String,
        action: String,
        resource: String,
    }

    struct AuditTrail {
        events: Vec<AuditEvent>,
    }

    impl AuditTrail {
        fn new() -> Self {
            AuditTrail { events: Vec::new() }
        }

        fn record(&mut self, actor: &str, action: &str, resource: &str) {
            self.events.push(AuditEvent {
                timestamp: self.events.len() as u64 + 1000,
                actor: actor.to_string(),
                action: action.to_string(),
                resource: resource.to_string(),
            });
        }

        fn get_by_actor(&self, actor: &str) -> Vec<&AuditEvent> {
            self.events.iter().filter(|e| e.actor == actor).collect()
        }

        fn get_by_action(&self, action: &str) -> Vec<&AuditEvent> {
            self.events.iter().filter(|e| e.action == action).collect()
        }

        fn last_n(&self, n: usize) -> &[AuditEvent] {
            let len = self.events.len();
            if n >= len {
                &self.events
            } else {
                &self.events[len - n..]
            }
        }
    }

    let mut trail = AuditTrail::new();
    trail.record("alice", "login", "/dashboard");
    trail.record("bob", "read", "/secrets/api_key");
    trail.record("alice", "write", "/config/settings");
    trail.record("bob", "delete", "/logs/old");

    println!("  Alice's events: {}", trail.get_by_actor("alice").len());
    println!("  Read actions: {}", trail.get_by_action("read").len());
    println!("  Last 2 events: {:?}", trail.last_n(2));

    solutions::solution_7();
}

// =============================================================================
// EXERCISE 8: Password Validator
// =============================================================================
//
// Create a password validator that uses references to check
// password against various rules without copying.
//
// YOUR TASK: Implement validation functions using borrows.
//
fn exercise_8() {
    struct PasswordPolicy {
        min_length: usize,
        require_uppercase: bool,
        require_lowercase: bool,
        require_digit: bool,
        require_special: bool,
        forbidden_words: Vec<String>,
    }

    fn validate_password(password: &str, policy: &PasswordPolicy) -> Vec<&'static str> {
        let mut errors = Vec::new();

        if password.len() < policy.min_length {
            errors.push("Password too short");
        }

        if policy.require_uppercase && !password.chars().any(|c| c.is_uppercase()) {
            errors.push("Missing uppercase letter");
        }

        if policy.require_lowercase && !password.chars().any(|c| c.is_lowercase()) {
            errors.push("Missing lowercase letter");
        }

        if policy.require_digit && !password.chars().any(|c| c.is_ascii_digit()) {
            errors.push("Missing digit");
        }

        if policy.require_special && !password.chars().any(|c| "!@#$%^&*()".contains(c)) {
            errors.push("Missing special character");
        }

        let lower_password = password.to_lowercase();
        for word in &policy.forbidden_words {
            if lower_password.contains(&word.to_lowercase()) {
                errors.push("Contains forbidden word");
                break;
            }
        }

        errors
    }

    let policy = PasswordPolicy {
        min_length: 12,
        require_uppercase: true,
        require_lowercase: true,
        require_digit: true,
        require_special: true,
        forbidden_words: vec!["password".to_string(), "admin".to_string()],
    };

    let test_passwords = ["weak", "StrongPass1!", "admin123!@#ADMIN"];

    for pwd in &test_passwords {
        let errors = validate_password(pwd, &policy);
        if errors.is_empty() {
            println!("  '{}': VALID", pwd);
        } else {
            println!("  '{}': {:?}", pwd, errors);
        }
    }

    solutions::solution_8();
}

// =============================================================================
// EXERCISE 9: Network Packet Inspector
// =============================================================================
//
// Implement a packet inspector that borrows packet data for analysis
// without copying the potentially large payload.
//
// YOUR TASK: Create efficient packet analysis using references.
//
fn exercise_9() {
    struct Packet {
        source: [u8; 4],
        destination: [u8; 4],
        protocol: u8,
        payload: Vec<u8>,
    }

    impl Packet {
        fn new(src: [u8; 4], dst: [u8; 4], proto: u8, data: Vec<u8>) -> Self {
            Packet {
                source: src,
                destination: dst,
                protocol: proto,
                payload: data,
            }
        }

        fn source_str(&self) -> String {
            format!("{}.{}.{}.{}", self.source[0], self.source[1], self.source[2], self.source[3])
        }

        fn dest_str(&self) -> String {
            format!("{}.{}.{}.{}", self.destination[0], self.destination[1], self.destination[2], self.destination[3])
        }
    }

    fn is_suspicious(packet: &Packet) -> bool {
        // Check for null bytes in payload (potential binary exploit)
        packet.payload.iter().any(|&b| b == 0x00)
    }

    fn contains_pattern(packet: &Packet, pattern: &[u8]) -> bool {
        packet.payload.windows(pattern.len()).any(|window| window == pattern)
    }

    fn get_payload_preview(packet: &Packet, max_len: usize) -> &[u8] {
        if packet.payload.len() <= max_len {
            &packet.payload
        } else {
            &packet.payload[..max_len]
        }
    }

    let packet = Packet::new(
        [192, 168, 1, 100],
        [10, 0, 0, 1],
        6, // TCP
        vec![0x47, 0x45, 0x54, 0x20, 0x2F, 0x00, 0x48, 0x54, 0x54, 0x50], // "GET /.HTTP"
    );

    println!("  Packet: {} -> {}", packet.source_str(), packet.dest_str());
    println!("  Suspicious: {}", is_suspicious(&packet));
    println!("  Contains 'GET': {}", contains_pattern(&packet, b"GET"));
    println!("  Preview: {:?}", get_payload_preview(&packet, 5));

    solutions::solution_9();
}

// =============================================================================
// EXERCISE 10: Challenge - Access Control System
// =============================================================================
//
// Build an access control system that uses borrowing to efficiently
// check permissions without copying user or resource data.
//
// YOUR TASK: Implement the AccessControl system with proper borrowing.
//
fn exercise_10() {
    #[derive(Debug)]
    struct User {
        id: u32,
        name: String,
        roles: Vec<String>,
    }

    #[derive(Debug)]
    struct Resource {
        id: u32,
        name: String,
        required_role: String,
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

        fn add_user(&mut self, id: u32, name: &str, roles: Vec<String>) {
            self.users.push(User {
                id,
                name: name.to_string(),
                roles,
            });
        }

        fn add_resource(&mut self, id: u32, name: &str, required_role: &str) {
            self.resources.push(Resource {
                id,
                name: name.to_string(),
                required_role: required_role.to_string(),
            });
        }

        fn get_user(&self, id: u32) -> Option<&User> {
            self.users.iter().find(|u| u.id == id)
        }

        fn get_resource(&self, id: u32) -> Option<&Resource> {
            self.resources.iter().find(|r| r.id == id)
        }

        fn check_access(&self, user_id: u32, resource_id: u32) -> bool {
            let user = match self.get_user(user_id) {
                Some(u) => u,
                None => return false,
            };

            let resource = match self.get_resource(resource_id) {
                Some(r) => r,
                None => return false,
            };

            user.roles.iter().any(|role| role == &resource.required_role)
        }

        fn get_accessible_resources(&self, user_id: u32) -> Vec<&Resource> {
            let user = match self.get_user(user_id) {
                Some(u) => u,
                None => return Vec::new(),
            };

            self.resources
                .iter()
                .filter(|r| user.roles.contains(&r.required_role))
                .collect()
        }
    }

    let mut ac = AccessControl::new();

    ac.add_user(1, "alice", vec!["admin".to_string(), "user".to_string()]);
    ac.add_user(2, "bob", vec!["user".to_string()]);

    ac.add_resource(100, "secret_data", "admin");
    ac.add_resource(101, "public_data", "user");
    ac.add_resource(102, "config", "admin");

    println!("  Alice access to secret_data: {}", ac.check_access(1, 100));
    println!("  Bob access to secret_data: {}", ac.check_access(2, 100));

    let alice_resources = ac.get_accessible_resources(1);
    println!("  Alice can access {} resources", alice_resources.len());

    let bob_resources = ac.get_accessible_resources(2);
    println!("  Bob can access {} resources", bob_resources.len());

    solutions::solution_10();
}
