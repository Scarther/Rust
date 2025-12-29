//! # B01: Hello Security World
//!
//! Introduction to Rust programming with security-focused output formatting.
//!
//! ## Learning Objectives
//! - Rust project structure
//! - println! macro and formatting
//! - Variables and basic types
//! - Security output conventions

fn main() {
    // ═══════════════════════════════════════════════════════════════
    // ASCII Art Banner
    // ═══════════════════════════════════════════════════════════════
    let banner = r#"
    ╔═══════════════════════════════════════════╗
    ║     RUST SECURITY TRAINING - B01          ║
    ║     Hello Security World                  ║
    ╚═══════════════════════════════════════════╝
    "#;

    println!("{}", banner);

    // ═══════════════════════════════════════════════════════════════
    // Variables and Types
    // ═══════════════════════════════════════════════════════════════

    // &str - String slice (borrowed, immutable)
    let tool_name = "RustRecon";

    // String - Owned, heap-allocated, growable
    let mut version = String::from("1.0");
    version.push_str(".0");

    // Various types
    let author = "Security Student";
    let year: u16 = 2025;
    let is_production = false;

    // ═══════════════════════════════════════════════════════════════
    // Basic Output
    // ═══════════════════════════════════════════════════════════════

    println!("[*] Tool: {} v{}", tool_name, version);
    println!("[*] Author: {}", author);
    println!("[*] Year: {}", year);
    println!("[*] Production: {}", is_production);
    println!();

    // ═══════════════════════════════════════════════════════════════
    // Security-Style Log Levels
    // ═══════════════════════════════════════════════════════════════

    println!("[+] Success - Action completed successfully");
    println!("[-] Failure - Action failed");
    println!("[*] Info - General information");
    println!("[!] Warning - Attention required");
    println!("[?] Question - Uncertain status");
    println!();

    // ═══════════════════════════════════════════════════════════════
    // Report-Style Output
    // ═══════════════════════════════════════════════════════════════

    let target = "192.168.1.1";
    let ports_found = 3;
    let scan_time = 2.45;

    println!("═══════════════════════════════════════════");
    println!(" SCAN RESULTS");
    println!("═══════════════════════════════════════════");
    println!(" Target:      {}", target);
    println!(" Open Ports:  {}", ports_found);
    println!(" Scan Time:   {:.2}s", scan_time);
    println!("═══════════════════════════════════════════");
    println!();

    // ═══════════════════════════════════════════════════════════════
    // Advanced Formatting
    // ═══════════════════════════════════════════════════════════════

    // Width and alignment
    println!("{:<15} {:>10}", "PORT", "STATUS");
    println!("{:-<15} {:->10}", "", "");
    println!("{:<15} {:>10}", "22", "OPEN");
    println!("{:<15} {:>10}", "80", "OPEN");
    println!("{:<15} {:>10}", "443", "OPEN");
    println!();

    // Hexadecimal and binary (common in security)
    let byte: u8 = 255;
    println!("Decimal: {}, Hex: {:#x}, Binary: {:08b}", byte, byte, byte);

    // ═══════════════════════════════════════════════════════════════
    // Completion
    // ═══════════════════════════════════════════════════════════════

    println!();
    println!("[*] B01 Complete! Proceed to B02: CLI Arguments");
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_string_formatting() {
        let formatted = format!("{:05}", 42);
        assert_eq!(formatted, "00042");
    }

    #[test]
    fn test_hex_formatting() {
        let formatted = format!("{:#x}", 255);
        assert_eq!(formatted, "0xff");
    }
}
