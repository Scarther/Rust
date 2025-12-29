//! # Sandbox Demo Binary
//!
//! Demonstrates various sandbox capabilities.

use sandbox::{
    sandbox_status, Sandbox, SandboxConfig, SeccompAction,
    is_seccomp_available, supported_namespaces, get_mounts,
    print_capabilities, get_current_capabilities, profiles,
};

fn main() {
    println!("=== Linux Sandbox Demonstration ===\n");

    // 1. Show system capabilities
    println!("1. System Capabilities");
    println!("   Seccomp available: {}", is_seccomp_available());
    println!("   Supported namespaces:");
    for ns in supported_namespaces() {
        println!("     - {:?}", ns);
    }
    println!();

    // 2. Current process status
    println!("2. Current Process Status");
    println!("{}", sandbox_status());

    // 3. Current capabilities
    println!("3. Current Capabilities");
    match get_current_capabilities() {
        Ok(caps) if caps.is_empty() => println!("   No special capabilities"),
        Ok(caps) => {
            for cap in caps {
                println!("   - {}", cap);
            }
        }
        Err(e) => println!("   Error: {}", e),
    }
    println!();

    // 4. Mount points (first 5)
    println!("4. Current Mount Points (first 5)");
    match get_mounts() {
        Ok(mounts) => {
            for mount in mounts.iter().take(5) {
                println!("   {} -> {:?} ({})",
                    mount.source, mount.target, mount.fstype);
            }
        }
        Err(e) => println!("   Error: {}", e),
    }
    println!();

    // 5. Seccomp profiles
    println!("5. Seccomp Profiles");
    println!("   Minimal profile: {} rules", profiles::minimal().rules().len());
    println!("   Standard profile: {} rules", profiles::standard().rules().len());
    println!("   Network profile: {} rules", profiles::network().rules().len());
    println!();

    // 6. Sandbox configurations
    println!("6. Sandbox Configurations");

    let minimal = SandboxConfig::minimal();
    println!("   Minimal:");
    println!("     User NS: {}", minimal.enable_user_ns);
    println!("     Mount NS: {}", minimal.enable_mount_ns);
    println!("     Network NS: {}", minimal.enable_network_ns);

    let strict = SandboxConfig::strict();
    println!("   Strict:");
    println!("     Allowed syscalls: {}", strict.allowed_syscalls.len());
    println!("     Drop all caps: {}", strict.drop_all_caps);
    println!("     Strict mode: {}", strict.strict_mode);
    println!();

    // 7. Run a simple sandboxed operation
    println!("7. Running Sandboxed Echo");
    let sandbox = Sandbox::new(SandboxConfig::minimal()).unwrap();
    match sandbox.run_command("echo", &["Hello from sandbox!"]) {
        Ok(code) => println!("   Exit code: {}", code),
        Err(e) => println!("   Error: {}", e),
    }
    println!();

    println!("=== Demo Complete ===");
}
