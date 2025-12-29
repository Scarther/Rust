//! # Sandbox CLI Tool
//!
//! Command-line interface for running programs in a sandboxed environment.

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use sandbox::{
    sandbox_status, Sandbox, SandboxConfig, SeccompAction, Capability,
    print_capabilities, is_seccomp_available, profiles,
};
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

#[derive(Parser)]
#[command(name = "sandbox")]
#[command(author = "Security Researcher")]
#[command(version = "0.1.0")]
#[command(about = "Run programs in a secure sandbox", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run a command in the sandbox
    Run {
        /// Disable network access
        #[arg(short = 'n', long)]
        no_network: bool,

        /// Enable PID namespace isolation
        #[arg(short = 'p', long)]
        pid_ns: bool,

        /// Apply strict seccomp filter
        #[arg(short = 's', long)]
        seccomp: bool,

        /// Drop all capabilities
        #[arg(short = 'c', long)]
        drop_caps: bool,

        /// Use strict mode (maximum isolation)
        #[arg(long)]
        strict: bool,

        /// Set CPU time limit (seconds)
        #[arg(long)]
        cpu_limit: Option<u64>,

        /// Set memory limit (MB)
        #[arg(long)]
        mem_limit: Option<u64>,

        /// Readonly bind mount path
        #[arg(long = "ro", value_name = "PATH")]
        readonly: Vec<PathBuf>,

        /// Command to run
        #[arg(required = true)]
        command: String,

        /// Command arguments
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
    },

    /// Show current sandbox status
    Status,

    /// Show current capabilities
    Caps,

    /// Check if seccomp is available
    Seccomp,

    /// Run a demo showing sandbox features
    Demo,

    /// Test sandbox with a simple closure
    Test {
        /// Which test to run
        #[arg(default_value = "basic")]
        test: String,
    },
}

fn main() {
    // Initialize logging
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber).ok();

    let cli = Cli::parse();

    match cli.command {
        Commands::Run {
            no_network,
            pid_ns,
            seccomp,
            drop_caps,
            strict,
            cpu_limit,
            mem_limit,
            readonly,
            command,
            args,
        } => {
            let config = if strict {
                SandboxConfig::strict()
            } else {
                let mut builder = SandboxConfig::builder()
                    .enable_network(!no_network)
                    .enable_pid_ns(pid_ns);

                if drop_caps {
                    builder = builder.drop_all_capabilities();
                }

                for path in readonly {
                    builder = builder.readonly_path(path);
                }

                if seccomp {
                    builder = builder
                        .seccomp_action(SeccompAction::Errno(libc::EPERM as u32))
                        .allow_syscall("read")
                        .allow_syscall("write")
                        .allow_syscall("exit")
                        .allow_syscall("exit_group")
                        .allow_syscall("brk")
                        .allow_syscall("mmap")
                        .allow_syscall("munmap")
                        .allow_syscall("close")
                        .allow_syscall("fstat")
                        .allow_syscall("mprotect")
                        .allow_syscall("arch_prctl")
                        .allow_syscall("set_tid_address")
                        .allow_syscall("set_robust_list")
                        .allow_syscall("prlimit64")
                        .allow_syscall("getrandom")
                        .allow_syscall("rt_sigaction")
                        .allow_syscall("rt_sigprocmask")
                        .allow_syscall("sigaltstack")
                        .allow_syscall("futex")
                        .allow_syscall("rseq");
                }

                let mut config = builder.build();

                // Apply resource limits
                if let Some(cpu) = cpu_limit {
                    config.resource_limits.max_cpu_time = Some(cpu);
                }
                if let Some(mem) = mem_limit {
                    config.resource_limits.max_memory = Some(mem * 1024 * 1024);
                }

                config
            };

            let sandbox = match Sandbox::new(config) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("Failed to create sandbox: {}", e);
                    if let Some(suggestion) = e.suggestion() {
                        eprintln!("Suggestion: {}", suggestion);
                    }
                    std::process::exit(1);
                }
            };

            let args: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
            match sandbox.run_command(&command, &args) {
                Ok(exit_code) => {
                    std::process::exit(exit_code);
                }
                Err(e) => {
                    eprintln!("Sandbox execution failed: {}", e);
                    std::process::exit(1);
                }
            }
        }

        Commands::Status => {
            let status = sandbox_status();
            println!("{}", status);
        }

        Commands::Caps => {
            print_capabilities();
        }

        Commands::Seccomp => {
            if is_seccomp_available() {
                println!("Seccomp is available on this system");
                let mode = sandbox::get_seccomp_mode();
                println!("Current seccomp mode: {}", match mode {
                    0 => "disabled",
                    1 => "strict",
                    2 => "filter",
                    _ => "unknown",
                });
            } else {
                println!("Seccomp is NOT available on this system");
            }
        }

        Commands::Demo => {
            run_demo();
        }

        Commands::Test { test } => {
            run_test(&test);
        }
    }
}

fn run_demo() {
    println!("=== Sandbox Demo ===\n");

    println!("1. Current status:");
    println!("{}", sandbox_status());

    println!("\n2. Available features:");
    println!("   - Seccomp: {}", if is_seccomp_available() { "yes" } else { "no" });

    println!("\n3. Namespace support:");
    for ns in sandbox::supported_namespaces() {
        println!("   - {:?}", ns);
    }

    println!("\n4. Current capabilities:");
    print_capabilities();

    println!("\n5. Mount points:");
    if let Ok(mounts) = sandbox::get_mounts() {
        for mount in mounts.iter().take(5) {
            println!("   {}", mount);
        }
        if mounts.len() > 5 {
            println!("   ... and {} more", mounts.len() - 5);
        }
    }

    println!("\n6. Sandbox configuration examples:");
    println!("   Minimal: {:?}", SandboxConfig::minimal());
    println!("   Strict:  {} allowed syscalls", SandboxConfig::strict().allowed_syscalls.len());

    println!("\n=== Demo Complete ===");
}

fn run_test(test: &str) {
    match test {
        "basic" => {
            println!("Running basic sandbox test...");

            let config = SandboxConfig::minimal();
            let sandbox = Sandbox::new(config).expect("Failed to create sandbox");

            match sandbox.run(|| {
                println!("Hello from inside the sandbox!");
                println!("PID: {}", std::process::id());
            }) {
                Ok(_) => println!("Basic test passed!"),
                Err(e) => println!("Basic test failed: {}", e),
            }
        }

        "namespace" => {
            println!("Running namespace test...");

            let config = SandboxConfig::builder()
                .enable_user_ns(true)
                .enable_mount_ns(true)
                .enable_pid_ns(true)
                .hostname("test-sandbox")
                .build();

            let sandbox = Sandbox::new(config).expect("Failed to create sandbox");

            match sandbox.run(|| {
                println!("Hostname: {:?}", nix::unistd::gethostname());
                println!("PID: {}", std::process::id());
                println!("UID: {}", nix::unistd::getuid());
            }) {
                Ok(_) => println!("Namespace test passed!"),
                Err(e) => println!("Namespace test failed: {}", e),
            }
        }

        "seccomp" => {
            println!("Running seccomp test...");

            // Just test that the filter can be built
            let filter = profiles::minimal();
            println!("Minimal seccomp profile has {} rules", filter.rules().len());

            let filter = profiles::standard();
            println!("Standard seccomp profile has {} rules", filter.rules().len());

            println!("Seccomp test passed!");
        }

        "caps" => {
            println!("Running capabilities test...");

            let current = sandbox::get_current_capabilities()
                .expect("Failed to get capabilities");

            println!("Current capabilities: {}", current.len());
            for cap in &current {
                println!("  - {}", cap);
            }

            println!("Capabilities test passed!");
        }

        _ => {
            println!("Unknown test: {}", test);
            println!("Available tests: basic, namespace, seccomp, caps");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_parse() {
        // Just verify CLI can be parsed
        let cli = Cli::try_parse_from(&["sandbox", "status"]);
        assert!(cli.is_ok());
    }

    #[test]
    fn test_run_command_parse() {
        let cli = Cli::try_parse_from(&[
            "sandbox", "run", "--no-network", "--seccomp", "ls", "-la"
        ]);
        assert!(cli.is_ok());
    }
}
