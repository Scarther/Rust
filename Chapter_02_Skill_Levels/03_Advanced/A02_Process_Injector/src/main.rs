//! # Process Injector - Educational Tool
//!
//! This is an EDUCATIONAL tool demonstrating process memory analysis techniques.
//! It shows how debuggers and security tools interact with process memory.
//!
//! ## Legal Disclaimer
//!
//! This tool is for EDUCATIONAL and AUTHORIZED SECURITY RESEARCH only.
//! Using these techniques without authorization is ILLEGAL.
//! Only use on systems and processes you own or have explicit permission to test.
//!
//! ## What This Tool Demonstrates
//!
//! 1. ptrace-based process attachment
//! 2. Memory reading via /proc/[pid]/mem
//! 3. Memory map analysis
//! 4. Register inspection
//! 5. Memory searching and dumping
//!
//! ## Usage Examples
//!
//! ```bash
//! # Analyze a process
//! sudo process_injector analyze 1234
//!
//! # Dump memory maps
//! sudo process_injector maps 1234
//!
//! # Read memory at address
//! sudo process_injector read 1234 0x7fff12345678 64
//!
//! # Search for string in memory
//! sudo process_injector search 1234 "password"
//!
//! # Dump a memory region
//! sudo process_injector dump 1234 0x7fff12345678 4096 output.bin
//! ```

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use colored::*;
use log::{debug, error, info, warn, LevelFilter};
use process_injector::{
    disasm, elf, InjectorError, MemoryRegion, ProcessAnalyzer, ProcessInfo, ProcessState,
};
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

/// Educational Process Memory Analysis Tool
///
/// Demonstrates advanced process debugging and memory analysis techniques.
/// For educational and authorized security research only.
#[derive(Parser, Debug)]
#[command(name = "process_injector")]
#[command(author = "Security Researcher")]
#[command(version = "1.0.0")]
#[command(about = "Educational process memory analysis tool")]
#[command(long_about = None)]
struct Cli {
    /// Verbosity level (-v, -vv, -vvv)
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Output format (text, json)
    #[arg(short, long, default_value = "text")]
    format: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Analyze a process (attach, inspect, detach)
    Analyze {
        /// Process ID to analyze
        pid: i32,

        /// Show memory maps
        #[arg(long)]
        maps: bool,

        /// Show registers
        #[arg(long)]
        regs: bool,
    },

    /// List memory maps for a process
    Maps {
        /// Process ID
        pid: i32,

        /// Filter: only show executable regions
        #[arg(long)]
        executable_only: bool,

        /// Filter: only show writable regions
        #[arg(long)]
        writable_only: bool,

        /// Filter by path pattern
        #[arg(long)]
        filter: Option<String>,
    },

    /// Read memory from a process
    Read {
        /// Process ID
        pid: i32,

        /// Memory address (hex, e.g., 0x7fff12345678)
        #[arg(value_parser = parse_hex)]
        address: u64,

        /// Number of bytes to read
        #[arg(default_value = "64")]
        size: usize,

        /// Output as hexdump
        #[arg(long)]
        hex: bool,

        /// Output as ASCII
        #[arg(long)]
        ascii: bool,
    },

    /// Search for a pattern in process memory
    Search {
        /// Process ID
        pid: i32,

        /// Pattern to search for (string or hex with --hex flag)
        pattern: String,

        /// Treat pattern as hex bytes
        #[arg(long)]
        hex: bool,

        /// Maximum results to show
        #[arg(long, default_value = "100")]
        max_results: usize,
    },

    /// Dump a memory region to a file
    Dump {
        /// Process ID
        pid: i32,

        /// Memory address (hex)
        #[arg(value_parser = parse_hex)]
        address: u64,

        /// Number of bytes to dump
        size: usize,

        /// Output file path
        output: PathBuf,
    },

    /// Show CPU registers
    Registers {
        /// Process ID
        pid: i32,
    },

    /// Get process information
    Info {
        /// Process ID
        pid: i32,
    },

    /// Find specific memory regions
    Find {
        /// Process ID
        pid: i32,

        /// Region type to find
        #[arg(value_enum)]
        region_type: RegionType,
    },

    /// Disassemble memory (basic)
    Disasm {
        /// Process ID
        pid: i32,

        /// Memory address (hex)
        #[arg(value_parser = parse_hex)]
        address: u64,

        /// Number of bytes
        #[arg(default_value = "64")]
        size: usize,
    },
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum RegionType {
    Heap,
    Stack,
    Executable,
    Writable,
    Shared,
}

/// Parse a hexadecimal string to u64
fn parse_hex(s: &str) -> Result<u64, String> {
    let s = s.trim_start_matches("0x").trim_start_matches("0X");
    u64::from_str_radix(s, 16).map_err(|e| format!("Invalid hex address: {}", e))
}

/// Format bytes as a hexdump
fn hexdump(data: &[u8], start_addr: u64) -> String {
    let mut output = String::new();
    let bytes_per_line = 16;

    for (i, chunk) in data.chunks(bytes_per_line).enumerate() {
        let addr = start_addr + (i * bytes_per_line) as u64;

        // Address
        output.push_str(&format!("{:016x}  ", addr));

        // Hex bytes
        for (j, byte) in chunk.iter().enumerate() {
            output.push_str(&format!("{:02x} ", byte));
            if j == 7 {
                output.push(' ');
            }
        }

        // Padding for incomplete lines
        if chunk.len() < bytes_per_line {
            let padding = bytes_per_line - chunk.len();
            for j in 0..padding {
                output.push_str("   ");
                if chunk.len() + j == 7 {
                    output.push(' ');
                }
            }
        }

        // ASCII representation
        output.push_str(" |");
        for byte in chunk {
            if *byte >= 0x20 && *byte < 0x7f {
                output.push(*byte as char);
            } else {
                output.push('.');
            }
        }
        output.push_str("|\n");
    }

    output
}

/// Print memory region information
fn print_memory_region(region: &MemoryRegion) {
    let perms_color = if region.permissions.execute {
        "red"
    } else if region.permissions.write {
        "yellow"
    } else {
        "white"
    };

    let pathname = region
        .pathname
        .as_ref()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|| "[anonymous]".to_string());

    println!(
        "{:016x}-{:016x} {} {:>8} {}",
        region.start,
        region.end,
        format!("{}", region.permissions).color(perms_color),
        format_size(region.size()),
        pathname.cyan()
    );
}

/// Format size in human-readable format
fn format_size(size: u64) -> String {
    if size >= 1024 * 1024 * 1024 {
        format!("{:.1}G", size as f64 / (1024.0 * 1024.0 * 1024.0))
    } else if size >= 1024 * 1024 {
        format!("{:.1}M", size as f64 / (1024.0 * 1024.0))
    } else if size >= 1024 {
        format!("{:.1}K", size as f64 / 1024.0)
    } else {
        format!("{}B", size)
    }
}

/// Print process info
fn print_process_info(info: &ProcessInfo) {
    println!("{}", "=== Process Information ===".cyan().bold());
    println!("  {} {}", "PID:".yellow(), info.pid);
    println!("  {} {}", "Name:".yellow(), info.name);
    println!("  {} {}", "State:".yellow(), info.state);

    if let Some(ref exe) = info.exe_path {
        println!("  {} {:?}", "Executable:".yellow(), exe);
    }

    println!("  {} {}", "Command:".yellow(), info.cmdline);
    println!("  {} {}", "UID:".yellow(), info.uid);
    println!("  {} {}", "GID:".yellow(), info.gid);
    println!("  {} {}", "Parent PID:".yellow(), info.parent_pid);
    println!("  {} {:?}", "Threads:".yellow(), info.threads);
}

/// Print registers
fn print_registers(regs: &libc::user_regs_struct) {
    println!("{}", "=== CPU Registers (x86_64) ===".cyan().bold());
    println!();

    println!("{}", "General Purpose:".yellow());
    println!("  RAX: {:016x}    RBX: {:016x}", regs.rax, regs.rbx);
    println!("  RCX: {:016x}    RDX: {:016x}", regs.rcx, regs.rdx);
    println!("  RSI: {:016x}    RDI: {:016x}", regs.rsi, regs.rdi);
    println!("  R8:  {:016x}    R9:  {:016x}", regs.r8, regs.r9);
    println!("  R10: {:016x}    R11: {:016x}", regs.r10, regs.r11);
    println!("  R12: {:016x}    R13: {:016x}", regs.r12, regs.r13);
    println!("  R14: {:016x}    R15: {:016x}", regs.r14, regs.r15);
    println!();

    println!("{}", "Stack/Frame:".yellow());
    println!("  RSP: {:016x}    RBP: {:016x}", regs.rsp, regs.rbp);
    println!();

    println!("{}", "Instruction:".yellow());
    println!("  RIP: {:016x}", regs.rip);
    println!("  EFLAGS: {:016x}", regs.eflags);
    println!();

    println!("{}", "Segment:".yellow());
    println!("  CS: {:04x}  SS: {:04x}  DS: {:04x}", regs.cs, regs.ss, regs.ds);
    println!("  ES: {:04x}  FS: {:04x}  GS: {:04x}", regs.es, regs.fs, regs.gs);
    println!("  FS_BASE: {:016x}", regs.fs_base);
    println!("  GS_BASE: {:016x}", regs.gs_base);
}

/// Check if running with root privileges
fn check_privileges() -> bool {
    nix::unistd::Uid::effective().is_root()
}

/// Initialize logging
fn init_logging(verbosity: u8) {
    let level = match verbosity {
        0 => LevelFilter::Warn,
        1 => LevelFilter::Info,
        2 => LevelFilter::Debug,
        _ => LevelFilter::Trace,
    };

    env_logger::Builder::new()
        .filter_level(level)
        .format_timestamp_secs()
        .init();
}

/// Print the educational disclaimer
fn print_disclaimer() {
    println!();
    println!(
        "{}",
        "========================================".red()
    );
    println!(
        "{}",
        "  EDUCATIONAL TOOL - USE RESPONSIBLY".red().bold()
    );
    println!(
        "{}",
        "========================================".red()
    );
    println!();
    println!(
        "{}",
        "This tool demonstrates process memory analysis techniques."
    );
    println!(
        "{}",
        "It is intended for:"
    );
    println!("  - Learning how debuggers work");
    println!("  - Security research on systems you own");
    println!("  - Authorized penetration testing");
    println!();
    println!(
        "{}",
        "Using these techniques without authorization is ILLEGAL.".red()
    );
    println!();
}

/// Print banner
fn print_banner() {
    println!(
        "{}",
        r#"
  ____                              ___        _           _
 |  _ \ _ __ ___   ___ ___  ___ ___|_ _|_ __  (_) ___  ___| |_ ___  _ __
 | |_) | '__/ _ \ / __/ _ \/ __/ __|| || '_ \ | |/ _ \/ __| __/ _ \| '__|
 |  __/| | | (_) | (_|  __/\__ \__ \| || | | || |  __/ (__| || (_) | |
 |_|   |_|  \___/ \___\___||___/___/___|_| |_|/ |\___|\___|\__\___/|_|
                                            |__/
"#
        .cyan()
    );
    println!(
        "{}",
        "  Educational Process Memory Analysis Tool".cyan()
    );
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    init_logging(cli.verbose);

    print_banner();
    print_disclaimer();

    if !check_privileges() {
        eprintln!(
            "{} This tool requires root privileges for ptrace operations.",
            "WARNING:".yellow().bold()
        );
        eprintln!();
    }

    match cli.command {
        Commands::Analyze { pid, maps, regs } => {
            analyze_process(pid, maps, regs).await?;
        }

        Commands::Maps {
            pid,
            executable_only,
            writable_only,
            filter,
        } => {
            show_maps(pid, executable_only, writable_only, filter).await?;
        }

        Commands::Read {
            pid,
            address,
            size,
            hex,
            ascii,
        } => {
            read_memory(pid, address, size, hex || !ascii).await?;
        }

        Commands::Search {
            pid,
            pattern,
            hex,
            max_results,
        } => {
            search_memory(pid, &pattern, hex, max_results).await?;
        }

        Commands::Dump {
            pid,
            address,
            size,
            output,
        } => {
            dump_memory(pid, address, size, output).await?;
        }

        Commands::Registers { pid } => {
            show_registers(pid).await?;
        }

        Commands::Info { pid } => {
            show_info(pid).await?;
        }

        Commands::Find { pid, region_type } => {
            find_regions(pid, region_type).await?;
        }

        Commands::Disasm { pid, address, size } => {
            disassemble(pid, address, size).await?;
        }
    }

    Ok(())
}

/// Analyze a process
async fn analyze_process(pid: i32, show_maps: bool, show_regs: bool) -> Result<()> {
    println!("{}", "=== Process Analysis ===".cyan().bold());
    println!("Target PID: {}", pid);
    println!();

    // Get basic info without attaching
    let mut analyzer = ProcessAnalyzer::new(pid)
        .context("Failed to create analyzer")?;

    let info = analyzer.get_process_info()?;
    print_process_info(&info);
    println!();

    // Attach to process
    println!("{}", "Attaching to process...".yellow());
    analyzer.attach().context("Failed to attach to process")?;
    println!("{}", "Successfully attached!".green());
    println!();

    // Show memory maps if requested
    if show_maps {
        println!("{}", "=== Memory Maps ===".cyan().bold());
        for region in analyzer.get_memory_maps() {
            print_memory_region(region);
        }
        println!();
    }

    // Show registers if requested
    if show_regs {
        let regs = analyzer.get_registers()?;
        print_registers(&regs);
        println!();
    }

    // Show summary
    let maps = analyzer.get_memory_maps();
    let exec_count = maps.iter().filter(|r| r.is_executable()).count();
    let write_count = maps.iter().filter(|r| r.is_writable()).count();
    let total_size: u64 = maps.iter().map(|r| r.size()).sum();

    println!("{}", "=== Summary ===".cyan().bold());
    println!("  Total memory regions: {}", maps.len());
    println!("  Executable regions: {}", exec_count);
    println!("  Writable regions: {}", write_count);
    println!("  Total mapped memory: {}", format_size(total_size));

    // Check for ELF at entry point
    if let Some(heap) = analyzer.find_heap() {
        println!("  Heap: {:016x}-{:016x} ({})",
            heap.start, heap.end, format_size(heap.size()));
    }
    if let Some(stack) = analyzer.find_stack() {
        println!("  Stack: {:016x}-{:016x} ({})",
            stack.start, stack.end, format_size(stack.size()));
    }

    // Detach is automatic via Drop
    println!();
    println!("{}", "Analysis complete. Detaching...".yellow());

    Ok(())
}

/// Show memory maps
async fn show_maps(
    pid: i32,
    executable_only: bool,
    writable_only: bool,
    filter: Option<String>,
) -> Result<()> {
    println!("{}", "=== Memory Maps ===".cyan().bold());
    println!("PID: {}", pid);
    println!();

    // Parse maps without attaching (just read /proc/[pid]/maps)
    let maps = ProcessAnalyzer::parse_memory_maps(pid)?;

    let filtered: Vec<_> = maps
        .iter()
        .filter(|r| {
            if executable_only && !r.is_executable() {
                return false;
            }
            if writable_only && !r.is_writable() {
                return false;
            }
            if let Some(ref pattern) = filter {
                if let Some(ref pathname) = r.pathname {
                    if !pathname.to_string_lossy().contains(pattern) {
                        return false;
                    }
                } else {
                    return false;
                }
            }
            true
        })
        .collect();

    for region in &filtered {
        print_memory_region(region);
    }

    println!();
    println!(
        "Showing {} of {} regions",
        filtered.len(),
        maps.len()
    );

    Ok(())
}

/// Read memory
async fn read_memory(pid: i32, address: u64, size: usize, as_hex: bool) -> Result<()> {
    println!("{}", "=== Memory Read ===".cyan().bold());
    println!("PID: {}, Address: {:#x}, Size: {}", pid, address, size);
    println!();

    let mut analyzer = ProcessAnalyzer::new(pid)?;
    analyzer.attach()?;

    let data = analyzer.read_memory(address, size)?;

    if as_hex {
        println!("{}", hexdump(&data, address));
    } else {
        // Print as string (lossy)
        let s = String::from_utf8_lossy(&data);
        println!("{}", s);
    }

    Ok(())
}

/// Search memory
async fn search_memory(pid: i32, pattern: &str, is_hex: bool, max_results: usize) -> Result<()> {
    println!("{}", "=== Memory Search ===".cyan().bold());
    println!("PID: {}, Pattern: {}", pid, pattern);
    println!();

    let mut analyzer = ProcessAnalyzer::new(pid)?;
    analyzer.attach()?;

    let search_bytes = if is_hex {
        hex::decode(pattern).context("Invalid hex pattern")?
    } else {
        pattern.as_bytes().to_vec()
    };

    println!("Searching for {} bytes...", search_bytes.len());

    let matches = analyzer.search_memory(&search_bytes)?;

    if matches.is_empty() {
        println!("{}", "No matches found.".yellow());
    } else {
        println!(
            "{} Found {} matches:",
            "OK".green(),
            matches.len()
        );
        println!();

        for (i, addr) in matches.iter().take(max_results).enumerate() {
            // Try to read context around the match
            let context_start = addr.saturating_sub(8);
            if let Ok(context) = analyzer.read_memory(context_start, 32) {
                println!("Match {}: {:#x}", i + 1, addr);
                println!("{}", hexdump(&context, context_start));
            } else {
                println!("Match {}: {:#x}", i + 1, addr);
            }
        }

        if matches.len() > max_results {
            println!(
                "... and {} more matches (use --max-results to see more)",
                matches.len() - max_results
            );
        }
    }

    Ok(())
}

/// Dump memory to file
async fn dump_memory(pid: i32, address: u64, size: usize, output: PathBuf) -> Result<()> {
    println!("{}", "=== Memory Dump ===".cyan().bold());
    println!(
        "PID: {}, Address: {:#x}, Size: {}, Output: {:?}",
        pid, address, size, output
    );
    println!();

    let mut analyzer = ProcessAnalyzer::new(pid)?;
    analyzer.attach()?;

    let data = analyzer.read_memory(address, size)?;

    let mut file = File::create(&output)?;
    file.write_all(&data)?;

    println!(
        "{} Wrote {} bytes to {:?}",
        "OK".green(),
        data.len(),
        output
    );

    // Show first bytes as preview
    println!();
    println!("Preview (first 64 bytes):");
    println!("{}", hexdump(&data[..std::cmp::min(64, data.len())], address));

    Ok(())
}

/// Show registers
async fn show_registers(pid: i32) -> Result<()> {
    let mut analyzer = ProcessAnalyzer::new(pid)?;
    analyzer.attach()?;

    let regs = analyzer.get_registers()?;
    print_registers(&regs);

    Ok(())
}

/// Show process info
async fn show_info(pid: i32) -> Result<()> {
    let analyzer = ProcessAnalyzer::new(pid)?;
    let info = analyzer.get_process_info()?;
    print_process_info(&info);

    Ok(())
}

/// Find specific memory regions
async fn find_regions(pid: i32, region_type: RegionType) -> Result<()> {
    println!("{}", "=== Find Memory Regions ===".cyan().bold());
    println!("PID: {}, Type: {:?}", pid, region_type);
    println!();

    let mut analyzer = ProcessAnalyzer::new(pid)?;
    analyzer.attach()?;

    let maps = analyzer.get_memory_maps();

    let filtered: Vec<_> = match region_type {
        RegionType::Heap => maps
            .iter()
            .filter(|r| {
                r.pathname
                    .as_ref()
                    .map_or(false, |p| p.to_string_lossy().contains("[heap]"))
            })
            .collect(),
        RegionType::Stack => maps
            .iter()
            .filter(|r| {
                r.pathname
                    .as_ref()
                    .map_or(false, |p| p.to_string_lossy().contains("[stack]"))
            })
            .collect(),
        RegionType::Executable => maps.iter().filter(|r| r.is_executable()).collect(),
        RegionType::Writable => maps.iter().filter(|r| r.is_writable()).collect(),
        RegionType::Shared => maps.iter().filter(|r| r.permissions.shared).collect(),
    };

    if filtered.is_empty() {
        println!("{}", "No matching regions found.".yellow());
    } else {
        println!("Found {} regions:", filtered.len());
        println!();
        for region in filtered {
            print_memory_region(region);
        }
    }

    Ok(())
}

/// Basic disassembly
async fn disassemble(pid: i32, address: u64, size: usize) -> Result<()> {
    println!("{}", "=== Disassembly (Basic) ===".cyan().bold());
    println!("PID: {}, Address: {:#x}, Size: {}", pid, address, size);
    println!();
    println!(
        "{}",
        "Note: This is a simplified disassembler for educational purposes.".dimmed()
    );
    println!(
        "{}",
        "For full disassembly, use tools like objdump or a proper disassembler.".dimmed()
    );
    println!();

    let mut analyzer = ProcessAnalyzer::new(pid)?;
    analyzer.attach()?;

    let data = analyzer.read_memory(address, size)?;

    // Simple byte-by-byte analysis
    let mut offset = 0;
    while offset < data.len() {
        let remaining = &data[offset..];
        let instruction = disasm::identify_instruction(remaining);

        // Estimate instruction length (simplified)
        let inst_len = match data[offset] {
            disasm::INT3 | disasm::NOP | disasm::RET => 1,
            disasm::JMP_REL8 => 2,
            disasm::CALL_REL32 | disasm::JMP_REL32 => 5,
            0x48 if remaining.len() >= 3 => 3, // REX prefix + 2 bytes
            _ => 1,
        };

        let bytes: Vec<String> = remaining
            .iter()
            .take(inst_len)
            .map(|b| format!("{:02x}", b))
            .collect();

        println!(
            "{:016x}:  {:20}  {}",
            address + offset as u64,
            bytes.join(" "),
            instruction.cyan()
        );

        offset += inst_len;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hex() {
        assert_eq!(parse_hex("0x1234").unwrap(), 0x1234);
        assert_eq!(parse_hex("0X1234").unwrap(), 0x1234);
        assert_eq!(parse_hex("1234").unwrap(), 0x1234);
        assert_eq!(parse_hex("7fff12345678").unwrap(), 0x7fff12345678);
    }

    #[test]
    fn test_hexdump() {
        let data = b"Hello, World!";
        let output = hexdump(data, 0x1000);
        assert!(output.contains("1000"));
        assert!(output.contains("Hello"));
    }

    #[test]
    fn test_format_size() {
        assert_eq!(format_size(100), "100B");
        assert_eq!(format_size(1024), "1.0K");
        assert_eq!(format_size(1024 * 1024), "1.0M");
        assert_eq!(format_size(1024 * 1024 * 1024), "1.0G");
    }

    #[test]
    fn test_cli_parsing() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }
}
