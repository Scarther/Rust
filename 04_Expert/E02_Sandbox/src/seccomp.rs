//! # Seccomp-BPF Syscall Filtering
//!
//! This module implements syscall filtering using seccomp-BPF (Secure Computing Mode).
//!
//! ## Overview
//!
//! Seccomp allows restricting which system calls a process can make:
//! - KILL: Terminate process on violation
//! - TRAP: Send SIGSYS signal
//! - ERRNO: Return error code
//! - ALLOW: Permit the syscall
//! - LOG: Log the syscall but allow it
//!
//! ## Security Considerations
//!
//! - Seccomp filters are inherited by child processes
//! - Once applied, filters cannot be removed
//! - Filters should be applied after forking but before execve

use std::collections::HashMap;

use crate::error::{SandboxError, SandboxResult};

/// Seccomp action to take when a syscall matches
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeccompAction {
    /// Allow the syscall
    Allow,
    /// Kill the process
    Kill,
    /// Kill the thread
    KillThread,
    /// Send SIGSYS
    Trap,
    /// Return an error code
    Errno(u32),
    /// Log the syscall (requires kernel 4.14+)
    Log,
    /// Allow but log (requires kernel 5.0+)
    Notify,
}

impl SeccompAction {
    /// Convert to seccomp return value
    pub fn to_seccomp_ret(&self) -> u32 {
        use libc::*;
        match self {
            SeccompAction::Allow => SECCOMP_RET_ALLOW,
            SeccompAction::Kill => SECCOMP_RET_KILL_PROCESS,
            SeccompAction::KillThread => SECCOMP_RET_KILL_THREAD,
            SeccompAction::Trap => SECCOMP_RET_TRAP,
            SeccompAction::Errno(errno) => SECCOMP_RET_ERRNO | (*errno & 0xFFFF),
            SeccompAction::Log => SECCOMP_RET_LOG,
            SeccompAction::Notify => SECCOMP_RET_USER_NOTIF,
        }
    }
}

/// Syscall filter rule
#[derive(Debug, Clone)]
pub struct SeccompRule {
    /// Syscall name
    pub syscall: String,
    /// Syscall number (resolved at runtime)
    pub syscall_nr: Option<i64>,
    /// Action to take
    pub action: SeccompAction,
    /// Argument filters (index -> (op, value))
    pub arg_filters: Vec<ArgFilter>,
}

/// Argument filter for syscall arguments
#[derive(Debug, Clone)]
pub struct ArgFilter {
    /// Argument index (0-5)
    pub arg_index: u32,
    /// Comparison operation
    pub op: ArgOp,
    /// Value to compare against
    pub value: u64,
}

/// Comparison operations for argument filters
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArgOp {
    /// Argument equals value
    Eq,
    /// Argument not equal to value
    Ne,
    /// Argument less than value
    Lt,
    /// Argument less than or equal to value
    Le,
    /// Argument greater than value
    Gt,
    /// Argument greater than or equal to value
    Ge,
    /// Argument has all bits set
    MaskedEq(u64),
}

/// Syscall number lookup table for x86_64
fn get_syscall_number(name: &str) -> Option<i64> {
    // Common syscalls for x86_64 Linux
    // This is a subset - a full implementation would use libseccomp
    static SYSCALLS: &[(&str, i64)] = &[
        ("read", 0),
        ("write", 1),
        ("open", 2),
        ("close", 3),
        ("stat", 4),
        ("fstat", 5),
        ("lstat", 6),
        ("poll", 7),
        ("lseek", 8),
        ("mmap", 9),
        ("mprotect", 10),
        ("munmap", 11),
        ("brk", 12),
        ("rt_sigaction", 13),
        ("rt_sigprocmask", 14),
        ("rt_sigreturn", 15),
        ("ioctl", 16),
        ("pread64", 17),
        ("pwrite64", 18),
        ("readv", 19),
        ("writev", 20),
        ("access", 21),
        ("pipe", 22),
        ("select", 23),
        ("sched_yield", 24),
        ("mremap", 25),
        ("msync", 26),
        ("mincore", 27),
        ("madvise", 28),
        ("dup", 32),
        ("dup2", 33),
        ("pause", 34),
        ("nanosleep", 35),
        ("getpid", 39),
        ("socket", 41),
        ("connect", 42),
        ("accept", 43),
        ("sendto", 44),
        ("recvfrom", 45),
        ("bind", 49),
        ("listen", 50),
        ("clone", 56),
        ("fork", 57),
        ("vfork", 58),
        ("execve", 59),
        ("exit", 60),
        ("wait4", 61),
        ("kill", 62),
        ("fcntl", 72),
        ("flock", 73),
        ("fsync", 74),
        ("fdatasync", 75),
        ("getcwd", 79),
        ("chdir", 80),
        ("fchdir", 81),
        ("rename", 82),
        ("mkdir", 83),
        ("rmdir", 84),
        ("creat", 85),
        ("link", 86),
        ("unlink", 87),
        ("symlink", 88),
        ("readlink", 89),
        ("chmod", 90),
        ("fchmod", 91),
        ("chown", 92),
        ("fchown", 93),
        ("umask", 95),
        ("getuid", 102),
        ("getgid", 104),
        ("geteuid", 107),
        ("getegid", 108),
        ("setpgid", 109),
        ("getppid", 110),
        ("getpgrp", 111),
        ("setsid", 112),
        ("getgroups", 115),
        ("setgroups", 116),
        ("uname", 63),
        ("arch_prctl", 158),
        ("prctl", 157),
        ("clock_gettime", 228),
        ("clock_getres", 229),
        ("clock_nanosleep", 230),
        ("exit_group", 231),
        ("epoll_wait", 232),
        ("epoll_ctl", 233),
        ("tgkill", 234),
        ("openat", 257),
        ("mkdirat", 258),
        ("fchownat", 260),
        ("newfstatat", 262),
        ("unlinkat", 263),
        ("renameat", 264),
        ("linkat", 265),
        ("symlinkat", 266),
        ("readlinkat", 267),
        ("fchmodat", 268),
        ("faccessat", 269),
        ("set_robust_list", 273),
        ("get_robust_list", 274),
        ("set_tid_address", 218),
        ("futex", 202),
        ("getrandom", 318),
        ("memfd_create", 319),
        ("statx", 332),
        ("prlimit64", 302),
        ("rseq", 334),
        ("clone3", 435),
        ("close_range", 436),
        ("openat2", 437),
        ("pidfd_open", 434),
        ("pidfd_getfd", 438),
        ("sigaltstack", 131),
    ];

    SYSCALLS.iter()
        .find(|(n, _)| *n == name)
        .map(|(_, nr)| *nr)
}

/// Build a seccomp BPF filter
pub struct SeccompFilterBuilder {
    rules: Vec<SeccompRule>,
    default_action: SeccompAction,
}

impl SeccompFilterBuilder {
    /// Create a new filter builder with default action
    pub fn new(default_action: SeccompAction) -> Self {
        Self {
            rules: Vec::new(),
            default_action,
        }
    }

    /// Add a rule to allow a syscall
    pub fn allow_syscall(mut self, name: &str) -> Self {
        if let Some(nr) = get_syscall_number(name) {
            self.rules.push(SeccompRule {
                syscall: name.to_string(),
                syscall_nr: Some(nr),
                action: SeccompAction::Allow,
                arg_filters: Vec::new(),
            });
        } else {
            tracing::warn!("Unknown syscall: {}", name);
        }
        self
    }

    /// Add a rule to deny a syscall
    pub fn deny_syscall(mut self, name: &str, action: SeccompAction) -> Self {
        if let Some(nr) = get_syscall_number(name) {
            self.rules.push(SeccompRule {
                syscall: name.to_string(),
                syscall_nr: Some(nr),
                action,
                arg_filters: Vec::new(),
            });
        }
        self
    }

    /// Add a rule with argument filter
    pub fn allow_syscall_with_arg(
        mut self,
        name: &str,
        arg_index: u32,
        op: ArgOp,
        value: u64,
    ) -> Self {
        if let Some(nr) = get_syscall_number(name) {
            self.rules.push(SeccompRule {
                syscall: name.to_string(),
                syscall_nr: Some(nr),
                action: SeccompAction::Allow,
                arg_filters: vec![ArgFilter { arg_index, op, value }],
            });
        }
        self
    }

    /// Build and apply the filter
    pub fn apply(self) -> SandboxResult<()> {
        apply_seccomp_raw(&self.rules, self.default_action)
    }

    /// Get the rules for inspection
    pub fn rules(&self) -> &[SeccompRule] {
        &self.rules
    }
}

/// Apply a seccomp filter using the kernel interface directly
fn apply_seccomp_raw(rules: &[SeccompRule], default_action: SeccompAction) -> SandboxResult<()> {
    use libc::{
        prctl, PR_SET_NO_NEW_PRIVS, PR_SET_SECCOMP, SECCOMP_MODE_FILTER,
        sock_filter, sock_fprog,
        BPF_ABS, BPF_JEQ, BPF_JMP, BPF_K, BPF_LD, BPF_RET, BPF_W,
    };

    // First, set no_new_privs to allow unprivileged seccomp
    // SAFETY: prctl with PR_SET_NO_NEW_PRIVS is safe
    let result = unsafe { prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if result < 0 {
        return Err(SandboxError::Seccomp(format!(
            "Failed to set no_new_privs: {}",
            std::io::Error::last_os_error()
        )));
    }

    // Build BPF program
    let mut bpf_program: Vec<sock_filter> = Vec::new();

    // Offset of syscall number in seccomp_data struct
    const SYSCALL_NR_OFFSET: u32 = 0;
    const ARCH_OFFSET: u32 = 4;

    // Expected architecture (x86_64)
    const AUDIT_ARCH_X86_64: u32 = 0xc000003e;

    // Load architecture and verify
    bpf_program.push(sock_filter {
        code: (BPF_LD | BPF_W | BPF_ABS) as u16,
        jt: 0,
        jf: 0,
        k: ARCH_OFFSET,
    });

    // Jump over the kill if architecture matches
    bpf_program.push(sock_filter {
        code: (BPF_JMP | BPF_JEQ | BPF_K) as u16,
        jt: 1, // Skip the kill instruction
        jf: 0,
        k: AUDIT_ARCH_X86_64,
    });

    // Kill if architecture doesn't match
    bpf_program.push(sock_filter {
        code: BPF_RET as u16,
        jt: 0,
        jf: 0,
        k: SeccompAction::Kill.to_seccomp_ret(),
    });

    // Load syscall number
    bpf_program.push(sock_filter {
        code: (BPF_LD | BPF_W | BPF_ABS) as u16,
        jt: 0,
        jf: 0,
        k: SYSCALL_NR_OFFSET,
    });

    // Add rules for each syscall
    // Calculate jump offsets from the end
    let rules_count = rules.len();
    for (i, rule) in rules.iter().enumerate() {
        if let Some(nr) = rule.syscall_nr {
            // Jump to action if syscall matches, otherwise continue
            let remaining = rules_count - i - 1;
            bpf_program.push(sock_filter {
                code: (BPF_JMP | BPF_JEQ | BPF_K) as u16,
                jt: (remaining + 1) as u8, // Jump to corresponding action
                jf: 0, // Continue checking
                k: nr as u32,
            });
        }
    }

    // Default action (return it if no rule matched)
    bpf_program.push(sock_filter {
        code: BPF_RET as u16,
        jt: 0,
        jf: 0,
        k: default_action.to_seccomp_ret(),
    });

    // Add action returns for each rule (in reverse order)
    for rule in rules.iter().rev() {
        bpf_program.push(sock_filter {
            code: BPF_RET as u16,
            jt: 0,
            jf: 0,
            k: rule.action.to_seccomp_ret(),
        });
    }

    // Create the BPF program structure
    let prog = sock_fprog {
        len: bpf_program.len() as u16,
        filter: bpf_program.as_ptr() as *mut sock_filter,
    };

    // Apply the filter
    // SAFETY: prctl with SECCOMP_MODE_FILTER and valid prog is safe
    let result = unsafe {
        prctl(
            PR_SET_SECCOMP,
            SECCOMP_MODE_FILTER as libc::c_ulong,
            &prog as *const sock_fprog,
            0,
            0,
        )
    };

    if result < 0 {
        return Err(SandboxError::Seccomp(format!(
            "Failed to apply seccomp filter: {}",
            std::io::Error::last_os_error()
        )));
    }

    tracing::info!("Seccomp filter applied with {} rules", rules.len());
    Ok(())
}

/// Apply a seccomp filter from lists of allowed/denied syscalls
pub fn apply_seccomp_filter(
    allowed: &[String],
    denied: &[String],
    default_action: SeccompAction,
) -> SandboxResult<()> {
    let mut builder = SeccompFilterBuilder::new(default_action);

    // Add denied syscalls first (they take precedence)
    for syscall in denied {
        builder = builder.deny_syscall(syscall, SeccompAction::Kill);
    }

    // Add allowed syscalls
    for syscall in allowed {
        builder = builder.allow_syscall(syscall);
    }

    builder.apply()
}

/// Check if seccomp is available
pub fn is_seccomp_available() -> bool {
    use libc::{prctl, PR_GET_SECCOMP};

    // SAFETY: prctl with PR_GET_SECCOMP is safe for querying
    let result = unsafe { prctl(PR_GET_SECCOMP, 0, 0, 0, 0) };

    // Returns -1 with EINVAL if not supported, 0 if disabled, 1/2 if enabled
    result >= 0
}

/// Get current seccomp mode
pub fn get_seccomp_mode() -> i32 {
    use libc::{prctl, PR_GET_SECCOMP};

    // SAFETY: prctl with PR_GET_SECCOMP is safe
    unsafe { prctl(PR_GET_SECCOMP, 0, 0, 0, 0) }
}

/// Predefined seccomp profiles
pub mod profiles {
    use super::*;

    /// Minimal profile - only basic I/O
    pub fn minimal() -> SeccompFilterBuilder {
        SeccompFilterBuilder::new(SeccompAction::Kill)
            .allow_syscall("read")
            .allow_syscall("write")
            .allow_syscall("exit")
            .allow_syscall("exit_group")
            .allow_syscall("brk")
            .allow_syscall("mmap")
            .allow_syscall("munmap")
            .allow_syscall("mprotect")
    }

    /// Network profile - allows network operations
    pub fn network() -> SeccompFilterBuilder {
        minimal()
            .allow_syscall("socket")
            .allow_syscall("connect")
            .allow_syscall("accept")
            .allow_syscall("bind")
            .allow_syscall("listen")
            .allow_syscall("sendto")
            .allow_syscall("recvfrom")
            .allow_syscall("close")
            .allow_syscall("poll")
            .allow_syscall("epoll_wait")
            .allow_syscall("epoll_ctl")
    }

    /// File operations profile
    pub fn file_ops() -> SeccompFilterBuilder {
        minimal()
            .allow_syscall("open")
            .allow_syscall("openat")
            .allow_syscall("close")
            .allow_syscall("fstat")
            .allow_syscall("newfstatat")
            .allow_syscall("lseek")
            .allow_syscall("getcwd")
            .allow_syscall("readlink")
            .allow_syscall("readlinkat")
    }

    /// Standard profile for most applications
    pub fn standard() -> SeccompFilterBuilder {
        SeccompFilterBuilder::new(SeccompAction::Errno(libc::EPERM as u32))
            .allow_syscall("read")
            .allow_syscall("write")
            .allow_syscall("open")
            .allow_syscall("openat")
            .allow_syscall("close")
            .allow_syscall("fstat")
            .allow_syscall("newfstatat")
            .allow_syscall("stat")
            .allow_syscall("lstat")
            .allow_syscall("lseek")
            .allow_syscall("mmap")
            .allow_syscall("mprotect")
            .allow_syscall("munmap")
            .allow_syscall("brk")
            .allow_syscall("rt_sigaction")
            .allow_syscall("rt_sigprocmask")
            .allow_syscall("rt_sigreturn")
            .allow_syscall("ioctl")
            .allow_syscall("access")
            .allow_syscall("pipe")
            .allow_syscall("dup")
            .allow_syscall("dup2")
            .allow_syscall("nanosleep")
            .allow_syscall("getpid")
            .allow_syscall("clone")
            .allow_syscall("clone3")
            .allow_syscall("fork")
            .allow_syscall("wait4")
            .allow_syscall("exit")
            .allow_syscall("exit_group")
            .allow_syscall("futex")
            .allow_syscall("set_tid_address")
            .allow_syscall("set_robust_list")
            .allow_syscall("prlimit64")
            .allow_syscall("getrandom")
            .allow_syscall("rseq")
            .allow_syscall("arch_prctl")
            .allow_syscall("sigaltstack")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_syscall_lookup() {
        assert_eq!(get_syscall_number("read"), Some(0));
        assert_eq!(get_syscall_number("write"), Some(1));
        assert_eq!(get_syscall_number("exit"), Some(60));
        assert_eq!(get_syscall_number("nonexistent"), None);
    }

    #[test]
    fn test_seccomp_action() {
        assert_eq!(SeccompAction::Allow.to_seccomp_ret(), libc::SECCOMP_RET_ALLOW);
        assert_eq!(SeccompAction::Kill.to_seccomp_ret(), libc::SECCOMP_RET_KILL_PROCESS);
    }

    #[test]
    fn test_filter_builder() {
        let builder = SeccompFilterBuilder::new(SeccompAction::Kill)
            .allow_syscall("read")
            .allow_syscall("write");

        assert_eq!(builder.rules().len(), 2);
    }

    #[test]
    fn test_seccomp_available() {
        // This should return true on modern Linux kernels
        let available = is_seccomp_available();
        println!("Seccomp available: {}", available);
    }
}
