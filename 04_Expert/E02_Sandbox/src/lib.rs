//! # Process Sandboxing Library
//!
//! This crate provides comprehensive process sandboxing for Linux using:
//! - Linux namespaces (user, mount, PID, network, IPC, UTS)
//! - Seccomp-BPF syscall filtering
//! - Linux capabilities
//! - Filesystem restrictions
//!
//! ## Security Layers
//!
//! The sandbox implements defense-in-depth with multiple security mechanisms:
//!
//! 1. **Namespaces**: Isolate the process's view of the system
//! 2. **Seccomp**: Filter which syscalls can be executed
//! 3. **Capabilities**: Limit privileged operations
//! 4. **Filesystem**: Restrict file access via bind mounts
//!
//! ## Example
//!
//! ```rust,no_run
//! use sandbox::{Sandbox, SandboxConfig};
//!
//! let config = SandboxConfig::builder()
//!     .enable_network(false)
//!     .allow_syscall("read")
//!     .allow_syscall("write")
//!     .readonly_path("/usr")
//!     .build();
//!
//! let sandbox = Sandbox::new(config)?;
//! sandbox.run(|| {
//!     // This code runs in the sandbox
//!     println!("Hello from the sandbox!");
//! })?;
//! # Ok::<(), sandbox::SandboxError>(())
//! ```

pub mod capabilities;
pub mod error;
pub mod filesystem;
pub mod namespace;
pub mod seccomp;

pub use capabilities::*;
pub use error::*;
pub use filesystem::*;
pub use namespace::*;
pub use seccomp::*;

use std::ffi::CString;
use std::path::PathBuf;

/// Main sandbox structure
pub struct Sandbox {
    config: SandboxConfig,
}

/// Sandbox configuration builder
#[derive(Debug, Clone)]
pub struct SandboxConfig {
    /// Enable network namespace (isolate networking)
    pub enable_network_ns: bool,
    /// Enable PID namespace (isolate process tree)
    pub enable_pid_ns: bool,
    /// Enable mount namespace (isolate filesystem)
    pub enable_mount_ns: bool,
    /// Enable user namespace (unprivileged containers)
    pub enable_user_ns: bool,
    /// Enable IPC namespace (isolate IPC)
    pub enable_ipc_ns: bool,
    /// Enable UTS namespace (isolate hostname)
    pub enable_uts_ns: bool,
    /// Enable cgroup namespace
    pub enable_cgroup_ns: bool,
    /// New root filesystem path (for pivot_root)
    pub new_root: Option<PathBuf>,
    /// Bind mounts (source, target, readonly)
    pub bind_mounts: Vec<(PathBuf, PathBuf, bool)>,
    /// Allowed syscalls (empty = allow all with logging)
    pub allowed_syscalls: Vec<String>,
    /// Denied syscalls (takes precedence)
    pub denied_syscalls: Vec<String>,
    /// Seccomp default action
    pub seccomp_default_action: SeccompAction,
    /// Capabilities to keep
    pub keep_capabilities: Vec<Capability>,
    /// Drop all capabilities except these
    pub drop_all_caps: bool,
    /// Working directory in sandbox
    pub working_dir: Option<PathBuf>,
    /// Hostname in sandbox
    pub hostname: Option<String>,
    /// UID mapping for user namespace
    pub uid_map: Option<(u32, u32, u32)>,
    /// GID mapping for user namespace
    pub gid_map: Option<(u32, u32, u32)>,
    /// Environment variables
    pub env_vars: Vec<(String, String)>,
    /// Clear environment
    pub clear_env: bool,
    /// Resource limits
    pub resource_limits: ResourceLimits,
    /// Enable strict mode (most restrictive)
    pub strict_mode: bool,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            enable_network_ns: true,
            enable_pid_ns: true,
            enable_mount_ns: true,
            enable_user_ns: true,
            enable_ipc_ns: true,
            enable_uts_ns: true,
            enable_cgroup_ns: false,
            new_root: None,
            bind_mounts: Vec::new(),
            allowed_syscalls: Vec::new(),
            denied_syscalls: Vec::new(),
            seccomp_default_action: SeccompAction::Allow,
            keep_capabilities: Vec::new(),
            drop_all_caps: true,
            working_dir: None,
            hostname: Some("sandbox".to_string()),
            uid_map: None,
            gid_map: None,
            env_vars: Vec::new(),
            clear_env: true,
            resource_limits: ResourceLimits::default(),
            strict_mode: false,
        }
    }
}

impl SandboxConfig {
    /// Create a new builder
    pub fn builder() -> SandboxConfigBuilder {
        SandboxConfigBuilder::new()
    }

    /// Create a minimal sandbox (namespaces only)
    pub fn minimal() -> Self {
        Self {
            enable_network_ns: false,
            enable_pid_ns: false,
            enable_mount_ns: true,
            enable_user_ns: true,
            enable_ipc_ns: false,
            enable_uts_ns: false,
            enable_cgroup_ns: false,
            drop_all_caps: false,
            ..Default::default()
        }
    }

    /// Create a strict sandbox (maximum isolation)
    pub fn strict() -> Self {
        Self {
            strict_mode: true,
            seccomp_default_action: SeccompAction::Kill,
            allowed_syscalls: vec![
                "read".to_string(),
                "write".to_string(),
                "exit".to_string(),
                "exit_group".to_string(),
                "brk".to_string(),
                "mmap".to_string(),
                "munmap".to_string(),
                "close".to_string(),
                "fstat".to_string(),
                "mprotect".to_string(),
                "arch_prctl".to_string(),
                "set_tid_address".to_string(),
                "set_robust_list".to_string(),
                "prlimit64".to_string(),
                "getrandom".to_string(),
                "rseq".to_string(),
                "futex".to_string(),
                "clone3".to_string(),
                "rt_sigprocmask".to_string(),
                "sigaltstack".to_string(),
                "newfstatat".to_string(),
            ],
            ..Default::default()
        }
    }
}

/// Builder for SandboxConfig
#[derive(Debug, Default)]
pub struct SandboxConfigBuilder {
    config: SandboxConfig,
}

impl SandboxConfigBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            config: SandboxConfig::default(),
        }
    }

    /// Enable or disable network namespace
    pub fn enable_network(mut self, enable: bool) -> Self {
        self.config.enable_network_ns = !enable; // Inverted: if network disabled, enable NS
        self
    }

    /// Enable or disable PID namespace
    pub fn enable_pid_ns(mut self, enable: bool) -> Self {
        self.config.enable_pid_ns = enable;
        self
    }

    /// Enable or disable mount namespace
    pub fn enable_mount_ns(mut self, enable: bool) -> Self {
        self.config.enable_mount_ns = enable;
        self
    }

    /// Enable or disable user namespace
    pub fn enable_user_ns(mut self, enable: bool) -> Self {
        self.config.enable_user_ns = enable;
        self
    }

    /// Set the new root filesystem
    pub fn new_root(mut self, path: impl Into<PathBuf>) -> Self {
        self.config.new_root = Some(path.into());
        self
    }

    /// Add a bind mount
    pub fn bind_mount(mut self, source: impl Into<PathBuf>, target: impl Into<PathBuf>) -> Self {
        self.config.bind_mounts.push((source.into(), target.into(), false));
        self
    }

    /// Add a readonly bind mount
    pub fn readonly_path(mut self, path: impl Into<PathBuf>) -> Self {
        let p = path.into();
        self.config.bind_mounts.push((p.clone(), p, true));
        self
    }

    /// Allow a syscall
    pub fn allow_syscall(mut self, name: &str) -> Self {
        self.config.allowed_syscalls.push(name.to_string());
        self
    }

    /// Deny a syscall
    pub fn deny_syscall(mut self, name: &str) -> Self {
        self.config.denied_syscalls.push(name.to_string());
        self
    }

    /// Set seccomp default action
    pub fn seccomp_action(mut self, action: SeccompAction) -> Self {
        self.config.seccomp_default_action = action;
        self
    }

    /// Keep a capability
    pub fn keep_capability(mut self, cap: Capability) -> Self {
        self.config.keep_capabilities.push(cap);
        self
    }

    /// Drop all capabilities
    pub fn drop_all_capabilities(mut self) -> Self {
        self.config.drop_all_caps = true;
        self
    }

    /// Set working directory
    pub fn working_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.config.working_dir = Some(path.into());
        self
    }

    /// Set hostname
    pub fn hostname(mut self, name: impl Into<String>) -> Self {
        self.config.hostname = Some(name.into());
        self
    }

    /// Add an environment variable
    pub fn env(mut self, key: &str, value: &str) -> Self {
        self.config.env_vars.push((key.to_string(), value.to_string()));
        self
    }

    /// Clear environment before running
    pub fn clear_env(mut self) -> Self {
        self.config.clear_env = true;
        self
    }

    /// Set resource limits
    pub fn resource_limits(mut self, limits: ResourceLimits) -> Self {
        self.config.resource_limits = limits;
        self
    }

    /// Enable strict mode
    pub fn strict(mut self) -> Self {
        self.config.strict_mode = true;
        self
    }

    /// Build the configuration
    pub fn build(self) -> SandboxConfig {
        self.config
    }
}

/// Resource limits for the sandbox
#[derive(Debug, Clone)]
pub struct ResourceLimits {
    /// Maximum CPU time (seconds)
    pub max_cpu_time: Option<u64>,
    /// Maximum memory (bytes)
    pub max_memory: Option<u64>,
    /// Maximum file size (bytes)
    pub max_file_size: Option<u64>,
    /// Maximum number of open files
    pub max_open_files: Option<u64>,
    /// Maximum number of processes
    pub max_processes: Option<u64>,
    /// Maximum stack size (bytes)
    pub max_stack_size: Option<u64>,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_cpu_time: Some(60),        // 1 minute
            max_memory: Some(256 * 1024 * 1024), // 256 MB
            max_file_size: Some(10 * 1024 * 1024), // 10 MB
            max_open_files: Some(64),
            max_processes: Some(16),
            max_stack_size: Some(8 * 1024 * 1024), // 8 MB
        }
    }
}

impl ResourceLimits {
    /// No limits
    pub fn none() -> Self {
        Self {
            max_cpu_time: None,
            max_memory: None,
            max_file_size: None,
            max_open_files: None,
            max_processes: None,
            max_stack_size: None,
        }
    }

    /// Apply resource limits using setrlimit
    pub fn apply(&self) -> SandboxResult<()> {
        use libc::{rlimit, setrlimit, RLIMIT_AS, RLIMIT_CPU, RLIMIT_FSIZE,
                   RLIMIT_NOFILE, RLIMIT_NPROC, RLIMIT_STACK, RLIM_INFINITY};

        fn set_limit(resource: i32, value: Option<u64>) -> SandboxResult<()> {
            if let Some(limit) = value {
                let rlim = rlimit {
                    rlim_cur: limit,
                    rlim_max: limit,
                };
                // SAFETY: setrlimit is safe to call with valid resource and rlimit struct
                let result = unsafe { setrlimit(resource as u32, &rlim) };
                if result != 0 {
                    return Err(SandboxError::ResourceLimit(
                        std::io::Error::last_os_error().to_string()
                    ));
                }
            }
            Ok(())
        }

        set_limit(RLIMIT_CPU as i32, self.max_cpu_time)?;
        set_limit(RLIMIT_AS as i32, self.max_memory)?;
        set_limit(RLIMIT_FSIZE as i32, self.max_file_size)?;
        set_limit(RLIMIT_NOFILE as i32, self.max_open_files)?;
        set_limit(RLIMIT_NPROC as i32, self.max_processes)?;
        set_limit(RLIMIT_STACK as i32, self.max_stack_size)?;

        Ok(())
    }
}

impl Sandbox {
    /// Create a new sandbox with the given configuration
    pub fn new(config: SandboxConfig) -> SandboxResult<Self> {
        Ok(Self { config })
    }

    /// Create a sandbox with default configuration
    pub fn default_sandbox() -> SandboxResult<Self> {
        Self::new(SandboxConfig::default())
    }

    /// Create a strict sandbox
    pub fn strict() -> SandboxResult<Self> {
        Self::new(SandboxConfig::strict())
    }

    /// Get the configuration
    pub fn config(&self) -> &SandboxConfig {
        &self.config
    }

    /// Run a closure in the sandbox
    ///
    /// This forks the process and applies sandbox restrictions to the child.
    pub fn run<F, T>(&self, f: F) -> SandboxResult<T>
    where
        F: FnOnce() -> T,
        T: Default,
    {
        use nix::sys::wait::{waitpid, WaitStatus};
        use nix::unistd::{fork, ForkResult};

        // Prepare namespace flags
        let ns_flags = self.build_namespace_flags();

        // Fork with namespaces
        // SAFETY: fork is generally safe, though care must be taken with locks
        match unsafe { fork() } {
            Ok(ForkResult::Parent { child }) => {
                // Wait for child
                match waitpid(child, None) {
                    Ok(WaitStatus::Exited(_, 0)) => Ok(T::default()),
                    Ok(WaitStatus::Exited(_, code)) => {
                        Err(SandboxError::ChildFailed(code))
                    }
                    Ok(WaitStatus::Signaled(_, signal, _)) => {
                        Err(SandboxError::ChildSignaled(signal as i32))
                    }
                    Ok(status) => {
                        Err(SandboxError::ChildFailed(-1))
                    }
                    Err(e) => Err(SandboxError::Fork(e.to_string())),
                }
            }
            Ok(ForkResult::Child) => {
                // Apply sandbox restrictions
                if let Err(e) = self.apply_restrictions() {
                    eprintln!("Sandbox setup failed: {}", e);
                    std::process::exit(1);
                }

                // Run the closure
                let _ = f();
                std::process::exit(0);
            }
            Err(e) => Err(SandboxError::Fork(e.to_string())),
        }
    }

    /// Run a command in the sandbox
    pub fn run_command(&self, program: &str, args: &[&str]) -> SandboxResult<i32> {
        use nix::sys::wait::{waitpid, WaitStatus};
        use nix::unistd::{execvp, fork, ForkResult};

        // SAFETY: fork is generally safe
        match unsafe { fork() } {
            Ok(ForkResult::Parent { child }) => {
                match waitpid(child, None) {
                    Ok(WaitStatus::Exited(_, code)) => Ok(code),
                    Ok(WaitStatus::Signaled(_, signal, _)) => Ok(128 + signal as i32),
                    _ => Ok(-1),
                }
            }
            Ok(ForkResult::Child) => {
                // Apply sandbox restrictions
                if let Err(e) = self.apply_restrictions() {
                    eprintln!("Sandbox setup failed: {}", e);
                    std::process::exit(1);
                }

                // Prepare arguments
                let program_cstr = CString::new(program).unwrap();
                let mut argv: Vec<CString> = vec![program_cstr.clone()];
                for arg in args {
                    argv.push(CString::new(*arg).unwrap());
                }

                // Execute
                match execvp(&program_cstr, &argv) {
                    Ok(_) => unreachable!(),
                    Err(e) => {
                        eprintln!("execvp failed: {}", e);
                        std::process::exit(127);
                    }
                }
            }
            Err(e) => Err(SandboxError::Fork(e.to_string())),
        }
    }

    /// Build namespace flags based on configuration
    fn build_namespace_flags(&self) -> nix::sched::CloneFlags {
        use nix::sched::CloneFlags;

        let mut flags = CloneFlags::empty();

        if self.config.enable_user_ns {
            flags |= CloneFlags::CLONE_NEWUSER;
        }
        if self.config.enable_mount_ns {
            flags |= CloneFlags::CLONE_NEWNS;
        }
        if self.config.enable_pid_ns {
            flags |= CloneFlags::CLONE_NEWPID;
        }
        if self.config.enable_network_ns {
            flags |= CloneFlags::CLONE_NEWNET;
        }
        if self.config.enable_ipc_ns {
            flags |= CloneFlags::CLONE_NEWIPC;
        }
        if self.config.enable_uts_ns {
            flags |= CloneFlags::CLONE_NEWUTS;
        }
        if self.config.enable_cgroup_ns {
            flags |= CloneFlags::CLONE_NEWCGROUP;
        }

        flags
    }

    /// Apply all sandbox restrictions
    fn apply_restrictions(&self) -> SandboxResult<()> {
        // 1. Apply resource limits first
        self.config.resource_limits.apply()?;

        // 2. Setup namespaces (already done if using clone, otherwise use unshare)
        if self.config.enable_user_ns {
            setup_user_namespace(
                self.config.uid_map,
                self.config.gid_map,
            )?;
        }

        // 3. Setup mount namespace and filesystem
        if self.config.enable_mount_ns {
            setup_mount_namespace(&self.config)?;
        }

        // 4. Set hostname
        if self.config.enable_uts_ns {
            if let Some(ref hostname) = self.config.hostname {
                nix::unistd::sethostname(hostname)?;
            }
        }

        // 5. Clear/set environment
        if self.config.clear_env {
            for (key, _) in std::env::vars() {
                std::env::remove_var(&key);
            }
        }
        for (key, value) in &self.config.env_vars {
            std::env::set_var(key, value);
        }

        // 6. Drop capabilities
        if self.config.drop_all_caps {
            drop_capabilities(&self.config.keep_capabilities)?;
        }

        // 7. Apply seccomp filter (must be last!)
        if !self.config.allowed_syscalls.is_empty() || !self.config.denied_syscalls.is_empty() {
            apply_seccomp_filter(
                &self.config.allowed_syscalls,
                &self.config.denied_syscalls,
                self.config.seccomp_default_action,
            )?;
        }

        Ok(())
    }
}

/// Get information about the current process's sandbox status
pub fn sandbox_status() -> SandboxStatus {
    SandboxStatus::current()
}

/// Information about the current sandbox state
#[derive(Debug)]
pub struct SandboxStatus {
    pub in_user_namespace: bool,
    pub in_pid_namespace: bool,
    pub in_mount_namespace: bool,
    pub seccomp_mode: u32,
    pub capabilities: Vec<Capability>,
    pub uid: u32,
    pub gid: u32,
}

impl SandboxStatus {
    /// Get the current sandbox status
    pub fn current() -> Self {
        use std::fs;

        // Check if in user namespace
        let in_user_namespace = fs::read_to_string("/proc/self/uid_map")
            .map(|s| !s.contains("4294967295"))
            .unwrap_or(false);

        // Check PID namespace
        let in_pid_namespace = nix::unistd::getpid().as_raw() == 1;

        // Check seccomp mode
        let seccomp_mode = fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|s| {
                s.lines()
                    .find(|l| l.starts_with("Seccomp:"))
                    .and_then(|l| l.split_whitespace().last())
                    .and_then(|v| v.parse().ok())
            })
            .unwrap_or(0);

        Self {
            in_user_namespace,
            in_pid_namespace,
            in_mount_namespace: false, // Hard to detect reliably
            seccomp_mode,
            capabilities: get_current_capabilities().unwrap_or_default(),
            uid: nix::unistd::getuid().as_raw(),
            gid: nix::unistd::getgid().as_raw(),
        }
    }
}

impl std::fmt::Display for SandboxStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Sandbox Status:")?;
        writeln!(f, "  User namespace: {}", self.in_user_namespace)?;
        writeln!(f, "  PID namespace: {}", self.in_pid_namespace)?;
        writeln!(f, "  Seccomp mode: {}", match self.seccomp_mode {
            0 => "disabled",
            1 => "strict",
            2 => "filter",
            _ => "unknown",
        })?;
        writeln!(f, "  UID/GID: {}/{}", self.uid, self.gid)?;
        writeln!(f, "  Capabilities: {}", self.capabilities.len())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_builder() {
        let config = SandboxConfig::builder()
            .enable_network(false)
            .enable_pid_ns(true)
            .hostname("test-sandbox")
            .allow_syscall("read")
            .allow_syscall("write")
            .build();

        assert!(config.enable_network_ns);
        assert!(config.enable_pid_ns);
        assert_eq!(config.hostname, Some("test-sandbox".to_string()));
        assert_eq!(config.allowed_syscalls.len(), 2);
    }

    #[test]
    fn test_minimal_config() {
        let config = SandboxConfig::minimal();
        assert!(!config.enable_network_ns);
        assert!(!config.enable_pid_ns);
        assert!(config.enable_mount_ns);
        assert!(config.enable_user_ns);
    }

    #[test]
    fn test_strict_config() {
        let config = SandboxConfig::strict();
        assert!(config.strict_mode);
        assert!(!config.allowed_syscalls.is_empty());
        assert!(matches!(config.seccomp_default_action, SeccompAction::Kill));
    }

    #[test]
    fn test_resource_limits() {
        let limits = ResourceLimits::default();
        assert!(limits.max_cpu_time.is_some());
        assert!(limits.max_memory.is_some());
    }

    #[test]
    fn test_sandbox_status() {
        let status = SandboxStatus::current();
        // Just verify it doesn't panic
        println!("{}", status);
    }
}
