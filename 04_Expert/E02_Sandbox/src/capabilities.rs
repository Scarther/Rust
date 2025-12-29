//! # Linux Capabilities
//!
//! This module handles Linux capabilities for fine-grained privilege control.
//!
//! ## Overview
//!
//! Linux capabilities divide root privileges into distinct units:
//! - CAP_NET_BIND_SERVICE: Bind to ports < 1024
//! - CAP_SYS_ADMIN: Various administrative operations
//! - CAP_DAC_OVERRIDE: Bypass file permission checks
//! - etc.
//!
//! ## Capability Sets
//!
//! - Effective: Currently active capabilities
//! - Permitted: Capabilities that can be made effective
//! - Inheritable: Capabilities passed to exec'd processes
//! - Bounding: Upper limit on capabilities
//! - Ambient: Capabilities preserved across non-privileged exec

use std::collections::HashSet;
use std::fmt;

use crate::error::{SandboxError, SandboxResult};

/// Linux capability identifiers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum Capability {
    /// Bypass file read, write, and execute permission checks
    DacOverride = 1,
    /// Bypass file read permission checks
    DacReadSearch = 2,
    /// Bypass permission checks on operations that normally require the filesystem
    /// UID of the process to match the UID of the file
    Fowner = 3,
    /// Don't clear set-user-ID and set-group-ID mode bits when a file is modified
    Fsetid = 4,
    /// Bypass permission checks for sending signals
    Kill = 5,
    /// Modify user/group ID of process
    Setgid = 6,
    /// Modify user ID of process
    Setuid = 7,
    /// Allows a process to modify its effective capability set
    Setpcap = 8,
    /// Bypass permission checks on operations that normally require the filesystem
    LinuxImmutable = 9,
    /// Bind to ports below 1024
    NetBindService = 10,
    /// Allow broadcasting, multicast
    NetBroadcast = 11,
    /// Allow network administration
    NetAdmin = 12,
    /// Allow use of RAW sockets
    NetRaw = 13,
    /// Lock memory
    IpcLock = 14,
    /// Bypass permission checks for IPC
    IpcOwner = 15,
    /// Load/unload kernel modules
    SysModule = 16,
    /// Perform I/O port operations
    SysRawio = 17,
    /// Use chroot
    SysChroot = 18,
    /// Allow ptrace
    SysPtrace = 19,
    /// Perform process accounting
    SysPacct = 20,
    /// Perform various system administration operations
    SysAdmin = 21,
    /// Use reboot
    SysBoot = 22,
    /// Raise process nice, set nice for other processes
    SysNice = 23,
    /// Override resource limits
    SysResource = 24,
    /// Set system clock
    SysTime = 25,
    /// Perform tty configuration
    SysTtyConfig = 26,
    /// Allow the privileged aspects of mknod
    Mknod = 27,
    /// Allow taking of leases on files
    Lease = 28,
    /// Write to audit log
    AuditWrite = 29,
    /// Configure audit subsystem
    AuditControl = 30,
    /// Set file capabilities
    Setfcap = 31,
    /// Override MAC access
    MacOverride = 32,
    /// Allow MAC configuration
    MacAdmin = 33,
    /// Use kernel's syslog
    Syslog = 34,
    /// Trigger sleep
    WakeAlarm = 35,
    /// Block system suspend
    BlockSuspend = 36,
    /// Read audit log
    AuditRead = 37,
    /// Performance monitoring
    Perfmon = 38,
    /// BPF operations
    Bpf = 39,
    /// Checkpoint/restore
    CheckpointRestore = 40,
}

impl Capability {
    /// Get the capability number
    pub fn as_u32(&self) -> u32 {
        *self as u32
    }

    /// Try to create from number
    pub fn from_u32(n: u32) -> Option<Self> {
        match n {
            1 => Some(Capability::DacOverride),
            2 => Some(Capability::DacReadSearch),
            3 => Some(Capability::Fowner),
            4 => Some(Capability::Fsetid),
            5 => Some(Capability::Kill),
            6 => Some(Capability::Setgid),
            7 => Some(Capability::Setuid),
            8 => Some(Capability::Setpcap),
            9 => Some(Capability::LinuxImmutable),
            10 => Some(Capability::NetBindService),
            11 => Some(Capability::NetBroadcast),
            12 => Some(Capability::NetAdmin),
            13 => Some(Capability::NetRaw),
            14 => Some(Capability::IpcLock),
            15 => Some(Capability::IpcOwner),
            16 => Some(Capability::SysModule),
            17 => Some(Capability::SysRawio),
            18 => Some(Capability::SysChroot),
            19 => Some(Capability::SysPtrace),
            20 => Some(Capability::SysPacct),
            21 => Some(Capability::SysAdmin),
            22 => Some(Capability::SysBoot),
            23 => Some(Capability::SysNice),
            24 => Some(Capability::SysResource),
            25 => Some(Capability::SysTime),
            26 => Some(Capability::SysTtyConfig),
            27 => Some(Capability::Mknod),
            28 => Some(Capability::Lease),
            29 => Some(Capability::AuditWrite),
            30 => Some(Capability::AuditControl),
            31 => Some(Capability::Setfcap),
            32 => Some(Capability::MacOverride),
            33 => Some(Capability::MacAdmin),
            34 => Some(Capability::Syslog),
            35 => Some(Capability::WakeAlarm),
            36 => Some(Capability::BlockSuspend),
            37 => Some(Capability::AuditRead),
            38 => Some(Capability::Perfmon),
            39 => Some(Capability::Bpf),
            40 => Some(Capability::CheckpointRestore),
            _ => None,
        }
    }

    /// Get the capability name
    pub fn name(&self) -> &'static str {
        match self {
            Capability::DacOverride => "CAP_DAC_OVERRIDE",
            Capability::DacReadSearch => "CAP_DAC_READ_SEARCH",
            Capability::Fowner => "CAP_FOWNER",
            Capability::Fsetid => "CAP_FSETID",
            Capability::Kill => "CAP_KILL",
            Capability::Setgid => "CAP_SETGID",
            Capability::Setuid => "CAP_SETUID",
            Capability::Setpcap => "CAP_SETPCAP",
            Capability::LinuxImmutable => "CAP_LINUX_IMMUTABLE",
            Capability::NetBindService => "CAP_NET_BIND_SERVICE",
            Capability::NetBroadcast => "CAP_NET_BROADCAST",
            Capability::NetAdmin => "CAP_NET_ADMIN",
            Capability::NetRaw => "CAP_NET_RAW",
            Capability::IpcLock => "CAP_IPC_LOCK",
            Capability::IpcOwner => "CAP_IPC_OWNER",
            Capability::SysModule => "CAP_SYS_MODULE",
            Capability::SysRawio => "CAP_SYS_RAWIO",
            Capability::SysChroot => "CAP_SYS_CHROOT",
            Capability::SysPtrace => "CAP_SYS_PTRACE",
            Capability::SysPacct => "CAP_SYS_PACCT",
            Capability::SysAdmin => "CAP_SYS_ADMIN",
            Capability::SysBoot => "CAP_SYS_BOOT",
            Capability::SysNice => "CAP_SYS_NICE",
            Capability::SysResource => "CAP_SYS_RESOURCE",
            Capability::SysTime => "CAP_SYS_TIME",
            Capability::SysTtyConfig => "CAP_SYS_TTY_CONFIG",
            Capability::Mknod => "CAP_MKNOD",
            Capability::Lease => "CAP_LEASE",
            Capability::AuditWrite => "CAP_AUDIT_WRITE",
            Capability::AuditControl => "CAP_AUDIT_CONTROL",
            Capability::Setfcap => "CAP_SETFCAP",
            Capability::MacOverride => "CAP_MAC_OVERRIDE",
            Capability::MacAdmin => "CAP_MAC_ADMIN",
            Capability::Syslog => "CAP_SYSLOG",
            Capability::WakeAlarm => "CAP_WAKE_ALARM",
            Capability::BlockSuspend => "CAP_BLOCK_SUSPEND",
            Capability::AuditRead => "CAP_AUDIT_READ",
            Capability::Perfmon => "CAP_PERFMON",
            Capability::Bpf => "CAP_BPF",
            Capability::CheckpointRestore => "CAP_CHECKPOINT_RESTORE",
        }
    }

    /// All capabilities
    pub fn all() -> Vec<Self> {
        (1..=40).filter_map(Self::from_u32).collect()
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Capability set types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapSet {
    Effective,
    Permitted,
    Inheritable,
    Bounding,
    Ambient,
}

/// Get current process capabilities
pub fn get_current_capabilities() -> SandboxResult<Vec<Capability>> {
    // Read from /proc/self/status
    let status = std::fs::read_to_string("/proc/self/status")?;

    let mut caps = Vec::new();

    for line in status.lines() {
        if line.starts_with("CapEff:") {
            let hex = line.split_whitespace().nth(1).unwrap_or("0");
            let bits = u64::from_str_radix(hex, 16).unwrap_or(0);

            for i in 0..64 {
                if bits & (1 << i) != 0 {
                    if let Some(cap) = Capability::from_u32(i as u32) {
                        caps.push(cap);
                    }
                }
            }
            break;
        }
    }

    Ok(caps)
}

/// Check if current process has a capability
pub fn has_capability(cap: Capability) -> bool {
    get_current_capabilities()
        .map(|caps| caps.contains(&cap))
        .unwrap_or(false)
}

/// Drop all capabilities except those specified
pub fn drop_capabilities(keep: &[Capability]) -> SandboxResult<()> {
    use libc::{prctl, PR_CAPBSET_DROP, PR_CAP_AMBIENT_CLEAR_ALL, PR_CAP_AMBIENT};

    let keep_set: HashSet<_> = keep.iter().copied().collect();

    // Drop from bounding set
    for cap in Capability::all() {
        if !keep_set.contains(&cap) {
            // SAFETY: prctl with PR_CAPBSET_DROP is safe
            let result = unsafe { prctl(PR_CAPBSET_DROP, cap.as_u32() as libc::c_ulong, 0, 0, 0) };
            if result < 0 {
                let err = std::io::Error::last_os_error();
                // EINVAL means capability not supported, which is fine
                if err.raw_os_error() != Some(libc::EINVAL) {
                    tracing::warn!("Failed to drop {} from bounding set: {}", cap, err);
                }
            }
        }
    }

    // Clear ambient capabilities
    // SAFETY: prctl with PR_CAP_AMBIENT is safe
    unsafe { prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL as libc::c_ulong, 0, 0, 0) };

    // Clear effective and permitted sets by setting them to empty (or just keep)
    // This requires using capset syscall or the caps crate
    clear_cap_sets(keep)?;

    tracing::info!("Dropped all capabilities except: {:?}",
        keep.iter().map(|c| c.name()).collect::<Vec<_>>());

    Ok(())
}

/// Clear capability sets, keeping only specified capabilities
fn clear_cap_sets(keep: &[Capability]) -> SandboxResult<()> {
    // Using the caps crate for proper capability manipulation
    // This is a simplified version that uses prctl
    use libc::{prctl, PR_SET_KEEPCAPS};

    // Set PR_SET_KEEPCAPS so capabilities survive setuid
    // SAFETY: prctl with PR_SET_KEEPCAPS is safe
    let result = unsafe { prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) };
    if result < 0 {
        return Err(SandboxError::Capability(format!(
            "Failed to set PR_SET_KEEPCAPS: {}",
            std::io::Error::last_os_error()
        )));
    }

    // Build the capability bitmask to keep
    let mut cap_mask: u64 = 0;
    for cap in keep {
        cap_mask |= 1 << cap.as_u32();
    }

    // Use capset syscall directly
    #[repr(C)]
    struct CapUserHeader {
        version: u32,
        pid: i32,
    }

    #[repr(C)]
    struct CapUserData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }

    // Linux capability version 3 (for 64-bit capabilities)
    const _LINUX_CAPABILITY_VERSION_3: u32 = 0x20080522;

    // For version 3, we need two data structures
    let header = CapUserHeader {
        version: _LINUX_CAPABILITY_VERSION_3,
        pid: 0, // 0 means current process
    };

    let data = [
        CapUserData {
            effective: (cap_mask & 0xFFFFFFFF) as u32,
            permitted: (cap_mask & 0xFFFFFFFF) as u32,
            inheritable: 0,
        },
        CapUserData {
            effective: ((cap_mask >> 32) & 0xFFFFFFFF) as u32,
            permitted: ((cap_mask >> 32) & 0xFFFFFFFF) as u32,
            inheritable: 0,
        },
    ];

    // SAFETY: capset syscall with valid header and data
    let result = unsafe {
        libc::syscall(
            libc::SYS_capset,
            &header as *const CapUserHeader,
            &data as *const CapUserData,
        )
    };

    if result < 0 {
        return Err(SandboxError::Capability(format!(
            "capset failed: {}",
            std::io::Error::last_os_error()
        )));
    }

    Ok(())
}

/// Raise a capability in the ambient set
pub fn raise_ambient_capability(cap: Capability) -> SandboxResult<()> {
    use libc::{prctl, PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE};

    // SAFETY: prctl with PR_CAP_AMBIENT is safe
    let result = unsafe {
        prctl(
            PR_CAP_AMBIENT,
            PR_CAP_AMBIENT_RAISE as libc::c_ulong,
            cap.as_u32() as libc::c_ulong,
            0,
            0,
        )
    };

    if result < 0 {
        return Err(SandboxError::Capability(format!(
            "Failed to raise ambient capability {}: {}",
            cap,
            std::io::Error::last_os_error()
        )));
    }

    Ok(())
}

/// Check if capability operations are likely to succeed
pub fn can_modify_capabilities() -> bool {
    // Check if we have CAP_SETPCAP
    has_capability(Capability::Setpcap)
}

/// Print current capabilities for debugging
pub fn print_capabilities() {
    match get_current_capabilities() {
        Ok(caps) => {
            if caps.is_empty() {
                println!("No capabilities");
            } else {
                println!("Current capabilities:");
                for cap in caps {
                    println!("  - {}", cap);
                }
            }
        }
        Err(e) => {
            println!("Failed to get capabilities: {}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capability_conversion() {
        let cap = Capability::NetBindService;
        assert_eq!(cap.as_u32(), 10);
        assert_eq!(Capability::from_u32(10), Some(Capability::NetBindService));
    }

    #[test]
    fn test_capability_name() {
        assert_eq!(Capability::SysAdmin.name(), "CAP_SYS_ADMIN");
        assert_eq!(Capability::NetRaw.name(), "CAP_NET_RAW");
    }

    #[test]
    fn test_all_capabilities() {
        let all = Capability::all();
        assert!(!all.is_empty());
        assert!(all.contains(&Capability::SysAdmin));
    }

    #[test]
    fn test_get_current_capabilities() {
        // This should not panic
        let result = get_current_capabilities();
        assert!(result.is_ok());
    }
}
