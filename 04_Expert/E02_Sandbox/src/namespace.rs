//! # Linux Namespaces
//!
//! This module handles Linux namespace operations:
//! - User namespace (UID/GID mapping)
//! - Mount namespace (filesystem isolation)
//! - PID namespace (process isolation)
//! - Network namespace (network isolation)
//! - IPC namespace (IPC isolation)
//! - UTS namespace (hostname isolation)
//!
//! ## Security Considerations
//!
//! - User namespaces allow unprivileged containerization
//! - Proper UID/GID mapping is critical for security
//! - Mount namespaces should be combined with pivot_root for isolation

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::Path;

use nix::sched::{unshare, CloneFlags};
use nix::sys::signal::Signal;

use crate::error::{SandboxError, SandboxResult};
use crate::SandboxConfig;

/// Namespace types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamespaceType {
    User,
    Mount,
    Pid,
    Network,
    Ipc,
    Uts,
    Cgroup,
}

impl NamespaceType {
    /// Get the clone flag for this namespace type
    pub fn clone_flag(&self) -> CloneFlags {
        match self {
            NamespaceType::User => CloneFlags::CLONE_NEWUSER,
            NamespaceType::Mount => CloneFlags::CLONE_NEWNS,
            NamespaceType::Pid => CloneFlags::CLONE_NEWPID,
            NamespaceType::Network => CloneFlags::CLONE_NEWNET,
            NamespaceType::Ipc => CloneFlags::CLONE_NEWIPC,
            NamespaceType::Uts => CloneFlags::CLONE_NEWUTS,
            NamespaceType::Cgroup => CloneFlags::CLONE_NEWCGROUP,
        }
    }

    /// Get the namespace file name in /proc/self/ns/
    pub fn ns_file(&self) -> &'static str {
        match self {
            NamespaceType::User => "user",
            NamespaceType::Mount => "mnt",
            NamespaceType::Pid => "pid",
            NamespaceType::Network => "net",
            NamespaceType::Ipc => "ipc",
            NamespaceType::Uts => "uts",
            NamespaceType::Cgroup => "cgroup",
        }
    }

    /// Check if this namespace type is supported
    pub fn is_supported(&self) -> bool {
        let path = format!("/proc/self/ns/{}", self.ns_file());
        Path::new(&path).exists()
    }
}

/// Information about a namespace
#[derive(Debug, Clone)]
pub struct NamespaceInfo {
    pub ns_type: NamespaceType,
    pub inode: u64,
}

impl NamespaceInfo {
    /// Get namespace info for the current process
    pub fn current(ns_type: NamespaceType) -> SandboxResult<Self> {
        let path = format!("/proc/self/ns/{}", ns_type.ns_file());
        let metadata = fs::metadata(&path)?;

        // Get inode from metadata
        use std::os::unix::fs::MetadataExt;
        let inode = metadata.ino();

        Ok(Self { ns_type, inode })
    }
}

/// Unshare into new namespaces
///
/// This creates new namespaces and moves the calling process into them.
///
/// # Arguments
/// * `flags` - CloneFlags specifying which namespaces to create
///
/// # Security
/// - User namespace must be created first for unprivileged operation
/// - Some combinations require specific ordering
pub fn unshare_namespaces(flags: CloneFlags) -> SandboxResult<()> {
    unshare(flags).map_err(|e| {
        SandboxError::NamespaceUnshare(format!(
            "Failed to unshare: {} (flags: {:?})",
            e, flags
        ))
    })
}

/// Setup user namespace with UID/GID mappings
///
/// # Arguments
/// * `uid_map` - Tuple of (inside_uid, outside_uid, count)
/// * `gid_map` - Tuple of (inside_gid, outside_gid, count)
///
/// # Security
/// - Mappings define how UIDs appear inside vs outside the namespace
/// - Only one mapping line is allowed for unprivileged users
pub fn setup_user_namespace(
    uid_map: Option<(u32, u32, u32)>,
    gid_map: Option<(u32, u32, u32)>,
) -> SandboxResult<()> {
    // Get current UID/GID before namespace changes
    let current_uid = nix::unistd::getuid().as_raw();
    let current_gid = nix::unistd::getgid().as_raw();

    // Default mappings: map current user to root inside namespace
    let (inner_uid, outer_uid, uid_count) = uid_map.unwrap_or((0, current_uid, 1));
    let (inner_gid, outer_gid, gid_count) = gid_map.unwrap_or((0, current_gid, 1));

    // Create new user namespace
    unshare_namespaces(CloneFlags::CLONE_NEWUSER)?;

    // Write deny to setgroups (required before writing gid_map as unprivileged user)
    write_file("/proc/self/setgroups", "deny")?;

    // Write UID mapping
    let uid_map_content = format!("{} {} {}\n", inner_uid, outer_uid, uid_count);
    write_file("/proc/self/uid_map", &uid_map_content)?;

    // Write GID mapping
    let gid_map_content = format!("{} {} {}\n", inner_gid, outer_gid, gid_count);
    write_file("/proc/self/gid_map", &gid_map_content)?;

    Ok(())
}

/// Setup mount namespace with proper isolation
pub fn setup_mount_namespace(config: &SandboxConfig) -> SandboxResult<()> {
    use nix::mount::{mount, MsFlags};

    // Create new mount namespace
    unshare_namespaces(CloneFlags::CLONE_NEWNS)?;

    // Make all mounts private (prevent propagation)
    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None::<&str>,
    ).map_err(|e| SandboxError::Mount(format!("Failed to make mounts private: {}", e)))?;

    // Apply bind mounts
    for (source, target, readonly) in &config.bind_mounts {
        apply_bind_mount(source, target, *readonly)?;
    }

    // If new root is specified, perform pivot_root
    if let Some(ref new_root) = config.new_root {
        perform_pivot_root(new_root)?;
    }

    Ok(())
}

/// Apply a bind mount
fn apply_bind_mount(
    source: &Path,
    target: &Path,
    readonly: bool,
) -> SandboxResult<()> {
    use nix::mount::{mount, MsFlags};

    // Create target if it doesn't exist
    if source.is_dir() {
        fs::create_dir_all(target)?;
    } else if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)?;
        if !target.exists() {
            File::create(target)?;
        }
    }

    // Bind mount
    mount(
        Some(source),
        target,
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REC,
        None::<&str>,
    ).map_err(|e| SandboxError::Mount(format!(
        "Failed to bind mount {:?} -> {:?}: {}",
        source, target, e
    )))?;

    // Remount readonly if requested
    if readonly {
        mount(
            None::<&str>,
            target,
            None::<&str>,
            MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY,
            None::<&str>,
        ).map_err(|e| SandboxError::Mount(format!(
            "Failed to remount {:?} readonly: {}",
            target, e
        )))?;
    }

    Ok(())
}

/// Perform pivot_root to change the root filesystem
///
/// This is more secure than chroot as it properly isolates the old root.
fn perform_pivot_root(new_root: &Path) -> SandboxResult<()> {
    use nix::mount::{mount, umount2, MntFlags, MsFlags};
    use std::os::unix::ffi::OsStrExt;

    // Ensure new_root is a mount point
    mount(
        Some(new_root),
        new_root,
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REC,
        None::<&str>,
    ).map_err(|e| SandboxError::Mount(format!(
        "Failed to bind mount new root: {}",
        e
    )))?;

    // Create old_root directory inside new_root
    let old_root = new_root.join("old_root");
    fs::create_dir_all(&old_root)?;

    // Pivot root
    nix::unistd::pivot_root(new_root, &old_root).map_err(|e| {
        SandboxError::PivotRoot(format!("pivot_root failed: {}", e))
    })?;

    // Change to new root
    std::env::set_current_dir("/")?;

    // Unmount old root
    umount2("/old_root", MntFlags::MNT_DETACH).map_err(|e| {
        SandboxError::Mount(format!("Failed to unmount old root: {}", e))
    })?;

    // Remove old_root directory
    fs::remove_dir("/old_root").ok(); // Ignore errors

    Ok(())
}

/// Clone with namespaces using raw syscall
///
/// This provides more control than fork+unshare.
///
/// # Safety
/// This function uses unsafe system calls for process creation.
#[allow(unused)]
pub fn clone_with_namespaces<F>(
    flags: CloneFlags,
    child_fn: F,
) -> SandboxResult<nix::unistd::Pid>
where
    F: FnOnce() -> i32,
{
    use libc::{c_int, c_void, SIGCHLD};
    use std::ptr;

    const STACK_SIZE: usize = 1024 * 1024; // 1 MB stack

    // Allocate stack for child
    let mut stack = vec![0u8; STACK_SIZE];
    let stack_top = stack.as_mut_ptr().wrapping_add(STACK_SIZE);

    // Wrapper function for clone
    extern "C" fn child_wrapper<F>(arg: *mut c_void) -> c_int
    where
        F: FnOnce() -> i32,
    {
        // SAFETY: We pass a valid Box<F> pointer
        let f = unsafe { Box::from_raw(arg as *mut F) };
        f()
    }

    // Box the closure
    let boxed_fn = Box::new(child_fn);
    let fn_ptr = Box::into_raw(boxed_fn) as *mut c_void;

    // Combine flags with SIGCHLD
    let clone_flags = flags.bits() as c_int | SIGCHLD;

    // SAFETY: clone is unsafe but we provide valid arguments
    let pid = unsafe {
        libc::clone(
            child_wrapper::<F>,
            stack_top as *mut c_void,
            clone_flags,
            fn_ptr,
        )
    };

    if pid < 0 {
        // Clean up the boxed function on error
        unsafe { drop(Box::from_raw(fn_ptr as *mut F)); }
        return Err(SandboxError::Clone(format!(
            "clone failed: {}",
            std::io::Error::last_os_error()
        )));
    }

    Ok(nix::unistd::Pid::from_raw(pid))
}

/// Enter an existing namespace
pub fn enter_namespace(ns_type: NamespaceType, pid: i32) -> SandboxResult<()> {
    use std::os::unix::io::AsRawFd;

    let path = format!("/proc/{}/ns/{}", pid, ns_type.ns_file());
    let file = File::open(&path)?;

    // SAFETY: setns with a valid file descriptor is safe
    let result = unsafe { libc::setns(file.as_raw_fd(), ns_type.clone_flag().bits() as i32) };

    if result < 0 {
        return Err(SandboxError::NamespaceCreation(format!(
            "setns failed: {}",
            std::io::Error::last_os_error()
        )));
    }

    Ok(())
}

/// Helper function to write to a file
fn write_file(path: &str, content: &str) -> SandboxResult<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(|e| SandboxError::Io(e))?;

    file.write_all(content.as_bytes())
        .map_err(|e| SandboxError::Io(e))?;

    Ok(())
}

/// Get all namespace types
pub fn all_namespace_types() -> Vec<NamespaceType> {
    vec![
        NamespaceType::User,
        NamespaceType::Mount,
        NamespaceType::Pid,
        NamespaceType::Network,
        NamespaceType::Ipc,
        NamespaceType::Uts,
        NamespaceType::Cgroup,
    ]
}

/// Check which namespaces are supported on this system
pub fn supported_namespaces() -> Vec<NamespaceType> {
    all_namespace_types()
        .into_iter()
        .filter(|ns| ns.is_supported())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_namespace_types() {
        assert_eq!(NamespaceType::User.ns_file(), "user");
        assert_eq!(NamespaceType::Mount.ns_file(), "mnt");
        assert_eq!(NamespaceType::Pid.ns_file(), "pid");
    }

    #[test]
    fn test_supported_namespaces() {
        let supported = supported_namespaces();
        // At minimum, user namespace should be supported on modern kernels
        assert!(!supported.is_empty());
    }

    #[test]
    fn test_namespace_info() {
        // This should work even without privileges
        if NamespaceType::User.is_supported() {
            let info = NamespaceInfo::current(NamespaceType::User);
            assert!(info.is_ok());
        }
    }
}
