//! # Sandbox Error Types
//!
//! Comprehensive error handling for sandbox operations.

use thiserror::Error;

/// Main error type for sandbox operations
#[derive(Error, Debug)]
pub enum SandboxError {
    /// Namespace creation failed
    #[error("Failed to create namespace: {0}")]
    NamespaceCreation(String),

    /// Namespace unshare failed
    #[error("Failed to unshare namespace: {0}")]
    NamespaceUnshare(String),

    /// User namespace setup failed
    #[error("User namespace setup failed: {0}")]
    UserNamespace(String),

    /// Mount operation failed
    #[error("Mount operation failed: {0}")]
    Mount(String),

    /// Pivot root failed
    #[error("Pivot root failed: {0}")]
    PivotRoot(String),

    /// Chroot failed
    #[error("Chroot failed: {0}")]
    Chroot(String),

    /// Seccomp setup failed
    #[error("Seccomp setup failed: {0}")]
    Seccomp(String),

    /// Invalid seccomp rule
    #[error("Invalid seccomp rule: {0}")]
    SeccompRule(String),

    /// Capability operation failed
    #[error("Capability operation failed: {0}")]
    Capability(String),

    /// Resource limit setup failed
    #[error("Resource limit setup failed: {0}")]
    ResourceLimit(String),

    /// Fork failed
    #[error("Fork failed: {0}")]
    Fork(String),

    /// Clone failed
    #[error("Clone failed: {0}")]
    Clone(String),

    /// Child process failed with exit code
    #[error("Child process failed with exit code: {0}")]
    ChildFailed(i32),

    /// Child process was killed by signal
    #[error("Child process killed by signal: {0}")]
    ChildSignaled(i32),

    /// Exec failed
    #[error("Exec failed: {0}")]
    Exec(String),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Nix error
    #[error("System error: {0}")]
    Nix(#[from] nix::Error),

    /// Path error
    #[error("Invalid path: {0}")]
    Path(String),

    /// Permission denied
    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    /// Feature not available
    #[error("Feature not available: {0}")]
    NotAvailable(String),

    /// Configuration error
    #[error("Configuration error: {0}")]
    Config(String),
}

/// Result type alias
pub type SandboxResult<T> = Result<T, SandboxError>;

impl SandboxError {
    /// Check if this error indicates insufficient privileges
    pub fn is_permission_error(&self) -> bool {
        matches!(self, SandboxError::PermissionDenied(_))
            || match self {
                SandboxError::Nix(nix::Error::EPERM) => true,
                SandboxError::Nix(nix::Error::EACCES) => true,
                SandboxError::Io(e) => {
                    e.kind() == std::io::ErrorKind::PermissionDenied
                }
                _ => false,
            }
    }

    /// Check if this is a namespace-related error
    pub fn is_namespace_error(&self) -> bool {
        matches!(
            self,
            SandboxError::NamespaceCreation(_)
                | SandboxError::NamespaceUnshare(_)
                | SandboxError::UserNamespace(_)
        )
    }

    /// Get a user-friendly suggestion for fixing the error
    pub fn suggestion(&self) -> Option<&'static str> {
        match self {
            SandboxError::PermissionDenied(_) => Some(
                "Try running with root privileges or enable user namespaces"
            ),
            SandboxError::NamespaceCreation(_) => Some(
                "Ensure the kernel supports namespaces and they are enabled"
            ),
            SandboxError::UserNamespace(_) => Some(
                "Check /proc/sys/kernel/unprivileged_userns_clone is set to 1"
            ),
            SandboxError::Seccomp(_) => Some(
                "Ensure the kernel has seccomp support enabled"
            ),
            SandboxError::Mount(_) => Some(
                "Mount operations may require CAP_SYS_ADMIN or user namespace"
            ),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = SandboxError::Seccomp("test error".to_string());
        assert!(err.to_string().contains("Seccomp"));
        assert!(err.to_string().contains("test error"));
    }

    #[test]
    fn test_permission_check() {
        let err = SandboxError::PermissionDenied("test".to_string());
        assert!(err.is_permission_error());

        let err = SandboxError::Nix(nix::Error::EPERM);
        assert!(err.is_permission_error());
    }

    #[test]
    fn test_suggestion() {
        let err = SandboxError::PermissionDenied("test".to_string());
        assert!(err.suggestion().is_some());

        let err = SandboxError::ChildFailed(1);
        assert!(err.suggestion().is_none());
    }
}
