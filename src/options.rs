#[cfg(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "freebsd",
    target_os = "netbsd",
    windows
))]
use crate::{Error, Result};

/// Atomic destination policy. Neither policy is an inode compare-and-swap.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Publication {
    /// Replace an absent or verified private destination.
    #[default]
    Replace,
    /// Fail atomically if any destination exists. Unsupported on NetBSD.
    CreateNew,
}

/// Requested data access. Metadata inspection remains mandatory at acquisition.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum FileAccess {
    #[default]
    Read,
    ReadWrite,
}

/// How a missing or existing directory entry is handled.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum FileCreation {
    #[default]
    Existing,
    CreateNew,
    OpenOrCreate,
}

/// When streaming I/O rechecks mutable security metadata.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Verification {
    /// Check before and after each read, write, flush, and seek.
    #[default]
    PerIo,
    /// Check at acquisition and explicit `verify`, `set_len`, and sync calls.
    /// The caller must bracket a logical transaction with `verify` and handle
    /// failures after I/O. Access changes during streaming are not detected.
    OnDemand,
}

/// Secure file acquisition. Existing objects are validated before truncation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OpenOptions {
    /// Native data access rights.
    pub access: FileAccess,
    /// Existing entries are verified without permission repair.
    pub creation: FileCreation,
    /// Resize to zero after validation; requires read/write access.
    pub truncate: bool,
    /// Streaming verification frequency; acquisition always verifies.
    pub verification: Verification,
}

impl OpenOptions {
    #[cfg(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "netbsd",
        windows
    ))]
    pub(crate) fn validate(self) -> Result<()> {
        if self.access == FileAccess::Read
            && (self.truncate || self.creation != FileCreation::Existing)
        {
            return Err(Error::UnsupportedPolicy {
                policy: "creation and truncation require read/write access",
            });
        }
        Ok(())
    }
}
