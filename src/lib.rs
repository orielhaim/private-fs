#![doc = include_str!("../README.md")]
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(unsafe_code)]

#[cfg(all(test, any(target_os = "linux", target_os = "macos", windows)))]
mod stress;

mod error;
#[cfg(any(target_os = "linux", target_os = "macos", windows, test))]
mod path;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod unix;
pub use error::{Error, Result};
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub use unix::{PrivateDir, PrivateFile};

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
mod unsupported;
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
pub use unsupported::{AtomicFile, PrivateDir, PrivateFile};

#[cfg(target_os = "macos")]
mod macos;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::{PrivateDir, PrivateFile};

/// Requested persistence, independently of private access and atomic visibility.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Durability {
    /// No explicit sync. Visibility is atomic, but power loss may discard it.
    #[default]
    None,
    /// Sync file data after linking and before publication; no directory sync.
    Data,
    /// Sync file contents/metadata before publication and its directory afterward.
    /// On macOS this also requests F_FULLFSYNC; unsupported flushes are errors.
    Full,
}
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
mod atomic;
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
pub use atomic::AtomicFile;

/// Verify current file privacy through the supplied handle, without mutation.
/// This cannot establish private creation, pathname history, or tree membership.
pub fn verify(file: &std::fs::File) -> Result<()> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        unix::verify_existing(file)
    }
    #[cfg(windows)]
    {
        windows::verify_existing(file)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        let _ = file;
        Err(Error::UnsupportedFilesystem {
            capability: "native file security",
        })
    }
}
/// Secure the exact supplied file object without path lookup, then revalidate.
/// Refuses unexpected owners, object kinds, and link counts. Existing exposure
/// cannot be undone; this does not adopt the object into a private tree.
pub fn harden(file: &std::fs::File) -> Result<()> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        unix::harden_existing(file)
    }
    #[cfg(windows)]
    {
        windows::harden_existing(file)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        let _ = file;
        Err(Error::UnsupportedFilesystem {
            capability: "native file security",
        })
    }
}
