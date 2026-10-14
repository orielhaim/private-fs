#![doc = include_str!("../README.md")]
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(unsafe_code)]

#[cfg(all(
    test,
    any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "netbsd",
        windows
    )
))]
mod stress;

mod error;
#[cfg(all(
    test,
    any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "netbsd",
        windows
    )
))]
mod lifecycle_tests;
mod options;
pub use options::{FileAccess, FileCreation, OpenOptions, Publication, Verification};
#[cfg(any(target_os = "freebsd", target_os = "netbsd"))]
mod bsd;
#[cfg(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "freebsd",
    target_os = "netbsd",
    windows,
    test
))]
mod path;
#[cfg(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "freebsd",
    target_os = "netbsd"
))]
mod unix;
pub use error::{Error, Result};
#[cfg(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "freebsd",
    target_os = "netbsd"
))]
pub use unix::{PrivateDir, PrivateFile};

#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "freebsd",
    target_os = "netbsd",
    windows
)))]
mod unsupported;
#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "freebsd",
    target_os = "netbsd",
    windows
)))]
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
#[cfg(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "freebsd",
    target_os = "netbsd",
    windows
))]
mod atomic;
#[cfg(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "freebsd",
    target_os = "netbsd",
    windows
))]
pub use atomic::AtomicFile;

impl PrivateDir {
    /// Create and verify each component through retained private capabilities.
    /// Existing components are never hardened. A later failure can leave earlier
    /// private directories in place; the operation is not atomic or durable.
    pub fn ensure_dir_all(&self, path: impl AsRef<std::path::Path>) -> Result<Self> {
        #[cfg(any(
            target_os = "linux",
            target_os = "macos",
            target_os = "freebsd",
            target_os = "netbsd",
            windows
        ))]
        {
            let parts = path::RelativePath::new(path.as_ref())?;
            let mut names = parts.0.into_iter();
            let mut dir = self.ensure_dir(names.next().ok_or(Error::InvalidRelativePath)?)?;
            for name in names {
                dir = dir.ensure_dir(name)?;
            }
            Ok(dir)
        }
        #[cfg(not(any(
            target_os = "linux",
            target_os = "macos",
            target_os = "freebsd",
            target_os = "netbsd",
            windows
        )))]
        {
            let _ = path;
            Err(Error::UnsupportedFilesystem {
                capability: "native platform security backend",
            })
        }
    }
}

/// Verify current file privacy through the supplied handle, without mutation.
/// This cannot establish private creation, pathname history, or tree membership.
pub fn verify(file: &std::fs::File) -> Result<()> {
    #[cfg(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "netbsd"
    ))]
    {
        unix::verify_existing(file)
    }
    #[cfg(windows)]
    {
        windows::verify_existing(file)
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "netbsd",
        windows
    )))]
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
    #[cfg(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "netbsd"
    ))]
    {
        unix::harden_existing(file)
    }
    #[cfg(windows)]
    {
        windows::harden_existing(file)
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "netbsd",
        windows
    )))]
    {
        let _ = file;
        Err(Error::UnsupportedFilesystem {
            capability: "native file security",
        })
    }
}
