//! FreeBSD 15.1+ and NetBSD 11.0+ descriptor ACL boundary.
#![allow(unsafe_code)]
use crate::{Error, Result};
use std::{
    ffi::c_void,
    io,
    os::fd::{AsFd, AsRawFd},
    ptr::NonNull,
};

const ACCESS: i32 = 2;
const DEFAULT: i32 = 3;
const NFS4: i32 = 4;
#[cfg(target_os = "freebsd")]
const PC_NFS4: i32 = libc::_PC_ACL_NFS4;
#[cfg(target_os = "netbsd")]
const PC_NFS4: i32 = 17;

unsafe extern "C" {
    fn acl_get_fd_np(fd: i32, kind: i32) -> *mut c_void;
    fn acl_set_fd_np(fd: i32, acl: *mut c_void, kind: i32) -> i32;
    fn acl_delete_fd_np(fd: i32, kind: i32) -> i32;
    fn acl_is_trivial_np(acl: *mut c_void, trivial: *mut i32) -> i32;
    fn acl_get_entry(acl: *mut c_void, which: i32, entry: *mut *mut c_void) -> i32;
    fn acl_strip_np(acl: *mut c_void, recalculate_mask: i32) -> *mut c_void;
    fn acl_free(acl: *mut c_void) -> i32;
}

#[cfg(target_os = "freebsd")]
unsafe extern "C" {
    fn funlinkat(parent: i32, name: *const libc::c_char, file: i32, flags: i32) -> i32;
    fn renameat2(
        from: i32,
        name: *const libc::c_char,
        to: i32,
        target: *const libc::c_char,
        flags: libc::c_uint,
    ) -> i32;
}

#[cfg(target_os = "freebsd")]
pub(super) fn unlink(parent: impl AsFd, name: &std::ffi::OsStr, file: impl AsFd) -> Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let name = std::ffi::CString::new(name.as_bytes()).map_err(|_| Error::InvalidRelativePath)?;
    // SAFETY: live parent and target descriptors and a NUL-terminated name.
    let result = unsafe {
        funlinkat(
            parent.as_fd().as_raw_fd(),
            name.as_ptr(),
            file.as_fd().as_raw_fd(),
            libc::AT_RESOLVE_BENEATH,
        )
    };
    if result != 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EDEADLK) {
        return Err(Error::IdentityChanged);
    }
    check(result)
}

#[cfg(target_os = "freebsd")]
pub(super) fn publish_new(
    parent: impl AsFd,
    name: &std::ffi::OsStr,
    target: &std::ffi::OsStr,
) -> Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let name = std::ffi::CString::new(name.as_bytes()).map_err(|_| Error::InvalidRelativePath)?;
    let target =
        std::ffi::CString::new(target.as_bytes()).map_err(|_| Error::InvalidRelativePath)?;
    let fd = parent.as_fd().as_raw_fd();
    // SAFETY: retained parent and live validated single-component names. FreeBSD 15.1 AT_RENAME_NOREPLACE is 1.
    check(unsafe { renameat2(fd, name.as_ptr(), fd, target.as_ptr(), 1) })
}

struct Acl(NonNull<c_void>);
impl Acl {
    fn owned(raw: *mut c_void) -> Result<Self> {
        NonNull::new(raw)
            .map(Self)
            .ok_or_else(|| io::Error::last_os_error().into())
    }
    fn get(fd: impl AsFd, kind: i32) -> Result<Self> {
        // SAFETY: live descriptor; successful retrieval transfers an ACL allocation.
        Self::owned(unsafe { acl_get_fd_np(fd.as_fd().as_raw_fd(), kind) })
    }
    fn trivial(&self) -> Result<()> {
        let mut trivial = 0;
        // SAFETY: owned ACL and writable scalar output.
        check(unsafe { acl_is_trivial_np(self.0.as_ptr(), &mut trivial) })?;
        if trivial != 1 {
            return Err(Error::InsecureAcl);
        }
        Ok(())
    }
    fn empty(&self) -> Result<()> {
        let mut entry = std::ptr::null_mut();
        // SAFETY: owned ACL and writable entry output. BSD returns 0 at end.
        match unsafe { acl_get_entry(self.0.as_ptr(), 0, &mut entry) } {
            0 => Ok(()),
            1 => Err(Error::InsecureAcl),
            _ => Err(io::Error::last_os_error().into()),
        }
    }
}
impl Drop for Acl {
    fn drop(&mut self) {
        // SAFETY: allocation came from the matching libc ACL allocator.
        unsafe {
            acl_free(self.0.as_ptr());
        }
    }
}
fn check(result: i32) -> Result<()> {
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error().into())
    }
}
fn option(fd: impl AsFd, name: i32) -> Result<bool> {
    // SAFETY: this thread's errno slot is writable and lives for the native call.
    #[cfg(target_os = "freebsd")]
    unsafe {
        *libc::__error() = 0;
    }
    #[cfg(target_os = "netbsd")]
    unsafe {
        *libc::__errno() = 0;
    }
    // SAFETY: a live descriptor and a platform-defined pathconf selector.
    match unsafe { libc::fpathconf(fd.as_fd().as_raw_fd(), name) } {
        0 => Ok(false),
        1 => Ok(true),
        -1 => {
            let error = io::Error::last_os_error();
            if matches!(
                error.raw_os_error(),
                Some(0 | libc::EINVAL | libc::EOPNOTSUPP)
            ) {
                Err(Error::UnsupportedFilesystem {
                    capability: "unambiguous BSD ACL model reporting",
                })
            } else {
                Err(error.into())
            }
        }
        _ => Err(Error::UnsupportedFilesystem {
            capability: "unambiguous BSD ACL model reporting",
        }),
    }
}
fn model(fd: impl AsFd) -> Result<Option<i32>> {
    supported_kernel()?;
    match (
        option(fd.as_fd(), libc::_PC_ACL_EXTENDED)?,
        option(fd, PC_NFS4)?,
    ) {
        (false, false) => Ok(None),
        (true, false) => Ok(Some(ACCESS)),
        (false, true) => Ok(Some(NFS4)),
        (true, true) => Err(Error::UnsupportedFilesystem {
            capability: "unambiguous BSD ACL model",
        }),
    }
}
pub(super) fn verify(fd: impl AsFd, directory: bool) -> Result<()> {
    #[cfg(target_os = "freebsd")]
    if directory {
        static CONTAINMENT: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        if !*CONTAINMENT.get_or_init(|| {
            let raw = fd.as_fd().as_raw_fd();
            // SAFETY: no AT_REMOVEDIR, so this directory probe cannot remove any
            // object. Patched kernels must reject escape before inode comparison.
            (unsafe {
                funlinkat(
                    raw,
                    c"../.private-fs-containment-probe".as_ptr(),
                    raw,
                    libc::AT_RESOLVE_BENEATH,
                )
            }) == -1
                && io::Error::last_os_error().raw_os_error() == Some(libc::ENOTCAPABLE)
        }) {
            return Err(Error::UnsupportedFilesystem {
                capability: "patched FreeBSD funlinkat containment",
            });
        }
    }
    if let Some(kind) = model(fd.as_fd())? {
        Acl::get(fd.as_fd(), kind)?.trivial()?;
        if directory && kind == ACCESS {
            Acl::get(fd, DEFAULT)?.empty()?;
        }
    }
    Ok(())
}

fn supported_kernel() -> Result<()> {
    static SUPPORTED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    if !*SUPPORTED.get_or_init(|| {
        let mut system = std::mem::MaybeUninit::<libc::utsname>::uninit();
        // SAFETY: uname initializes the complete structure on success.
        if unsafe { libc::uname(system.as_mut_ptr()) } != 0 {
            return false;
        }
        // SAFETY: successful uname supplies a NUL-terminated release field.
        let system = unsafe { system.assume_init() };
        let release = unsafe { std::ffi::CStr::from_ptr(system.release.as_ptr()) };
        let Ok(release) = release.to_str() else {
            return false;
        };
        let mut version = release.split(['.', '-']);
        let Some(major) = version.next().and_then(|v| v.parse::<u32>().ok()) else {
            return false;
        };
        let Some(minor) = version.next().and_then(|v| v.parse::<u32>().ok()) else {
            return false;
        };
        #[cfg(target_os = "freebsd")]
        {
            (major, minor) >= (15, 1)
        }
        #[cfg(target_os = "netbsd")]
        {
            (major, minor) >= (11, 0)
        }
    }) {
        return Err(Error::UnsupportedFilesystem {
            capability: "supported BSD kernel release",
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests;
pub(super) fn creation_parent(fd: impl AsFd) -> Result<()> {
    // Trivial NFSv4 ACLs contain no inheritance rules; POSIX defaults must be empty.
    verify(fd, true)
}
pub(super) fn harden(fd: impl AsFd, directory: bool) -> Result<()> {
    if let Some(kind) = model(fd.as_fd())? {
        let current = Acl::get(fd.as_fd(), kind)?;
        // SAFETY: valid owned ACL; strip returns an independent mode-equivalent ACL.
        let stripped = Acl::owned(unsafe { acl_strip_np(current.0.as_ptr(), 0) })?;
        // SAFETY: descriptor and ACL remain live; only this object's ACL is changed.
        check(unsafe { acl_set_fd_np(fd.as_fd().as_raw_fd(), stripped.0.as_ptr(), kind) })?;
        if directory && kind == ACCESS {
            // SAFETY: delete the default ACL of the retained directory descriptor.
            check(unsafe { acl_delete_fd_np(fd.as_fd().as_raw_fd(), DEFAULT) })?;
        }
    }
    verify(fd, directory)
}
