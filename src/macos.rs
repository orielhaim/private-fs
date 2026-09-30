//! Darwin's extended ACL ABI, deliberately kept descriptor-only.
#![allow(unsafe_code)]
use crate::{Error, Result};
use std::{
    ffi::c_void,
    io,
    os::fd::{AsFd, AsRawFd},
    ptr::NonNull,
};

const ACL_TYPE_EXTENDED: i32 = 0x100;
const ACL_FIRST_ENTRY: i32 = 0;
// XNU's MNT_UNKNOWNPERMISSIONS is the compatibility name of this flag.
const MNT_UNKNOWNPERMISSIONS: u32 = libc::MNT_IGNORE_OWNERSHIP as u32;
unsafe extern "C" {
    fn acl_get_fd_np(fd: i32, kind: i32) -> *mut c_void;
    fn acl_set_fd_np(fd: i32, acl: *mut c_void, kind: i32) -> i32;
    fn acl_init(count: i32) -> *mut c_void;
    fn acl_valid(acl: *mut c_void) -> i32;
    fn acl_get_entry(acl: *mut c_void, entry_id: i32, entry: *mut *mut c_void) -> i32;
    fn acl_free(acl: *mut c_void) -> i32;
}
struct Acl(NonNull<c_void>);
impl Acl {
    fn from_raw(raw: *mut c_void) -> Result<Self> {
        NonNull::new(raw)
            .map(Self)
            .ok_or_else(|| acl_error(io::Error::last_os_error()))
    }
    fn get(fd: impl AsFd) -> Result<Self> {
        // SAFETY: a live borrowed descriptor; the returned allocation is owned.
        let raw = unsafe { acl_get_fd_np(fd.as_fd().as_raw_fd(), ACL_TYPE_EXTENDED) };
        if raw.is_null() {
            let error = io::Error::last_os_error();
            // Darwin's acl_get_fd_np returns NULL/ENOENT when fstatx_np succeeds
            // but FILESEC_ACL is absent. This specifically means no extended ACL;
            // unsupported inspection and all other failures remain errors.
            if error.raw_os_error() != Some(libc::ENOENT) {
                return Err(acl_error(error));
            }
            // SAFETY: represent the known absent ACL with a separately owned empty ACL.
            return Self::from_raw(unsafe { acl_init(0) });
        }
        Self::from_raw(raw)
    }
    fn is_empty(&self) -> Result<bool> {
        let mut entry = std::ptr::null_mut();
        // SAFETY: self owns a libc ACL allocation, and entry is a writable output.
        unsafe {
            if acl_valid(self.0.as_ptr()) != 0 {
                return Err(io::Error::last_os_error().into());
            }
            if acl_get_entry(self.0.as_ptr(), ACL_FIRST_ENTRY, &mut entry) == 0 {
                return Ok(false);
            }
        }
        let error = io::Error::last_os_error();
        // Darwin returns -1/EINVAL for index zero on a valid, empty ACL.
        if error.raw_os_error() == Some(libc::EINVAL) {
            Ok(true)
        } else {
            Err(error.into())
        }
    }
}
impl Drop for Acl {
    fn drop(&mut self) {
        // SAFETY: the allocation was returned by the matching ACL allocator.
        unsafe {
            acl_free(self.0.as_ptr());
        }
    }
}
fn acl_error(error: io::Error) -> Error {
    if error.raw_os_error() == Some(libc::ENOTSUP) {
        Error::UnsupportedFilesystem {
            capability: "descriptor-bound extended ACL inspection",
        }
    } else {
        error.into()
    }
}
pub(super) fn ownership(fd: impl AsFd) -> Result<()> {
    ownership_flags(rustix::fs::fstatfs(fd)?.f_flags)
}
fn ownership_flags(flags: u32) -> Result<()> {
    if flags & MNT_UNKNOWNPERMISSIONS != 0 {
        Err(Error::UnsupportedFilesystem {
            capability: "enforced Unix ownership",
        })
    } else {
        Ok(())
    }
}
pub(super) fn verify(fd: impl AsFd) -> Result<()> {
    ownership(fd.as_fd())?;
    verify_acl(fd)
}
pub(super) fn verify_acl(fd: impl AsFd) -> Result<()> {
    if !Acl::get(fd)?.is_empty()? {
        return Err(Error::InsecureAcl);
    }
    Ok(())
}
pub(super) fn clear(fd: impl AsFd) -> Result<()> {
    ownership(fd.as_fd())?;
    // SAFETY: acl_init returns a separately owned empty ACL.
    let empty = Acl::from_raw(unsafe { acl_init(0) })?;
    // SAFETY: both the descriptor and the ACL allocation remain live for the call.
    if unsafe { acl_set_fd_np(fd.as_fd().as_raw_fd(), empty.0.as_ptr(), ACL_TYPE_EXTENDED) } != 0 {
        return Err(acl_error(io::Error::last_os_error()));
    }
    verify(fd)
}
pub(super) fn creation_parent(fd: impl AsFd) -> Result<()> {
    // Unlike Windows, mkdirat has no security-descriptor argument. An empty
    // parent ACL cannot inject grants at birth. Require its owner to be our user
    // too, so a different principal cannot change its ACL between this check and
    // creation. Modes of acquisition ancestors are never changed.
    ownership(fd.as_fd())?;
    let stat = rustix::fs::fstat(fd.as_fd())?;
    let expected = rustix::process::geteuid().as_raw();
    if stat.st_uid != expected {
        return Err(Error::WrongOwner {
            expected,
            actual: stat.st_uid,
        });
    }
    verify_acl(fd)
}

#[cfg(test)]
mod tests;
