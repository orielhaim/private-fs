//! Owned SIDs and protected owner-only descriptors. No pathname ACL APIs.
#![allow(unsafe_code)]
use super::bindings::*;
use crate::{Error, Result};
use std::{
    ffi::c_void,
    io,
    mem::size_of,
    os::windows::io::{AsHandle, AsRawHandle, FromRawHandle, OwnedHandle},
    ptr,
};

#[derive(Clone, Debug)]
pub(super) struct Sid(Vec<u32>);
impl Sid {
    pub(super) fn process_user() -> Result<Self> {
        let mut token = ptr::null_mut();
        // SAFETY: a pseudo process handle and writable HANDLE output.
        bool_result(unsafe {
            OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY as u32, &mut token)
        })?;
        // SAFETY: OpenProcessToken succeeded and transferred a unique live handle.
        let token = unsafe { OwnedHandle::from_raw_handle(token) };
        let mut bytes = 0;
        // SAFETY: this is the documented size query with a null buffer.
        let result = unsafe {
            GetTokenInformation(
                token.as_raw_handle(),
                TokenUser,
                ptr::null_mut(),
                0,
                &mut bytes,
            )
        };
        if result != 0
            || io::Error::last_os_error().raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER)
        {
            return Err(io::Error::last_os_error().into());
        }
        if (bytes as usize) < size_of::<TOKEN_USER>() {
            return Err(Error::OwnerMismatch);
        }
        // Pointer-aligned storage: TOKEN_USER contains a pointer to the SID in it.
        let mut buffer = vec![0usize; (bytes as usize).div_ceil(size_of::<usize>())];
        // SAFETY: allocation is aligned and covers bytes; the token stays live.
        bool_result(unsafe {
            GetTokenInformation(
                token.as_raw_handle(),
                TokenUser,
                buffer.as_mut_ptr().cast(),
                bytes,
                &mut bytes,
            )
        })?;
        // SAFETY: the successful API filled TOKEN_USER at the aligned buffer start.
        unsafe { Self::copy_from((*(buffer.as_ptr().cast::<TOKEN_USER>())).User.Sid) }
    }
    pub(super) unsafe fn copy_from(sid: PSID) -> Result<Self> {
        // SAFETY: caller guarantees a live SID from the Windows security APIs.
        if sid.is_null() || unsafe { IsValidSid(sid) } == 0 {
            return Err(Error::OwnerMismatch);
        }
        // SAFETY: IsValidSid accepted the live SID.
        let bytes = unsafe { GetLengthSid(sid) };
        let mut copy = vec![0u32; (bytes as usize).div_ceil(size_of::<u32>())];
        // SAFETY: aligned destination covers bytes; source remains live.
        bool_result(unsafe { CopySid(bytes, copy.as_mut_ptr().cast(), sid) })?;
        Ok(Self(copy))
    }
    pub(super) fn as_ptr(&self) -> PSID {
        self.0.as_ptr().cast_mut().cast()
    }
}

pub(super) fn bool_result(result: BOOL) -> Result<()> {
    if result == 0 {
        Err(io::Error::last_os_error().into())
    } else {
        Ok(())
    }
}

pub(super) struct Descriptor<'a> {
    _sid: &'a Sid,
    _acl: Vec<u32>,
    descriptor: SECURITY_DESCRIPTOR,
}
impl<'a> Descriptor<'a> {
    pub(super) fn new(user: &'a Sid) -> Result<Self> {
        // SAFETY: user owns a valid SID copied from TokenUser.
        let bytes = size_of::<ACL>() + size_of::<ACCESS_ALLOWED_ACE>() - size_of::<u32>()
            + unsafe { GetLengthSid(user.as_ptr()) } as usize;
        let mut acl = vec![0u32; bytes.div_ceil(size_of::<u32>())];
        let acl_ptr = acl.as_mut_ptr().cast::<ACL>();
        let mut descriptor = SECURITY_DESCRIPTOR::default();
        let sd = (&mut descriptor as *mut SECURITY_DESCRIPTOR).cast();
        // SAFETY: writable, aligned allocations have the required sizes. All SID
        // and ACL references point to retained heap storage, never stack interiors.
        unsafe {
            bool_result(InitializeAcl(acl_ptr, bytes as u32, ACL_REVISION as u32))?;
            bool_result(AddAccessAllowedAceEx(
                acl_ptr,
                ACL_REVISION as u32,
                0,
                FILE_ALL_ACCESS as u32,
                user.as_ptr(),
            ))?;
            bool_result(InitializeSecurityDescriptor(
                sd,
                SECURITY_DESCRIPTOR_REVISION as u32,
            ))?;
            bool_result(SetSecurityDescriptorOwner(sd, user.as_ptr(), 0))?;
            bool_result(SetSecurityDescriptorDacl(sd, 1, acl_ptr, 0))?;
            bool_result(SetSecurityDescriptorControl(
                sd,
                SE_DACL_PROTECTED as u16,
                SE_DACL_PROTECTED as u16,
            ))?;
        }
        Ok(Self {
            _sid: user,
            _acl: acl,
            descriptor,
        })
    }
    pub(super) fn as_ptr(&mut self) -> PSECURITY_DESCRIPTOR {
        (&mut self.descriptor as *mut SECURITY_DESCRIPTOR).cast()
    }
}
struct SecurityInfo(PSECURITY_DESCRIPTOR);
impl Drop for SecurityInfo {
    fn drop(&mut self) {
        // SAFETY: GetSecurityInfo allocated the descriptor with LocalAlloc.
        unsafe {
            LocalFree(self.0);
        }
    }
}
pub(super) fn verify(handle: impl AsHandle, user: &Sid) -> Result<()> {
    inspect(handle, user, true)
}
fn inspect(handle: impl AsHandle, user: &Sid, check_acl: bool) -> Result<()> {
    let mut owner = ptr::null_mut();
    let mut acl = ptr::null_mut();
    let mut raw = ptr::null_mut();
    // SAFETY: live borrowed handle, matching writable outputs. Windows owns the
    // owner/ACL subobjects inside the returned self-relative descriptor.
    let error = unsafe {
        GetSecurityInfo(
            handle.as_handle().as_raw_handle(),
            SE_FILE_OBJECT,
            (OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION) as u32,
            &mut owner,
            ptr::null_mut(),
            &mut acl,
            ptr::null_mut(),
            &mut raw,
        )
    };
    if error != 0 {
        return Err(io::Error::from_raw_os_error(error as i32).into());
    }
    let info = SecurityInfo(raw);
    if raw.is_null() || owner.is_null() {
        return Err(Error::OwnerMismatch);
    }
    // SAFETY: owner belongs to info and user to the retained Sid allocation.
    if unsafe { IsValidSid(owner) == 0 || EqualSid(owner, user.as_ptr()) == 0 } {
        return Err(Error::OwnerMismatch);
    }
    if !check_acl {
        return Ok(());
    }
    let mut control = 0;
    let mut revision = 0;
    // SAFETY: initialized security descriptor and writable scalar outputs.
    bool_result(unsafe { GetSecurityDescriptorControl(info.0, &mut control, &mut revision) })?;
    if control & (SE_DACL_PROTECTED | SE_DACL_PRESENT) as u16
        != (SE_DACL_PROTECTED | SE_DACL_PRESENT) as u16
        || acl.is_null()
    {
        return Err(Error::InsecureAcl);
    }
    // SAFETY: a non-null ACL inside the successful GetSecurityInfo allocation.
    unsafe {
        if IsValidAcl(acl) == 0 || (*acl).AceCount != 1 {
            return Err(Error::InsecureAcl);
        }
        let mut raw_ace: *mut c_void = ptr::null_mut();
        bool_result(GetAce(acl, 0, &mut raw_ace))?;
        let header = &*raw_ace.cast::<ACE_HEADER>();
        let sid_offset = size_of::<ACCESS_ALLOWED_ACE>() - size_of::<u32>();
        if header.AceType != ACCESS_ALLOWED_ACE_TYPE as u8
            || header.AceFlags != 0
            || (header.AceSize as usize) < sid_offset + 8
        {
            return Err(Error::InsecureAcl);
        }
        let ace = &*raw_ace.cast::<ACCESS_ALLOWED_ACE>();
        if ace.Mask != FILE_ALL_ACCESS as u32 {
            return Err(Error::InsecureAcl);
        }
        // SID header is eight bytes; bound its variable subauthority count before
        // asking Windows to inspect it. GetAce and IsValidAcl bound the ACE itself.
        let sid_bytes = raw_ace.cast::<u8>().add(sid_offset);
        if 8 + usize::from(*sid_bytes.add(1)) * 4 != usize::from(header.AceSize) - sid_offset {
            return Err(Error::InsecureAcl);
        }
        let sid = (&ace.SidStart as *const u32).cast_mut().cast();
        if IsValidSid(sid) == 0
            || GetLengthSid(sid) as usize + size_of::<ACCESS_ALLOWED_ACE>() - size_of::<u32>()
                != ace.Header.AceSize as usize
            || EqualSid(sid, user.as_ptr()) == 0
        {
            return Err(Error::InsecureAcl);
        }
    }
    Ok(())
}

pub(super) fn harden(handle: impl AsHandle, user: &Sid) -> Result<()> {
    inspect(handle.as_handle(), user, false)?;
    let descriptor = Descriptor::new(user)?;
    // SAFETY: descriptor retains the ACL, handle remains live, and only the DACL
    // is changed. Owner mismatch must fail before mutation, never be repaired.
    let error = unsafe {
        SetSecurityInfo(
            handle.as_handle().as_raw_handle(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION as u32 | PROTECTED_DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            descriptor._acl.as_ptr().cast_mut().cast(),
            ptr::null(),
        )
    };
    if error != 0 {
        return Err(io::Error::from_raw_os_error(error as i32).into());
    }
    verify(handle, user)
}
