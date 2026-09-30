#![allow(unsafe_code)]
use super::*;
use bindings::*;
use security::bool_result;
use std::{
    mem::size_of,
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle},
    },
    ptr,
};
fn fixture() -> (tempfile::TempDir, PrivateDir) {
    let temp = tempfile::tempdir().unwrap();
    let dir = PrivateDir::ensure(temp.path().join("private")).unwrap();
    (temp, dir)
}

#[test]
fn classic_publication_fallback_is_atomic_handle_relative_and_keeps_identity() {
    let (temp, dir) = fixture();
    dir.create("data").unwrap().write_all(b"old").unwrap();
    let mut staging = dir.create("staging").unwrap();
    staging.write_all(b"complete-new").unwrap();
    nt::rename_classic(&staging.file, &dir.handle, OsStr::new("data")).unwrap();
    let published = dir.open_file("data").unwrap();
    assert!(published.same_object(&staging));
    published.verify().unwrap();
    staging.verify().unwrap();
    assert_eq!(
        std::fs::read(temp.path().join("private/data")).unwrap(),
        b"complete-new"
    );
    assert!(!temp.path().join("private/staging").exists());
}

#[test]
fn reparse_and_directory_replacement_stress() {
    let (temp, dir) = fixture();
    let outside = tempfile::tempdir().unwrap();
    let outside_root = outside.path().join("private");
    let outside_dir = PrivateDir::ensure(&outside_root).unwrap();
    outside_dir
        .create("data")
        .unwrap()
        .write_all(b"outside")
        .unwrap();
    dir.create_dir("slot").unwrap();
    dir.create("slot/data")
        .unwrap()
        .write_all(b"inside")
        .unwrap();
    let bad = dir.create_dir("bad").unwrap();
    junction(&bad, &outside_root);
    drop(bad);
    crate::stress::redirect(&dir, &temp.path().join("private"), &outside_root);
}
fn world() -> Sid {
    let mut bytes = 68;
    let mut storage = vec![0u32; 17];
    // SAFETY: the documented maximum SID allocation is 68 bytes, DWORD-aligned.
    bool_result(unsafe {
        CreateWellKnownSid(
            WinWorldSid,
            ptr::null_mut(),
            storage.as_mut_ptr().cast(),
            &mut bytes,
        )
    })
    .unwrap();
    // SAFETY: CreateWellKnownSid initialized a valid SID in the allocation.
    unsafe { Sid::copy_from(storage.as_mut_ptr().cast()) }.unwrap()
}
fn set_acl(handle: impl AsHandle, entries: &[(&Sid, u32, u32)], protected: bool) {
    let mut acl = vec![0u32; 256];
    let raw = acl.as_mut_ptr().cast::<ACL>();
    // SAFETY: aligned ACL allocation covers all small test ACEs and SIDs stay live.
    unsafe {
        bool_result(InitializeAcl(
            raw,
            (acl.len() * 4) as u32,
            ACL_REVISION as u32,
        ))
        .unwrap();
        for (sid, mask, flags) in entries {
            bool_result(AddAccessAllowedAceEx(
                raw,
                ACL_REVISION as u32,
                *flags,
                *mask,
                sid.as_ptr(),
            ))
            .unwrap();
        }
        let control = if protected {
            PROTECTED_DACL_SECURITY_INFORMATION
        } else {
            UNPROTECTED_DACL_SECURITY_INFORMATION as u32
        };
        assert_eq!(
            SetSecurityInfo(
                handle.as_handle().as_raw_handle(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION as u32 | control,
                ptr::null_mut(),
                ptr::null_mut(),
                raw,
                ptr::null()
            ),
            0
        );
    }
}
fn junction(handle: impl AsHandle, target: &Path) {
    let substitute: Vec<u16> = OsStr::new(r"\??\")
        .encode_wide()
        .chain(target.as_os_str().encode_wide())
        .collect();
    let length = (substitute.len() * 2) as u16;
    let mut buffer = Vec::new();
    buffer.extend_from_slice(&IO_REPARSE_TAG_MOUNT_POINT.to_le_bytes());
    buffer.extend_from_slice(&(length + 12).to_le_bytes());
    buffer.extend_from_slice(&0u16.to_le_bytes());
    for field in [0u16, length, length + 2, 0] {
        buffer.extend_from_slice(&field.to_le_bytes());
    }
    for unit in substitute {
        buffer.extend_from_slice(&unit.to_le_bytes());
    }
    buffer.extend_from_slice(&[0, 0, 0, 0]);
    let mut returned = 0;
    // SAFETY: correctly encoded mount-point reparse buffer, live directory handle,
    // and synchronous call with no output payload or OVERLAPPED structure.
    bool_result(unsafe {
        DeviceIoControl(
            handle.as_handle().as_raw_handle(),
            FSCTL_SET_REPARSE_POINT as u32,
            buffer.as_ptr().cast(),
            buffer.len() as u32,
            ptr::null_mut(),
            0,
            &mut returned,
            ptr::null_mut(),
        )
    })
    .unwrap();
}
#[test]
fn round_trip_private_creation_and_noninheritance() {
    let (temp, dir) = fixture();
    let nested = dir.create_dir("nested").unwrap();
    let mut file = dir.create(r"nested\key").unwrap();
    file.write_all(b"secret").unwrap();
    file.seek(SeekFrom::Start(0)).unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();
    assert_eq!(contents, "secret");
    file.verify().unwrap();
    security::verify(&dir, &dir.user).unwrap();
    security::verify(&nested, &dir.user).unwrap();
    assert_eq!(
        std::fs::read(temp.path().join(r"private\nested\key")).unwrap(),
        b"secret"
    );
    for handle in [dir.as_handle(), nested.as_handle(), file.as_handle()] {
        let mut flags = 0;
        // SAFETY: live handle and writable scalar output.
        bool_result(unsafe { GetHandleInformation(handle.as_raw_handle(), &mut flags) }).unwrap();
        assert_eq!(flags & HANDLE_FLAG_INHERIT as u32, 0);
    }
    assert!(dir.create(r"nested\key").is_err());
    assert!(dir.create_dir("nested").is_err());
    dir.ensure_dir("nested").unwrap();
}
#[test]
fn insecure_existing_acls_are_rejected_without_repair() {
    let (temp, dir) = fixture();
    let file = dir.create("key").unwrap();
    let other = world();
    for entries in [
        vec![(
            &dir.user,
            (FILE_READ_DATA | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE) as u32,
            0,
        )],
        vec![(&other, FILE_ALL_ACCESS as u32, 0)],
        vec![
            (&dir.user, FILE_ALL_ACCESS as u32, 0),
            (&other, FILE_READ_DATA as u32, 0),
        ],
    ] {
        set_acl(&file, &entries, true);
        assert!(matches!(file.verify(), Err(Error::InsecureAcl)));
        assert!(matches!(dir.open_file("key"), Err(Error::InsecureAcl)));
    }
    set_acl(&file, &[(&dir.user, FILE_ALL_ACCESS as u32, 0)], false);
    assert!(matches!(file.verify(), Err(Error::InsecureAcl)));
    assert!(PrivateDir::open(temp.path().join("private")).is_ok());
}
#[test]
fn inherited_permissive_parent_cannot_broaden_new_objects() {
    let (_temp, dir) = fixture();
    let other = world();
    set_acl(
        &dir,
        &[
            (&dir.user, FILE_ALL_ACCESS as u32, 0),
            (
                &other,
                FILE_ALL_ACCESS as u32,
                (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) as u32,
            ),
        ],
        true,
    );
    assert!(matches!(dir.create("blocked"), Err(Error::InsecureAcl)));
    // Root acquisition permits public ancestors, but supplies its own protected
    // DACL in the creation syscall. The parent's inheritable grants cannot enter it.
    let private = PrivateDir::ensure(_temp.path().join("private/child")).unwrap();
    security::verify(&private, &private.user).unwrap();
    private.create("key").unwrap().verify().unwrap();
}
#[test]
fn hard_links_owner_and_full_file_identity_are_checked() {
    let (temp, dir) = fixture();
    let mut file = dir.create("key").unwrap();
    assert!(matches!(
        security::verify(&file, &world()),
        Err(Error::OwnerMismatch)
    ));
    let different = dir.create("other").unwrap();
    assert!(matches!(
        nt::metadata(&different, false, Some(file.id)),
        Err(Error::IdentityChanged)
    ));
    std::fs::hard_link(temp.path().join("private/key"), temp.path().join("alias")).unwrap();
    assert!(matches!(
        file.verify(),
        Err(Error::MultipleHardLinks { links: 2 })
    ));
    assert!(matches!(
        dir.open_file("key"),
        Err(Error::MultipleHardLinks { .. })
    ));
    assert!(file.write(b"blocked").is_err());
    assert!(file.read(&mut [0]).is_err());
    assert!(std::fs::read(temp.path().join("alias")).unwrap().is_empty());
}
#[test]
fn retained_capabilities_survive_path_replacement() {
    let (temp, dir) = fixture();
    let mut original = dir.create("key").unwrap();
    original.write_all(b"original").unwrap();
    let root = temp.path().join("private");
    std::fs::rename(root.join("key"), root.join("old-key")).unwrap();
    dir.create("key")
        .unwrap()
        .write_all(b"replacement")
        .unwrap();
    original.seek(SeekFrom::Start(0)).unwrap();
    let mut contents = String::new();
    original.read_to_string(&mut contents).unwrap();
    assert_eq!(contents, "original");
    // Windows does not rename a directory while descendant file handles are open.
    drop(original);
    std::fs::rename(&root, temp.path().join("moved")).unwrap();
    PrivateDir::ensure(&root).unwrap();
    dir.create("retained").unwrap();
    assert!(temp.path().join("moved/retained").exists());
    assert!(!root.join("retained").exists());
}
#[test]
fn junctions_are_rejected_in_every_position() {
    let (_temp, dir) = fixture();
    let outside = tempfile::tempdir().unwrap();
    let link = dir.create_dir("junction").unwrap();
    junction(&link, outside.path());
    assert!(matches!(
        dir.open_file("junction"),
        Err(Error::PathRedirect)
    ));
    assert!(matches!(
        dir.create("junction/escape"),
        Err(Error::PathRedirect)
    ));
    assert!(matches!(link.create("escape"), Err(Error::PathRedirect)));
    assert_eq!(std::fs::read_dir(outside.path()).unwrap().count(), 0);
    assert!(matches!(
        PrivateDir::open(_temp.path().join("private/junction")),
        Err(Error::PathRedirect)
    ));
}
#[test]
fn namespace_replacement_after_validation_keeps_the_original_parent() {
    let (temp, dir) = fixture();
    let outside = tempfile::tempdir().unwrap();
    dir.create_dir("slot").unwrap();
    let bad = dir.create_dir("bad").unwrap();
    junction(&bad, outside.path());
    drop(bad);
    // Pin and validate the real parent before the attacker changes its name.
    let (parent, leaf) = dir.parent(Path::new("slot/key")).unwrap();
    let root = temp.path().join("private");
    let worker_root = root.clone();
    std::thread::spawn(move || {
        std::fs::rename(worker_root.join("slot"), worker_root.join("spare")).unwrap();
        std::fs::rename(worker_root.join("bad"), worker_root.join("slot")).unwrap();
    })
    .join()
    .unwrap();
    // This is the same publication-independent create sequence used by create.
    let mut file = dir.create_at(&parent, leaf).unwrap();
    file.write_all(b"original-parent").unwrap();
    assert_eq!(
        std::fs::read(root.join("spare/key")).unwrap(),
        b"original-parent"
    );
    assert!(matches!(
        dir.create("slot/escape"),
        Err(Error::PathRedirect)
    ));
    assert_eq!(std::fs::read_dir(outside.path()).unwrap().count(), 0);
}
#[test]
fn unsupported_volume_and_path_forms_fail_closed() {
    assert!(matches!(
        nt::volume_flags(0),
        Err(Error::UnsupportedFilesystem { .. })
    ));
    nt::volume_flags(FILE_PERSISTENT_ACLS as u32).unwrap();
    let (_temp, dir) = fixture();
    for path in [
        "..",
        r"..\escape",
        "C:key",
        r"C:\key",
        r"\\host\share",
        r"\\?\GLOBALROOT\Device",
        "key:stream",
        "",
    ] {
        assert!(matches!(dir.create(path), Err(Error::InvalidRelativePath)));
    }
    assert!(matches!(dir.open_file("missing"), Err(Error::Io(_))));
    dir.create_dir("directory").unwrap();
    assert!(matches!(
        dir.open_file("directory"),
        Err(Error::WrongObjectKind)
    ));
}
#[test]
fn owner_uses_token_user_even_when_default_owner_differs() {
    let (_temp, dir) = fixture();
    let file = dir.create("key").unwrap();
    // TokenUser is the authoritative identity in both elevated and normal runs.
    // Query TokenOwner independently to exercise the distinct ABI, without using
    // it as policy or assuming elevation is available on the test runner.
    let mut raw = ptr::null_mut();
    // SAFETY: process pseudo-handle and writable output.
    bool_result(unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY as u32, &mut raw) })
        .unwrap();
    // SAFETY: successful OpenProcessToken transferred a live unique handle.
    let token = unsafe { std::os::windows::io::OwnedHandle::from_raw_handle(raw) };
    let mut bytes = 0;
    // SAFETY: documented size query, no buffer.
    unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenOwner,
            ptr::null_mut(),
            0,
            &mut bytes,
        );
    }
    let mut data = vec![0usize; (bytes as usize).div_ceil(size_of::<usize>())];
    // SAFETY: aligned and sufficiently large buffer and live token.
    bool_result(unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenOwner,
            data.as_mut_ptr().cast(),
            bytes,
            &mut bytes,
        )
    })
    .unwrap();
    // SAFETY: successful output is an aligned TOKEN_OWNER with a live SID.
    let owner = unsafe { Sid::copy_from((*(data.as_ptr().cast::<TOKEN_OWNER>())).Owner) }.unwrap();
    // SAFETY: both SIDs are owned valid allocations.
    if unsafe { EqualSid(owner.as_ptr(), dir.user.as_ptr()) } == 0 {
        assert!(matches!(
            security::verify(&file, &owner),
            Err(Error::OwnerMismatch)
        ));
    }
    security::verify(&file, &Sid::process_user().unwrap()).unwrap();
}

#[test]
fn hardening_is_explicit_descriptor_bound_and_revalidated() {
    let (temp, dir) = fixture();
    let mut file = dir.create("key").unwrap();
    let other = world();
    let root = temp.path().join("private");
    std::fs::rename(root.join("key"), root.join("old")).unwrap();
    let replacement = dir.create("key").unwrap();
    set_acl(&file, &[(&other, FILE_ALL_ACCESS as u32, 0)], true);
    set_acl(&replacement, &[(&other, FILE_ALL_ACCESS as u32, 0)], true);
    assert!(matches!(file.verify(), Err(Error::InsecureAcl)));
    assert!(file.write(b"blocked").is_err());
    file.harden().unwrap();
    file.verify().unwrap();
    file.write_all(b"original").unwrap();
    assert!(matches!(replacement.verify(), Err(Error::InsecureAcl)));
    replacement.harden().unwrap();
    replacement.verify().unwrap();
    assert_eq!(std::fs::read(root.join("old")).unwrap(), b"original");
    set_acl(&dir, &[(&other, FILE_ALL_ACCESS as u32, 0)], false);
    assert!(matches!(dir.create("blocked"), Err(Error::InsecureAcl)));
    dir.harden().unwrap();
    dir.create("ok").unwrap();
    std::fs::hard_link(root.join("old"), root.join("alias")).unwrap();
    set_acl(&file, &[(&other, FILE_ALL_ACCESS as u32, 0)], true);
    assert!(matches!(
        file.harden(),
        Err(Error::MultipleHardLinks { .. })
    ));
    assert!(matches!(
        security::verify(&file, &dir.user),
        Err(Error::InsecureAcl)
    ));
}
#[test]
fn empty_and_null_dacls_and_inheritable_aces_are_rejected() {
    let (_temp, dir) = fixture();
    let file = dir.create("key").unwrap();
    set_acl(&file, &[], true);
    assert!(matches!(file.verify(), Err(Error::InsecureAcl)));
    file.harden().unwrap();
    // SAFETY: deliberate null DACL on a test object, queried through its live handle.
    assert_eq!(
        unsafe {
            SetSecurityInfo(
                file.as_handle().as_raw_handle(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION as u32 | PROTECTED_DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null(),
                ptr::null(),
            )
        },
        0
    );
    assert!(matches!(file.verify(), Err(Error::InsecureAcl)));
    file.harden().unwrap();
    file.verify().unwrap();
    set_acl(
        &dir,
        &[(&dir.user, FILE_ALL_ACCESS as u32, OBJECT_INHERIT_ACE as u32)],
        true,
    );
    assert!(matches!(dir.create("new-key"), Err(Error::InsecureAcl)));
    dir.harden().unwrap();
    dir.create("new-key").unwrap();
}
#[test]
fn unpaired_utf16_names_are_not_lossily_converted() {
    use std::{ffi::OsString, os::windows::ffi::OsStringExt};
    let (_temp, dir) = fixture();
    let name = OsString::from_wide(&[b'k' as u16, 0xd800]);
    dir.create(&name).unwrap();
    dir.open_file(&name).unwrap().verify().unwrap();
}

#[test]
fn parent_directory_flush_is_available() {
    let (_temp, dir) = fixture();
    nt::flush(&dir).unwrap();
    let read_only = PrivateDir::open(_temp.path().join("private")).unwrap();
    let reopened = nt::directory_for_sync(&read_only.handle).unwrap();
    assert_eq!(nt::metadata(&reopened, true, None).unwrap(), dir.id);
    nt::flush(&reopened).unwrap();
}

#[test]
fn borrowed_library_handle_hardening_never_reopens_a_path() {
    let (temp, dir) = fixture();
    let original = dir.create("data").unwrap();
    let donor = std::fs::File::open(temp.path().join("private/data")).unwrap();
    std::fs::rename(
        temp.path().join("private/data"),
        temp.path().join("private/original"),
    )
    .unwrap();
    let replacement = dir.create("data").unwrap();
    let other = world();
    set_acl(&original, &[(&other, FILE_ALL_ACCESS as u32, 0)], true);
    set_acl(&replacement, &[(&other, FILE_ALL_ACCESS as u32, 0)], true);
    assert!(matches!(crate::verify(&donor), Err(Error::InsecureAcl)));
    crate::harden(&donor).unwrap();
    crate::verify(&donor).unwrap();
    original.verify().unwrap();
    assert!(matches!(replacement.verify(), Err(Error::InsecureAcl)));
    assert!(matches!(
        security::harden(&donor, &other),
        Err(Error::OwnerMismatch)
    ));
}
