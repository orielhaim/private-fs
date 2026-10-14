use super::*;
use crate::{Durability, PrivateDir};
use std::{ffi::CString, io::Write, os::unix::fs::PermissionsExt};

unsafe extern "C" {
    fn acl_from_text(text: *const libc::c_char) -> *mut c_void;
}

fn set(fd: impl AsFd, kind: i32, text: &str) {
    let text = CString::new(text).unwrap();
    // SAFETY: live NUL-terminated ACL text; successful parsing transfers ownership.
    let acl = Acl::owned(unsafe { acl_from_text(text.as_ptr()) }).unwrap();
    // SAFETY: live descriptor and parsed owned ACL of the requested model.
    check(unsafe { acl_set_fd_np(fd.as_fd().as_raw_fd(), acl.0.as_ptr(), kind) }).unwrap();
}

#[test]
fn required_acl_model_is_reported_by_the_filesystem() {
    let temp = tempfile::tempdir().unwrap();
    let fd = std::fs::File::open(temp.path()).unwrap();
    let actual = model(&fd).unwrap();
    if let Some(expected) = std::env::var_os("PRIVATE_FS_EXPECT_ACL") {
        let expected = match expected.to_str().unwrap() {
            "posix" => Some(ACCESS),
            "nfs4" => Some(NFS4),
            "none" => None,
            _ => panic!("unknown ACL test profile"),
        };
        assert_eq!(actual, expected);
    }
}

#[test]
fn acl_grants_inheritance_and_handle_bound_hardening() {
    let temp = tempfile::tempdir().unwrap();
    let dir = PrivateDir::ensure(temp.path().join("private")).unwrap();
    let Some(kind) = model(&dir).unwrap() else {
        assert!(std::env::var_os("PRIVATE_FS_EXPECT_ACL").is_none_or(|v| v == "none"));
        eprintln!("ACL mutation cases require the posix/nfs4 native filesystem profiles");
        return;
    };
    let file = dir.create("data").unwrap();
    let (grant, inherit) = if kind == ACCESS {
        (
            "u::rw-,u:12345:r--,g::---,m::r--,o::---",
            "u::rwx,u:12345:rwx,g::---,m::rwx,o::---",
        )
    } else {
        (
            "owner@:rw-p--aARWcCos:-------:allow,user:12345:r-----a-R-c---:-------:allow,group@:------a-R-c--s:-------:allow,everyone@:------a-R-c--s:-------:allow",
            "owner@:rwxpDdaARWcCos:-------:allow,user:12345:rwxpDdaARWcCos:fd-----:allow,group@:------a-R-c--s:-------:allow,everyone@:------a-R-c--s:-------:allow",
        )
    };
    set(&file, kind, grant);
    assert!(crate::verify(file.raw_file()).is_err());
    assert!(dir.open_file("data").is_err());
    std::fs::rename(
        temp.path().join("private/data"),
        temp.path().join("private/original"),
    )
    .unwrap();
    dir.create("data")
        .unwrap()
        .write_all(b"replacement")
        .unwrap();
    file.harden().unwrap();
    file.verify().unwrap();
    let mode_compatible = if kind == ACCESS {
        "u::rw-,u:12345:r--,g::---,m::---,o::---"
    } else {
        "owner@:rw-p--aARWcCos:-------:allow,user:12345:r-----a-R-c---:-------:deny,group@:------a-R-c--s:-------:allow,everyone@:------a-R-c--s:-------:allow"
    };
    set(&file, kind, mode_compatible);
    assert_eq!(rustix::fs::fstat(&file).unwrap().st_mode & 0o7777, 0o600);
    assert!(matches!(file.verify(), Err(Error::InsecureAcl)));
    file.harden().unwrap();
    assert_eq!(
        std::fs::read(temp.path().join("private/data")).unwrap(),
        b"replacement"
    );
    if kind == ACCESS {
        set(&dir, DEFAULT, inherit);
    } else {
        set(&dir, NFS4, inherit);
    }
    assert!(matches!(dir.create("blocked"), Err(Error::InsecureAcl)));
    assert!(matches!(
        dir.create_dir("blocked-dir"),
        Err(Error::InsecureAcl)
    ));
    assert!(!temp.path().join("private/blocked").exists());
    assert!(!temp.path().join("private/blocked-dir").exists());
    dir.harden().unwrap();
    dir.create("allowed").unwrap();
    dir.write_atomic_with_durability("state", b"private", Durability::Full)
        .unwrap();
    dir.remove_file("allowed", Durability::Full).unwrap();
}

#[test]
fn immutable_metadata_is_readable_but_native_mutation_errors_are_preserved() {
    let temp = tempfile::tempdir().unwrap();
    let dir = PrivateDir::ensure(temp.path().join("private")).unwrap();
    let file = dir.create("data").unwrap();
    // SAFETY: live file descriptor and the platform-defined user immutable flag.
    let result =
        check(unsafe { libc::fchflags(file.as_fd().as_raw_fd(), libc::UF_IMMUTABLE as _) });
    if matches!(&result, Err(Error::Io(e)) if e.raw_os_error() == Some(libc::EOPNOTSUPP)) {
        assert!(std::env::var_os("PRIVATE_FS_EXPECT_FLAGS").is_none());
        file.verify().unwrap();
        eprintln!(
            "this filesystem does not implement immutable flags; UFS/FFS profiles require them"
        );
        return;
    }
    result.unwrap();
    file.verify().unwrap();
    assert!(file.set_len(0).is_err());
    assert!(matches!(
        dir.remove_file("data", Durability::None),
        Err(Error::Removal {
            may_have_removed: false,
            ..
        })
    ));
    // SAFETY: reset only the test object's flag through the retained descriptor.
    check(unsafe { libc::fchflags(file.as_fd().as_raw_fd(), 0) }).unwrap();
    assert_eq!(
        std::fs::metadata(temp.path().join("private/data"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o600
    );
}

#[cfg(target_os = "freebsd")]
#[test]
fn funlinkat_containment_refusal_is_a_definite_non_removal() {
    let temp = tempfile::tempdir().unwrap();
    let parent = PrivateDir::ensure(temp.path().join("private")).unwrap();
    let dir = parent.create_dir("inner").unwrap();
    let mut outside = parent.create("outside").unwrap();
    outside.write_all(b"preserved").unwrap();
    let error = unlink(&dir, std::ffi::OsStr::new("../outside"), &outside).unwrap_err();
    assert!(matches!(&error, Error::Io(e) if e.raw_os_error() == Some(libc::ENOTCAPABLE)));
    assert!(error.namespace_unchanged());
    assert_eq!(
        std::fs::read(temp.path().join("private/outside")).unwrap(),
        b"preserved"
    );
}

#[cfg(target_os = "freebsd")]
#[test]
fn funlinkat_refuses_a_substituted_name_and_removes_the_original() {
    let temp = tempfile::tempdir().unwrap();
    let dir = PrivateDir::ensure(temp.path().join("private")).unwrap();
    let original = dir.create("data").unwrap();
    std::fs::rename(
        temp.path().join("private/data"),
        temp.path().join("private/original"),
    )
    .unwrap();
    dir.create("data")
        .unwrap()
        .write_all(b"replacement")
        .unwrap();
    assert!(matches!(
        unlink(&dir, std::ffi::OsStr::new("data"), &original),
        Err(Error::IdentityChanged)
    ));
    assert_eq!(
        std::fs::read(temp.path().join("private/data")).unwrap(),
        b"replacement"
    );
    unlink(&dir, std::ffi::OsStr::new("original"), &original).unwrap();
    assert!(!temp.path().join("private/original").exists());
}
