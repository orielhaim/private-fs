use super::*;
use crate::PrivateDir;
use std::{
    fs::File,
    io::{Read, Write},
    os::unix::fs::PermissionsExt,
    path::Path,
    process::Command,
};
fn fixture() -> (tempfile::TempDir, PrivateDir) {
    let temp = tempfile::tempdir().unwrap();
    clear(File::open(temp.path()).unwrap()).unwrap();
    let dir = PrivateDir::ensure(temp.path().join("private")).unwrap();
    (temp, dir)
}

#[test]
fn symlink_and_directory_replacement_stress() {
    let (temp, dir) = fixture();
    let outside = tempfile::tempdir().unwrap();
    clear(File::open(outside.path()).unwrap()).unwrap();
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
    std::os::unix::fs::symlink(&outside_root, temp.path().join("private/bad")).unwrap();
    crate::stress::redirect(&dir, &temp.path().join("private"), &outside_root);
}

#[test]
fn writable_nonsticky_creation_parent_is_rejected_even_without_acl() {
    let temp = tempfile::tempdir().unwrap();
    clear(File::open(temp.path()).unwrap()).unwrap();
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
    assert!(matches!(
        PrivateDir::ensure(temp.path().join("private")),
        Err(Error::UntrustedCreationParent)
    ));
    assert!(!temp.path().join("private").exists());
}
fn add_acl(path: &Path, permissions: &str) {
    assert!(
        Command::new("/bin/chmod")
            .args(["+a", permissions])
            .arg(path)
            .status()
            .unwrap()
            .success()
    );
}
#[test]
fn empty_acl_round_trip() {
    let (temp, dir) = fixture();
    let mut file = dir.create("key").unwrap();
    file.write_all(b"secret").unwrap();
    verify(&file).unwrap();
    let mut read = dir.open_file("key").unwrap();
    let mut contents = String::new();
    read.read_to_string(&mut contents).unwrap();
    assert_eq!(contents, "secret");
    dir.create_dir("nested").unwrap();
    dir.create("nested/item").unwrap();
    assert_eq!(
        std::fs::metadata(temp.path().join("private/key"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o600
    );
}
#[test]
fn acl_grants_override_mode_and_reading_never_repairs_them() {
    let (temp, dir) = fixture();
    dir.create("key").unwrap();
    let path = temp.path().join("private/key");
    add_acl(&path, "everyone allow read,write");
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o7777,
        0o600
    );
    assert!(matches!(dir.open_file("key"), Err(Error::InsecureAcl)));
    assert!(
        !Acl::get(File::open(&path).unwrap())
            .unwrap()
            .is_empty()
            .unwrap()
    );
}
#[test]
fn hardening_is_bound_to_the_original_descriptor() {
    let (temp, dir) = fixture();
    let file = dir.create("key").unwrap();
    let original = temp.path().join("private/original");
    std::fs::rename(temp.path().join("private/key"), &original).unwrap();
    let replacement = dir.create("key").unwrap();
    add_acl(&original, "everyone allow read,write");
    add_acl(&temp.path().join("private/key"), "everyone allow read");
    assert!(matches!(file.verify(), Err(Error::InsecureAcl)));
    file.harden().unwrap();
    file.verify().unwrap();
    assert!(Acl::get(&file).unwrap().is_empty().unwrap());
    assert!(matches!(replacement.verify(), Err(Error::InsecureAcl)));
    replacement.harden().unwrap();
    replacement.verify().unwrap();
}
#[test]
fn directory_acl_hardening_and_inheritance_rejection() {
    let (temp, dir) = fixture();
    let path = temp.path().join("private");
    add_acl(
        &path,
        "everyone allow read,write,add_file,add_subdirectory,file_inherit,directory_inherit",
    );
    assert!(matches!(dir.create("blocked"), Err(Error::InsecureAcl)));
    assert!(!path.join("blocked").exists());
    dir.harden().unwrap();
    verify(&dir).unwrap();
    dir.create("key").unwrap();
    dir.create_dir("nested").unwrap();
    let parent = temp.path().join("parent");
    std::fs::create_dir(&parent).unwrap();
    add_acl(
        &parent,
        "everyone allow read,write,file_inherit,directory_inherit",
    );
    assert!(matches!(
        PrivateDir::ensure(parent.join("child")),
        Err(Error::InsecureAcl)
    ));
    assert!(!parent.join("child").exists());
}
#[test]
fn ownership_disabled_mount_policy_is_fail_closed() {
    assert!(matches!(
        ownership_flags(MNT_UNKNOWNPERMISSIONS),
        Err(Error::UnsupportedFilesystem { .. })
    ));
    ownership_flags(0).unwrap();
    let (temp, _) = fixture();
    ownership(File::open(temp.path()).unwrap()).unwrap();
}
#[test]
fn hard_links_and_special_modes_remain_rejected() {
    let (temp, dir) = fixture();
    let file = dir.create("key").unwrap();
    let path = temp.path().join("private/key");
    std::fs::hard_link(&path, temp.path().join("alias")).unwrap();
    assert!(matches!(
        file.harden(),
        Err(Error::MultipleHardLinks { .. })
    ));
    assert!(matches!(
        dir.open_file("key"),
        Err(Error::MultipleHardLinks { .. })
    ));
    std::fs::remove_file(temp.path().join("alias")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o4600)).unwrap();
    assert!(matches!(
        file.verify(),
        Err(Error::InsecurePermissions { .. })
    ));
    file.harden().unwrap();
    file.verify().unwrap();
}

#[test]
fn absent_extended_acl_is_distinct_from_an_inspection_error() {
    let (temp, dir) = fixture();
    let file = dir.create("key").unwrap();
    assert!(
        Command::new("/bin/chmod")
            .arg("-N")
            .arg(temp.path().join("private/key"))
            .status()
            .unwrap()
            .success()
    );
    file.verify().unwrap();
    assert!(Acl::get(&file).unwrap().is_empty().unwrap());
    assert!(matches!(
        acl_error(io::Error::from_raw_os_error(libc::ENOTSUP)),
        Error::UnsupportedFilesystem { .. }
    ));
    assert!(matches!(
        acl_error(io::Error::from_raw_os_error(libc::EACCES)),
        Error::Io(_)
    ));
}

#[test]
fn borrowed_file_acl_hardening_is_descriptor_bound() {
    let (temp, dir) = fixture();
    let original = dir.create("data").unwrap();
    let donor = std::fs::File::open(temp.path().join("private/data")).unwrap();
    std::fs::rename(
        temp.path().join("private/data"),
        temp.path().join("private/original"),
    )
    .unwrap();
    let replacement = dir.create("data").unwrap();
    add_acl(
        &temp.path().join("private/original"),
        "everyone allow read,write",
    );
    add_acl(&temp.path().join("private/data"), "everyone allow read");
    assert!(matches!(crate::verify(&donor), Err(Error::InsecureAcl)));
    crate::harden(&donor).unwrap();
    crate::verify(&donor).unwrap();
    original.verify().unwrap();
    assert!(matches!(replacement.verify(), Err(Error::InsecureAcl)));
}
