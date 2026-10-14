use crate::*;
use rstest::rstest;
use std::{
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
};

fn fixture() -> (tempfile::TempDir, PrivateDir) {
    let temp = tempfile::tempdir().unwrap();
    #[cfg(target_os = "macos")]
    assert!(
        std::process::Command::new("/bin/chmod")
            .arg("-N")
            .arg(temp.path())
            .status()
            .unwrap()
            .success()
    );
    let dir = PrivateDir::ensure(temp.path().join("private")).unwrap();
    (temp, dir)
}

#[rstest]
fn open_lifecycle(
    #[values(
        FileCreation::Existing,
        FileCreation::CreateNew,
        FileCreation::OpenOrCreate
    )]
    creation: FileCreation,
    #[values(false, true)] present: bool,
    #[values(false, true)] truncate: bool,
    #[values(Verification::PerIo, Verification::OnDemand)] verification: Verification,
) {
    let (_temp, dir) = fixture();
    if present {
        dir.create("data").unwrap().write_all(b"old").unwrap();
    }
    let opened = dir.open_file_with(
        "data",
        OpenOptions {
            access: FileAccess::ReadWrite,
            creation,
            truncate,
            verification,
        },
    );
    if (!present && creation == FileCreation::Existing)
        || (present && creation == FileCreation::CreateNew)
    {
        assert!(opened.is_err());
        if present {
            let mut contents = Vec::new();
            dir.open_file("data")
                .unwrap()
                .read_to_end(&mut contents)
                .unwrap();
            assert_eq!(contents, b"old");
        }
        return;
    }
    let mut file = opened.unwrap();
    let mut contents = Vec::new();
    file.read_to_end(&mut contents).unwrap();
    assert_eq!(
        contents,
        if present && !truncate {
            b"old".as_slice()
        } else {
            b""
        }
    );
    file.seek(SeekFrom::Start(0)).unwrap();
    file.write_all(b"new").unwrap();
    file.set_len(3).unwrap();
    file.verify().unwrap();
    let mut contents = Vec::new();
    dir.open_file("data")
        .unwrap()
        .read_to_end(&mut contents)
        .unwrap();
    assert_eq!(contents, b"new");
}

#[test]
fn read_only_and_invalid_options_never_mutate() {
    let (_temp, dir) = fixture();
    dir.create("data").unwrap().write_all(b"secret").unwrap();
    let mut file = dir.open_file("data").unwrap();
    assert!(file.write(b"bad").is_err());
    assert!(file.set_len(0).is_err());
    for creation in [
        FileCreation::Existing,
        FileCreation::CreateNew,
        FileCreation::OpenOrCreate,
    ] {
        assert!(matches!(
            dir.open_file_with(
                "data",
                OpenOptions {
                    creation,
                    truncate: true,
                    ..OpenOptions::default()
                }
            ),
            Err(Error::UnsupportedPolicy { .. })
        ));
    }
    let mut contents = Vec::new();
    file.read_to_end(&mut contents).unwrap();
    assert_eq!(contents, b"secret");
}

#[test]
fn recursive_creation_is_sequential_and_existing_directories_are_verified() {
    let (_temp, dir) = fixture();
    assert!(dir.open_dir("missing").is_err());
    let nested = dir.ensure_dir_all("a/b/c").unwrap();
    nested.create("data").unwrap();
    dir.open_file("a/b/c/data").unwrap();
    dir.ensure_dir_all("a/b/c").unwrap();
    assert_eq!(
        dir.open_dir("a/b/c").unwrap().entries().unwrap(),
        [std::ffi::OsString::from("data")]
    );
    assert!(matches!(
        dir.ensure_dir_all("a/../escape"),
        Err(Error::InvalidRelativePath)
    ));
}

#[cfg(unix)]
#[rstest]
fn verification_policy_reports_mutation_at_its_documented_boundary(
    #[values(Verification::PerIo, Verification::OnDemand)] policy: Verification,
) {
    use std::os::unix::fs::PermissionsExt;
    let (temp, dir) = fixture();
    dir.create("data").unwrap().write_all(b"secret").unwrap();
    let mut file = dir
        .open_file_with(
            "data",
            OpenOptions {
                verification: policy,
                ..OpenOptions::default()
            },
        )
        .unwrap();
    std::fs::set_permissions(
        temp.path().join("private/data"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    assert!(matches!(
        file.verify(),
        Err(Error::InsecurePermissions { .. })
    ));
    let mut buffer = [0u8; 6];
    if policy == Verification::PerIo {
        assert!(file.read(&mut buffer).is_err());
    } else {
        file.read_exact(&mut buffer).unwrap();
        assert_eq!(&buffer, b"secret");
    }
    assert!(file.sync_all().is_err());
}

#[rstest]
fn enumeration_and_removal(
    #[values(Durability::None, Durability::Data, Durability::Full)] durability: Durability,
) {
    let (temp, dir) = fixture();
    dir.create_dir("nested").unwrap();
    dir.create("a").unwrap();
    dir.create("nested/b").unwrap();
    let root = temp.path().join("private");
    std::fs::rename(&root, temp.path().join("moved")).unwrap();
    std::fs::create_dir(&root).unwrap();
    for _ in 0..2 {
        let mut names = dir.entries().unwrap();
        names.sort();
        assert_eq!(names, [std::ffi::OsString::from("a"), "nested".into()]);
    }
    assert!(matches!(
        dir.remove_file("nested", durability),
        Err(Error::WrongObjectKind)
    ));
    dir.remove_file("nested/b", durability).unwrap();
    assert!(
        matches!(dir.open_file("nested/b"), Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound)
    );
    assert!(
        matches!(dir.remove_file("missing", durability), Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound)
    );
    dir.remove_file("a", durability).unwrap();
    assert_eq!(dir.entries().unwrap(), [std::ffi::OsString::from("nested")]);
    assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0);
}

#[test]
fn native_names_round_trip_through_enumeration() {
    let (_temp, dir) = fixture();
    #[cfg(all(unix, not(target_os = "macos")))]
    let name = {
        use std::os::unix::ffi::OsStringExt;
        std::ffi::OsString::from_vec(vec![b'k', 0xff])
    };
    #[cfg(target_os = "macos")]
    let name = std::ffi::OsString::from("k雪");
    #[cfg(windows)]
    let name = {
        use std::os::windows::ffi::OsStringExt;
        std::ffi::OsString::from_wide(&[b'k' as u16, 0xd800])
    };
    dir.create(&name).unwrap();
    assert_eq!(dir.entries().unwrap(), std::slice::from_ref(&name));
    dir.open_file(&name).unwrap().verify().unwrap();
    dir.remove_file(&name, Durability::None).unwrap();
    assert!(dir.entries().unwrap().is_empty());
}

#[test]
fn explicit_orphan_maintenance_does_not_infer_authority_from_prefix() {
    let (_temp, dir) = fixture();
    let name;
    {
        let writer = crate::atomic::AtomicFile::new(
            &dir,
            Path::new("data"),
            Durability::None,
            crate::atomic::Faults {
                force_named: true,
                names: ["chosen-orphan".into()].into(),
                ..Default::default()
            },
        )
        .unwrap();
        name = "chosen-orphan";
        drop(writer);
    }
    #[cfg(any(windows, target_os = "freebsd"))]
    assert!(dir.entries().unwrap().is_empty());
    #[cfg(all(unix, not(target_os = "freebsd")))]
    {
        assert_eq!(dir.entries().unwrap(), [std::ffi::OsString::from(name)]);
        dir.remove_file(name, Durability::Full).unwrap();
        assert!(dir.entries().unwrap().is_empty());
    }
    let _ = name;
}

#[test]
fn atomic_create_only_preserves_existing_destination() {
    let (_temp, dir) = fixture();
    #[cfg(target_os = "netbsd")]
    {
        assert!(matches!(
            dir.atomic_with_policy("data", Durability::None, Publication::CreateNew),
            Err(Error::UnsupportedPolicy { .. })
        ));
        assert!(dir.entries().unwrap().is_empty());
    }
    #[cfg(not(target_os = "netbsd"))]
    {
        let mut writer = dir
            .atomic_with_policy("data", Durability::Full, Publication::CreateNew)
            .unwrap();
        writer.write_all(b"first").unwrap();
        writer.commit().unwrap();
        let mut writer = dir
            .atomic_with_policy("data", Durability::None, Publication::CreateNew)
            .unwrap();
        writer.write_all(b"second").unwrap();
        assert!(
            matches!(writer.commit(), Err(Error::AtomicCommit { may_have_published: false, source })
            if matches!(*source, Error::Io(ref e) if e.kind() == std::io::ErrorKind::AlreadyExists))
        );
        let mut contents = Vec::new();
        dir.open_file("data")
            .unwrap()
            .read_to_end(&mut contents)
            .unwrap();
        assert_eq!(contents, b"first");
    }
}

#[cfg(unix)]
#[rstest]
fn insecure_files_never_truncate_or_unlink(#[values(0o644, 0o400, 0o4600)] mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let (temp, dir) = fixture();
    dir.create("data").unwrap().write_all(b"secret").unwrap();
    std::fs::set_permissions(
        temp.path().join("private/data"),
        std::fs::Permissions::from_mode(mode),
    )
    .unwrap();
    let options = OpenOptions {
        access: FileAccess::ReadWrite,
        truncate: true,
        ..OpenOptions::default()
    };
    assert!(dir.open_file_with("data", options).is_err());
    assert!(dir.remove_file("data", Durability::None).is_err());
    assert_eq!(
        std::fs::read(temp.path().join("private/data")).unwrap(),
        b"secret"
    );
}
