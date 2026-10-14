use super::*;
use rustix::io::{FdFlags, fcntl_getfd};
use std::os::unix::{
    ffi::OsStrExt,
    fs::{PermissionsExt, symlink},
};

fn each(mut test: impl FnMut(PrivateDir, &Path)) {
    #[cfg(target_os = "linux")]
    let resolvers = [
        Resolver::Auto,
        Resolver::OpenAt2,
        Resolver::Walk,
        Resolver::Unavailable,
    ]
    .into_iter();
    #[cfg(not(target_os = "linux"))]
    let resolvers = std::iter::once(Resolver::Auto);
    for resolver in resolvers {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("private");
        let dir = PrivateDir::acquire(&root, true, resolver).unwrap();
        test(dir, &root);
    }
}
fn chmod(p: &Path, mode: u32) {
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
}

#[test]
fn symlink_and_directory_replacement_stress() {
    each(|dir, root| {
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
        symlink(&outside_root, root.join("bad")).unwrap();
        crate::stress::redirect(&dir, root, &outside_root);
    });
}

#[test]
fn directory_creation_rejects_replaceable_parents_without_mutating_them() {
    let temp = tempfile::tempdir().unwrap();
    chmod(temp.path(), 0o777);
    let root = temp.path().join("private");
    assert!(matches!(
        PrivateDir::ensure(&root),
        Err(Error::UntrustedCreationParent)
    ));
    assert!(!root.exists());
    chmod(temp.path(), 0o1777);
    PrivateDir::ensure(&root).unwrap();
    chmod(temp.path(), 0o777);
    // Opening an already-private root does not require repairing its ancestors.
    PrivateDir::ensure(&root).unwrap();
    let mut stat = fs::fstat(std::fs::File::open(temp.path()).unwrap()).unwrap();
    stat.st_uid = rustix::process::geteuid().as_raw().wrapping_add(1).max(1);
    stat.st_mode = 0o1777;
    assert!(matches!(
        creation_parent_stat(&stat),
        Err(Error::UntrustedCreationParent)
    ));
}

#[test]
fn round_trip_and_exclusive_creation() {
    each(|dir, root| {
        let child = dir.create_dir("nested").unwrap();
        let mut file = dir.create("nested/key").unwrap();
        file.write_all(b"secret").unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();
        let mut data = String::new();
        file.read_to_string(&mut data).unwrap();
        assert_eq!(data, "secret");
        assert!(dir.create("nested/key").is_err());
        assert!(dir.create_dir("nested").is_err());
        dir.ensure_dir("nested").unwrap();
        assert_eq!(std::fs::read(root.join("nested/key")).unwrap(), b"secret");
        for fd in [dir.as_fd(), child.as_fd(), file.as_fd()] {
            assert!(fcntl_getfd(fd).unwrap().contains(FdFlags::CLOEXEC));
        }
        assert_eq!(
            std::fs::metadata(root.join("nested/key"))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(root.join("nested"))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o700
        );
    });
}
#[test]
fn strict_modes_and_no_implicit_repair() {
    each(|dir, root| {
        dir.create("key").unwrap();
        for mode in [0o644, 0o400, 0o4600, 0o2600, 0o1600] {
            chmod(&root.join("key"), mode);
            assert!(matches!(
                dir.open_file("key"),
                Err(Error::InsecurePermissions { .. })
            ));
            assert_eq!(
                std::fs::metadata(root.join("key"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o7777,
                mode
            );
        }
        dir.create_dir("nested").unwrap();
        for mode in [0o755, 0o4700, 0o2700, 0o1700] {
            chmod(&root.join("nested"), mode);
            assert!(matches!(
                dir.ensure_dir("nested"),
                Err(Error::InsecurePermissions { .. })
            ));
            assert!(matches!(
                dir.create("nested/key"),
                Err(Error::InsecurePermissions { .. })
            ));
        }
        chmod(root, 0o755);
        assert!(matches!(
            PrivateDir::ensure(root),
            Err(Error::InsecurePermissions { .. })
        ));
        assert!(matches!(
            dir.create("other"),
            Err(Error::InsecurePermissions { .. })
        ));
    });
}
#[test]
fn redirects_and_unexpected_kinds() {
    each(|dir, root| {
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("secret"), b"outside").unwrap();
        symlink(outside.path(), root.join("link")).unwrap();
        symlink(outside.path().join("secret"), root.join("file-link")).unwrap();
        assert!(matches!(
            dir.open_file("file-link"),
            Err(Error::PathRedirect)
        ));
        assert!(dir.open_file("link/secret").is_err());
        assert!(dir.create("link/new").is_err());
        assert!(!outside.path().join("new").exists());
        assert!(PrivateDir::open(root.join("link")).is_err());
        dir.create_dir("directory").unwrap();
        assert!(matches!(
            dir.open_file("directory"),
            Err(Error::WrongObjectKind)
        ));
        fs::mknodat(&dir, "fifo", FileType::Fifo, Mode::from_raw_mode(0o600), 0).unwrap();
        assert!(matches!(dir.open_file("fifo"), Err(Error::WrongObjectKind)));
        let socket = std::os::unix::net::UnixListener::bind(root.join("socket")).unwrap();
        assert!(dir.open_file("socket").is_err());
        drop(socket);
        symlink("/proc/self/fd/0", root.join("magic")).unwrap();
        assert!(matches!(dir.open_file("magic"), Err(Error::PathRedirect)));
    });
}
#[test]
fn retained_identity_survives_namespace_replacement() {
    each(|dir, root| {
        let mut file = dir.create("key").unwrap();
        file.write_all(b"original").unwrap();
        std::fs::rename(root.join("key"), root.join("old-key")).unwrap();
        let mut other = dir.create("key").unwrap();
        other.write_all(b"replacement").unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();
        let mut s = String::new();
        file.read_to_string(&mut s).unwrap();
        assert_eq!(s, "original");
        let old = root.with_file_name("renamed");
        std::fs::rename(root, &old).unwrap();
        std::fs::create_dir(root).unwrap();
        chmod(root, 0o700);
        dir.create("through-capability").unwrap();
        assert!(old.join("through-capability").exists());
        assert!(!root.join("through-capability").exists());
        let wrong = fs::fstat(&other).unwrap();
        assert!(matches!(
            validate(&file, false, Some(identity(&wrong))),
            Err(Error::IdentityChanged)
        ));
    });
}
#[test]
fn hard_links_are_checked_again_before_io() {
    each(|dir, root| {
        let mut file = dir.create("key").unwrap();
        std::fs::hard_link(root.join("key"), root.join("alias")).unwrap();
        assert!(matches!(
            dir.open_file("key"),
            Err(Error::MultipleHardLinks { links: 2 })
        ));
        assert!(matches!(
            file.verify(),
            Err(Error::MultipleHardLinks { links: 2 })
        ));
        assert!(file.write_all(b"blocked").is_err());
        assert!(file.read(&mut [0]).is_err());
        assert!(std::fs::read(root.join("alias")).unwrap().is_empty());
    });
}
#[test]
fn non_utf8_names_and_invalid_paths() {
    each(|dir, _| {
        let name = OsStr::from_bytes(b"key-\xff");
        dir.create(name).unwrap();
        dir.open_file(name).unwrap();
        for p in ["../escape", "/absolute", "a/../b", "", "a/./b", "C:\\key"] {
            assert!(matches!(dir.create(p), Err(Error::InvalidRelativePath)));
        }
    });
}
#[test]
fn wrong_owner() {
    // chown requires privilege; normal-user CI exercises the metadata policy below.
    let temp = tempfile::tempdir().unwrap();
    let dir = PrivateDir::ensure(temp.path().join("root")).unwrap();
    let file = dir.create("key").unwrap();
    let mut metadata = fs::fstat(&file).unwrap();
    metadata.st_uid = metadata.st_uid.wrapping_add(1);
    assert!(matches!(
        validate_stat(&metadata, false, None),
        Err(Error::WrongOwner { .. })
    ));
    if rustix::process::geteuid().is_root() {
        fs::fchown(&file, Some(rustix::process::Uid::from_raw(12345)), None).unwrap();
        assert!(matches!(file.verify(), Err(Error::WrongOwner { .. })));
        assert!(matches!(file.harden(), Err(Error::WrongOwner { .. })));
    }
}
#[test]
fn restrictive_umask_subprocess() {
    if std::env::var_os("PRIVATE_FS_UMASK_CHILD").is_some() {
        // Only this isolated process changes its umask. The library never does.
        let temp = tempfile::tempdir().unwrap();
        rustix::process::umask(Mode::from_raw_mode(0o200));
        let dir = PrivateDir::ensure(temp.path().join("root")).unwrap();
        let file = dir.create("key").unwrap();
        file.verify().unwrap();
        assert_eq!(
            rustix::process::umask(Mode::from_raw_mode(0o200)),
            Mode::from_raw_mode(0o200)
        );
        return;
    }
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "unix::tests::restrictive_umask_subprocess"])
        .env("PRIVATE_FS_UMASK_CHILD", "1")
        .status()
        .unwrap();
    assert!(status.success());
}

#[test]
fn parent_modes_are_preserved_and_missing_parents_fail() {
    each(|dir, root| {
        let parent = root.parent().unwrap();
        chmod(parent, 0o755);
        PrivateDir::ensure(root).unwrap();
        assert_eq!(
            std::fs::metadata(parent).unwrap().permissions().mode() & 0o7777,
            0o755
        );
        assert!(PrivateDir::ensure(parent.join("absent/root")).is_err());
        assert!(!parent.join("absent").exists());
        assert!(dir.create_dir("absent/nested").is_err());
        assert!(dir.open_file("missing").is_err());
        assert!(!root.join("missing").exists());
        let alias = parent.join("alias");
        symlink(root, &alias).unwrap();
        assert!(PrivateDir::ensure(alias.join("new-root")).is_err());
        assert!(!root.join("new-root").exists());
    });
}

#[test]
fn mutable_permissions_are_checked_before_io() {
    each(|dir, root| {
        let mut file = dir.create("key").unwrap();
        chmod(&root.join("key"), 0o644);
        assert!(file.write(b"blocked").is_err());
        assert!(file.read(&mut [0]).is_err());
        assert!(file.seek(SeekFrom::Start(0)).is_err());
        assert!(file.sync_all().is_err());
        assert!(file.sync_data().is_err());
    });
}

#[test]
fn normalization_never_repairs_untrusted_properties() {
    each(|dir, root| {
        let file = dir.create("key").unwrap();
        chmod(&root.join("key"), 0o400);
        let stat = fs::fstat(&file).unwrap();
        let wrong = Identity {
            ino: stat.st_ino.wrapping_add(1),
            dev: stat.st_dev,
        };
        assert!(matches!(
            normalize_created(&file, false, wrong),
            Err(Error::IdentityChanged)
        ));
        assert_eq!(fs::fstat(&file).unwrap().st_mode & 0o7777, 0o400);
        std::fs::hard_link(root.join("key"), root.join("alias")).unwrap();
        assert!(matches!(
            normalize_created(&file, false, identity(&stat)),
            Err(Error::MultipleHardLinks { .. })
        ));
        assert_eq!(fs::fstat(&file).unwrap().st_mode & 0o7777, 0o400);
    });
}

#[test]
fn hardening_is_explicit_and_does_not_repair_hard_links() {
    each(|dir, root| {
        let file = dir.create("key").unwrap();
        chmod(&root.join("key"), 0o644);
        assert!(matches!(
            file.verify(),
            Err(Error::InsecurePermissions { .. })
        ));
        file.harden().unwrap();
        file.verify().unwrap();
        chmod(root, 0o755);
        assert!(matches!(
            dir.create("blocked"),
            Err(Error::InsecurePermissions { .. })
        ));
        dir.harden().unwrap();
        dir.create("allowed").unwrap();
        std::fs::hard_link(root.join("key"), root.join("alias")).unwrap();
        chmod(&root.join("key"), 0o644);
        assert!(matches!(
            file.harden(),
            Err(Error::MultipleHardLinks { links: 2 })
        ));
        assert_eq!(
            std::fs::metadata(root.join("alias"))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o644
        );
    });
}

#[cfg(target_os = "linux")]
#[test]
fn posix_acl_mask_and_inherited_modes_prevent_additional_access() {
    each(|dir, root| {
        let mut acl = 2u32.to_le_bytes().to_vec();
        for (tag, permissions, id) in [
            (1u16, 7u16, u32::MAX),
            (2, 7, 12345),
            (4, 7, u32::MAX),
            (16, 7, u32::MAX),
            (32, 7, u32::MAX),
        ] {
            acl.extend_from_slice(&tag.to_le_bytes());
            acl.extend_from_slice(&permissions.to_le_bytes());
            acl.extend_from_slice(&id.to_le_bytes());
        }
        fs::fsetxattr(
            &dir,
            "system.posix_acl_default",
            &acl,
            fs::XattrFlags::empty(),
        )
        .unwrap();
        let nested = dir.create_dir("nested-acl").unwrap();
        let file = nested.create("data").unwrap();
        file.verify().unwrap();
        assert_eq!(fs::fstat(&file).unwrap().st_mode & 0o7777, 0o600);
        assert_eq!(fs::fstat(&nested).unwrap().st_mode & 0o7777, 0o700);
        let mut inherited = [0u8; 256];
        let size = fs::fgetxattr(&file, "system.posix_acl_access", &mut inherited).unwrap();
        assert!(size > 0);
        chmod(&root.join("nested-acl/data"), 0o640);
        assert!(matches!(
            file.verify(),
            Err(Error::InsecurePermissions { .. })
        ));
        file.harden().unwrap();
        assert_eq!(fs::fstat(&file).unwrap().st_mode & 0o7777, 0o600);
        file.verify().unwrap();
    });
}
