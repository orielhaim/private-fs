use super::*;
use std::{cell::RefCell, rc::Rc};

#[test]
fn named_temp_collision_budget_fails_without_touching_existing_objects() {
    let (root, dir) = fixture();
    dir.create("data").unwrap().write_all(b"old").unwrap();
    dir.create("collision")
        .unwrap()
        .write_all(b"sentinel")
        .unwrap();
    let faults = Faults {
        force_named: true,
        names: std::iter::repeat_n(OsString::from("collision"), 128).collect(),
        ..Default::default()
    };
    assert!(
        matches!(AtomicFile::new(&dir, Path::new("data"), Durability::None, faults),
        Err(Error::Io(e)) if e.kind() == io::ErrorKind::AlreadyExists)
    );
    assert_eq!(
        std::fs::read(root.path().join("private/data")).unwrap(),
        b"old"
    );
    assert_eq!(
        std::fs::read(root.path().join("private/collision")).unwrap(),
        b"sentinel"
    );
    assert_eq!(
        std::fs::read_dir(root.path().join("private"))
            .unwrap()
            .count(),
        2
    );
    dir.write_atomic("data", b"retry").unwrap();
    assert_eq!(
        std::fs::read(root.path().join("private/data")).unwrap(),
        b"retry"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn anonymous_link_collision_budget_closes_unlinked_staging_and_allows_retry() {
    let (root, dir) = fixture();
    dir.create("data").unwrap().write_all(b"old").unwrap();
    dir.create("collision")
        .unwrap()
        .write_all(b"sentinel")
        .unwrap();
    let faults = Faults {
        names: std::iter::repeat_n(OsString::from("collision"), 128).collect(),
        ..Default::default()
    };
    let mut writer = AtomicFile::new(&dir, Path::new("data"), Durability::None, faults).unwrap();
    assert!(writer.name.is_none());
    writer.write_all(b"new").unwrap();
    assert!(
        matches!(writer.commit(), Err(Error::AtomicCommit { may_have_published: false, source })
        if matches!(*source, Error::Io(ref e) if e.kind() == io::ErrorKind::AlreadyExists))
    );
    assert_eq!(
        std::fs::read(root.path().join("private/data")).unwrap(),
        b"old"
    );
    assert_eq!(
        std::fs::read(root.path().join("private/collision")).unwrap(),
        b"sentinel"
    );
    assert_eq!(
        std::fs::read_dir(root.path().join("private"))
            .unwrap()
            .count(),
        2
    );
    dir.write_atomic("data", b"retry").unwrap();
    assert_eq!(
        std::fs::read(root.path().join("private/data")).unwrap(),
        b"retry"
    );
}
fn fixture() -> (tempfile::TempDir, PrivateDir) {
    let temp = tempfile::tempdir().unwrap();
    #[cfg(target_os = "macos")]
    crate::macos::clear(std::fs::File::open(temp.path()).unwrap()).unwrap();
    let dir = PrivateDir::ensure(temp.path().join("private")).unwrap();
    (temp, dir)
}
#[test]
fn streaming_replacement_and_durability_tiers() {
    for durability in [Durability::None, Durability::Data, Durability::Full] {
        let (root, dir) = fixture();
        dir.create_dir("nested").unwrap();
        dir.create("nested/data")
            .unwrap()
            .write_all(b"old")
            .unwrap();
        let mut writer = dir
            .atomic_with_durability("nested/data", durability)
            .unwrap();
        writer.write_all(b"complete-new").unwrap();
        assert_eq!(
            std::fs::read(root.path().join("private/nested/data")).unwrap(),
            b"old"
        );
        writer.commit().unwrap();
        assert_eq!(
            std::fs::read(root.path().join("private/nested/data")).unwrap(),
            b"complete-new"
        );
        dir.open_file("nested/data").unwrap().verify().unwrap();
        assert_eq!(
            std::fs::read_dir(root.path().join("private/nested"))
                .unwrap()
                .count(),
            1
        );
    }
}
#[test]
fn high_level_new_destination_and_round_trip() {
    let (root, dir) = fixture();
    dir.write_atomic("data", b"first").unwrap();
    dir.write_atomic_durable("data", b"second").unwrap();
    dir.write_atomic_with_durability("data", b"third", Durability::Data)
        .unwrap();
    assert_eq!(
        std::fs::read(root.path().join("private/data")).unwrap(),
        b"third"
    );
    assert_eq!(
        std::fs::read_dir(root.path().join("private"))
            .unwrap()
            .count(),
        1
    );
}
#[test]
fn every_commit_checkpoint_preserves_visibility_and_retry() {
    use FaultPoint::*;
    let points = [
        BeforeTempCreate,
        AfterTempCreate,
        BeforeTempValidate,
        AfterTempValidate,
        BeforeFileSync,
        AfterFileSync,
        BeforePublish,
        AfterPublish,
        BeforeReopen,
        AfterReopen,
        BeforePublishedValidate,
        AfterPublishedValidate,
        BeforeParentSync,
        AfterParentSync,
        BeforeFinalValidate,
        AfterFinalValidate,
    ];
    for failure in points {
        let (root, dir) = fixture();
        dir.create("data").unwrap().write_all(b"old").unwrap();
        let visited = Rc::new(RefCell::new(Vec::new()));
        let log = visited.clone();
        let faults = Faults {
            force_named: true,
            callback: Some(Box::new(move |point, _| {
                log.borrow_mut().push(point);
                if point == failure {
                    Err(io::Error::other("injected").into())
                } else {
                    Ok(())
                }
            })),
            ..Default::default()
        };
        let result = AtomicFile::new(&dir, Path::new("data"), Durability::Full, faults).and_then(
            |mut file| {
                file.write_all(b"new")?;
                file.commit()
            },
        );
        assert!(result.is_err(), "{failure:?}");
        assert!(visited.borrow().contains(&failure));
        let after_publication = matches!(
            failure,
            AfterPublish
                | BeforeReopen
                | AfterReopen
                | BeforePublishedValidate
                | AfterPublishedValidate
                | BeforeParentSync
                | AfterParentSync
                | BeforeFinalValidate
                | AfterFinalValidate
        );
        assert_eq!(
            std::fs::read(root.path().join("private/data")).unwrap(),
            if after_publication { b"new" } else { b"old" }
        );
        if let Err(Error::AtomicCommit {
            may_have_published, ..
        }) = &result
        {
            assert_eq!(*may_have_published, after_publication);
        }
        dir.open_file("data").unwrap().verify().unwrap();
        dir.write_atomic_durable("data", b"retry").unwrap();
        assert_eq!(
            std::fs::read(root.path().join("private/data")).unwrap(),
            b"retry"
        );
    }
}
#[test]
fn no_implicit_sync_and_full_sync_order() {
    for durability in [Durability::None, Durability::Data, Durability::Full] {
        let (_root, dir) = fixture();
        let log = Rc::new(RefCell::new(Vec::new()));
        let trace = log.clone();
        let faults = Faults {
            callback: Some(Box::new(move |point, view| {
                // The context exposes only retained handles and capability-relative names.
                view.parent.check_private()?;
                if let Some(file) = view.file {
                    let _ = file.metadata()?;
                }
                trace.borrow_mut().push(point);
                Ok(())
            })),
            ..Default::default()
        };
        let mut file = AtomicFile::new(&dir, Path::new("data"), durability, faults).unwrap();
        file.write_all(b"data").unwrap();
        file.commit().unwrap();
        let log = log.borrow();
        let index = |p| log.iter().position(|v| *v == p).unwrap();
        assert_eq!(
            log.contains(&FaultPoint::BeforeFileSync),
            durability != Durability::None
        );
        assert_eq!(
            log.contains(&FaultPoint::BeforeParentSync),
            durability == Durability::Full
        );
        if durability != Durability::None {
            assert!(index(FaultPoint::AfterFileSync) < index(FaultPoint::BeforePublish));
        }
        if durability == Durability::Full {
            assert!(
                index(FaultPoint::AfterPublishedValidate) < index(FaultPoint::BeforeParentSync)
            );
            assert!(index(FaultPoint::AfterParentSync) < index(FaultPoint::BeforeFinalValidate));
        }
        #[cfg(target_os = "linux")]
        if log.contains(&FaultPoint::AfterTempLink) && durability != Durability::None {
            assert!(index(FaultPoint::AfterTempLink) < index(FaultPoint::BeforeFileSync));
        }
    }
}
#[test]
fn write_failures_poison_transaction_and_preserve_old_data() {
    for failure in [FaultPoint::BeforeWrite, FaultPoint::AfterWrite] {
        let (root, dir) = fixture();
        dir.create("data").unwrap().write_all(b"old").unwrap();
        let faults = Faults {
            callback: Some(Box::new(move |p, _| {
                if p == failure {
                    Err(io::Error::other("write failed").into())
                } else {
                    Ok(())
                }
            })),
            ..Default::default()
        };
        let mut writer =
            AtomicFile::new(&dir, Path::new("data"), Durability::None, faults).unwrap();
        assert!(writer.write_all(b"partial").is_err());
        assert!(writer.write_all(b"later").is_err());
        assert!(
            matches!(writer.commit(), Err(Error::AtomicCommit { may_have_published: false, source }) if matches!(*source, Error::WriterFailed))
        );
        assert_eq!(
            std::fs::read(root.path().join("private/data")).unwrap(),
            b"old"
        );
    }
}
#[test]
fn exclusive_temp_collisions_and_target_name_are_skipped() {
    let (root, dir) = fixture();
    dir.create("collision")
        .unwrap()
        .write_all(b"sentinel")
        .unwrap();
    let faults = Faults {
        force_named: true,
        names: [
            OsString::from("data"),
            OsString::from("collision"),
            OsString::from("staging"),
        ]
        .into(),
        ..Default::default()
    };
    let mut writer = AtomicFile::new(&dir, Path::new("data"), Durability::None, faults).unwrap();
    assert!(!root.path().join("private/data").exists());
    writer.write_all(b"new").unwrap();
    writer.commit().unwrap();
    assert_eq!(
        std::fs::read(root.path().join("private/collision")).unwrap(),
        b"sentinel"
    );
    assert_eq!(
        std::fs::read(root.path().join("private/data")).unwrap(),
        b"new"
    );
}
#[test]
fn published_name_replacement_is_detected_without_cleanup_of_target() {
    for stage in [
        FaultPoint::AfterPublish,
        FaultPoint::AfterReopen,
        FaultPoint::BeforeFinalValidate,
    ] {
        let (root, dir) = fixture();
        let path = root.path().join("private");
        let faults = Faults {
            callback: Some(Box::new(move |p, view| {
                if p == stage {
                    std::fs::rename(path.join("data"), path.join("ours"))?;
                    view.parent.create("data")?.write_all(b"replacement")?;
                }
                Ok(())
            })),
            ..Default::default()
        };
        let mut writer =
            AtomicFile::new(&dir, Path::new("data"), Durability::None, faults).unwrap();
        writer.write_all(b"ours").unwrap();
        assert!(
            matches!(writer.commit(), Err(Error::AtomicCommit { may_have_published: true, source }) if matches!(*source, Error::IdentityChanged))
        );
        assert_eq!(
            std::fs::read(root.path().join("private/data")).unwrap(),
            b"replacement"
        );
        assert_eq!(
            std::fs::read(root.path().join("private/ours")).unwrap(),
            b"ours"
        );
    }
}
#[test]
fn original_parent_survives_root_path_replacement() {
    let (root, dir) = fixture();
    let original = root.path().join("private");
    let moved = root.path().join("moved");
    let original_hook = original.clone();
    let moved_hook = moved.clone();
    let mut changed = false;
    let faults = Faults {
        callback: Some(Box::new(move |p, _| {
            if p == FaultPoint::BeforeTempCreate && !changed {
                std::fs::rename(&original_hook, &moved_hook)?;
                PrivateDir::ensure(&original_hook)?;
                changed = true;
            }
            Ok(())
        })),
        ..Default::default()
    };
    let mut writer = AtomicFile::new(&dir, Path::new("data"), Durability::Full, faults).unwrap();
    writer.write_all(b"original-parent").unwrap();
    writer.commit().unwrap();
    assert_eq!(
        std::fs::read(moved.join("data")).unwrap(),
        b"original-parent"
    );
    assert!(!original.join("data").exists());
}
#[test]
fn cleanup_never_deletes_a_replacement_object() {
    let (root, dir) = fixture();
    let mut writer = AtomicFile::new(
        &dir,
        Path::new("data"),
        Durability::None,
        Faults {
            force_named: true,
            ..Default::default()
        },
    )
    .unwrap();
    writer.write_all(b"ours").unwrap();
    let name = writer.name.clone().unwrap();
    let path = root.path().join("private");
    std::fs::rename(path.join(&name), path.join("ours")).unwrap();
    dir.create(&name)
        .unwrap()
        .write_all(b"replacement")
        .unwrap();
    let result = writer.abort();
    #[cfg(windows)]
    assert!(result.is_ok());
    #[cfg(unix)]
    assert!(matches!(result, Err(Error::IdentityChanged)));
    assert_eq!(std::fs::read(path.join(&name)).unwrap(), b"replacement");
}
#[test]
fn abort_cleanup_reports_platform_guarantees() {
    let (root, dir) = fixture();
    let writer = AtomicFile::new(
        &dir,
        Path::new("data"),
        Durability::None,
        Faults {
            force_named: true,
            ..Default::default()
        },
    )
    .unwrap();
    let result = writer.abort();
    assert!(!root.path().join("private/data").exists());
    #[cfg(windows)]
    {
        result.unwrap();
        assert_eq!(
            std::fs::read_dir(root.path().join("private"))
                .unwrap()
                .count(),
            0
        );
    }
    #[cfg(unix)]
    {
        assert!(matches!(result, Err(Error::UnsupportedFilesystem { .. })));
        assert_eq!(
            std::fs::read_dir(root.path().join("private"))
                .unwrap()
                .count(),
            1
        );
    }
}
#[cfg(target_os = "linux")]
#[test]
fn anonymous_abort_and_link_failure_are_clean() {
    for failure in [FaultPoint::BeforeTempLink, FaultPoint::AfterTempLink] {
        let (root, dir) = fixture();
        let faults = Faults {
            callback: Some(Box::new(move |p, _| {
                if p == failure {
                    Err(io::Error::other("link fault").into())
                } else {
                    Ok(())
                }
            })),
            ..Default::default()
        };
        let mut writer =
            AtomicFile::new(&dir, Path::new("data"), Durability::None, faults).unwrap();
        assert!(writer.name.is_none());
        writer.write_all(b"new").unwrap();
        assert!(writer.commit().is_err());
        assert_eq!(
            std::fs::read_dir(root.path().join("private"))
                .unwrap()
                .count(),
            usize::from(failure == FaultPoint::AfterTempLink)
        );
    }
    let (root, dir) = fixture();
    dir.atomic("data").unwrap().abort().unwrap();
    assert_eq!(
        std::fs::read_dir(root.path().join("private"))
            .unwrap()
            .count(),
        0
    );
}
#[test]
fn cleanup_faults_are_not_retried_by_drop() {
    let (_root, dir) = fixture();
    let calls = Rc::new(RefCell::new(0));
    let count = calls.clone();
    let faults = Faults {
        callback: Some(Box::new(move |p, _| {
            if p == FaultPoint::BeforeCleanup {
                *count.borrow_mut() += 1;
                return Err(io::Error::other("cleanup fault").into());
            }
            Ok(())
        })),
        ..Default::default()
    };
    let writer = AtomicFile::new(&dir, Path::new("data"), Durability::None, faults).unwrap();
    assert!(writer.abort().is_err());
    assert_eq!(*calls.borrow(), 1);
}

#[test]
fn temp_name_substitution_cannot_publish_or_delete_the_replacement() {
    let (root, dir) = fixture();
    dir.create("data").unwrap().write_all(b"old").unwrap();
    let folder = root.path().join("private");
    let changed_name = Rc::new(RefCell::new(None));
    let seen = changed_name.clone();
    let faults = Faults {
        force_named: true,
        callback: Some(Box::new(move |p, view| {
            if p == FaultPoint::BeforePublish {
                let name = view.temp_name.unwrap().to_os_string();
                std::fs::rename(folder.join(&name), folder.join("original-temp"))?;
                view.parent.create(&name)?.write_all(b"replacement")?;
                *seen.borrow_mut() = Some(name);
            }
            Ok(())
        })),
        ..Default::default()
    };
    let mut writer = AtomicFile::new(&dir, Path::new("data"), Durability::None, faults).unwrap();
    writer.write_all(b"new").unwrap();
    assert!(
        matches!(writer.commit(), Err(Error::AtomicCommit { may_have_published: false, source }) if matches!(*source, Error::IdentityChanged))
    );
    let name = changed_name.borrow().clone().unwrap();
    assert_eq!(
        std::fs::read(root.path().join("private").join(name)).unwrap(),
        b"replacement"
    );
    assert_eq!(
        std::fs::read(root.path().join("private/data")).unwrap(),
        b"old"
    );
}
#[test]
fn hard_link_injection_before_and_after_publication_is_rejected() {
    for stage in [FaultPoint::BeforePublish, FaultPoint::AfterPublish] {
        let (root, dir) = fixture();
        let folder = root.path().join("private");
        let faults = Faults {
            force_named: true,
            callback: Some(Box::new(move |p, view| {
                if p == stage {
                    std::fs::hard_link(
                        folder.join(if stage == FaultPoint::BeforePublish {
                            view.temp_name.unwrap()
                        } else {
                            OsStr::new("data")
                        }),
                        folder.join("alias"),
                    )?;
                }
                Ok(())
            })),
            ..Default::default()
        };
        let mut writer =
            AtomicFile::new(&dir, Path::new("data"), Durability::None, faults).unwrap();
        writer.write_all(b"private").unwrap();
        assert!(
            matches!(writer.commit(), Err(Error::AtomicCommit { may_have_published, source }) if may_have_published == (stage == FaultPoint::AfterPublish) && matches!(*source, Error::MultipleHardLinks { links: 2 }))
        );
        assert_eq!(
            std::fs::read(root.path().join("private/alias")).unwrap(),
            b"private"
        );
        assert_eq!(
            root.path().join("private/data").exists(),
            stage == FaultPoint::AfterPublish
        );
    }
}
#[test]
fn existing_targets_are_validated_without_repair() {
    let (root, dir) = fixture();
    dir.create("data").unwrap().write_all(b"old").unwrap();
    std::fs::hard_link(root.path().join("private/data"), root.path().join("alias")).unwrap();
    assert!(
        matches!(dir.write_atomic("data", b"new"), Err(Error::AtomicCommit { may_have_published: false, source }) if matches!(*source, Error::MultipleHardLinks { .. }))
    );
    assert_eq!(std::fs::read(root.path().join("alias")).unwrap(), b"old");
    dir.create_dir("directory").unwrap();
    assert!(dir.write_atomic("directory", b"new").is_err());
    for path in ["../escape", "/absolute", "", "C:stream"] {
        assert!(matches!(dir.atomic(path), Err(Error::InvalidRelativePath)));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{PermissionsExt, symlink};
        std::fs::remove_file(root.path().join("alias")).unwrap();
        std::fs::set_permissions(
            root.path().join("private/data"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(
            matches!(dir.write_atomic("data", b"new"), Err(Error::AtomicCommit { may_have_published: false, source }) if matches!(*source, Error::InsecurePermissions { .. }))
        );
        symlink(
            root.path().join("outside"),
            root.path().join("private/link"),
        )
        .unwrap();
        assert!(
            matches!(dir.write_atomic("link", b"new"), Err(Error::AtomicCommit { source, .. }) if matches!(*source, Error::PathRedirect))
        );
        assert!(!root.path().join("outside").exists());
    }
}
#[test]
fn cleanup_after_checkpoint_and_primary_error_are_preserved() {
    let (_root, dir) = fixture();
    let cleanup_calls = Rc::new(RefCell::new(0));
    let count = cleanup_calls.clone();
    let faults = Faults {
        callback: Some(Box::new(move |p, _| {
            if p == FaultPoint::BeforeCleanup {
                *count.borrow_mut() += 1;
                return Err(io::Error::other("cleanup failed").into());
            }
            if p == FaultPoint::BeforePublish {
                return Err(io::Error::other("primary failure").into());
            }
            Ok(())
        })),
        ..Default::default()
    };
    let mut file = AtomicFile::new(&dir, Path::new("data"), Durability::None, faults).unwrap();
    file.write_all(b"new").unwrap();
    assert!(
        matches!(file.commit(), Err(Error::AtomicCommit { source, .. }) if source.to_string() == "primary failure")
    );
    assert_eq!(*cleanup_calls.borrow(), 1);
    let hit = Rc::new(RefCell::new(false));
    let seen = hit.clone();
    let faults = Faults {
        callback: Some(Box::new(move |p, _| {
            if p == FaultPoint::AfterCleanup {
                *seen.borrow_mut() = true;
                return Err(io::Error::other("after cleanup").into());
            }
            Ok(())
        })),
        ..Default::default()
    };
    // Default staging is anonymous on Linux, exact-handle-deletable on Windows.
    #[cfg(not(target_os = "macos"))]
    {
        let writer = AtomicFile::new(&dir, Path::new("other"), Durability::None, faults).unwrap();
        assert!(writer.abort().is_err());
        assert!(*hit.borrow());
    }
    #[cfg(target_os = "macos")]
    {
        let _ = faults;
    }
}
#[test]
fn concurrent_readers_observe_complete_replacements() {
    let (root, dir) = fixture();
    let path = root.path().join("private/data");
    let old = vec![b'a'; 32768];
    let new = vec![b'b'; 32768];
    dir.write_atomic("data", &old).unwrap();
    let reader_old = old.clone();
    let reader_new = new.clone();
    let reader_path = path.clone();
    let reader = std::thread::spawn(move || {
        for _ in 0..80 {
            let bytes = std::fs::read(&reader_path).unwrap();
            assert!(bytes == reader_old || bytes == reader_new);
        }
    });
    for i in 0..20 {
        dir.write_atomic("data", if i % 2 == 0 { &new } else { &old })
            .unwrap();
    }
    reader.join().unwrap();
    assert_eq!(std::fs::read(path).unwrap(), old);
}
#[test]
fn arbitrary_handle_hardening_uses_the_original_object_and_preserves_cursor() {
    use std::io::{Read, Seek};
    let (root, dir) = fixture();
    let mut creator = dir.create("data").unwrap();
    creator.write_all(b"original").unwrap();
    let path = root.path().join("private/data");
    let mut donor = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    donor.seek(SeekFrom::Start(3)).unwrap();
    std::fs::rename(&path, root.path().join("private/moved")).unwrap();
    let replacement = dir.create("data").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            root.path().join("private/moved"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(matches!(
            crate::verify(&donor),
            Err(Error::InsecurePermissions { .. })
        ));
    }
    crate::harden(&donor).unwrap();
    crate::verify(&donor).unwrap();
    replacement.verify().unwrap();
    assert_eq!(donor.stream_position().unwrap(), 3);
    let mut rest = String::new();
    donor.read_to_string(&mut rest).unwrap();
    assert_eq!(rest, "ginal");
    std::fs::hard_link(root.path().join("private/moved"), root.path().join("alias")).unwrap();
    assert!(matches!(
        crate::verify(&donor),
        Err(Error::MultipleHardLinks { .. })
    ));
    assert!(matches!(
        crate::harden(&donor),
        Err(Error::MultipleHardLinks { .. })
    ));
    #[cfg(unix)]
    {
        let directory_file = std::fs::File::open(root.path().join("private")).unwrap();
        assert!(matches!(
            crate::harden(&directory_file),
            Err(Error::WrongObjectKind)
        ));
    }
}
#[cfg(target_os = "linux")]
#[test]
fn anonymous_link_collision_and_unexpected_alias_are_rejected() {
    let (root, dir) = fixture();
    dir.create("collision")
        .unwrap()
        .write_all(b"sentinel")
        .unwrap();
    let faults = Faults {
        names: [
            OsString::from("data"),
            OsString::from("collision"),
            OsString::from("linked"),
        ]
        .into(),
        ..Default::default()
    };
    let mut writer = AtomicFile::new(&dir, Path::new("data"), Durability::None, faults).unwrap();
    writer.write_all(b"new").unwrap();
    writer.commit().unwrap();
    assert_eq!(
        std::fs::read(root.path().join("private/collision")).unwrap(),
        b"sentinel"
    );
    use std::os::fd::AsFd;
    let faults = Faults {
        callback: Some(Box::new(move |p, view| {
            if p == FaultPoint::AfterTempCreate {
                rustix::fs::linkat(
                    view.file.unwrap(),
                    "",
                    view.parent.as_fd(),
                    "outside-alias",
                    rustix::fs::AtFlags::EMPTY_PATH,
                )?;
            }
            Ok(())
        })),
        ..Default::default()
    };
    assert!(matches!(
        AtomicFile::new(&dir, Path::new("other"), Durability::None, faults),
        Err(Error::UnexpectedLinkCount {
            expected: 0,
            actual: 1
        })
    ));
}

#[test]
fn process_exit_at_transaction_boundaries_preserves_complete_target() {
    if let Some(path) = std::env::var_os("PRIVATE_FS_CRASH_ROOT") {
        let point = match std::env::var("PRIVATE_FS_CRASH_STAGE").unwrap().as_str() {
            "write" => FaultPoint::AfterWrite,
            "publish" => FaultPoint::BeforePublish,
            "published" => FaultPoint::AfterPublish,
            "synced" => FaultPoint::AfterParentSync,
            _ => unreachable!(),
        };
        let dir = PrivateDir::open(path).unwrap();
        let faults = Faults {
            callback: Some(Box::new(move |p, _| {
                if p == point {
                    std::process::exit(37);
                }
                Ok(())
            })),
            ..Default::default()
        };
        let mut writer =
            AtomicFile::new(&dir, Path::new("data"), Durability::Full, faults).unwrap();
        writer.write_all(b"new").unwrap();
        writer.commit().unwrap();
        panic!("checkpoint not reached");
    }
    for stage in ["write", "publish", "published", "synced"] {
        let (root, dir) = fixture();
        dir.write_atomic_durable("data", b"old").unwrap();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "atomic::tests::process_exit_at_transaction_boundaries_preserves_complete_target",
            ])
            .env("PRIVATE_FS_CRASH_ROOT", root.path().join("private"))
            .env("PRIVATE_FS_CRASH_STAGE", stage)
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(37));
        assert_eq!(
            std::fs::read(root.path().join("private/data")).unwrap(),
            if stage == "published" || stage == "synced" {
                b"new"
            } else {
                b"old"
            }
        );
        for entry in std::fs::read_dir(root.path().join("private")).unwrap() {
            dir.open_file(entry.unwrap().file_name())
                .unwrap()
                .verify()
                .unwrap();
        }
        dir.write_atomic_durable("data", b"retry").unwrap();
        assert_eq!(
            std::fs::read(root.path().join("private/data")).unwrap(),
            b"retry"
        );
    }
}
#[test]
fn failed_seek_cannot_publish_an_unintended_stream() {
    let (root, dir) = fixture();
    dir.write_atomic("data", b"old").unwrap();
    let mut writer = dir.atomic("data").unwrap();
    writer.write_all(b"new").unwrap();
    assert!(writer.seek(SeekFrom::Current(-100)).is_err());
    assert!(
        matches!(writer.commit(), Err(Error::AtomicCommit { source, .. }) if matches!(*source, Error::WriterFailed))
    );
    assert_eq!(
        std::fs::read(root.path().join("private/data")).unwrap(),
        b"old"
    );
}
#[test]
fn random_temp_names_have_full_entropy_encoding() {
    let mut source = Faults::default();
    for _ in 0..64 {
        let name = source.name().unwrap();
        let spelling = name.to_str().unwrap();
        let suffix = spelling
            .strip_prefix(".private-fs-")
            .unwrap()
            .strip_suffix(".tmp")
            .unwrap();
        assert_eq!(suffix.len(), 32);
        assert!(suffix.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(
            crate::path::RelativePath::new(Path::new(&name))
                .unwrap()
                .0
                .len(),
            1
        );
    }
}

#[test]
fn an_open_reader_survives_replacement_without_partial_contents() {
    let (root, dir) = fixture();
    dir.write_atomic("data", b"old-complete").unwrap();
    let mut reader = std::fs::File::open(root.path().join("private/data")).unwrap();
    dir.write_atomic("data", b"new-complete").unwrap();
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"old-complete");
    assert_eq!(
        std::fs::read(root.path().join("private/data")).unwrap(),
        b"new-complete"
    );
}
#[test]
fn non_unicode_target_names_remain_lossless() {
    #[cfg(unix)]
    let name = {
        use std::os::unix::ffi::OsStringExt;
        OsString::from_vec(vec![b'k', 0xff])
    };
    #[cfg(windows)]
    let name = {
        use std::os::windows::ffi::OsStringExt;
        OsString::from_wide(&[b'k' as u16, 0xd800])
    };
    let (_root, dir) = fixture();
    dir.write_atomic(&name, b"first").unwrap();
    dir.write_atomic_durable(&name, b"second").unwrap();
    let mut file = dir.open_file(&name).unwrap();
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"second");
}
