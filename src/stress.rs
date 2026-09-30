//! Native namespace stress. Attacker operations use ambient paths deliberately;
//! the victim always uses the retained capability and must never follow redirects.
use crate::PrivateDir;
use std::{
    io::Read,
    path::Path,
    sync::{
        Barrier,
        atomic::{AtomicUsize, Ordering},
    },
};

#[test]
fn acquisition_rejects_interior_dots_before_path_normalization() {
    let temp = tempfile::tempdir().unwrap();
    for path in [
        temp.path().join(".").join("private"),
        temp.path().join("..").join("private"),
    ] {
        assert!(matches!(
            PrivateDir::ensure(path),
            Err(crate::Error::InvalidRelativePath)
        ));
    }
    assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 0);
}

pub(crate) fn redirect(dir: &PrivateDir, root: &Path, outside: &Path) {
    let barrier = Barrier::new(2);
    let replacements = AtomicUsize::new(0);
    std::thread::scope(|scope| {
        scope.spawn(|| {
            barrier.wait();
            for _ in 0..600 {
                if std::fs::rename(root.join("slot"), root.join("park")).is_err() {
                    continue;
                }
                if std::fs::rename(root.join("bad"), root.join("slot")).is_ok() {
                    replacements.fetch_add(1, Ordering::Relaxed);
                    std::thread::yield_now();
                    std::fs::rename(root.join("slot"), root.join("bad")).unwrap();
                }
                std::fs::rename(root.join("park"), root.join("slot")).unwrap();
            }
        });
        barrier.wait();
        for n in 0..600 {
            if let Ok(mut file) = dir.open_file("slot/data") {
                let mut bytes = Vec::new();
                if file.read_to_end(&mut bytes).is_ok() {
                    assert_eq!(bytes, b"inside");
                }
            }
            let _ = dir.create(format!("slot/new-{n}"));
        }
    });
    assert!(
        replacements.load(Ordering::Relaxed) > 0,
        "attacker made no replacements"
    );
    assert_eq!(std::fs::read(outside.join("data")).unwrap(), b"outside");
    assert_eq!(std::fs::read_dir(outside).unwrap().count(), 1);
}

#[test]
fn hard_link_races_never_accept_a_stable_alias() {
    let temp = tempfile::tempdir().unwrap();
    #[cfg(target_os = "macos")]
    crate::macos::clear(std::fs::File::open(temp.path()).unwrap()).unwrap();
    let dir = PrivateDir::ensure(temp.path().join("private")).unwrap();
    dir.create("data").unwrap();
    let root = temp.path().join("private");
    let barrier = Barrier::new(2);
    std::thread::scope(|scope| {
        scope.spawn(|| {
            barrier.wait();
            for _ in 0..600 {
                std::fs::hard_link(root.join("data"), root.join("alias")).unwrap();
                std::thread::yield_now();
                std::fs::remove_file(root.join("alias")).unwrap();
            }
        });
        barrier.wait();
        for _ in 0..600 {
            if let Ok(file) = dir.open_file("data") {
                let _ = file.verify(); // A concurrent change may legitimately fail.
            }
        }
    });
    std::fs::hard_link(root.join("data"), root.join("alias")).unwrap();
    assert!(dir.open_file("data").is_err());
    std::fs::remove_file(root.join("alias")).unwrap();
    dir.open_file("data").unwrap().verify().unwrap();
}

#[test]
fn concurrent_atomic_publishers_leave_a_complete_private_destination() {
    let temp = tempfile::tempdir().unwrap();
    #[cfg(target_os = "macos")]
    crate::macos::clear(std::fs::File::open(temp.path()).unwrap()).unwrap();
    let dir = PrivateDir::ensure(temp.path().join("private")).unwrap();
    let a = vec![b'a'; 8192];
    let b = vec![b'b'; 8192];
    dir.write_atomic("data", &a).unwrap();
    let barrier = Barrier::new(3);
    let committed = AtomicUsize::new(0);
    std::thread::scope(|scope| {
        for bytes in [&a, &b] {
            scope.spawn(|| {
                barrier.wait();
                for _ in 0..80 {
                    // A competing rename can make final identity validation fail;
                    // it cannot justify rollback or deletion of another writer.
                    match dir.write_atomic("data", bytes) {
                        Ok(()) => {
                            committed.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(crate::Error::AtomicCommit { .. }) => (),
                        Err(error) => panic!("unexpected pre-commit failure: {error}"),
                    }
                }
            });
        }
        barrier.wait();
        for _ in 0..300 {
            let bytes = std::fs::read(temp.path().join("private/data")).unwrap();
            assert!(bytes == a || bytes == b);
        }
    });
    assert!(
        committed.load(Ordering::Relaxed) > 0,
        "no publisher completed validation"
    );
    let mut file = dir.open_file("data").unwrap();
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).unwrap();
    assert!(bytes == a || bytes == b);
    file.verify().unwrap();
}
