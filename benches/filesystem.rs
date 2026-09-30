use private_fs::{Durability, PrivateDir};
use std::{fs::File, io::Write};

fn main() {
    divan::main();
}

struct Fixture {
    dir: PrivateDir,
    _temp: tempfile::TempDir,
}
impl Fixture {
    fn new() -> Self {
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
        dir.create_dir("nested").unwrap();
        dir.create("nested/data")
            .unwrap()
            .write_all(b"secret")
            .unwrap();
        Self { dir, _temp: temp }
    }
}

// Fixtures are constructed outside the timed operation. Every measured operation
// retains the normal security checks; no relaxed benchmark-only implementation.
#[divan::bench]
fn child_open(bencher: divan::Bencher) {
    let fixture = Fixture::new();
    bencher.bench_local(|| drop(fixture.dir.open_file("nested/data").unwrap()));
}

#[divan::bench]
fn create_verify(bencher: divan::Bencher) {
    bencher.with_inputs(Fixture::new).bench_refs(|fixture| {
        let file = fixture.dir.create("new").unwrap();
        file.verify().unwrap();
    });
}

#[divan::bench]
fn child_directory(bencher: divan::Bencher) {
    let fixture = Fixture::new();
    bencher.bench_local(|| drop(fixture.dir.ensure_dir("nested").unwrap()));
}

#[divan::bench]
fn create_directory(bencher: divan::Bencher) {
    bencher.with_inputs(Fixture::new).bench_refs(|fixture| {
        fixture.dir.create_dir("new").unwrap();
    });
}

#[divan::bench(args = [Durability::None, Durability::Data, Durability::Full])]
fn atomic_write(bencher: divan::Bencher, durability: Durability) {
    let fixture = Fixture::new();
    bencher.bench_local(|| {
        fixture
            .dir
            .write_atomic_with_durability("nested/data", b"secret", durability)
            .unwrap();
    });
}

#[divan::bench]
fn handle_verify(bencher: divan::Bencher) {
    let fixture = Fixture::new();
    let file = File::open(fixture._temp.path().join("private/nested/data")).unwrap();
    bencher.bench_local(|| private_fs::verify(&file).unwrap());
}

#[divan::bench]
fn handle_harden(bencher: divan::Bencher) {
    let fixture = Fixture::new();
    let file = File::options()
        .read(true)
        .write(true)
        .open(fixture._temp.path().join("private/nested/data"))
        .unwrap();
    bencher.bench_local(|| private_fs::harden(&file).unwrap());
}
