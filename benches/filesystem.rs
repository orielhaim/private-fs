use private_fs::{Durability, OpenOptions, PrivateDir, Verification};
use std::{
    fs::File,
    io::{Read, Write},
};

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

#[divan::bench]
fn enumerate(bencher: divan::Bencher) {
    let fixture = Fixture::new();
    for n in 0..100 {
        fixture.dir.create(format!("entry-{n}")).unwrap();
    }
    bencher.bench_local(|| divan::black_box(fixture.dir.entries().unwrap()));
}

#[divan::bench]
fn remove(bencher: divan::Bencher) {
    bencher.with_inputs(Fixture::new).bench_refs(|fixture| {
        fixture
            .dir
            .remove_file("nested/data", Durability::None)
            .unwrap();
    });
}

#[divan::bench(args = [Verification::PerIo, Verification::OnDemand])]
fn streaming_read(bencher: divan::Bencher, verification: Verification) {
    let fixture = Fixture::new();
    fixture
        .dir
        .create("stream")
        .unwrap()
        .write_all(&[42; 65536])
        .unwrap();
    bencher.bench_local(|| {
        let mut file = fixture
            .dir
            .open_file_with(
                "stream",
                OpenOptions {
                    verification,
                    ..OpenOptions::default()
                },
            )
            .unwrap();
        file.verify().unwrap();
        let mut buffer = [0u8; 1024];
        while file.read(&mut buffer).unwrap() != 0 {
            divan::black_box(&buffer);
        }
        file.verify().unwrap();
    });
}
