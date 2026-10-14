use crate::{Error, Result};
use std::path::Path;
#[derive(Debug)]
pub struct PrivateDir {
    _unavailable: (),
}
#[derive(Debug)]
pub struct PrivateFile {
    _unavailable: (),
}
impl PrivateDir {
    pub fn harden(&self) -> Result<()> {
        unsupported()
    }
    pub fn open(_: impl AsRef<Path>) -> Result<Self> {
        unsupported()
    }
    pub fn ensure(_: impl AsRef<Path>) -> Result<Self> {
        unsupported()
    }
    pub fn open_file(&self, _: impl AsRef<Path>) -> Result<PrivateFile> {
        unsupported()
    }
    pub fn open_file_with(
        &self,
        _: impl AsRef<Path>,
        _: crate::OpenOptions,
    ) -> Result<PrivateFile> {
        unsupported()
    }
    pub fn entries(&self) -> Result<Vec<std::ffi::OsString>> {
        unsupported()
    }
    pub fn remove_file(&self, _: impl AsRef<Path>, _: crate::Durability) -> Result<()> {
        unsupported()
    }
    pub fn create(&self, _: impl AsRef<Path>) -> Result<PrivateFile> {
        unsupported()
    }
    pub fn open_dir(&self, _: impl AsRef<Path>) -> Result<Self> {
        unsupported()
    }
    pub fn create_dir(&self, _: impl AsRef<Path>) -> Result<Self> {
        unsupported()
    }
    pub fn ensure_dir(&self, _: impl AsRef<Path>) -> Result<Self> {
        unsupported()
    }
    pub fn sync_all(&self) -> Result<()> {
        unsupported()
    }
}
fn unsupported<T>() -> Result<T> {
    Err(Error::UnsupportedFilesystem {
        capability: "native platform security backend",
    })
}

impl PrivateFile {
    pub fn harden(&self) -> Result<()> {
        unsupported()
    }
    pub fn set_len(&self, _: u64) -> Result<()> {
        unsupported()
    }
    pub fn verify(&self) -> Result<()> {
        unsupported()
    }
    pub fn sync_data(&self) -> Result<()> {
        unsupported()
    }
    pub fn sync_all(&self) -> Result<()> {
        unsupported()
    }
}
fn unsupported_io<T>() -> std::io::Result<T> {
    unsupported().map_err(std::io::Error::other)
}
impl std::io::Read for PrivateFile {
    fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
        unsupported_io()
    }
}
impl std::io::Write for PrivateFile {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        unsupported_io()
    }
    fn flush(&mut self) -> std::io::Result<()> {
        unsupported_io()
    }
}
impl std::io::Seek for PrivateFile {
    fn seek(&mut self, _: std::io::SeekFrom) -> std::io::Result<u64> {
        unsupported_io()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn acquisition_fails_without_creating_entries() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("private");
        assert!(matches!(
            PrivateDir::open(&path),
            Err(Error::UnsupportedFilesystem { .. })
        ));
        assert!(matches!(
            PrivateDir::ensure(&path),
            Err(Error::UnsupportedFilesystem { .. })
        ));
        assert!(!path.exists());
    }
}

#[derive(Debug)]
pub struct AtomicFile {
    _unavailable: (),
}
impl PrivateDir {
    pub fn atomic(&self, _: impl AsRef<Path>) -> Result<AtomicFile> {
        unsupported()
    }
    pub fn atomic_with_policy(
        &self,
        _: impl AsRef<Path>,
        _: crate::Durability,
        _: crate::Publication,
    ) -> Result<AtomicFile> {
        unsupported()
    }
    pub fn atomic_durable(&self, _: impl AsRef<Path>) -> Result<AtomicFile> {
        unsupported()
    }
    pub fn atomic_with_durability(
        &self,
        _: impl AsRef<Path>,
        _: crate::Durability,
    ) -> Result<AtomicFile> {
        unsupported()
    }
    pub fn write_atomic(&self, _: impl AsRef<Path>, _: &[u8]) -> Result<()> {
        unsupported()
    }
    pub fn write_atomic_durable(&self, _: impl AsRef<Path>, _: &[u8]) -> Result<()> {
        unsupported()
    }
    pub fn write_atomic_with_durability(
        &self,
        _: impl AsRef<Path>,
        _: &[u8],
        _: crate::Durability,
    ) -> Result<()> {
        unsupported()
    }
}
impl AtomicFile {
    pub fn commit(self) -> Result<()> {
        unsupported()
    }
    pub fn abort(self) -> Result<()> {
        unsupported()
    }
}
impl std::io::Write for AtomicFile {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        unsupported_io()
    }
    fn flush(&mut self) -> std::io::Result<()> {
        unsupported_io()
    }
}
impl std::io::Read for AtomicFile {
    fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
        unsupported_io()
    }
}
impl std::io::Seek for AtomicFile {
    fn seek(&mut self, _: std::io::SeekFrom) -> std::io::Result<u64> {
        unsupported_io()
    }
}
