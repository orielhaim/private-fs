//! Atomic transaction state and persistence ordering, shared by native backends.
use crate::{Durability, Error, PrivateDir, PrivateFile, Publication, Result};
use std::{
    ffi::{OsStr, OsString},
    io::{self, Read, Seek, SeekFrom, Write},
    path::Path,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FaultPoint {
    BeforeTempCreate,
    AfterTempCreate,
    BeforeTempValidate,
    AfterTempValidate,
    BeforeWrite,
    AfterWrite,
    BeforeTempLink,
    AfterTempLink,
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
    BeforeCleanup,
    AfterCleanup,
}
#[cfg(test)]
pub(crate) struct FaultView<'a> {
    pub parent: &'a PrivateDir,
    pub file: Option<&'a std::fs::File>,
    pub temp_name: Option<&'a OsStr>,
}
#[cfg(test)]
type FaultCallback = Box<dyn for<'a> FnMut(FaultPoint, FaultView<'a>) -> Result<()>>;
#[derive(Default)]
pub(crate) struct Faults {
    #[cfg(test)]
    pub callback: Option<FaultCallback>,
    #[cfg(test)]
    pub force_named: bool,
    #[cfg(test)]
    pub names: std::collections::VecDeque<OsString>,
}
impl Faults {
    fn checkpoint(
        &mut self,
        point: FaultPoint,
        parent: &PrivateDir,
        temp: Option<&PrivateFile>,
        name: Option<&OsStr>,
    ) -> Result<()> {
        #[cfg(test)]
        if let Some(callback) = &mut self.callback {
            callback(
                point,
                FaultView {
                    parent,
                    file: temp.map(PrivateFile::raw_file),
                    temp_name: name,
                },
            )?;
        }
        let _ = (point, parent, temp, name);
        Ok(())
    }
    fn name(&mut self) -> Result<OsString> {
        #[cfg(test)]
        if let Some(name) = self.names.pop_front() {
            return Ok(name);
        }
        let mut nonce = [0u8; 16];
        getrandom::fill(&mut nonce).map_err(io::Error::other)?;
        let mut name = String::with_capacity(48);
        name.push_str(".private-fs-");
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for byte in nonce {
            name.push(HEX[(byte >> 4) as usize] as char);
            name.push(HEX[(byte & 15) as usize] as char);
        }
        name.push_str(".tmp");
        Ok(name.into())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Unpublished,
    Publishing,
    Published,
    Finished,
}
/// A private staging file with atomic visibility at commit, not before.
/// Dropping abandons staging without publishing. See `abort` for cleanup errors.
pub struct AtomicFile {
    parent: PrivateDir,
    target: OsString,
    temp: PrivateFile,
    name: Option<OsString>,
    durability: Durability,
    policy: Publication,
    state: State,
    failed_io: bool,
    faults: Faults,
}
impl std::fmt::Debug for AtomicFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AtomicFile")
            .field("durability", &self.durability)
            .field("state", &self.state)
            .field("failed_io", &self.failed_io)
            .finish_non_exhaustive()
    }
}
impl PrivateDir {
    /// Stage a private atomic replacement without an implicit persistence cost.
    pub fn atomic(&self, path: impl AsRef<Path>) -> Result<AtomicFile> {
        self.atomic_with_durability(path, Durability::None)
    }
    /// Stage a replacement with explicit persistence semantics.
    pub fn atomic_with_durability(
        &self,
        path: impl AsRef<Path>,
        durability: Durability,
    ) -> Result<AtomicFile> {
        AtomicFile::new(self, path.as_ref(), durability, Faults::default())
    }
    /// Stage with explicit atomic destination and persistence policies.
    /// NetBSD rejects `CreateNew` before creating staging.
    pub fn atomic_with_policy(
        &self,
        path: impl AsRef<Path>,
        durability: Durability,
        policy: Publication,
    ) -> Result<AtomicFile> {
        #[cfg(target_os = "netbsd")]
        if policy == Publication::CreateNew {
            return Err(Error::UnsupportedPolicy {
                policy: "atomic create-only publication",
            });
        }
        let mut writer = AtomicFile::new(self, path.as_ref(), durability, Faults::default())?;
        writer.policy = policy;
        Ok(writer)
    }
    /// Stage with `Full` durability: file sync, publication, then parent sync.
    pub fn atomic_durable(&self, path: impl AsRef<Path>) -> Result<AtomicFile> {
        self.atomic_with_durability(path, Durability::Full)
    }
    /// Publish complete private contents without explicit persistence requests.
    pub fn write_atomic(&self, path: impl AsRef<Path>, bytes: &[u8]) -> Result<()> {
        self.write_atomic_with_durability(path, bytes, Durability::None)
    }
    /// Publish complete private contents with file and parent persistence requests.
    pub fn write_atomic_durable(&self, path: impl AsRef<Path>, bytes: &[u8]) -> Result<()> {
        self.write_atomic_with_durability(path, bytes, Durability::Full)
    }
    /// Publish complete contents with explicit, independent durability selection.
    pub fn write_atomic_with_durability(
        &self,
        path: impl AsRef<Path>,
        bytes: &[u8],
        durability: Durability,
    ) -> Result<()> {
        let mut writer = self.atomic_with_durability(path, durability)?;
        writer.write_all(bytes)?;
        writer.commit()
    }
}
impl AtomicFile {
    pub(crate) fn new(
        dir: &PrivateDir,
        path: &Path,
        durability: Durability,
        mut faults: Faults,
    ) -> Result<Self> {
        let (parent, target) = dir.atomic_parent(path)?;
        #[cfg(test)]
        let named = faults.force_named;
        #[cfg(not(test))]
        let named = false;
        let anonymous = if named {
            None
        } else {
            faults.checkpoint(FaultPoint::BeforeTempCreate, &parent, None, None)?;
            parent.anonymous_temp()?
        };
        let (temp, name) = if let Some(temp) = anonymous {
            (temp, None)
        } else {
            let mut created = None;
            for _ in 0..128 {
                let name = faults.name()?;
                if name == target {
                    continue;
                }
                faults.checkpoint(FaultPoint::BeforeTempCreate, &parent, None, Some(&name))?;
                match parent.create(&name) {
                    Ok(file) => {
                        created = Some((file, Some(name)));
                        break;
                    }
                    Err(Error::Io(e)) if e.kind() == io::ErrorKind::AlreadyExists => (),
                    Err(e) => return Err(e),
                }
            }
            created.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "temporary-name collision limit",
                )
            })?
        };
        let mut writer = Self {
            parent,
            target,
            temp,
            name,
            durability,
            policy: Publication::Replace,
            state: State::Unpublished,
            failed_io: false,
            faults,
        };
        writer.checkpoint(FaultPoint::AfterTempCreate)?;
        writer.checkpoint(FaultPoint::BeforeTempValidate)?;
        writer.temp.verify()?;
        writer.checkpoint(FaultPoint::AfterTempValidate)?;
        Ok(writer)
    }
    fn checkpoint(&mut self, point: FaultPoint) -> Result<()> {
        self.faults
            .checkpoint(point, &self.parent, Some(&self.temp), self.name.as_deref())
    }
    fn binding(&self, name: &OsStr) -> Result<()> {
        let opened = self.parent.open_file(name)?;
        if !opened.same_object(&self.temp) {
            return Err(Error::IdentityChanged);
        }
        opened.verify()
    }
    fn target_private(&self) -> Result<()> {
        match self.parent.open_file(&self.target) {
            Ok(_) => Ok(()),
            Err(Error::Io(e)) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }
    fn materialize(&mut self) -> Result<()> {
        if self.name.is_some() {
            return Ok(());
        }
        for _ in 0..128 {
            let name = self.faults.name()?;
            if name == self.target {
                continue;
            }
            self.faults.checkpoint(
                FaultPoint::BeforeTempLink,
                &self.parent,
                Some(&self.temp),
                Some(&name),
            )?;
            self.parent.check_private()?;
            self.temp.verify()?;
            match self.parent.link_temp(&mut self.temp, &name) {
                Ok(()) => {
                    self.name = Some(name);
                    self.checkpoint(FaultPoint::AfterTempLink)?;
                    self.temp.verify()?;
                    self.binding(self.name.as_deref().expect("linked name recorded"))?;
                    return Ok(());
                }
                Err(Error::Io(e)) if e.kind() == io::ErrorKind::AlreadyExists => (),
                Err(e) => return Err(e),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "temporary-name collision limit",
        )
        .into())
    }
    /// Publish the complete file. Errors may occur after atomic visibility has
    /// changed; `Error::AtomicCommit`'s `may_have_published` reports that uncertainty.
    /// Retry by constructing a fresh transaction, never by reusing this writer.
    pub fn commit(mut self) -> Result<()> {
        self.commit_inner().map_err(|source| Error::AtomicCommit {
            may_have_published: self.state != State::Unpublished,
            source: Box::new(source),
        })
    }
    fn commit_inner(&mut self) -> Result<()> {
        if self.failed_io {
            return Err(Error::WriterFailed);
        }
        self.parent.check_private()?;
        self.temp.verify()?;
        self.materialize()?;
        // Sync after linking: unnamed-inode syncs are insufficient on some Linux
        // filesystems. No extra sync is performed for Durability::None.
        if self.durability != Durability::None {
            self.checkpoint(FaultPoint::BeforeFileSync)?;
            self.temp.verify()?;
            self.temp.sync_atomic(self.durability)?;
            self.checkpoint(FaultPoint::AfterFileSync)?;
        }
        self.checkpoint(FaultPoint::BeforePublish)?;
        self.parent.check_private()?;
        self.temp.verify()?;
        self.target_private()?;
        let name = self
            .name
            .as_deref()
            .expect("materialized before publication");
        self.binding(name)?;
        self.state = State::Publishing; // A syscall error may have ambiguous effects.
        if let Err(error) = self
            .parent
            .publish_temp(&self.temp, name, &self.target, self.policy)
        {
            if error.namespace_unchanged() {
                self.state = State::Unpublished;
            }
            return Err(error);
        }
        self.state = State::Published; // Set before any fallible post-publication step.
        self.checkpoint(FaultPoint::AfterPublish)?;
        self.checkpoint(FaultPoint::BeforeReopen)?;
        let published = self.parent.open_file(&self.target)?;
        self.checkpoint(FaultPoint::AfterReopen)?;
        self.checkpoint(FaultPoint::BeforePublishedValidate)?;
        if !published.same_object(&self.temp) {
            return Err(Error::IdentityChanged);
        }
        published.verify()?;
        self.temp.verify()?;
        self.checkpoint(FaultPoint::AfterPublishedValidate)?;
        if self.durability == Durability::Full {
            self.checkpoint(FaultPoint::BeforeParentSync)?;
            self.parent.sync_all()?;
            self.checkpoint(FaultPoint::AfterParentSync)?;
        }
        self.checkpoint(FaultPoint::BeforeFinalValidate)?;
        self.parent.check_private()?;
        published.verify()?;
        self.temp.verify()?;
        // Validate the current directory entry too, not just the first reopened FD.
        self.binding(&self.target)?;
        self.checkpoint(FaultPoint::AfterFinalValidate)?;
        self.binding(&self.target)?;
        self.state = State::Finished;
        Ok(())
    }
    /// Abandon staging without publication and report cleanup failures. POSIX
    /// named staging can remain private when identity-bound deletion is unavailable.
    pub fn abort(mut self) -> Result<()> {
        self.cleanup()
    }
    fn cleanup(&mut self) -> Result<()> {
        if self.state != State::Unpublished {
            return Ok(());
        }
        self.state = State::Finished; // A fault here must not trigger a second cleanup in Drop.
        self.checkpoint(FaultPoint::BeforeCleanup)?;
        let result = self.parent.cleanup_temp(&self.temp, self.name.as_deref());
        self.state = State::Finished; // Never retry a failed cleanup in Drop.
        result?;
        self.checkpoint(FaultPoint::AfterCleanup)
    }
}
impl Drop for AtomicFile {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}
impl Write for AtomicFile {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.failed_io {
            return Err(io::Error::other(Error::WriterFailed));
        }
        let result = (|| {
            self.checkpoint(FaultPoint::BeforeWrite)
                .map_err(io::Error::other)?;
            let n = self.temp.write(bytes)?;
            self.checkpoint(FaultPoint::AfterWrite)
                .map_err(io::Error::other)?;
            Ok(n)
        })();
        if result.is_err() {
            self.failed_io = true;
        }
        result
    }
    fn flush(&mut self) -> io::Result<()> {
        if self.failed_io {
            return Err(io::Error::other(Error::WriterFailed));
        }
        let result = self.temp.flush();
        if result.is_err() {
            self.failed_io = true;
        }
        result
    }
}
impl Read for AtomicFile {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let result = self.temp.read(bytes);
        if result.is_err() {
            self.failed_io = true;
        }
        result
    }
}
impl Seek for AtomicFile {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        let result = self.temp.seek(position);
        if result.is_err() {
            self.failed_io = true;
        }
        result
    }
}

#[cfg(test)]
mod tests;
