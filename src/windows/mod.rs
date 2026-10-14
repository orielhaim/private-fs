//! Public capabilities. Raw Windows calls live in nt and security.
#![deny(unsafe_code)]
#[allow(
    unsafe_code,
    non_snake_case,
    non_upper_case_globals,
    non_camel_case_types,
    dead_code,
    clippy::upper_case_acronyms
)]
mod bindings;
mod nt;
mod security;
use crate::{
    Durability, Error, FileAccess, FileCreation, OpenOptions, Result, Verification,
    path::RelativePath,
};
use bindings::{FILE_CREATE, FILE_OPEN, FILE_OPEN_IF};
use security::Sid;
use std::{
    ffi::OsStr,
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
    os::windows::io::{AsHandle, BorrowedHandle, OwnedHandle},
    path::{Component, Path, Prefix},
};

#[derive(Debug)]
/// A verified private directory retained as a capability, independent of its name.
pub struct PrivateDir {
    handle: OwnedHandle,
    id: nt::Identity,
    user: Sid,
}
#[derive(Debug)]
/// A verified regular file. Native-handle operations are the caller's responsibility.
pub struct PrivateFile {
    file: File,
    id: nt::Identity,
    user: Sid,
    verification: Verification,
}
fn harden(handle: impl AsHandle, directory: bool, id: nt::Identity, user: &Sid) -> Result<()> {
    nt::metadata(handle.as_handle(), directory, Some(id))?;
    match security::harden(handle.as_handle(), user) {
        Ok(()) => (),
        Err(Error::Io(e)) if e.kind() == io::ErrorKind::PermissionDenied => {
            let writable = nt::security_handle(handle.as_handle())?;
            nt::identity_matches(&writable, id)?;
            security::harden(&writable, user)?;
        }
        Err(e) => return Err(e),
    }
    nt::validate(handle, directory, Some(id), user).map(|_| ())
}
impl PrivateDir {
    /// Explicitly restore owner-only access through this retained handle.
    pub fn harden(&self) -> Result<()> {
        harden(&self.handle, true, self.id, &self.user)
    }
    /// Open and verify a root without following ancestor reparse points.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::acquire(path.as_ref(), false)
    }
    /// Create only the final root if absent; never repair existing metadata.
    pub fn ensure(path: impl AsRef<Path>) -> Result<Self> {
        Self::acquire(path.as_ref(), true)
    }
    fn acquire(path: &Path, create: bool) -> Result<Self> {
        crate::path::validate_component_spelling(path)?;
        let absolute = if path.is_absolute() {
            path.to_path_buf()
        } else {
            RelativePath::new(path)?;
            std::env::current_dir()?.join(path)
        };
        let mut parts = absolute.components();
        let drive = match parts.next() {
            Some(Component::Prefix(prefix)) => match prefix.kind() {
                Prefix::Disk(drive) | Prefix::VerbatimDisk(drive) => drive,
                _ => return Err(Error::InvalidRelativePath),
            },
            _ => return Err(Error::InvalidRelativePath),
        };
        if !matches!(parts.next(), Some(Component::RootDir)) {
            return Err(Error::InvalidRelativePath);
        }
        let mut names = Vec::new();
        for component in parts {
            match component {
                Component::Normal(name) => {
                    RelativePath::new(Path::new(name))?;
                    names.push(name);
                }
                _ => return Err(Error::InvalidRelativePath),
            }
        }
        let leaf = names.pop().ok_or(Error::InvalidRelativePath)?;
        let anchor = format!(r"\??\{}:\", drive as char);
        let user = Sid::process_user()?;
        let mut parent = nt::open(None, OsStr::new(&anchor), true, FILE_OPEN as u32, None)?;
        nt::volume(&parent)?;
        for name in names {
            parent = nt::open(Some(&parent), name, true, FILE_OPEN as u32, None)?;
        }
        Self::directory_at(
            &parent,
            leaf,
            if create { FILE_OPEN_IF } else { FILE_OPEN } as u32,
            &user,
        )
    }
    fn directory_at(
        parent: &OwnedHandle,
        name: &OsStr,
        disposition: u32,
        user: &Sid,
    ) -> Result<Self> {
        // Check ACL capability before creation, not after making an insecure entry
        // on a volume that would ignore the supplied security descriptor.
        nt::volume(parent)?;
        let handle = nt::open(
            Some(parent),
            name,
            true,
            disposition,
            if disposition == FILE_OPEN as u32 {
                None
            } else {
                Some(user)
            },
        )?;
        let id = nt::validate(&handle, true, None, user)?;
        Ok(Self {
            handle,
            id,
            user: user.clone(),
        })
    }
    fn parent<'a>(&self, path: &'a Path) -> Result<(OwnedHandle, &'a OsStr)> {
        nt::validate(&self.handle, true, Some(self.id), &self.user)?;
        let mut parts = RelativePath::new(path)?.0;
        let leaf = parts.pop().ok_or(Error::InvalidRelativePath)?;
        let mut parent = self.handle.try_clone()?;
        for part in parts {
            parent = nt::open(Some(&parent), part, true, FILE_OPEN as u32, None)?;
            nt::validate(&parent, true, None, &self.user)?;
        }
        Ok((parent, leaf))
    }
    /// Open an existing regular file for reading without metadata mutation.
    pub fn open_file(&self, path: impl AsRef<Path>) -> Result<PrivateFile> {
        self.open_file_with(path, OpenOptions::default())
    }
    /// Exclusively create a readable and writable private file.
    pub fn create(&self, path: impl AsRef<Path>) -> Result<PrivateFile> {
        self.open_file_with(
            path,
            OpenOptions {
                access: FileAccess::ReadWrite,
                creation: FileCreation::CreateNew,
                ..OpenOptions::default()
            },
        )
    }
    /// Acquire through the retained parent, then validate before truncating.
    pub fn open_file_with(
        &self,
        path: impl AsRef<Path>,
        options: OpenOptions,
    ) -> Result<PrivateFile> {
        options.validate()?;
        let (parent, name) = self.parent(path.as_ref())?;
        nt::volume(&parent)?;
        let disposition = match options.creation {
            FileCreation::Existing => FILE_OPEN,
            FileCreation::CreateNew => FILE_CREATE,
            FileCreation::OpenOrCreate => FILE_OPEN_IF,
        } as u32;
        let handle = nt::open_file(
            &parent,
            name,
            disposition,
            (options.creation != FileCreation::Existing).then_some(&self.user),
            options.access == FileAccess::ReadWrite,
            false,
        )?;
        let id = nt::validate(&handle, false, None, &self.user)?;
        let file = PrivateFile {
            file: handle.into(),
            id,
            user: self.user.clone(),
            verification: options.verification,
        };
        if options.truncate {
            file.set_len(0)?;
        }
        Ok(file)
    }
    /// Enumerate native names through this handle. This is not a snapshot.
    /// Names confer no authority; securely open an entry before using it.
    pub fn entries(&self) -> Result<Vec<std::ffi::OsString>> {
        self.check_private()?;
        let listing = nt::directory_for_listing(&self.handle)?;
        nt::validate(&listing, true, Some(self.id), &self.user)?;
        let names = nt::entries(&listing)?;
        self.check_private()?;
        Ok(names)
    }
    /// Remove the exact validated regular file using native handle disposition.
    /// Missing files return `Io(NotFound)`. Removal can remain pending while other
    /// handles are open. `Full` flushes the parent; `Data` adds no deletion sync.
    pub fn remove_file(&self, path: impl AsRef<Path>, durability: Durability) -> Result<()> {
        let (parent, name) = self.atomic_parent(path.as_ref())?;
        let handle = nt::open_file(&parent.handle, &name, FILE_OPEN as u32, None, false, true)?;
        nt::validate(&handle, false, None, &self.user)?;
        parent.check_private()?;
        let mut may_have_removed = false;
        let result = (|| {
            if let Err(error) = nt::delete(&handle) {
                may_have_removed = !error.namespace_unchanged();
                return Err(error);
            }
            may_have_removed = true;
            drop(handle);
            if durability == Durability::Full {
                parent.sync_parent(durability)?;
            }
            parent.check_private()
        })();
        result.map_err(|source| Error::Removal {
            may_have_removed,
            source: Box::new(source),
        })
    }
    /// Open an existing private directory without creating or hardening it.
    pub fn open_dir(&self, path: impl AsRef<Path>) -> Result<Self> {
        let (parent, name) = self.parent(path.as_ref())?;
        Self::directory_at(&parent, name, FILE_OPEN as u32, &self.user)
    }
    /// Exclusively create the final private directory; private parents must exist.
    pub fn create_dir(&self, path: impl AsRef<Path>) -> Result<Self> {
        let (parent, name) = self.parent(path.as_ref())?;
        Self::directory_at(&parent, name, FILE_CREATE as u32, &self.user)
    }
    /// Create or verify the final directory without repairing existing entries.
    pub fn ensure_dir(&self, path: impl AsRef<Path>) -> Result<Self> {
        let (parent, name) = self.parent(path.as_ref())?;
        Self::directory_at(&parent, name, FILE_OPEN_IF as u32, &self.user)
    }
}
impl PrivateFile {
    /// Explicitly restore owner-only access through this retained handle.
    pub fn harden(&self) -> Result<()> {
        harden(&self.file, false, self.id, &self.user)
    }
    /// Recheck mutable security metadata through the retained handle.
    pub fn verify(&self) -> Result<()> {
        nt::validate(&self.file, false, Some(self.id), &self.user).map(|_| ())
    }
    /// Resize the exact validated object. An error after mutation can leave the
    /// new length in effect. Native read-only handles refuse this operation.
    pub fn set_len(&self, length: u64) -> Result<()> {
        self.verify()?;
        self.file.set_len(length)?;
        self.verify()
    }
    /// Sync file data with revalidation; does not sync a parent directory.
    pub fn sync_data(&self) -> Result<()> {
        self.verify()?;
        self.file.sync_data()?;
        self.verify()
    }
    /// Sync file contents/metadata; durable atomic writes also persist the name.
    pub fn sync_all(&self) -> Result<()> {
        self.verify()?;
        self.file.sync_all()?;
        self.verify()
    }
    fn check_io(&self) -> io::Result<()> {
        if self.verification == Verification::PerIo {
            self.verify().map_err(io::Error::other)
        } else {
            Ok(())
        }
    }
}
impl Read for PrivateFile {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.check_io()?;
        let n = self.file.read(bytes)?;
        self.check_io()?;
        Ok(n)
    }
}
impl Write for PrivateFile {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.check_io()?;
        let n = self.file.write(bytes)?;
        self.check_io()?;
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.check_io()?;
        self.file.flush()?;
        self.check_io()
    }
}
impl Seek for PrivateFile {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.check_io()?;
        let position = self.file.seek(position)?;
        self.check_io()?;
        Ok(position)
    }
}
impl AsHandle for PrivateDir {
    fn as_handle(&self) -> BorrowedHandle<'_> {
        self.handle.as_handle()
    }
}
impl AsHandle for PrivateFile {
    fn as_handle(&self) -> BorrowedHandle<'_> {
        self.file.as_handle()
    }
}
#[cfg(test)]
mod tests;

pub(crate) fn verify_existing(file: &File) -> Result<()> {
    let user = Sid::process_user()?;
    nt::validate(file, false, None, &user).map(|_| ())
}
pub(crate) fn harden_existing(file: &File) -> Result<()> {
    let user = Sid::process_user()?;
    let id = nt::metadata(file, false, None)?;
    harden(file, false, id, &user)
}
impl PrivateDir {
    pub(crate) fn atomic_parent(&self, path: &Path) -> Result<(Self, std::ffi::OsString)> {
        let (handle, leaf) = self.parent(path)?;
        let id = nt::validate(&handle, true, None, &self.user)?;
        Ok((
            Self {
                handle,
                id,
                user: self.user.clone(),
            },
            leaf.to_os_string(),
        ))
    }
    pub(crate) fn check_private(&self) -> Result<()> {
        nt::validate(&self.handle, true, Some(self.id), &self.user).map(|_| ())
    }
    pub(crate) fn anonymous_temp(&self) -> Result<Option<PrivateFile>> {
        Ok(None)
    }
    pub(crate) fn link_temp(&self, _file: &mut PrivateFile, _name: &OsStr) -> Result<()> {
        Err(Error::UnsupportedFilesystem {
            capability: "anonymous temporary linking",
        })
    }
    pub(crate) fn publish_temp(
        &self,
        temp: &PrivateFile,
        _name: &OsStr,
        target: &OsStr,
        policy: crate::Publication,
    ) -> Result<()> {
        nt::rename_with_policy(&temp.file, &self.handle, target, policy)
    }
    pub(crate) fn cleanup_temp(&self, temp: &PrivateFile, _name: Option<&OsStr>) -> Result<()> {
        self.check_private()?;
        temp.verify()?;
        nt::delete(&temp.file)
    }
    pub(crate) fn sync_parent(&self, _durability: crate::Durability) -> Result<()> {
        self.check_private()?;
        let writable = nt::directory_for_sync(&self.handle)?;
        nt::validate(&writable, true, Some(self.id), &self.user)?;
        nt::flush(&writable)?;
        self.check_private()
    }
}
impl PrivateFile {
    pub(crate) fn same_object(&self, other: &Self) -> bool {
        self.id == other.id
    }
    #[cfg(test)]
    pub(crate) fn raw_file(&self) -> &File {
        &self.file
    }
    pub(crate) fn sync_atomic(&self, durability: crate::Durability) -> Result<()> {
        match durability {
            crate::Durability::None => Ok(()),
            crate::Durability::Data => self.sync_data(),
            crate::Durability::Full => self.sync_all(),
        }
    }
}
