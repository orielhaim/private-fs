use crate::{
    Durability, Error, FileAccess, FileCreation, OpenOptions, Result, Verification,
    path::RelativePath,
};
use rustix::fs::{self, AtFlags, FileType, Mode, OFlags};
use std::{
    ffi::OsStr,
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
    os::fd::{AsFd, BorrowedFd, OwnedFd},
    path::{Component, Path},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Identity {
    dev: fs::Dev,
    ino: u64,
}
fn identity(s: &fs::Stat) -> Identity {
    Identity {
        dev: s.st_dev,
        ino: s.st_ino,
    }
}
fn creation_parent(fd: impl AsFd) -> Result<()> {
    let stat = fs::fstat(fd.as_fd())?;
    creation_parent_stat(&stat)?;
    #[cfg(target_os = "macos")]
    crate::macos::creation_parent(fd.as_fd())?;
    #[cfg(any(target_os = "freebsd", target_os = "netbsd"))]
    crate::bsd::creation_parent(fd)?;
    Ok(())
}
fn creation_parent_stat(stat: &fs::Stat) -> Result<()> {
    // mkdirat cannot return the created object's FD. A trusted owner and either
    // exclusive namespace writes or sticky protection bind the first observation
    // to our creation against other principals. Same-UID/root actors are trusted.
    if (stat.st_uid != rustix::process::geteuid().as_raw() && stat.st_uid != 0)
        || (stat.st_mode & 0o022 != 0 && stat.st_mode & 0o1000 == 0)
    {
        return Err(Error::UntrustedCreationParent);
    }
    Ok(())
}
#[derive(Clone, Copy, Debug)]
enum Resolver {
    Auto,
    #[cfg(all(test, target_os = "linux"))]
    Unavailable,
    #[cfg(target_os = "linux")]
    Walk,
    #[cfg(target_os = "linux")]
    OpenAt2,
}

#[derive(Debug)]
/// A verified private directory retained as a capability, independent of its name.
pub struct PrivateDir {
    fd: OwnedFd,
    id: Identity,
    resolver: Resolver,
}
#[derive(Debug)]
/// A verified regular file. Native-handle operations are the caller's responsibility.
pub struct PrivateFile {
    file: File,
    id: Identity,
    links: u64,
    verification: Verification,
}

fn permission_error(expected: impl Into<u32>, actual: impl Into<u32>) -> Error {
    Error::InsecurePermissions {
        expected: expected.into(),
        actual: actual.into(),
    }
}
fn link_count(value: impl Into<u64>) -> u64 {
    value.into()
}
fn link_error(links: impl Into<u64>) -> Error {
    Error::MultipleHardLinks {
        links: links.into(),
    }
}
fn validate(fd: impl AsFd, directory: bool, expected_id: Option<Identity>) -> Result<Identity> {
    validate_links(fd, directory, expected_id, 1)
}
fn validate_links(
    fd: impl AsFd,
    directory: bool,
    expected_id: Option<Identity>,
    links: u64,
) -> Result<Identity> {
    #[cfg(target_os = "macos")]
    crate::macos::ownership(fd.as_fd())?;
    let s = fs::fstat(fd.as_fd())?;
    let id = validate_stat_links(&s, directory, expected_id, links)?;
    #[cfg(target_os = "macos")]
    crate::macos::verify_acl(fd.as_fd())?;
    #[cfg(any(target_os = "freebsd", target_os = "netbsd"))]
    crate::bsd::verify(fd.as_fd(), directory)?;
    Ok(id)
}
fn validate_stat(s: &fs::Stat, directory: bool, expected_id: Option<Identity>) -> Result<Identity> {
    validate_stat_links(s, directory, expected_id, 1)
}
fn validate_stat_links(
    s: &fs::Stat,
    directory: bool,
    expected_id: Option<Identity>,
    links: u64,
) -> Result<Identity> {
    if expected_id.is_some_and(|id| id != identity(s)) {
        return Err(Error::IdentityChanged);
    }
    let kind = FileType::from_raw_mode(s.st_mode);
    if kind
        != if directory {
            FileType::Directory
        } else {
            FileType::RegularFile
        }
    {
        return Err(Error::WrongObjectKind);
    }
    let expected = rustix::process::geteuid().as_raw();
    if s.st_uid != expected {
        return Err(Error::WrongOwner {
            expected,
            actual: s.st_uid,
        });
    }
    let expected = if directory { 0o700 } else { 0o600 };
    let actual = s.st_mode & 0o7777;
    if actual != expected {
        return Err(permission_error(expected, actual));
    }
    if !directory && link_count(s.st_nlink) != links {
        if links == 0 {
            return Err(Error::UnexpectedLinkCount {
                expected: 0,
                actual: link_count(s.st_nlink),
            });
        }
        return Err(link_error(s.st_nlink));
    }
    Ok(identity(s))
}
#[cfg(target_os = "linux")]
fn open_fast(
    parent: impl AsFd,
    path: &OsStr,
    flags: OFlags,
    mode: Mode,
    resolver: Resolver,
) -> Result<Option<OwnedFd>> {
    if matches!(resolver, Resolver::Walk) {
        return Ok(None);
    }
    #[cfg(test)]
    let unavailable = matches!(resolver, Resolver::Unavailable);
    #[cfg(not(test))]
    let unavailable = false;
    let result = if unavailable {
        Err(rustix::io::Errno::NOSYS)
    } else {
        fs::openat2(
            parent,
            path,
            flags | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            mode,
            fs::ResolveFlags::BENEATH
                | fs::ResolveFlags::NO_SYMLINKS
                | fs::ResolveFlags::NO_MAGICLINKS,
        )
    };
    match result {
        Ok(fd) => Ok(Some(fd)),
        Err(e) if e == rustix::io::Errno::NOSYS => {
            if matches!(resolver, Resolver::OpenAt2) {
                return Err(e.into());
            }
            Ok(None)
        }
        Err(e) => Err(e.into()),
    }
}
fn open_component(
    parent: impl AsFd,
    name: &OsStr,
    flags: OFlags,
    mode: Mode,
    resolver: Resolver,
) -> Result<OwnedFd> {
    let flags = flags | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK;
    #[cfg(target_os = "freebsd")]
    let flags = flags | OFlags::from_bits_retain(libc::O_RESOLVE_BENEATH as u32);
    #[cfg(target_os = "linux")]
    if let Some(fd) = open_fast(parent.as_fd(), name, flags, mode, resolver)? {
        return Ok(fd);
    }
    #[cfg(not(target_os = "linux"))]
    let _ = resolver;
    // Check redirects through the parent descriptor when O_DIRECTORY reports ENOTDIR.
    match fs::openat(parent.as_fd(), name, flags, mode) {
        Ok(fd) => Ok(fd),
        Err(e) => {
            #[cfg(target_os = "freebsd")]
            if e == rustix::io::Errno::MLINK {
                return Err(Error::PathRedirect);
            }
            if e == rustix::io::Errno::NOTDIR
                && fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW)
                    .is_ok_and(|s| FileType::from_raw_mode(s.st_mode) == FileType::Symlink)
            {
                Err(Error::PathRedirect)
            } else {
                Err(e.into())
            }
        }
    }
}
fn open_existing_file(
    parent: impl AsFd,
    name: &OsStr,
    flags: OFlags,
    resolver: Resolver,
) -> Result<(OwnedFd, Identity)> {
    let observed = fs::statat(parent.as_fd(), name, AtFlags::SYMLINK_NOFOLLOW)?;
    match FileType::from_raw_mode(observed.st_mode) {
        FileType::Symlink => return Err(Error::PathRedirect),
        FileType::RegularFile => (),
        _ => return Err(Error::WrongObjectKind),
    }
    let fd = open_component(parent, name, flags, Mode::empty(), resolver)?;
    let id = validate(&fd, false, Some(identity(&observed)))?;
    Ok((fd, id))
}
fn normalize_created(fd: impl AsFd, directory: bool, id: Identity) -> Result<()> {
    #[cfg(target_os = "macos")]
    crate::macos::verify(fd.as_fd())?;
    #[cfg(any(target_os = "freebsd", target_os = "netbsd"))]
    crate::bsd::verify(fd.as_fd(), directory)?;
    let s = fs::fstat(fd.as_fd())?;
    let expected = if directory { 0o700 } else { 0o600 };
    let actual = s.st_mode & 0o7777;
    if actual == expected {
        return validate(fd, directory, Some(id)).map(|_| ());
    }
    if actual & !expected != 0 {
        return Err(permission_error(expected, actual));
    }
    // Validate every property except the narrower permission bits before widening.
    let mut normalized = s;
    normalized.st_mode = (s.st_mode & !0o7777) | expected;
    validate_stat(&normalized, directory, Some(id))?;
    fs::fchmod(fd.as_fd(), Mode::from_raw_mode(expected))?;
    validate(fd, directory, Some(id)).map(|_| ())
}
fn harden(fd: impl AsFd, directory: bool, id: Identity) -> Result<()> {
    #[cfg(target_os = "macos")]
    crate::macos::ownership(fd.as_fd())?;
    let mut stat = fs::fstat(fd.as_fd())?;
    let mode = if directory { 0o700 } else { 0o600 };
    stat.st_mode = (stat.st_mode & !0o7777) | mode;
    validate_stat(&stat, directory, Some(id))?;
    fs::fchmod(fd.as_fd(), Mode::from_raw_mode(mode))?;
    #[cfg(target_os = "macos")]
    crate::macos::clear(fd.as_fd())?;
    #[cfg(any(target_os = "freebsd", target_os = "netbsd"))]
    crate::bsd::harden(fd.as_fd(), directory)?;
    validate(fd, directory, Some(id)).map(|_| ())
}
impl PrivateDir {
    /// Explicitly restore private access on this retained capability.
    pub fn harden(&self) -> Result<()> {
        harden(&self.fd, true, self.id)
    }
    /// Open and verify a root. Every ancestor is resolved without following links.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::acquire(path.as_ref(), false, Resolver::Auto)
    }
    /// Create the final root if absent. Existing ancestors are never hardened.
    pub fn ensure(path: impl AsRef<Path>) -> Result<Self> {
        Self::acquire(path.as_ref(), true, Resolver::Auto)
    }
    fn acquire(path: &Path, create: bool, resolver: Resolver) -> Result<Self> {
        crate::path::validate_component_spelling(path)?;
        if !path.is_absolute() {
            RelativePath::new(path)?;
        }
        #[cfg(all(target_os = "linux", feature = "force-walk"))]
        let resolver = if matches!(resolver, Resolver::Auto) {
            Resolver::Walk
        } else {
            resolver
        };
        #[cfg(target_os = "macos")]
        let canonical = canonical_alias(path);
        #[cfg(target_os = "macos")]
        let path = canonical.as_path();
        let mut names = Vec::new();
        for c in path.components() {
            match c {
                Component::Normal(n) => names.push(n),
                Component::RootDir => (),
                _ => return Err(Error::InvalidRelativePath),
            }
        }
        let leaf = names.pop().ok_or(Error::InvalidRelativePath)?;
        let mut parent = fs::open(
            if path.is_absolute() { "/" } else { "." },
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        #[cfg(target_os = "linux")]
        let resolver = if matches!(resolver, Resolver::Auto) {
            if open_fast(
                &parent,
                OsStr::new("."),
                OFlags::RDONLY | OFlags::DIRECTORY,
                Mode::empty(),
                resolver,
            )?
            .is_some()
            {
                Resolver::OpenAt2
            } else {
                Resolver::Walk
            }
        } else {
            resolver
        };
        #[cfg(target_os = "linux")]
        let fast = if names.is_empty() {
            None
        } else {
            let relative: std::path::PathBuf = names.iter().collect();
            open_fast(
                &parent,
                relative.as_os_str(),
                OFlags::RDONLY | OFlags::DIRECTORY,
                Mode::empty(),
                resolver,
            )?
        };
        #[cfg(not(target_os = "linux"))]
        let fast: Option<OwnedFd> = None;
        if let Some(fd) = fast {
            parent = fd;
        } else {
            for n in names {
                parent = open_component(
                    &parent,
                    n,
                    OFlags::RDONLY | OFlags::DIRECTORY,
                    Mode::empty(),
                    resolver,
                )?;
            }
        }
        Self::directory_at(&parent, leaf, create, false, resolver)
    }
    fn directory_at(
        parent: impl AsFd,
        name: &OsStr,
        create: bool,
        exclusive: bool,
        resolver: Resolver,
    ) -> Result<Self> {
        if create {
            if !exclusive {
                match open_component(
                    parent.as_fd(),
                    name,
                    OFlags::RDONLY | OFlags::DIRECTORY,
                    Mode::empty(),
                    resolver,
                ) {
                    Ok(fd) => {
                        let id = validate(&fd, true, None)?;
                        return Ok(Self { fd, id, resolver });
                    }
                    Err(Error::Io(e)) if e.kind() == io::ErrorKind::NotFound => (),
                    Err(e) => return Err(e),
                }
            }
            creation_parent(parent.as_fd())?;
        }
        let created = if create {
            match fs::mkdirat(parent.as_fd(), name, Mode::from_raw_mode(0o700)) {
                Ok(()) => true,
                Err(e) if e == rustix::io::Errno::EXIST && !exclusive => false,
                Err(e) => return Err(e.into()),
            }
        } else {
            false
        };
        // mkdirat returns no descriptor. Bind its observed identity to the opened
        // object before returning; never chmod or unlink a possibly replaced name.
        let observed = if created {
            Some(identity(&fs::statat(
                parent.as_fd(),
                name,
                AtFlags::SYMLINK_NOFOLLOW,
            )?))
        } else {
            None
        };
        let fd = open_component(
            parent,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY,
            Mode::empty(),
            resolver,
        )?;
        if let Some(id) = observed {
            normalize_created(&fd, true, id)?;
        }
        let id = validate(&fd, true, observed)?;
        Ok(Self { fd, id, resolver })
    }
    fn parent<'a>(&self, path: &'a Path) -> Result<(OwnedFd, &'a OsStr)> {
        validate(&self.fd, true, Some(self.id))?;
        let mut p = RelativePath::new(path)?.0;
        let leaf = p.pop().ok_or(Error::InvalidRelativePath)?;
        let mut parent = rustix::io::fcntl_dupfd_cloexec(&self.fd, 0)?;
        for name in p {
            parent = open_component(
                &parent,
                name,
                OFlags::RDONLY | OFlags::DIRECTORY,
                Mode::empty(),
                self.resolver,
            )?;
            validate(&parent, true, None)?;
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
    /// Acquire a file through its retained parent, then validate before truncating.
    /// `OpenOrCreate` never truncates unless `truncate` is explicitly selected.
    pub fn open_file_with(
        &self,
        path: impl AsRef<Path>,
        options: OpenOptions,
    ) -> Result<PrivateFile> {
        options.validate()?;
        let (parent, leaf) = self.parent(path.as_ref())?;
        let access = match options.access {
            FileAccess::Read => OFlags::RDONLY,
            FileAccess::ReadWrite => OFlags::RDWR,
        };
        let create = || -> Result<(OwnedFd, Identity)> {
            creation_parent(&parent)?;
            let fd = open_component(
                &parent,
                leaf,
                access | OFlags::CREATE | OFlags::EXCL,
                Mode::from_raw_mode(0o600),
                self.resolver,
            )?;
            let id = identity(&fs::fstat(&fd)?);
            normalize_created(&fd, false, id)?;
            Ok((fd, id))
        };
        let (fd, id) = match options.creation {
            FileCreation::Existing => open_existing_file(&parent, leaf, access, self.resolver)?,
            FileCreation::CreateNew => create()?,
            FileCreation::OpenOrCreate => {
                let mut acquired = None;
                for _ in 0..128 {
                    match open_existing_file(&parent, leaf, access, self.resolver) {
                        Ok(file) => {
                            acquired = Some(file);
                            break;
                        }
                        Err(Error::Io(e)) if e.kind() == io::ErrorKind::NotFound => (),
                        Err(e) => return Err(e),
                    }
                    match create() {
                        Ok(file) => {
                            acquired = Some(file);
                            break;
                        }
                        Err(Error::Io(e)) if e.kind() == io::ErrorKind::AlreadyExists => (),
                        Err(e) => return Err(e),
                    }
                }
                acquired.ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "file acquisition repeatedly raced",
                    )
                })?
            }
        };
        let file = PrivateFile {
            file: fd.into(),
            id,
            links: 1,
            verification: options.verification,
        };
        if options.truncate {
            file.set_len(0)?;
        }
        Ok(file)
    }
    /// Enumerate native names through this descriptor. This is not a snapshot.
    /// Names confer no authority; securely open an entry before using it.
    pub fn entries(&self) -> Result<Vec<std::ffi::OsString>> {
        use std::os::unix::ffi::OsStrExt;
        self.check_private()?;
        let entries = fs::Dir::read_from(&self.fd)?;
        let mut names = Vec::new();
        for entry in entries {
            let entry = entry?;
            let name = entry.file_name().to_bytes();
            if name == b"." || name == b".." {
                continue;
            }
            let name = OsStr::from_bytes(name);
            RelativePath::new(Path::new(name))?;
            names.push(name.to_os_string());
        }
        self.check_private()?;
        Ok(names)
    }
    /// Remove a verified regular file. Missing files return `Io(NotFound)`.
    /// Unix unlink acts on the current name; callers must coordinate same-user
    /// namespace writers. `Full` syncs the parent; `Data` adds no deletion sync.
    /// This also permits caller-selected orphan removal during exclusive maintenance.
    pub fn remove_file(&self, path: impl AsRef<Path>, durability: Durability) -> Result<()> {
        let (parent, name) = self.atomic_parent(path.as_ref())?;
        let target = parent.open_file(&name)?;
        target.verify()?;
        let current = parent.open_file(&name)?;
        if !current.same_object(&target) {
            return Err(Error::IdentityChanged);
        }
        parent.check_private()?;
        let mut may_have_removed = false;
        let result = (|| {
            #[cfg(target_os = "freebsd")]
            let removal = crate::bsd::unlink(&parent.fd, &name, &target);
            #[cfg(not(target_os = "freebsd"))]
            let removal = fs::unlinkat(&parent.fd, &name, AtFlags::empty()).map_err(Error::from);
            if let Err(error) = removal {
                may_have_removed = !error.namespace_unchanged();
                return Err(error);
            }
            may_have_removed = true;
            if durability == Durability::Full {
                parent.sync_all()?;
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
        let (parent, leaf) = self.parent(path.as_ref())?;
        Self::directory_at(parent, leaf, false, false, self.resolver)
    }
    /// Exclusively create the final directory. Private parents must already exist.
    pub fn create_dir(&self, path: impl AsRef<Path>) -> Result<Self> {
        let (parent, leaf) = self.parent(path.as_ref())?;
        Self::directory_at(parent, leaf, true, true, self.resolver)
    }
    /// Create or verify the final directory, without repairing existing entries.
    pub fn ensure_dir(&self, path: impl AsRef<Path>) -> Result<Self> {
        let (parent, leaf) = self.parent(path.as_ref())?;
        Self::directory_at(parent, leaf, true, false, self.resolver)
    }
}
impl PrivateFile {
    /// Explicitly restore private access on this retained capability.
    pub fn harden(&self) -> Result<()> {
        harden(&self.file, false, self.id)
    }
    /// Recheck mutable security metadata on the retained descriptor.
    pub fn verify(&self) -> Result<()> {
        validate_links(&self.file, false, Some(self.id), self.links).map(|_| ())
    }
    /// Resize the exact validated object. An error after mutation can leave the
    /// new length in effect. Native read-only handles refuse this operation.
    pub fn set_len(&self, length: u64) -> Result<()> {
        self.verify()?;
        self.file.set_len(length)?;
        self.verify()
    }
    /// Sync file data with security revalidation; does not sync a parent directory.
    pub fn sync_data(&self) -> Result<()> {
        self.verify()?;
        self.file.sync_data()?;
        self.verify()
    }
    /// Sync file contents and metadata; use durable atomic writes for name persistence.
    /// This is the standard file sync, not macOS atomic `Full`'s stronger flush.
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
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        self.check_io()?;
        let n = self.file.read(b)?;
        self.check_io()?;
        Ok(n)
    }
}
impl Write for PrivateFile {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.check_io()?;
        let n = self.file.write(b)?;
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
    fn seek(&mut self, p: SeekFrom) -> io::Result<u64> {
        self.check_io()?;
        let position = self.file.seek(p)?;
        self.check_io()?;
        Ok(position)
    }
}
impl AsFd for PrivateFile {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.file.as_fd()
    }
}
impl AsFd for PrivateDir {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

#[cfg(all(test, not(target_os = "macos")))]
mod tests;

#[cfg(target_os = "macos")]
fn canonical_alias(path: &Path) -> std::path::PathBuf {
    for alias in ["/var", "/tmp", "/etc"] {
        if let Ok(suffix) = path.strip_prefix(alias) {
            return Path::new("/private")
                .join(alias.trim_start_matches('/'))
                .join(suffix);
        }
    }
    path.to_path_buf()
}

pub(crate) fn verify_existing(file: &File) -> Result<()> {
    validate(file, false, None).map(|_| ())
}
pub(crate) fn harden_existing(file: &File) -> Result<()> {
    let id = identity(&fs::fstat(file)?);
    harden(file, false, id)
}
impl PrivateDir {
    pub(crate) fn atomic_parent(&self, path: &Path) -> Result<(Self, std::ffi::OsString)> {
        let (fd, leaf) = self.parent(path)?;
        let id = validate(&fd, true, None)?;
        Ok((
            Self {
                fd,
                id,
                resolver: self.resolver,
            },
            leaf.to_os_string(),
        ))
    }
    pub(crate) fn check_private(&self) -> Result<()> {
        validate(&self.fd, true, Some(self.id)).map(|_| ())
    }
    pub(crate) fn anonymous_temp(&self) -> Result<Option<PrivateFile>> {
        self.check_private()?;
        #[cfg(target_os = "linux")]
        {
            let fd = match open_component(
                &self.fd,
                OsStr::new("."),
                OFlags::RDWR | OFlags::TMPFILE,
                Mode::from_raw_mode(0o600),
                self.resolver,
            ) {
                Ok(fd) => fd,
                Err(Error::Io(e))
                    if e.raw_os_error().is_some_and(|code| {
                        matches!(
                            rustix::io::Errno::from_raw_os_error(code),
                            rustix::io::Errno::OPNOTSUPP
                                | rustix::io::Errno::ISDIR
                                | rustix::io::Errno::INVAL
                        )
                    }) =>
                {
                    return Ok(None);
                }
                Err(e) => return Err(e),
            };
            let mut stat = fs::fstat(&fd)?;
            let id = identity(&stat);
            let actual = stat.st_mode & 0o7777;
            if actual & !0o600 != 0 {
                return Err(permission_error(0o600u32, actual));
            }
            stat.st_mode = (stat.st_mode & !0o7777) | 0o600;
            validate_stat_links(&stat, false, Some(id), 0)?;
            if actual != 0o600 {
                fs::fchmod(&fd, Mode::from_raw_mode(0o600))?;
            }
            validate_links(&fd, false, Some(id), 0)?;
            Ok(Some(PrivateFile {
                file: fd.into(),
                id,
                links: 0,
                verification: Verification::PerIo,
            }))
        }
        #[cfg(not(target_os = "linux"))]
        Ok(None)
    }
    pub(crate) fn link_temp(&self, temp: &mut PrivateFile, name: &OsStr) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            fs::linkat(&temp.file, "", &self.fd, name, AtFlags::EMPTY_PATH)?;
            temp.links = 1;
            Ok(())
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (temp, name);
            Err(Error::UnsupportedFilesystem {
                capability: "anonymous temporary linking",
            })
        }
    }
    pub(crate) fn publish_temp(
        &self,
        _temp: &PrivateFile,
        name: &OsStr,
        target: &OsStr,
        policy: crate::Publication,
    ) -> Result<()> {
        if policy == crate::Publication::CreateNew {
            #[cfg(target_os = "freebsd")]
            return crate::bsd::publish_new(&self.fd, name, target);
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            {
                fs::renameat_with(&self.fd, name, &self.fd, target, fs::RenameFlags::NOREPLACE)?;
                return Ok(());
            }
            #[cfg(target_os = "netbsd")]
            return Err(Error::UnsupportedPolicy {
                policy: "atomic create-only publication",
            });
        }
        fs::renameat(&self.fd, name, &self.fd, target)?;
        Ok(())
    }
    pub(crate) fn cleanup_temp(&self, temp: &PrivateFile, name: Option<&OsStr>) -> Result<()> {
        self.check_private()?;
        temp.verify()?;
        if let Some(name) = name {
            match self.open_file(name) {
                Ok(found) if !found.same_object(temp) => return Err(Error::IdentityChanged),
                Err(Error::Io(e)) if e.kind() == io::ErrorKind::NotFound => {
                    return Err(Error::IdentityChanged);
                }
                Err(e) => return Err(e),
                _ => (),
            }
            #[cfg(target_os = "freebsd")]
            return crate::bsd::unlink(&self.fd, name, temp);
            #[cfg(not(target_os = "freebsd"))]
            return Err(Error::UnsupportedFilesystem {
                capability: "identity-bound named-temp deletion",
            });
        }
        Ok(()) // The last descriptor closes the anonymous inode automatically.
    }
    pub fn sync_all(&self) -> Result<()> {
        self.check_private()?;
        fs::fsync(&self.fd)?;
        #[cfg(target_os = "macos")]
        fs::fcntl_fullfsync(&self.fd)?;
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
            crate::Durability::Full => {
                self.sync_all()?;
                #[cfg(target_os = "macos")]
                fs::fcntl_fullfsync(&self.file)?;
                self.verify()
            }
        }
    }
}
