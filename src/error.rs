pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("directory creation parent permits untrusted namespace replacement")]
    UntrustedCreationParent,
    #[error("unexpected hard-link count: expected {expected}, found {actual}")]
    UnexpectedLinkCount { expected: u64, actual: u64 },
    #[error("atomic commit failed; publication may have occurred: {may_have_published}")]
    AtomicCommit {
        may_have_published: bool,
        #[source]
        source: Box<Error>,
    },
    #[error("atomic writer cannot commit after an I/O failure")]
    WriterFailed,
    #[error("object has an unexpected owner")]
    OwnerMismatch,
    #[error("object has an insecure ACL")]
    InsecureAcl,
    #[error("object has insecure permissions: expected {expected:o}, found {actual:o}")]
    InsecurePermissions { expected: u32, actual: u32 },
    #[error("object has unexpected owner: expected {expected}, found {actual}")]
    WrongOwner { expected: u32, actual: u32 },
    #[error("private file must have one hard link, found {links}")]
    MultipleHardLinks { links: u64 },
    #[error("symbolic link or path redirect is not permitted")]
    PathRedirect,
    #[error("object has an unexpected type")]
    WrongObjectKind,
    #[error("object identity changed")]
    IdentityChanged,
    #[error("required filesystem capability is unavailable: {capability}")]
    UnsupportedFilesystem { capability: &'static str },
    #[error("invalid capability-relative path")]
    InvalidRelativePath,
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[cfg(unix)]
impl From<rustix::io::Errno> for Error {
    fn from(error: rustix::io::Errno) -> Self {
        if error == rustix::io::Errno::LOOP {
            Self::PathRedirect
        } else {
            Self::Io(error.into())
        }
    }
}
