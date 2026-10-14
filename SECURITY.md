# Security contract

`private-fs` protects application files from other unprivileged principals on
Linux, macOS, Windows, FreeBSD 15.1+, and NetBSD 11.0+ filesystems that truthfully
report metadata, enforce native access controls, and honor creation-time mode
or security-descriptor requests. It rejects hostile namespace state rather than
repairing it implicitly. Root/administrator bypass, the kernel, storage firmware,
process compromise, privileged access-control bypass, and actors sharing the
effective UID or Windows TokenUser are outside the isolation boundary. This is access control, not encryption.
Do not give an untrusted same-principal actor write access to a private tree.

## Guarantees

- Files are created exclusively and privately in the creation syscall; directories
  are private from birth. Unix modes are exactly `0600` / `0700`, including rejection
  of special bits. The library never changes process umask. A narrower creation
  mode may be normalized through the newly held descriptor.
- Unix ownership is the effective UID. Windows ownership is the process TokenUser,
  with a protected DACL containing exactly one noninheritable full-access user ACE.
  No extra SYSTEM or administrator grant is inserted.
- Relative paths reject roots, prefixes, traversal, interior dots, NULs, and colons
  (including Windows alternate streams). Unix also rejects backslashes. Native
  names are passed without lossy Unicode conversion; filesystem encoding rules
  still apply. [APFS requires valid UTF-8 filenames](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/APFS_Guide/FAQ/FAQ.html),
  so invalid Unix byte names can fail with `EILSEQ`, including during publication.
  The original filesystem error is propagated without renaming to a substitute.
  Windows root acquisition accepts drive-letter paths and relative paths on a
  drive-letter working directory. UNC and volume-device roots are unsupported.
  Windows NT names are not normalized to Win32 spelling conventions; callers should use the capability for subsequent access.
- Children are resolved through retained directory descriptors/handles. Redirects
  are rejected, including Linux magic links and Windows reparse points. Linux uses
  `openat2` where available and a secure descriptor walk otherwise. Acquisition
  ancestors must exist; they are never hardened. Unix directory creation requires
  a trusted parent owner (effective UID or root) and no group/other namespace write,
  unless sticky protection applies. macOS additionally requires a current-user
  parent with empty extended ACL and enforced ownership.
- Actual objects are checked for kind, ownership, permissions/ACL, identity, and
  regular-file hard-link count. Public regular files must have exactly one link.
  Internal anonymous Linux staging is validated separately with zero links.
  Mutable metadata is checked again before/after I/O by default and at publication boundaries.
  `Verification::OnDemand` instead checks at acquisition, explicit verification,
  resizing, and sync. The caller brackets a transaction with `verify()` and handles
  post-I/O failure. No policy provides a lock against concurrent metadata changes.
- macOS ACL operations are FD-bound. Nonempty extended ACLs are rejected; explicit
  hardening clears and revalidates them. Ownership-disabled mounts fail closed.
- Linux POSIX access ACLs are bounded by mode bits. Named users, named groups, and
  the owning group are limited by the ACL mask, represented by the group mode
  bits. Exact private modes set that mask and other permissions to zero. Inherited
  default ACLs are intersected with requested creation permissions by the kernel;
  they cannot grant nonowner access to a `0600` file or `0700` directory. A later
  mode change that activates dormant grants is rejected. Default ACLs can remain
  on private Linux directories; hardening restricts the access mask without
  deleting dormant entries. This reasoning applies to POSIX ACLs, not arbitrary
  server-specific access-control models.
- BSD queries both native ACL capability selectors through `fpathconf` on each
  object. Only explicit 0/1 responses establish no ACL enforcement, POSIX.1e,
  or NFSv4 semantics. Errors and ambiguous reporting fail closed. On ACL-enabled
  filesystems, descriptor ACL inspection must succeed. Access ACLs must be trivial,
  equivalent to the verified mode without lost rules. Nontrivial named grants,
  deny rules, and inheritance are rejected, including dormant POSIX entries.
  Directories must have an empty POSIX default ACL. Trivial NFSv4 ACLs have no
  inheritance rules. Creation checks the parent before the syscall and validates
  the child afterward. Explicit handle hardening strips access ACLs to their
  mode-equivalent representation and clears POSIX defaults; it never changes owners.
- FreeBSD uses `O_RESOLVE_BENEATH` on component opens, `funlinkat` for identity-bound
  unlink, and `renameat2(AT_RENAME_NOREPLACE)` for create-only publication. No older
  syscall fallback exists. The running kernel must include the
  [FreeBSD-SA-26:42.unlinkat fix](https://www.freebsd.org/security/advisories/FreeBSD-SA-26:42.unlinkat.asc),
  shipped in 15.1-RELEASE-p1. A non-destructive directory probe verifies that
  `funlinkat` rejects escape. That probe does not establish that every unrelated
  security patch is installed; keep the operating system patched.
  NetBSD uses retained descriptors and nofollow component traversal.
- BSD immutable, append-only, and no-unlink flags do not weaken privacy checks.
  The library does not reject harmless flags or clear them implicitly. Native
  write, resize, replace, and removal errors propagate when flags prohibit an operation.
- Windows validates persistent ACL support and volume plus 128-bit `FILE_ID_INFO`
  identity. Child creation and publication use native handle-relative operations.
- Existing-handle `verify` and `harden` use the supplied object, preserving its
  cursor. Hardening refuses wrong owners, kinds, and links, and revalidates access.
  It cannot undo previous disclosure or prove private creation/tree membership.

Native identity comparisons use device/inode pairs or Windows volume/file IDs
within the lifetime of retained handles. They are not persistent identifiers for
reopening objects after close, mount changes, or process restart. Filesystems and
protocols with unreliable identity or access-control reporting are outside the
verified contract.

## Publication and durability

Atomic staging is exclusive and private in the same validated directory. Named
temps have a 128-bit `getrandom` nonce. Publication retains staging identity,
reopens the destination through the parent capability, and checks identity and
security again. Readers observe whole old or new objects. Unix rename uses a
name within the private parent; Windows renames the exact source handle. These
checks detect same-principal replacement races, but cannot prevent a trusted
namespace writer from changing the destination immediately after validation.

Privacy, atomic visibility, and persistence are independent:

| Durability | Requested ordering |
| --- | --- |
| `None` | Atomic publication; no explicit flush |
| `Data` | File data sync before publication; directory entry may be lost |
| `Full` | File contents/metadata sync, publication, then parent directory sync |

BSD `Data` requests the native file-data sync; `Full` requests file and parent
`fsync` in publication order. Filesystem sync failures propagate.

macOS `Full` also requests `F_FULLFSYNC` for file and parent. Windows uses native
file flushes and a validated writable handle to the same parent object. Unsupported
flushes return errors rather than reducing the requested guarantee. Hardware may
still lie about persistence. Process-exit tests do not prove physical power-cut
behavior. On older Windows/filesystems, classic atomic rename may refuse replacing
an open destination when the extended POSIX rename class is unavailable.

A failed commit reports whether publication **may** have occurred. Post-publication
failure cannot safely roll back. Check the error and construct a fresh writer to
retry; do not assume an error means the old destination is still present. A stream
I/O error poisons the transaction. `flush` alone does not commit or request durability.

## Cleanup and unsupported filesystems

Cleanup never deletes a replacement object by stale name. Windows disposes the
original handle. FreeBSD uses identity-bound `funlinkat` cleanup. Unlinked Linux anonymous staging disappears on close. **Named
Linux, macOS, and NetBSD staging is retained on abort or pre-publication failure**, even when its
current name still matches: no supported identity-bound compare-and-unlink exists.
Explicit abort on those platforms reports `UnsupportedFilesystem`; drop preserves
the primary error. FreeBSD and Windows report native cleanup failures.
After an ambiguous publication attempt the library does not retry cleanup. Crashes
can leave private named orphans on every platform; macOS, FreeBSD, and NetBSD always use named staging,
and Linux may use it when `O_TMPFILE` is unavailable or after materialization.
Successful publication removes the staging name. There is no automatic prefix-based orphan collector. During exclusive maintenance,
call `entries()`, select known abandoned files using application knowledge, and
call `remove_file(name, durability)`. On Linux, macOS, and NetBSD, callers must
exclude concurrent same-principal namespace writers during that maintenance.
Enumeration alone never proves that a temp is abandoned.

## Acquisition, enumeration, and removal

`open_file_with` separates data access, creation, truncation, and verification.
Read-only acquisition cannot create or truncate. Read/write acquisition of an
existing object never passes native truncate flags; the library validates the
retained object first, then resizes that exact object. `OpenOrCreate` preserves
existing contents by default and creates exclusively if absent. Unix acquisition
checks the observed type before opening to reject known special files, then
validates the opened identity. Concurrent same-principal substitution is excluded
from the confidentiality boundary. Resizing and writes can take effect before a
post-operation verification error; these operations are not transactions.

`open_dir` verifies without creation. `ensure_dir_all` creates and validates each
component sequentially through private handles. Failure can leave earlier private
directories; it does not harden existing ancestors or promise crash persistence.

`entries()` reads the retained directory through a native enumeration handle and
returns native filenames, without type hints. It excludes `.` and `..`, reports
unusable names and native errors, and does not reopen the ambient root pathname.
Enumeration is not a snapshot; concurrently created or removed entries can be
missing, repeated, or stale. Fresh secure acquisition is required before use.
Each enumeration owns an independent scan cursor.

`remove_file` validates a private regular target and its parent. A missing file is
`Io(NotFound)`. Windows disposition selects the exact handle and can remain
pending while other handles exist. FreeBSD `funlinkat` atomically requires the
entry to refer to the retained file. Linux, macOS, and NetBSD `unlinkat` acts on
the current name. Identity checks before that syscall detect some replacements
but do not eliminate the compare/unlink race. Callers coordinate concurrent
same-principal namespace writers. Other principals cannot write a verified private
parent under this contract. The method does not recursively delete directories.
`None` and `Data` add no deletion sync; `Full` syncs the parent after removal.
`Error::Removal` distinguishes known native refusals from uncertain I/O outcomes.
It reports possible removal after success followed by a sync/verification failure.
A FreeBSD identity mismatch, access refusal, or supported sharing refusal reports
that removal did not occur. Unclassified native errors remain conservative.
It does not promise immediate reclamation or power-loss persistence on Windows
while disposition remains pending.

`Publication::Replace` validates any existing destination before replacement but
is not compare-and-swap. `CreateNew` uses native exclusive atomic rename on Linux,
macOS, FreeBSD, and Windows. A filesystem can reject that optional capability;
there is no non-atomic emulation. NetBSD rejects this policy before staging because
it lacks equivalent exclusive rename semantics. `AtomicCommit` reports definite non-publication for known native refusals such as
an existing create-only target. Unclassified syscall errors remain indeterminate.

Borrowed native descriptors/handles permit interoperability but bypass streaming
verification and the capability-relative API. Callers take responsibility for native
operations, access checks, mutable metadata, and namespace changes. Do not close
or transfer a borrowed handle. A later `verify` detects only the properties that
can currently be inspected; it cannot undo disclosure or prove creation history.

Other operating systems and older BSD releases fail closed.
BSD ACL capability queries must work even on a filesystem with ACLs disabled.
UFS, NetBSD FFSv2ea, and FreeBSD ZFS are exercised by the native profile script;
filesystems with unavailable or ambiguous ACL reporting are rejected. Windows volumes without persistent ACLs and
macOS mounts without ownership enforcement are rejected. Arbitrary network, FUSE,
and synthetic filesystems are not certified by these metadata checks; use a local
filesystem whose semantics you trust. The library cannot establish that a server
or filesystem implementation is truthful merely by querying it.

## Reporting

Do not post credentials, secret contents, or exploit details in public issues.
This repository currently declares no private security-reporting contact. Arrange
a private channel with the maintainer before disclosing a sensitive vulnerability.
