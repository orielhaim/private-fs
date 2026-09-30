# Security contract

`private-fs` protects application files from other unprivileged principals on
Linux, macOS, and Windows filesystems that truthfully report metadata and enforce
their native access controls. It rejects hostile namespace state rather than
repairing it implicitly. Root/administrator bypass, the kernel, storage firmware,
process compromise, and actors sharing the effective UID or Windows TokenUser
are outside the isolation boundary. This is access control, not encryption.
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
  non-Unicode names are preserved. Windows NT names are not normalized to Win32
  spelling conventions; callers should use the capability for subsequent access.
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
  Mutable metadata is checked again before/after I/O and at publication boundaries.
- macOS ACL operations are FD-bound. Nonempty extended ACLs are rejected; explicit
  hardening clears and revalidates them. Ownership-disabled mounts fail closed.
- Windows validates persistent ACL support and volume plus 128-bit `FILE_ID_INFO`
  identity. Child creation and publication use native handle-relative operations.
- Existing-handle `verify` and `harden` use the supplied object, preserving its
  cursor. Hardening refuses wrong owners, kinds, and links, and revalidates access.
  It cannot undo previous disclosure or prove private creation/tree membership.

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
original handle. Unlinked Linux anonymous staging disappears on close. **Named
Unix staging is retained on abort or pre-publication failure**, even when its
current name still matches: no supported identity-bound compare-and-unlink exists.
Explicit abort reports `UnsupportedFilesystem`; drop preserves the primary error.
After an ambiguous publication attempt the library does not retry cleanup. Crashes
can leave private named orphans on every platform; macOS always uses named staging,
and Linux may use it when `O_TMPFILE` is unavailable or after materialization.
Successful publication removes the staging name. The crate provides no automatic
orphan collector; unlinking names in an attacker-mutable namespace cannot be made
safe by checking metadata first.

Other operating systems fail closed. Windows volumes without persistent ACLs and
macOS mounts without ownership enforcement are rejected. Arbitrary network, FUSE,
and synthetic filesystems are not certified by these metadata checks; use a local
filesystem whose semantics you trust. The library cannot establish that a server
or filesystem implementation is truthful merely by querying it.

## Reporting

Do not post credentials, secret contents, or exploit details in public issues.
This repository currently declares no private security-reporting contact. Arrange
a private channel with the maintainer before disclosing a sensitive vulnerability.
