# private-fs

Private filesystem capabilities for Linux, macOS, Windows, FreeBSD and NetBSD

Files and directories are private from creation. Operations stay bound to validated filesystem objects instead of reopening full paths

See [`SECURITY.md`](SECURITY.md) for the full security contract

```rust,no_run
use private_fs::PrivateDir;
use std::io::Write;

fn main() -> private_fs::Result<()> {
    let dir = PrivateDir::ensure("app-private")?;

    let mut file = dir.create("token")?;
    file.write_all(b"secret")?;

    Ok(())
}
```

## Guarantees

`PrivateDir` is a validated directory capability. Child operations are resolved relative to its retained handle.

The crate:

- creates files as `0600` and directories as `0700` on Unix;
- verifies ownership, modes, hard links, ACLs, and object identity;
- rejects symlinks, reparse points, traversal, and namespace escape;
- uses protected user-only DACLs on Windows;
- validates macOS extended ACLs and ownership enforcement;
- verifies BSD POSIX/NFSv4 ACLs and creation inheritance;
- fails closed when the filesystem cannot provide the required semantics.

Existing objects are never hardened implicitly.

```rust,no_run
use private_fs::PrivateDir;

let dir = PrivateDir::open("app-private")?;
let file = dir.open_file("token")?;

file.verify()?;
file.harden()?;
# Ok::<(), private_fs::Error>(())
```

## Manage application state

```rust,no_run
use private_fs::{Durability, FileAccess, FileCreation, OpenOptions, PrivateDir};
use std::io::{Seek, SeekFrom, Write};

let dir = PrivateDir::open("app-private")?;
let state = dir.ensure_dir_all("cache/session")?;
let mut file = state.open_file_with("data", OpenOptions {
    access: FileAccess::ReadWrite,
    creation: FileCreation::OpenOrCreate,
    ..OpenOptions::default()
})?;
file.seek(SeekFrom::Start(0))?;
file.write_all(b"state")?;
file.set_len(5)?;
file.sync_all()?;
drop(file);

for name in state.entries()? {
    state.open_file(&name)?.verify()?;
}
state.remove_file("data", Durability::Full)?;
# Ok::<(), private_fs::Error>(())
```

Opening existing files preserves contents. Select `truncate: true` to resize only
after validation. `open_dir` verifies an existing child directory without creating
it. Enumeration returns native names, not authorized file objects or a snapshot.

`Verification::PerIo` is the default. `OnDemand` lets callers bracket a larger
streaming transaction with `verify()`; it does not detect metadata changes during
individual reads and writes. Sync and resizing still verify under both policies.
Strict owner-only access remains fixed. Hardening is explicit and handle-bound.

## Atomic writes

```rust,no_run
use private_fs::PrivateDir;
use std::io::Write;

let dir = PrivateDir::open("app-private")?;
let mut writer = dir.atomic("state.json")?;
writer.write_all(b"new state")?;
writer.commit()?;

dir.write_atomic_durable("state.json", b"durable state")?;
# Ok::<(), private_fs::Error>(())
```

Atomic writes stage privately in the same validated directory, publish relative to the directory capability, then verify the published object's identity and security state.

Durability is explicit:

| API | Persistence |
| --- | --- |
| `write_atomic` | no explicit sync |
| `Data` | sync file data before publication |
| `write_atomic_durable` | sync file, publish, then `PrivateDir::sync_all` |

`PrivateDir::sync_all` flushes the retained directory itself, including namespace
changes the filesystem reports for that directory. It does not sync file contents,
nested directories, or the name of this directory in its parent. It is not a
transaction and does not prove that a deletion occurred. On Windows a removal can
stay pending while other handles remain open.

`atomic_with_policy(path, durability, Publication::CreateNew)` fails atomically if
any destination exists. NetBSD explicitly rejects this optional policy.

Linux uses `O_TMPFILE` where available. FreeBSD uses `funlinkat` for identity-bound
named staging cleanup. Named Linux, macOS, and NetBSD staging files may intentionally remain after failure.
During exclusive maintenance, select known abandoned entries and use `remove_file`.
The library never deletes files solely because their names match a prefix.

FreeBSD requires the containment fix in 15.1-p1 or later and checks its behavior
at runtime. Keep every supported OS patched. See the security contract for
filesystem requirements and platform differences.

## Scope

`private-fs` is intended for private application state such as credentials, keys, tokens, configuration, and local databases.

It does not protect against root/Administrator, process compromise, malicious code running as the same user, or encryption-at-rest threats.

## License

[MIT](LICENSE-MIT) OR [Apache-2.0](LICENSE-APACHE) at your option
