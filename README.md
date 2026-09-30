# private-fs

Private filesystem capabilities for Linux, macOS, and Windows

Files and directories are private from creation. Operations stay bound to validated filesystem objects instead of reopening full paths

See [`SECURITY.md`](SECURITY.md) for the full security contract

```rust
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
- fails closed when the filesystem cannot provide the required semantics.

Existing objects are never hardened implicitly.

```rust
let dir = PrivateDir::open("app-private")?;
let file = dir.open_file("token")?;

file.verify()?;
file.harden()?;
```

## Atomic writes

```rust
let mut writer = dir.atomic("state.json")?;
writer.write_all(b"new state")?;
writer.commit()?;

dir.write_atomic_durable("state.json", b"durable state")?;
```

Atomic writes stage privately in the same validated directory, publish relative to the directory capability, then verify the published object's identity and security state.

Durability is explicit:

| API | Persistence |
| --- | --- |
| `write_atomic` | no explicit sync |
| `Data` | sync file data before publication |
| `write_atomic_durable` | sync file, publish, sync parent |

Linux uses `O_TMPFILE` where available. Named Unix staging files may intentionally remain after failure when safe identity-bound deletion is unavailable.

## Scope

`private-fs` is intended for private application state such as credentials, keys, tokens, configuration, and local databases.

It does not protect against root/Administrator, process compromise, malicious code running as the same user, or encryption-at-rest threats.

## License

[MIT](LICENSE-MIT) OR [Apache-2.0](LICENSE-APACHE) at your option
