# Native filesystem benchmarks

Run `cargo bench --locked --bench filesystem -- --sample-count 30 --sample-size 1`.
On Linux repeat with `--features force-walk` before `--`. Both runs exercise the
real capability implementation, including all metadata/security checks. Fixture
setup/teardown is outside timing; operations include closing the returned handle. Windows
handle benchmarks include SID/DACL/volume/identity work; macOS includes FD ACL
and ownership enforcement checks. CI runs every benchmark once with `--test`.

Local baseline on 2026-09-30, release builds, 30 samples, median per operation:

| Operation | WSL Linux openat2 | WSL Linux forced walk | Native Windows |
| --- | ---: | ---: | ---: |
| Existing child file | 1.584 us | 1.528 us | 68.99 us |
| Existing child directory | 0.964 us | 1.006 us | 86.84 us |
| Create + verify | 4.838 us | 4.500 us | 225.8 us |
| Create directory | 62.87 us | 56.65 us | 204.4 us |
| Atomic None | 74.57 us | 79.97 us | 1.588 ms |
| Atomic Data | 7.604 ms | 7.422 ms | 4.822 ms |
| Atomic Full | 15.30 ms | 14.42 ms | 7.171 ms |
| Existing-handle verify | 0.173 us | 0.162 us | 8.199 us |
| Existing-handle harden | 0.733 us | 0.728 us | 105.3 us |

These short baselines are diagnostic, not regression thresholds. WSL fixtures use
a private `TMPDIR` under `/home/oriel` on ext4 (default `/tmp` is tmpfs); Windows
uses native TEMP. Set `TMPDIR` to a trusted native disk directory when measuring
durability. `strace` confirmed default child operations issue `openat2`, while
forced-walk operations issue only `openat`. Load, caching, and virtualization
affect results; no security checks were removed for these measurements.
macOS benchmarks cross-check cleanly
but were not measured locally because no native macOS runtime is available.

## Capability overhaul measurements, 2026-10-14

The new cases enumerate 102 entries, remove an existing nested file, and read
64 KiB in 1 KiB chunks. Streaming cases include acquisition and explicit
verification before and after the complete read under both policies.

Short release-build measurements used `--sample-count 20 --min-time 0.01
--max-time 0.1`. Fixtures use Windows TEMP, WSL ext4 under `/home/oriel`,
FreeBSD ZFS under `/root`, and NetBSD FFS under `/root`. BSD guests run through
QEMU/KVM on WSL. The final FreeBSD image is backed by WSL ext4; the NetBSD image
is backed by host tmpfs. Their timings include virtualization and are not a platform
ranking. The existing-handle checks and namespace operations retain normal
security validation. `OnDemand` deliberately replaces individual I/O checks
with caller-bracketed verification; `PerIo` remains the default.

| Median | Windows | WSL ext4 | FreeBSD 15.1-p3 ZFS | NetBSD 11.0 FFS |
| --- | ---: | ---: | ---: | ---: |
| Open nested file | 61.99 us | 1.744 us | 5.662 us | 12.34 us |
| Enumerate | 94.89 us | 12.77 us | 11.05 us | 29.38 us |
| Remove file, no sync | 581.4 us | 7.976 us | 23.36 us | 246.6 us |
| Stream, PerIo | 1.081 ms | 29.53 us | 205.3 us | 816.5 us |
| Stream, OnDemand | 128.7 us | 10.19 us | 29.40 us | 67.29 us |
| Atomic None | 1.562 ms | 89.10 us | 98.19 us | 660.8 us |
| Atomic Data | 4.394 ms | 6.051 ms | 7.437 ms | 1.107 ms |
| Atomic Full | 5.795 ms | 11.25 ms | 15.18 ms | 1.256 ms |

The Linux tmpfs run was excluded from persistence comparisons. File and
parent sync timings do not prove physical power-loss persistence. No native
macOS timings were collected in this environment. CI still runs the native
macOS benchmark smoke cases.
