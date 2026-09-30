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
