
# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-10-14

### Added

* Native FreeBSD 15.1+ and NetBSD 11.0+ support with descriptor-relative
  filesystem operations and POSIX.1e/NFSv4 ACL verification.
* `PrivateDir::open_file_with` and `OpenOptions` for read/write access,
  exclusive creation, open-or-create, and explicit truncation after validation.
* `Verification::OnDemand` for applications that manage their own
  verification boundaries.
* Capability-relative directory enumeration, recursive directory creation,
  opening existing directories, and file deletion with durability options.
* `PrivateFile::set_len` with validation before and after resizing.
* `Publication::CreateNew` for atomic create-only publication on supported
  platforms.

### Changed

* Consolidated Unix filesystem operations while preserving native
  platform-specific security checks.
* Strengthened ownership, ACL, object identity, and path traversal validation.
* Improved atomic publication, durability, and temporary-file cleanup.
* Extended Windows handle-relative file access, enumeration, and deletion.
* Expanded lifecycle, fault-injection, and regression tests.

## [0.1.0] - 2026-09-30

Initial release.

* Private filesystem capabilities for Linux, macOS, and Windows.
* Secure file and directory creation with ownership, permissions, ACL,
  and object identity validation.
* Capability-relative filesystem operations and atomic writes with
  configurable durability.
* Protection against symlinks, reparse points, hard links, and path traversal.
