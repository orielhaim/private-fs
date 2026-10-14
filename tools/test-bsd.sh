#!/bin/sh
set -eu

os=$(uname -s)
work=$(mktemp -d /tmp/private-fs-native.XXXXXX)
mountpoint="$work/fs"
mkdir "$mountpoint"
device=
pool=
cleanup() {
    result=$?
    trap - EXIT HUP INT TERM
    cleanup_failed=0
    if [ -n "$pool" ]; then zpool destroy "$pool" || cleanup_failed=1; fi
    if mount | grep -q " on $mountpoint "; then umount "$mountpoint" || cleanup_failed=1; fi
    if [ -n "$device" ]; then
        case "$os" in
            FreeBSD) mdconfig -d -u "$device" || cleanup_failed=1 ;;
            NetBSD) vndconfig -u "$device" || cleanup_failed=1 ;;
        esac
    fi
    if [ "$cleanup_failed" = 0 ]; then
        rm -rf "$work"
    else
        echo "native fixture cleanup failed; retained $work" >&2
        if [ "$result" = 0 ]; then result=1; fi
    fi
    exit "$result"
}
trap cleanup EXIT HUP INT TERM

uname -a
rustc -vV
echo "private-fs profile=default property_cases=${PROPTEST_CASES:-256}"
cargo test --locked -p private-fs
cargo bench --locked --bench filesystem -- --test
for profile in none posix nfs4; do
    case "$os" in
        FreeBSD)
            truncate -s 256m "$work/$profile.img"
            device=$(mdconfig -a -t vnode -f "$work/$profile.img")
            newfs -U "/dev/$device"
            case "$profile" in
                posix) tunefs -a enable "/dev/$device" ;;
                nfs4) tunefs -N enable "/dev/$device" ;;
            esac
            mount "/dev/$device" "$mountpoint"
            ;;
        NetBSD)
            dd if=/dev/zero of="$work/$profile.img" bs=1m count=256
            newfs -F -O 2ea "$work/$profile.img"
            candidate=vnd0
            vndconfig "$candidate" "$work/$profile.img"
            device="$candidate"
            case "$profile" in
                none) mount -t ffs "/dev/${device}d" "$mountpoint" ;;
                posix) mount -t ffs -o posix1eacls "/dev/${device}d" "$mountpoint" ;;
                nfs4) mount -t ffs -o nfs4acls "/dev/${device}d" "$mountpoint" ;;
            esac
            ;;
        *) echo "unsupported native test OS: $os" >&2; exit 1 ;;
    esac
    chmod 700 "$mountpoint"
    echo "private-fs profile=$profile property_cases=${PROPTEST_CASES:-256}"
    df "$mountpoint"
    mount
    TMPDIR="$mountpoint" PRIVATE_FS_EXPECT_ACL="$profile" PRIVATE_FS_EXPECT_FLAGS=1 cargo test --locked -p private-fs
    umount "$mountpoint"
    case "$os" in
        FreeBSD) mdconfig -d -u "$device" ;;
        NetBSD) vndconfig -u "$device" ;;
    esac
    device=
done

if [ "$os" = FreeBSD ]; then
    truncate -s 512m "$work/zfs.img"
    candidate="privatefs_test_$$"
    zpool create -f -m "$mountpoint" "$candidate" "$work/zfs.img"
    pool="$candidate"
    zfs set acltype=nfsv4 "$pool"
    chmod 700 "$mountpoint"
    echo "private-fs profile=zfs-nfs4 property_cases=${PROPTEST_CASES:-256}"
    zfs get acltype "$pool"
    df -T "$mountpoint"
    TMPDIR="$mountpoint" PRIVATE_FS_EXPECT_ACL=nfs4 cargo test --locked -p private-fs
    zpool destroy "$pool"
    pool=
fi
