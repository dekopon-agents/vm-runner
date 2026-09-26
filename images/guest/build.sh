#!/usr/bin/env bash
set -euo pipefail
if [[ $# != 2 || $(uname -s) != Linux ]]; then
    echo 'usage (native Linux): build.sh <musl vm-guest-agent> <output-directory>' >&2
    exit 2
fi
case $(uname -m) in
    x86_64)
        arch=amd64
        kernel_sha=e41c7048bd2475e7e788153823fcb9166a7e0b78c4c443bd6446d015fa735f53
        ;;
    aarch64)
        arch=arm64
        kernel_sha=61baeae1ac6197be4fc5c71fa78df266acdc33c54570290d2f611c2b42c105be
        ;;
    *) echo 'unsupported architecture' >&2; exit 2 ;;
esac
source_dir=$(cd -- "$(dirname -- "$0")" && pwd)
mkdir -p "$2"
out=$(realpath "$2")
work=$(mktemp -d)
image="vm-runner-guest-build:$$"
container=
cleanup() {
    if [[ -n "$container" ]]; then docker rm "$container" >/dev/null; fi
    docker image rm "$image" >/dev/null 2>&1 || true
    sudo rm -rf "$work"
}
trap cleanup EXIT
mkdir "$work/context" "$work/root"
cp "$source_dir/Dockerfile" "$source_dir/vm-init" "$work/context/"
cp "$1" "$work/context/vm-guest-agent"
docker buildx build --platform "linux/$arch" --load --tag "$image" "$work/context"
container=$(docker create "$image")
docker export "$container" | sudo tar --numeric-owner -xp -C "$work/root"
bytes=$(sudo du --summarize --block-size=1 "$work/root" | cut -f1)
truncate -s "$((bytes + 256 * 1024 * 1024))" "$out/rootfs.ext4"
# The guest's 6.1 kernel predates orphan_file, now enabled by host e2fsprogs defaults.
sudo mkfs.ext4 -F -O '^orphan_file' -d "$work/root" "$out/rootfs.ext4"
zstd -T0 -f "$out/rootfs.ext4" -o "$out/rootfs.ext4.zst"
curl --fail --location --output "$out/vmlinux" \
    "https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.14/$(uname -m)/vmlinux-6.1.155"
printf '%s  %s\n' "$kernel_sha" "$out/vmlinux" | sha256sum --check
