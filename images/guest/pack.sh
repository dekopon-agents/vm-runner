#!/usr/bin/env bash
set -euo pipefail
arch=$1
reference=$2
shift 2
source_dir=$(cd -- "$(dirname -- "$0")" && pwd)
created=$(git -C "$source_dir" show -s --format=%cI HEAD)
jq -n --arg arch "$arch" '{architecture:$arch,os:"linux"}' > config.json
jq -n --arg created "$created" '{
    "$manifest": {"org.opencontainers.image.created":$created},
    "rootfs.ext4.zst": {"org.dekopon.vm-runner.guest.rootfs":"rootfs.ext4"},
    "vmlinux": {"org.dekopon.vm-runner.guest.kernel":"vmlinux"}
}' > annotations.json
oras push "$reference" "$@" --export-manifest manifest.json \
    --config config.json:application/vnd.oci.image.config.v1+json \
    --annotation-file annotations.json \
    rootfs.ext4.zst:application/vnd.dekopon.vm-runner.rootfs.v1.ext4+zstd \
    vmlinux:application/vnd.dekopon.vm-runner.kernel.v1
