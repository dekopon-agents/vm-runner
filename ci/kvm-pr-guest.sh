#!/usr/bin/env bash
set -euo pipefail
# The manifest and layers are the PR guest job's artifact, never a published tag.
cd "$RUNNER_TEMP/pr-guest"
for name in rootfs.ext4.zst vmlinux; do
  hash=$(jq -r --arg name "$name" '.layers[] | select(.annotations["org.dekopon.vm-runner.guest.rootfs"] == "rootfs.ext4" and $name == "rootfs.ext4.zst" or .annotations["org.dekopon.vm-runner.guest.kernel"] == "vmlinux" and $name == "vmlinux") | .digest | sub("^sha256:"; "")' manifest.json)
  test -n "$hash"
  printf '%s  %s\n' "$hash" "$name" | sha256sum -c
  sha256sum "$name"
done
hash=$(sha256sum manifest.json | cut -d' ' -f1)
export KVM_GUEST_IMAGE="ghcr.io/dekopon-agents/vm-runner-guest@sha256:$hash"
mkdir -p "$RUNNER_TEMP/images/sha256-$hash-x86_64"
zstd -d -c rootfs.ext4.zst > "$RUNNER_TEMP/images/sha256-$hash-x86_64/rootfs.ext4"
cp vmlinux "$RUNNER_TEMP/images/sha256-$hash-x86_64/vmlinux"
printf 'PR_HEAD=%s GUEST_MANIFEST_SHA256=%s ROOTFS_SHA256=%s\n' "$GITHUB_SHA" "$hash" "$(sha256sum "$RUNNER_TEMP/images/sha256-$hash-x86_64/rootfs.ext4" | cut -d' ' -f1)"
cd "$GITHUB_WORKSPACE"
sudo apt-get update && sudo apt-get install -y ffmpeg
cargo build -p vm-runner --locked --bin vm-runnerd
cargo test -p vm-runner --locked --test kvm --no-run --message-format=json > "$RUNNER_TEMP/kvm-build.jsonl"
python3 -c 'import json,sys; print(next(x["executable"] for x in map(json.loads,open(sys.argv[1])) if x.get("target",{}).get("name")=="kvm" and x.get("executable")))' "$RUNNER_TEMP/kvm-build.jsonl" > "$RUNNER_TEMP/kvm-executable"
mkdir "$RUNNER_TEMP/kvm-context"
cp Dockerfile target/debug/vm-runnerd "$RUNNER_TEMP/kvm-context/"
# The host-side KVM witness runs inside this container, not on the Ubuntu runner.
printf '\nUSER 0\nRUN apt-get update && apt-get install -y --no-install-recommends ffmpeg && rm -rf /var/lib/apt/lists/*\nUSER 1000:1000\n' >> "$RUNNER_TEMP/kvm-context/Dockerfile"
docker build --build-arg TARGETARCH=amd64 -t vm-runner:kvm "$RUNNER_TEMP/kvm-context"
gid=60000
while getent group "$gid" >/dev/null; do gid=$((gid + 1)); done
sudo chgrp "$gid" /dev/kvm
sudo chmod 0660 /dev/kvm
sudo chmod 0666 /dev/net/tun
docker run --rm --user 0:0 --group-add 1000 --cap-drop ALL \
  --cap-add NET_ADMIN --cap-add SETUID --cap-add SETGID \
  --security-opt no-new-privileges \
  --device /dev/kvm --device /dev/net/tun \
  --sysctl net.ipv4.ip_forward=0 \
  --sysctl net.ipv4.ip_unprivileged_port_start=0 \
  --sysctl net.ipv4.conf.all.rp_filter=1 \
  --sysctl net.ipv4.conf.default.rp_filter=1 \
  --sysctl net.ipv6.conf.all.disable_ipv6=0 \
  --sysctl net.ipv6.conf.default.disable_ipv6=0 \
  --tmpfs /run/vm-runner:rw,gid=1000,mode=2770 \
  -v "$RUNNER_TEMP/images:/images:ro" -v "$PWD:$PWD:ro" -w "$PWD" \
  -e KVM_GUEST_IMAGE -e KVM_PR_GUEST=1 --entrypoint "$(cat "$RUNNER_TEMP/kvm-executable")" vm-runner:kvm --nocapture
