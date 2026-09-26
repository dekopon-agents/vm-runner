#!/usr/bin/env bash
set -euo pipefail
rootfs=$1
for directory in / /usr/sbin /usr/local/bin /usr/bin /opt/ms-playwright; do
    debugfs -R "ls -l $directory" "$rootfs"
done
browser=$(debugfs -R 'cat /etc/vm-browser-path' "$rootfs" 2>/dev/null)
# Debian's merged /usr makes /sbin a symlink; debugfs does not traverse directory symlinks.
for path in /usr/sbin/vm-init /usr/local/bin/vm-guest-agent /usr/local/bin/node "$browser"; do
    stat=$(debugfs -R "stat $path" "$rootfs" 2>/dev/null)
    printf '%s\n%s\n' "$path" "$stat"
    grep -Eq 'Type: regular.*Mode:  +0755' <<< "$stat"
done
debugfs -R 'stat /sbin' "$rootfs" 2>/dev/null | grep '"usr/sbin"'
