#!/usr/bin/env bash
set -euo pipefail
rootfs=$1
for directory in / /usr/sbin /usr/local/bin /usr/bin /opt/ms-playwright; do
    debugfs -R "ls -l $directory" "$rootfs"
done
browser=$(debugfs -R 'cat /etc/vm-browser-path' "$rootfs" 2>/dev/null)
# Debian's merged /usr makes /sbin a symlink; debugfs does not traverse directory symlinks.
for path in /usr/sbin/vm-init /usr/local/bin/vm-guest-agent /usr/local/bin/browse /usr/local/bin/agent-browser /usr/local/bin/agent-browser-native /usr/local/bin/node /usr/local/bin/uv /usr/local/bin/uv-native /usr/bin/jq /usr/bin/rg /usr/bin/zip /usr/bin/unzip /usr/bin/pdftotext /usr/bin/pdfinfo /usr/bin/tini "$browser"; do
    stat=$(debugfs -R "stat $path" "$rootfs" 2>/dev/null)
    printf '%s\n%s\n' "$path" "$stat"
    grep -Eq 'Type: regular.*Mode:  +0755' <<< "$stat"
done
# python3 is a distro-managed symlink; debugfs does not follow it.
python=$(debugfs -R 'stat /usr/bin/python3' "$rootfs" 2>/dev/null | awk -F '"' '/Fast link dest:/ {print $2}')
[[ "$python" =~ ^python3\.[0-9]+$ ]]
debugfs -R "stat /usr/bin/$python" "$rootfs" 2>/dev/null | grep -Eq 'Type: regular.*Mode:  +0755'
debugfs -R 'stat /sbin' "$rootfs" 2>/dev/null | grep '"usr/sbin"'
debugfs -R 'stat /usr/local/bin/chromium' "$rootfs" 2>/dev/null | grep -F "\"$browser\""
