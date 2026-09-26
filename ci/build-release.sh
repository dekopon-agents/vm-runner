#!/usr/bin/env bash
set -euo pipefail
target="$1"
[[ "$target" == "$(uname -m)-unknown-linux-musl" ]]
rustup target add "$target"
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc
cargo build --release --locked --target "$target" --bins
mkdir -p dist
mapfile -t bins < <(cargo metadata --locked --no-deps --format-version 1 |
  jq -r '.packages[] | select(.name == "vm-runner") | .targets[] | select(.kind | index("bin")) | .name')
for bin in "${bins[@]}"; do
  install -m 0755 "target/$target/release/$bin" "dist/$bin-$target"
  (cd dist && sha256sum "$bin-$target" > "$bin-$target.sha256")
done
