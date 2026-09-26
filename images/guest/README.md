# Browser guest

Build on native Linux amd64 or arm64 with Docker/buildx, sudo, e2fsprogs,
zstd and curl. Compile `vm-guest-agent` for the matching musl target first:

```sh
rustup target add x86_64-unknown-linux-musl
cargo build --release --locked --bin vm-guest-agent --target x86_64-unknown-linux-musl
bash images/guest/build.sh target/x86_64-unknown-linux-musl/release/vm-guest-agent /tmp/guest
bash images/guest/verify.sh /tmp/guest/rootfs.ext4
```

On arm64 use `aarch64-unknown-linux-musl`. The build exports Debian trixie with
SHA-pinned Node 24.21.0 LTS tarballs, Playwright 1.63.0 and its Chromium, then populates ext4 with
content size + 256 MiB. It downloads Firecracker CI's `vmlinux-6.1.155` and
checks the architecture-specific SHA-256 embedded in `build.sh`.

Boot with `init=/sbin/vm-init ro`, a read-only rootfs on vda, the session CA PEM
on vdb, and a formatted scratch ext4 on vdc. Init pivots into an overlay backed
by scratch, mounts `/artifacts` there for uid 1000, installs system/NSS/Node
trust, and configures eth0 as 10.0.2.2/30 via 10.0.2.1 before starting the agent.
The `jail` user's default Node module and browser-cache paths point at the baked
Playwright installation; no browser download is needed at exec time.

The Guest image workflow builds both architectures on PRs without publishing.
An owner-pushed annotated `guest-v*` tag on main additionally publishes
`ghcr.io/dekopon-agents/vm-runner-guest:v*`. Each platform manifest has two
annotated layers (zstd ext4 and kernel); the OCI index advertises both platforms
and is provenance-attested. Profiles must use its digest, not its tag.

The PR proof reads ext4 using debugfs; it is not a VM boot or a KVM proof.
