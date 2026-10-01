# Browser and toolkit guest

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
trust, and configures eth0 as 10.0.2.2/30 via 10.0.2.1, then execs Debian's `tini` as
PID 1 with the agent as its only child. Orphans such as `browse`'s detached Chromium
reparent to tini, which reaps them; the agent waits only for its own execs.
The `jail` user's default Node module and browser-cache paths point at the baked
Playwright installation; no browser download is needed at exec time.

`browse` (`browse --help`) keeps one headless Chromium for the life of the jail. The first
call starts it in its own session, outside the exec's process group, with DevTools on
127.0.0.1:9222 and a profile under `~/.browse-profile`; every call reattaches over CDP, so
tabs, cookies and page state carry across execs. Playwright scripts can attach with
`chromium.connectOverCDP('http://127.0.0.1:9222')`.

The Guest image workflow builds both architectures on PRs without publishing.
An owner-pushed annotated `guest-v*` tag on main additionally publishes
`ghcr.io/dekopon-agents/vm-runner-guest:v*`. Each platform manifest has two
annotated layers (zstd ext4 and kernel); the OCI index advertises both platforms
and is provenance-attested. Profiles must use its digest, not its tag.

## Small offline toolkit

The image also includes distro `python3`, `jq`, `ripgrep` (`rg`), `zip`, `unzip`
and `poppler-utils` (`pdftotext`, `pdfinfo`), plus uv 0.12.21. uv's official
GNU/Linux amd64 and arm64 archives are SHA-256 pinned; only the `uv` binary is
installed, not `uvx`. There is no separately installed pip or `python3-venv`,
compiler, OCR or scientific stack.

The `uv` wrapper sets `UV_PYTHON_PREFERENCE=only-system` and
`UV_PYTHON_DOWNLOADS=never` on every exec, including cleared environments.
It does not force `UV_PYTHON`, so `uv pip` can target a nearby `.venv` or an
activated environment while venv creation uses the baked system interpreter. Its default cache is `/home/jail/.cache/uv`;
`UV_CACHE_DIR` can select another writable location. The jail home is writable
through the scratch-backed overlay, so a normal `uv venv ~/venv` works without
pip or interpreter downloads. Package installation/network access still requires
the existing egress policy; no additional hosts are allowed by this image.

An offline build-time smoke runs as uid 1000 with cleared environment and no
network. It executes Python, creates/writes a uv venv using the baked interpreter
without pip, installs/imports a tiny local wheel via `uv --offline pip install`
into the discovered `.venv`, checks jq/rg and a zip/unzip roundtrip, and extracts
text/metadata from a tiny generated PDF. Fixtures, the venv and its cache are removed.
`verify.sh` checks these shipped executables in ext4, including Python's symlink
target. Dual-arch guest CI is the full image gate.

The PR proof reads ext4 using debugfs; it is not a VM boot or a KVM proof.
