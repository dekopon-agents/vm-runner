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
Init sets `vm.overcommit_memory=1`: in a 512 MiB guest the default heuristic refuses
any single mapping larger than RAM, which is what V8's x64 CodeRange reservation is, so every
Chromium renderer would die at startup. Exhaustion becomes an in-guest OOM kill instead of `ENOMEM`,
and the victim can be the guest agent: tini then exits as PID 1, the guest panics and the jail
exits, losing the browser, scratch and any running exec. That session's next exec returns
`not_executed` with reason `boot_failure`.
The `jail` user's default Node module and browser-cache paths point at the baked
Playwright installation; no browser download is needed at exec time.

`browse` (`browse --help`) keeps one headless Chromium for the life of the jail. The first
call starts it in its own session, outside the exec's process group, with DevTools on
127.0.0.1:9222 and a profile under `~/.browse-profile`; every call reattaches over CDP, so
tabs, cookies and page state carry across execs. Playwright scripts can attach with
`chromium.connectOverCDP('http://127.0.0.1:9222')`.
`browse shot NAME` appends `.png` unless NAME ends in `.png`, `.jpg` or `.jpeg`
(case-insensitive); the final file name must fit 128 characters.

Before each `browse open` navigation, the CLI applies a desktop User-Agent without
`HeadlessChrome` and client hints derived from the installed Chromium version.
Node scripts share the same defaults with
`const { configurePage } = require('/opt/playwright/browser.cjs')`: await
`configurePage(page)` before navigating each new page. The returned CDP session
is retained for that script's lifetime; do not detach it before navigation or
extraction finishes. Overrides are scoped to the live attachment, not a persistent
browser policy. A site recipe can apply an explicit identity after the default.
This keeps Linux identity and software graphics; it adds no stealth package and
does not change grants, egress or TLS verification. These defaults normalize page identity; site access still depends on the
browser launch, session, network and site policy. They do not guarantee content access.

The Guest image workflow builds both architectures on PRs without publishing. Its
`KVM PR guest` job boots the amd64 artifact (not the released digest) against a
local fake; if hosted `/dev/kvm` is absent the job fails rather than proving a
published guest. The regular `kvm` workflow still boots a pinned release.
An owner-pushed annotated `guest-v*` tag on main additionally publishes
`ghcr.io/dekopon-agents/vm-runner-guest:v*`. Each platform manifest has two
annotated layers (zstd ext4 and kernel); the OCI index advertises both platforms
and is provenance-attested. Profiles must use its digest, not its tag.

## Compatibility evidence and validation boundary

A headed macOS browser completed a Discord sign-in and an application-page reload
on 2026-11-21 with its existing launch configuration: Chrome 158.0.8127.37,
playwright-cli 0.1.24, `--enable-automation` omitted and
`--disable-blink-features=AutomationControlled` supplied. No configuration change
or CAPTCHA was needed on that successful attempt. This is neither a controlled
attribution to those flags nor Linux, guest-proxy or restart-persistence proof.
Do not copy macOS keychain settings or a signed-in desktop profile into a guest.

The reusable layer is browser lifecycle plus platform-appropriate launch/page
configuration. `configurePage` applies only to its live page attachment; raw
Chromium and agent-browser clients do not inherit it as a persistent global
policy. Site-specific exceptions should follow the common setup, not duplicate it.
A startup-policy change needs its own tests rather than copying desktop flags and
assuming a headless guest will be accepted.

Before calling a configuration VM-validated:

- Build and boot the candidate guest artifact in the existing dual-architecture
  and PR KVM gates. Verify upstream HTTP headers against page JavaScript, separate
  execs, new tabs, retained identity sessions, site overrides and resource bounds.
- Use an authorized disposable Firecracker session through the actual runner
  egress proxy and an explicitly authorized origin set. Record the guest digest,
  architecture, subject/profile, browser version and final rendered evidence.
  A Mac container or a local fake is not the real-site result.
- Compare baseline, page helper and proposed launch changes in fresh sessions.
  Repeat successful public-content reads across two sessions and two threads;
  preserve DNS/egress failures, security blocks, CAPTCHA and partial renders.
- Treat authenticated browsing as a separate credential and persistence design.
  The guest currently holds no credential and loses its profile at jail expiry.
  Do not import desktop passwords, cookies, tokens or keychain material. A human
  verification requirement needs an owner interaction path, not a CAPTCHA solver.
- Publish only an owner-authorized version, then review the deployment digest
  change and verify a new authorized test session. Source, image publication,
  deployed pin and successful site access are different claims.

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

The ext4 proof reads with debugfs; the separate PR guest KVM job boots it.

## CDP video recipe

The image ships Debian ffmpeg/ffprobe and npm `@earendil-works/pi-coding-agent`
1.2.0, pinned by `pi/package-lock.json` with integrity
`sha512-h/4WaVWv1VlCaY8x8qEN5U+7jbF/e7+Ck6moPeEOFn5juMTWwNAXjwgYM7gRgbBYh8Zppwt6qWvJDzNTf4GNEQ==`.
The `pi` PATH wrapper selects `/home/jail/.pi-proxy/models.json` even when the exec environment
is cleared: only `vm-proxy/sol` via the existing `models.vm.internal` Responses
route, with a non-secret dummy key. It does not create a grant: absent model
routing fails closed, and egress still requires the subject's proxy grant.

Inside a jail, open a tab first (for example, `browse open 'data:text/html,<p>Capture me</p>'`),
then run `browse record proof` to record the current tab (the `*` in `browse tabs`) for
10 seconds. `browse record proof --seconds 3` selects a shorter duration; the range is 1–30.
NAME has no `.mp4` suffix and must keep NAME.mp4 within the provider's 128-character flat-name limit.
`record-cdp --help` describes the lower-level tool: `record-cdp proof` still records the last
tab for 30 seconds, and `record-cdp --seconds 3 proof` selects a duration.
Both commands capture one 1280×720 PNG frame per second from CDP `Page.startScreencast`,
with a visible frame counter to keep static pages updating. They encode
an H.264 MP4 with faststart and x264's `zerolatency` tune (no lookahead or B-frame
buffering) in a private `/scratch/recordings` directory
and probe it. Each finished file is copied into an unnamed `O_TMPFILE` in
`/artifacts` and only then linked as `/artifacts/proof.mp4` and `/artifacts/proof.png` (the first
captured frame), so listing and reads never see a partial file and an existing name is never
replaced.
Both print `/proc/meminfo` and `oom_kill /proc/vmstat` before and after encoding,
and ffprobe duration/size/codec.
A failed encode publishes nothing. A recording longer than the exec deadline returns a job;
poll it to completion before attaching the files. Do not assume Stop reclaims a still-running
child promptly.

## Limits in a 512 MiB jail

Use `browse record` for video within the existing browser. On `pw-1c512m` (one vCPU,
512 MiB), a second Playwright context with `recordVideo` produced 12 KB of blank frames;
a 40-screenshot loop took more than 3.5 minutes. Both reached the pod's 640 Mi
`memory.peak` limit. Do not use either approach for video. Given the shipped tool's name,
`record-cdp` produced a 30.0-second 1280×720 H.264 MP4 in 78 seconds. Capture plus encoding
takes longer than the resulting video's playback duration; poll the job instead of starting
another recorder.

For an offline memory regression check, run a built guest-stage image as `$guest_image`:

```sh
docker run --rm --init --network none --cpus 1 --memory 512m --memory-swap 512m \
  --user 1000:1000 --workdir /home/jail \
  --tmpfs /artifacts:uid=1000,gid=1000,mode=0755 \
  --tmpfs /scratch/recordings:uid=1000,gid=1000,mode=0700 \
  --mount "type=bind,src=$PWD/images/guest/recording-memory-smoke.sh,dst=/tmp/recording-memory-smoke.sh,readonly" \
  --entrypoint /usr/bin/env "$guest_image" \
  -i HOME=/home/jail PATH=/usr/local/bin:/usr/bin:/bin sh /tmp/recording-memory-smoke.sh
```

This cgroup v2 check records the selected of two tabs for the default 10 seconds,
requires no OOM kills (even if the encoder survives one), and checks the codec,
dimensions, duration, selected-page pixels and first-frame preview. The KVM gate
still proves the PR-built image in a 512 MiB guest.
