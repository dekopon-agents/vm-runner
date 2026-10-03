# vm-runner

Firecracker browser jails for Dekopon agents. Work in progress.

## Usage

```sh
cargo run --locked --bin vm-runnerd -- check --config examples/vm-runner.yaml
cargo run --locked --bin vm-runnerd -- openapi
cargo run --locked --bin vm-runnerd -- serve --config examples/vm-runner.yaml
```

Before serving, configure the issuer URL, optional CA/token files and exact service-account
subjects in the example config. `/healthz` is public; `/v1/whoami` requires a bearer JWT and
returns its subject and session quota. Optional `telemetry.otlp` selects `grpc` or `http`
with an endpoint and optional `caBundleFile` and `headersFile` (`key: value` per line).
Without telemetry configuration, tracing goes only to stdout JSON logs.

## Controller TLS (C3 config / C4 API)

Optional `tls: {certFile: /path/tls.crt, keyFile: /path/tls.key}` makes `serve` HTTPS-only
(TLS 1.2/1.3), including `/healthz` on the same listener. Supply a PEM certificate chain
(leaf first) and matching PEM private key. `check` and `serve` report unreadable, invalid
or mismatched pairs alongside other configuration conflicts before startup.
The listener checks file contents every second, including through cert-manager's rotated
symlinks, and reloads changed pairs or every ten minutes. A failed reload retains the last
valid pair and emits `vm_runner.tls.reload` with the failure cause, never key material.
Existing connections continue; new handshakes use the replacement pair. Without `tls`,
the controller remains HTTP. C1 bearer-token authentication is unchanged. The C7 jail API
remains plaintext pod-to-pod; deployment NetworkPolicy must restrict it to the controller.

## Named sessions

With a `jails` configuration, `serve` uses in-cluster Kubernetes credentials and rebuilds
its session registry from pod labels and annotations in `jails.namespace`.
**Deployment requirement:** this namespace is controller-owned. RBAC must grant pod
create/delete there only to the controller service account (apart from trusted cluster
administrators). Rebuild checks the subject annotation against its SHA-256 subject-hash
label (first 16 hex characters), the subject allowlist, configured profile and jail image.
Inconsistent or foreign pods are ignored; duplicate subject/name pods keep the oldest
`creationTimestamp`, and the rest are deleted.
Authenticated `POST /v1/sessions {"profile":"travel","name":"default"}` reserves a lazy
session (201), or returns the same subject/name session (200). Names are lowercase
alphanumeric with internal/trailing hyphens, at most 63 characters; omitted names are
`default`. Changing the profile for an existing name returns `409 session_profile_conflict`.
Admission applies the authenticated subject's `maxSessions` quota. Every ten seconds the
reaper deletes pods and reservations exceeding the profile's idle or maximum lifetime.
Both lifetimes must be at least 60 seconds. Terminating pods still consume quota until
Kubernetes confirms they are gone, but never satisfy create-or-get. Kubernetes cleanup
errors are logged and retried without blocking API admission; connect/read timeouts are
5/15 seconds.
No DELETE route is exposed. Without `jails`, session requests return 503.

Configure `jails` for both controller and jail roles; `controllerSubject` is required and
names the controller's service account, not a C4 caller from `auth.subjects`:

```yaml
jails:
  namespace: vm-runner
  image: ghcr.io/dekopon-agents/vm-runner@sha256:<64 hex digest>
  imageCacheHostPath: /var/lib/vm-runner/images
  controllerAudience: vm-runner-jail
  controllerSubject: system:serviceaccount:dekopon:vm-runner-controller
  tokenFile: /var/run/secrets/vm-runner-jail/token
  fetchTimeoutSeconds: 900 # default; image fetch has a separate 15-minute bound
  cpuRequestMilli: 250 # optional; default CPU request is the shape's full vCPU count
```

`cpuRequestMilli` reserves CPU for both image-fetch init and jail containers without
changing their limits (the shape's `vcpus`). It must be nonzero and no greater than
each configured profile shape's `vcpus * 1000`. Memory request and limit remain
`memoryMiB + 128Mi` for each container (for example, 512 MiB guests use 640 MiB).

`POST /v1/sessions/{id}/exec {"argv":["echo","hello"],"deadlineMs":25000}` boots the
reserved pod on first use, then proxies C7. It returns a terminal result (200), or an opaque
controller job ID (202) for `GET /v1/jobs/{jobId}`. Sessions and jobs are subject-scoped;
stdout/stderr are capped at 64 KiB each. The job map is capped at 64 per session and 1024
globally; a full map refuses exec before dispatch. `deadlineMs` must be 1000–25000.
A jail's terminal unknown job returns 200 `not_executed` with reason `unknown` and removes
the controller handle. Polling never refreshes session activity. Terminal boot failure retires
the reservation; transport/health errors return 502 `not_executed` without destroying it.
Terminating pods retain quota until confirmed gone. Jail and profile images require SHA-256 pins.

`GET /v1/sessions/{id}/artifacts` lists `{path, bytes, sha256}` for an already-booted,
owned session. `GET /v1/sessions/{id}/artifacts/{path}` streams a file with `sha256`,
`Content-Length` and `Accept-Ranges: bytes` headers. Encode the entire relative path as
one URL segment (`nested/file.txt` → `nested%2Ffile.txt`). Range is forwarded unchanged;
C7 supplies 200/206 or 416 with `Content-Range`. Traversal is refused. Listings are capped
at 1 MiB; one active download per controller holds its lease until body completion/drop,
returning 503 at capacity without blocking listings or general API admission. Downloads
reuse the 30-second C7 HTTP deadline, stream without collecting the file, and refresh
in-memory activity as chunks pass. Artifact requests do not boot unstarted sessions.

Deployment also requires a C7-capable `jails.image`, the `vm-runner-jail` service account,
`smarter-devices/kvm` and `smarter-devices/net_tun` device resources, a writable node image cache, and controller RBAC for pod
get/list/create/patch/delete and Secret create. Nodes must permit the pod's namespaced
IP-forwarding/rp-filter sysctls. Low-port binding uses `ip_unprivileged_port_start=0`, not an
extra capability. Pods drop ALL capabilities and add only NET_ADMIN/SETUID/SETGID, with
fsGroup 1000. An owned Secret contains selected profile/shape/telemetry configuration;
the controller token itself is never copied into the pod. Project `jails.tokenFile` with
`controllerAudience`; it is reread on every C7 request. Jail readiness uses TCP plus an
authenticated health check. The 60-second boot window starts at successful init completion,
not pod creation. GETs and exec/boot use separate workers, leaving reads and
health/whoami/session admission responsive. Credential volumes declare mode 0400.
The jail root filesystem is read-only; runtime files use emptyDir, with a separate 16 MiB
console volume. Pods have a 60-second termination grace period and request
`smarter-devices/kvm` and `smarter-devices/net_tun`.
POST bodies are bounded to 1 MiB minus 64 bytes and 30 seconds; C7 HTTP calls have a
30-second timeout. Empty argv returns 400 and oversize bodies return 413.

## Explicit egress proxy

```sh
export OTEL_RESOURCE_ATTRIBUTES='vm_runner.session_id=019955e0-0000-7000-8000-000000000001,vm_runner.subject=system:serviceaccount:dekopon:default'
cargo run --locked --bin vm-runnerd -- egress --config examples/vm-runner.yaml \
  --profile travel --listen 127.0.0.1:8080 --ca-out /tmp/vm-runner-ca
```

The launcher supplies the session UUIDv7 and service-account subject through the standard
`OTEL_RESOURCE_ATTRIBUTES` variable; profile and shape come from validated config. These are
local launcher metadata, not guest-provided identity. Replace the example session ID per session.
Trust the newly written `ca.pem` in the guest and configure its explicit HTTP proxy. Restarting
rotates the CA; its private key stays in memory. Upstream TLS uses WebPKI roots.

HTTP/1.1 and TLS-in-CONNECT are inspected; unsupported protocols fail closed. Each inner Host
must agree with CONNECT and TLS SNI, and every forwarded request loses W3C trace headers.
There is no credential injection, HTTP/2 or WebSocket tunneling.
After DNS resolution, every returned address must be global unicast before the proxy connects
using those exact addresses. Profile `egress.allowPrivate` CIDRs are the only exceptions (empty
by default); the host allow-list still applies. Mixed public/private DNS answers fail closed.
DNS lookup failures are `refused:dns`; empty answers and prohibited addresses are
`refused:address`. Both return 403 with the usual refusal body.

Profile `egress.idleSeconds` defaults to 90, `maxConnectionSeconds` to 1800, and `maxConnections`
to 128. `maxConnections` must be 1–255: one blocking worker and one DNS lookup per connection,
plus the refusal-export and gateway UDP workers, fit Tokio's default 512-thread blocking pool.
Successful client reads or writes reset the idle timeout, not the maximum lifetime.
Excess connections close immediately. One background worker coalesces their `refused:connections`
spans to at most one per second, with `count` giving the number refused since the previous span;
export never blocks the accept loop. Shutdown stops accepting and drains the bounded workers
and final refusal count before shutting down telemetry.

## Guest agent

`vm-guest-agent` runs as root inside a Linux guest and serves one length-prefixed JSON request
per vsock connection on port 1024. Requests are processed sequentially. Exec runs as uid/gid 1000
with HOME and default cwd `/home/jail`; deadlines kill the process group, and stdout/stderr are
capped at 64 KiB each while excess output is drained. `/artifacts` must be owned by uid 1000.
Artifact listing hashes regular files recursively without following symlinks; reads canonicalize
paths beneath `/artifacts` and open relative to a directory handle, so symlink replacements cannot
escape between the check and open. Large reads may return fewer bytes than requested to keep base64 and
its JSON envelope within the 1 MiB frame cap; continue at the returned byte count until `eof`.
A ping returns `{"ok":true}`. Other platforms print `linux only` and exit 2.

## Guest toolkit

Alongside the browser tools, the image includes Python 3, uv 0.12.21, jq,
ripgrep (`rg`), zip/unzip and Poppler's `pdftotext`/`pdfinfo`. The exec-safe uv
wrapper uses system interpreters and disables automatic interpreter downloads,
while allowing `uv pip` to discover nearby/activated venvs. Venvs and its default
cache are writable under the jail home.
No pip or `python3-venv` package is separately installed. Package/network access
still follows the existing egress policy, with no new allowlisting.
See [the guest image README](images/guest/README.md#small-offline-toolkit) for
build-time offline smoke checks and image verification.

## Guest browser tools

The guest keeps its existing Playwright-backed custom `browse` CLI as the default.
It does **not** install Microsoft's `playwright-cli`. Alongside it, `agent-browser`
0.38.1 uses the checksum-pinned upstream Linux native binary (the same release asset
selected by that npm version's postinstall), on both amd64 and arm64. Both tools use
`/usr/local/bin/chromium`, the baked Playwright Chromium; no `agent-browser install`
or runtime browser download is needed.

```sh
browse open 'data:text/html,<h1>Local page</h1>'
browse snapshot
browse reset
agent-browser open 'data:text/html,<h1>Local page</h1>'
agent-browser snapshot
agent-browser close
```

The AB wrapper supplies the executable, launch args, socket directory and `guest`
session on every invocation because guest exec clears its environment. uid 1000
writes AB sockets/state under `/home/jail/.agent-browser` and its separate persistent
profile under `/home/jail/.agent-browser-profile`; it never attaches to browse's
port 9222 or `.browse-profile`. `close` stops AB but retains that profile until the
jail expires. Do not select browse's profile or CDP endpoint for AB. Upstream AB's
Unix daemon calls `setsid`, like browse's detached Chromium, so exec process-group
cleanup does not kill it; the VM lifetime still bounds both. No guest-agent or
isolation policy changes are required, and TLS verification remains enabled.

The image build runs a uid-1000, cleared-environment smoke test using only static
data URLs. It checks open/snapshot/close across separate exec groups, kills each
client group on exit, and verifies browse and AB coexist without sharing pages.
`verify.sh` checks the exported ext4 contains both CLIs, AB's native binary and the
Chromium target. Dual-arch guest PR CI is the full image gate. **An image build is
not Firecracker/KVM proof**: guest boot, trusted-CA egress and real execs still need
separate authorized KVM validation before deployment.

### Paired evaluation (instructions only)

Do not compare inside an existing jail or run this as part of an image build.
Use two newly named sessions per task/repetition, on an explicitly approved image,
with the same profile/shape, model/version, model settings, task text, starting URL,
egress policy and browser binary. Example setup against an authorized controller
(`TOKEN`, `CONTROLLER`, `PROFILE`, `TASK_URL` supplied by the operator):

```sh
pair=$(date +%s)-$RANDOM
fresh() {
  curl --fail-with-body -sS "$CONTROLLER/v1/sessions" \
    -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg profile "$PROFILE" --arg name "$1" '{profile:$profile,name:$name}')" | jq -er .sessionId
}
exec_in() {
  local session=$1; shift
  curl --fail-with-body -sS "$CONTROLLER/v1/sessions/$session/exec" \
    -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
    -d "$(jq -nc --args '{argv:$ARGS.positional,deadlineMs:25000}' -- "$@")"
}
browse_jail=$(fresh "eval-browse-$pair")
ab_jail=$(fresh "eval-ab-$pair")
exec_in "$browse_jail" browse open "$TASK_URL"
exec_in "$ab_jail" agent-browser open "$TASK_URL"
exec_in "$ab_jail" agent-browser set viewport 1280 900
# Give the model the same task separately, routed ONLY to the corresponding jail.
# Browse arm: "Use only browse for browser interaction; no agent-browser or direct CDP/Playwright."
# AB arm: "Use only agent-browser for browser interaction; no browse or direct CDP/Playwright."
# Keep all other instructions and budgets identical; alternate arm order between repetitions.
exec_in "$browse_jail" browse reset
exec_in "$ab_jail" agent-browser close
```

Inspect exec responses; if HTTP 202, await the returned controller job via
`GET /v1/jobs/{jobId}` before continuing. Record each arm's total model input/output
tokens (including retries/tool output), task correctness against the same predefined
answer rubric, end-to-end wall time, failures, and peak CPU/RSS/scratch usage from
available resource measurements (mark unavailable values, do not infer them from
image size). Include model, image digest, Chromium version, shape and repetitions.
Do not reuse either session for another arm/task: close tools and let these isolated
jails expire under their configured lifetime (there is no session DELETE API).
No evaluation campaign, deployment or release is performed by this change.

## Release builds

CI builds every package binary for native x86_64 and aarch64 Linux musl, then builds and
smoke-tests the runtime image without pushing. To build locally on either Linux architecture:

```sh
sudo apt-get install musl-tools
bash ci/build-release.sh "$(uname -m)-unknown-linux-musl"
```

The `dist/` directory contains target-suffixed binaries and individual SHA-256 checksums.
The Dockerfile takes a prebuilt `vm-runnerd` in its build context, uses digest-pinned Debian
trixie-slim with CA certificates, and defaults to uid/gid 1000; no compiler is included.

Maintainer-created annotated `v<package-version>` tags must point at current `main` HEAD.
The release workflow waits up to 20 minutes for that commit's CI checks, builds on both native
architectures, pushes untagged per-arch manifests, and publishes an attested multi-arch index at
`ghcr.io/dekopon-agents/vm-runner:<package-version>` plus binaries/checksums in a GitHub release.
Only the publish job can sign attestations or create a release; image jobs can push package
content but do not publish version tags. No workflow creates Git tags.

## Gateway egress

With the same session metadata, replace `--listen` with `--gateway 10.0.2.1` to bind UDP/TCP 53
and TCP 80/443 on that IPv4 address; both flags may also be used together. Binding these ports
requires the appropriate OS permission. The caller must configure the tap, guest route and
firewall; this command does not configure networking.

The DNS stub never queries upstream: allowed A names receive the gateway address (TTL 30),
allowed AAAA names receive NOERROR with no answers, and disallowed names or other types receive
NXDOMAIN. Each question emits `egress.dns` with its ASCII name, type and final decision;
malformed queries and frames emit `refused:protocol`, and QR=1 packets are never answered.
UDP replies are limited to 512 bytes; per-datagram I/O failures do not stop the stub.
DNS only answers usable peer addresses in the gateway's /30 (tests supply an explicit loopback
peer set); port-zero datagrams are dropped. Unspecified, broadcast, multicast and loopback
`--gateway` values are rejected alongside all configuration conflicts. TCP DNS has a 10-second
idle timeout and shares the connection cap and maximum lifetime with HTTP/TLS. Both gateway HTTP ports use the same fail-closed classifier and upstream address
policy as the explicit proxy; origin-form HTTP uses Host, and TLS uses SNI checked against Host.

## Model route (`jails.models`)

Optional, and additive: without it nothing below applies.

```yaml
jails:
  models:
    upstream: https://dekopon.dekopon.svc.cluster.local:9090 # dekopond's proxy listener
    clientCertSecret: vm-runner-jail-models-tls # cert-manager Secret in jails.namespace
```

The controller mounts `clientCertSecret` into each jail pod at `/models-tls` (0440 root:1000
under the pod's fsGroup, like `/kube/token`). The Secret must hold `tls.crt`, `tls.key` and
`ca.crt`, and `ca.crt` must also anchor dekopond's server certificate. The controller also writes
`jails.models.subject` into the jail config: the caller's service account as
`namespace:name` (for example `dekopon:gylmar-vm`). A `subject` in the controller's own config
is ignored.

In the jail, the DNS stub answers `models.vm.internal`. Requests addressed to it by SNI,
origin-form Host or CONNECT skip the allowlist and the address policy. They go to `upstream`
over mTLS, and the jail rereads the Secret files on every connection, so rotation needs no
restart. Host is rewritten to the upstream authority and the path is unchanged. The jail sets
`x-dekopon-vm-subject` to the subject. It strips that header from all guest egress (requests,
trailers and responses), so a guest can never set it. Guests use
`https://models.vm.internal` (Anthropic) or `https://models.vm.internal/v1` (OpenAI); the
paths dekopond serves are `/v1/messages`, `/v1/messages/count_tokens`, `/v1/responses` and
`/v1/chat/completions`. `Jails` denies unknown fields, so ship the image before this key.

## Jail runtime and image cache

`vm-runnerd fetch-image --digest <ref@sha256:…> --cache <dir>` anonymously selects the native
Linux guest image, locks the cache directory, streams and verifies both layer digests, and
unpacks the rootfs before atomically publishing a digest/architecture directory. Layers are
limited to 16 GiB each and the expanded rootfs to 16 GiB. Registry references are restricted
to `ghcr.io`; alternate layer URLs are refused. Verified files and staging metadata are
fsynced before atomic rename, followed by fsync of the cache directory. The cache is trusted host storage;
delete an affected digest directory while no jail uses it to reset a damaged entry.

On Linux, `vm-runnerd jail --config <file> --profile <name> --session <UUIDv7>` boots Firecracker
with the profile's shape, a read-only cached rootfs, a fresh CA drive padded to 4 KiB, and a
sparse scratch ext4. Mount the cache read-only at `/images` and a fresh emptyDir at
`/run/vm-runner`. Supply `vm_runner.subject` via `OTEL_RESOURCE_ATTRIBUTES`. The container
requires uid 0 with exactly `NET_ADMIN`, `SETUID`, and `SETGID`, plus `/dev/kvm` and
`/dev/net/tun`, with default seccomp and container `allowPrivilegeEscalation: false`
(`--security-opt no-new-privileges` in Docker). The runtime image has no setuid/setgid files.
Set pod `fsGroup: 1000`; the runtime volume must be owned by group 1000.
Firecracker runs through util-linux `setpriv` as uid/gid 1000 with supplementary groups
1000 and the runtime `/dev/kvm` group, plus `/dev/net/tun`'s group when that device is not
world-readable/writable (duplicate groups are removed). Devices must allow group read/write
or world read/write; `/dev/kvm` may be root-owned mode 0660 with a host-specific group.
The VMM has zero effective, permitted, inheritable and ambient capabilities and `NoNewPrivs: 1`.
The bounding set is not cleared: no-new-privileges prevents gaining capabilities through exec.
Runtime files are group-writable; the private CA key stays in memory.
Shape keys `diskMBps` (default 100) and `netMbps` (default 200) set nonzero SI bandwidth
limits on the scratch drive and each NIC direction, using one-second token buckets. Guest serial output
and VMM diagnostics go to `/run/vm-runner/console/serial.log`, separate from stdout JSON telemetry.
A pre-boot VMM exit includes the first console line in its failure span.
Configure these **pod network-namespace sysctls before startup** (the container's default
`/proc/sys` mount is read-only): `net.ipv4.ip_forward=0`,
`net.ipv4.conf.all.rp_filter=1`, and `net.ipv4.conf.default.rp_filter=1`.
Gateway ports also require `net.ipv4.ip_unprivileged_port_start=0` with this capability set.
The jail verifies forwarding/rp_filter and the new tap's inherited `rp_filter=1`, installs the guest-source
and gateway-port firewall, then brings tap0 up. Node policy must permit those pod sysctls.
The runtime image includes digest-verified Firecracker 1.17.0, iproute2, nftables and e2fsprogs;
curl is removed after the Firecracker download (the guest retains curl). Fetch, tap, nftables
and drive failures emit `vm_runner.boot` spans with a phase and bounded failure cause.
SIGTERM kills and reaps the VM before flushing telemetry; the pod owns netns/emptyDir cleanup.

The same process serves gateway DNS, HTTP and HTTPS using the CA supplied to the guest.
The jail serves `:8080` before boot: authenticated `GET /healthz` returns 503 until the
guest answers `ping`, then 200. It also serves `POST /exec {argv, stdin?, deadlineMs}` and
`GET /jobs/{id}`. Tokens must have audience `vm-runner-jail` and exactly the subject from
`jails.controllerSubject`; C4's `auth.subjects` grants no jail access. GET admission is
independent of long-poll exec admission. Guest stdout, stderr and refusal reasons are capped
at 64 KiB each on a UTF-8 boundary, setting `truncated: true` when cut. A response deadline (0–25000 ms) returns
202 with a job ID; execution continues up to the guest's 600 s limit. Transport loss leaves
an unknown outcome, never a false success or automatic retry. The table retains at most 64
jobs, evicting non-running records first; when all slots are active, exec returns
`{outcome: not_executed, reason: quota}` without sending anything to the guest.

Authenticated `GET /artifacts` lists guest files; `GET /artifacts/{path}` streams bytes with
a `sha256` header for the whole file. Percent-encode the path parameter, including `/` in
nested names (for example, `nested%2Fscreenshot.png`). Single byte ranges return 206 with
`Content-Range`; unsatisfiable byte ranges return 416. Unsupported units and multi-range requests are served in full.
At most four response bodies stream concurrently, in 64 KiB chunks, with slots released on
completion or cancellation. Transfers use a one-chunk backpressure channel and share the
existing 64-worker lifecycle owner with exec. Fetch artifacts after execution finishes: metadata is an
observation of guest files, not an immutable snapshot. Short or inconsistent chunks fail the
transfer rather than succeeding with truncation.

The explicit `cargo test --locked --test kvm` target requires the runtime setup above and
`KVM_GUEST_IMAGE`; ordinary `cargo test` excludes it. On Linux, ordinary `cargo test` needs `tini`
(the guest's init) on `PATH`. The KVM workflow probes `/dev/kvm` and
omits the hardware job when unavailable; when present it boots under the stated capability,
device and mount constraints. Both native Linux architectures still run ordinary CI.

Licensed under either of Apache-2.0 or MIT at your option.
