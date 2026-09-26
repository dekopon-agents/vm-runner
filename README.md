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

## Jail boot and image cache

`vm-runnerd fetch-image --digest <ref@sha256:…> --cache <dir>` anonymously selects the native
Linux guest image, locks the cache directory, streams and verifies both layer digests, and
unpacks the rootfs before atomically publishing a digest/architecture directory. Layers are
limited to 16 GiB each and the expanded rootfs to 64 GiB. The cache is trusted host storage;
delete an affected digest directory while no jail uses it to reset a damaged entry.

On Linux, `vm-runnerd jail --config <file> --profile <name> --session <UUIDv7>` boots Firecracker
with the profile's shape, a read-only cached rootfs, a fresh CA drive padded to 4 KiB, and a
sparse scratch ext4. Mount the cache read-only at `/images` and a fresh emptyDir at
`/run/vm-runner`. Supply `vm_runner.subject` via `OTEL_RESOURCE_ATTRIBUTES`. The container
requires uid 0, only `NET_ADMIN`, `/dev/kvm` and `/dev/net/tun`, with default seccomp.
Configure these **pod network-namespace sysctls before startup** (the container's default
`/proc/sys` mount is read-only): `net.ipv4.ip_forward=0`,
`net.ipv4.conf.all.rp_filter=1`, and `net.ipv4.conf.default.rp_filter=1`.
The jail verifies these and the new tap's inherited `rp_filter=1`, installs the guest-source
and gateway-port firewall, then brings tap0 up. Node policy must permit those pod sysctls.
The runtime image includes digest-verified Firecracker 1.17.0, iproute2, nftables and e2fsprogs.
SIGTERM kills and reaps the VM before flushing telemetry; the pod owns netns/emptyDir cleanup.

This boot-only command does not yet serve the jail API or in-process egress; guest network
traffic remains blocked beyond the allowed local gateway ports, which have no listener.
The explicit `cargo test --locked --test kvm` target requires the runtime setup above and
`KVM_GUEST_IMAGE`; ordinary `cargo test` excludes it. The KVM workflow probes `/dev/kvm` and
omits the hardware job when unavailable; when present it boots under the stated capability,
device and mount constraints. Both native Linux architectures still run ordinary CI.

Licensed under either of Apache-2.0 or MIT at your option.
