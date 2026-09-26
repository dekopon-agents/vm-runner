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
NXDOMAIN. Each question emits `egress.dns` with its name, type and final decision. UDP replies
are limited to 512 bytes. TCP DNS shares the connection cap, idle timeout and maximum lifetime
with HTTP/TLS. Both gateway HTTP ports use the same fail-closed classifier and upstream address
policy as the explicit proxy; origin-form HTTP uses Host, and TLS uses SNI checked against Host.

Licensed under either of Apache-2.0 or MIT at your option.
