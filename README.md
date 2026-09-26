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
There is no transparent routing, credential injection, HTTP/2 or WebSocket tunneling.
After DNS resolution, every returned address must be global unicast before the proxy connects
using those exact addresses. Profile `egress.allowPrivate` CIDRs are the only exceptions (empty
by default); the host allow-list still applies. Mixed public/private DNS answers fail closed.
DNS lookup failures are `refused:dns`; empty answers and prohibited addresses are
`refused:address`. Both return 403 with the usual refusal body.

Profile `egress.idleSeconds` defaults to 90, `maxConnectionSeconds` to 1800, and `maxConnections`
to 128. `maxConnections` must be 1–255: one blocking worker and one DNS lookup per connection,
plus a refusal-export worker and one spare, fit Tokio's default 512-thread blocking pool.
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

Licensed under either of Apache-2.0 or MIT at your option.
