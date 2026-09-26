# CI and OTLP conformance

`ci.yml` runs fmt, clippy, tests (including OpenAPI parity), the config smoke,
cargo-machete and cargo-deny on native GitHub-hosted amd64 and arm64 runners.
The repository's `rust-toolchain.toml` selects Rust; actions use commit pins.

The amd64 conformance job uses disposable, digest-pinned OpenObserve 1.0.4 and
Quickwit 0.8.2 service containers. Quickwit is started with `docker run` because
GitHub's service syntax cannot pass its required `run` subcommand. Version 0.8.2
provides the contracted `otel-traces-v0_7` index; 0.9.1 uses `otel-traces-v0_9`.

`otlp_conformance.py` uses Python 3.11+ and its standard library. It starts one
loopback HTTP upstream, then runs the real `vm-runnerd egress` command once per
backend: OpenObserve HTTP/protobuf with a Basic header file, then Quickwit gRPC.
Each invocation has a fresh UUIDv7 session and forwards one request. It verifies
the upstream body and trace-header stripping, gracefully stops the proxy, and
checks all C2 jail resource and request attributes in backend search results.
Session and trace-id searches must identify the same span; missing-session and
missing-trace controls must return no hits. Quickwit resource filtering works;
there is no fallback that weakens that assertion.

OpenObserve stores resource keys as `service_*` columns with dots replaced by
underscores, and status codes as strings; Quickwit retains dotted resource keys.
Both promote `service.name` to `service_name`. These storage representations are
normalized only when asserting results. Readiness and eventual indexing are
polled with deadlines; emission is never retried. Quickwit's node readiness
precedes its ingest queue, so the harness also waits for the trace index's
read-only `tail` and search endpoints before starting either egress process.

To run against **disposable local backends**, build with `cargo build --locked`,
set `ZO_ROOT_USER_EMAIL` and `ZO_ROOT_USER_PASSWORD` to those containers' test
credentials, then run:

```sh
python3 ci/otlp_conformance.py --artifacts /tmp/vm-runner-conformance
```

Optional `--openobserve`, `--quickwit`, and `--quickwit-grpc` override loopback
URLs (defaults: ports 5080, 7280 and 7281). `--binary` selects the built binary.
Artifacts contain process logs, public CA certificates, generated config and
asserted search evidence; header files are removed after each proxy invocation.
CI prints evidence and service/process logs, then removes its Quickwit container;
GitHub owns cleanup of the OpenObserve service.
