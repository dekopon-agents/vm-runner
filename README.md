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

Licensed under either of Apache-2.0 or MIT at your option.
