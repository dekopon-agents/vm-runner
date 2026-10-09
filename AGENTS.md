# Guidance for coding agents

Firecracker browser jails for Dekopon agents: `vm-runnerd` (controller, jail API, egress proxy and
gateway), `vm-guest-agent`, and the guest image under `images/guest/`. [README.md](README.md) is
the design; read the section your change touches.

## Contract

- This file and the documents it links are the whole contract. A cloud agent in a bare checkout has
  no owner memories, machine instructions or sibling repositories, and needs none. Name every gate
  you could not run; KVM and the per-arch image builds run only in CI.
- Core's [boundaries](https://github.com/dekopon-agents/dekopon/blob/main/AGENTS.md#boundaries-that-must-survive),
  [proportionate remedies](https://github.com/dekopon-agents/dekopon/blob/main/AGENTS.md#proportionate-remedies)
  and [Rust guidelines](https://github.com/dekopon-agents/dekopon/blob/main/AGENTS.md#rust-guidelines)
  apply here. This file adds only what is particular to this repository.
- Tags, releases and version bumps need the owner's authorization for that version. A PR never
  pushes `main`. No workflow creates tags; the release workflow publishes from an annotated
  `v<version>` tag on `main` HEAD.

## Boundaries particular to vm-runner

- Identity is launcher metadata or a verified bearer JWT, never something the guest sends.
- Egress fails closed: every resolved address is global unicast unless a profile's
  `egress.allowPrivate` names it, the host allow-list still applies, and unsupported protocols are
  refused. The proxy injects no credentials and strips W3C trace headers.
- The guest holds no credential. The image pins every download by version and per-arch sha256.

## Build and verify

A PR passes `Test (ubuntu-24.04)`, `Test (ubuntu-24.04-arm)`, `Image (…)`, `OTLP conformance`,
`kvm` and `Guest (…)` before merge. Run `Test`'s steps before a push (Linux, with `tini` installed):

```console
cargo fmt --all --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-features --locked
cargo run --locked --bin vm-runnerd -- check --config examples/vm-runner.yaml
cargo machete
cargo deny --all-features --locked check
```

A change under `images/guest/` also builds the guest stage for your architecture
([images/guest/README.md](images/guest/README.md)). A change to `ci/` runs
`python3 -m unittest discover -s ci -p 'test_*.py'`; [ci/README.md](ci/README.md) covers OTLP
conformance.

## Change rules

- No comments or doc comments by default; core's
  [Comments](https://github.com/dekopon-agents/dekopon/blob/main/AGENTS.md#comments) rule decides
  the exceptions. Clap `///` is help text and stays.
- Test names are sentences that state the invariant. An egress or gateway test asserts what reached
  the upstream: the full URI, exactly one request, and no guest-supplied identity or credential.
- A config change keeps `examples/vm-runner.yaml` passing `vm-runnerd check`. An API change keeps
  `openapi.yaml` in parity (the test suite checks it).
- A change to a CI gate edits the sentence here or in `ci/README.md` that describes it.

## Concurrency

[`clippy.toml`](clippy.toml) bans the raw forms through `disallowed-methods`. Every task, thread
and queue has an owner, a bound and a shutdown path: spawn into a `JoinSet` the owner joins, use a
bounded `mpsc::channel(N)` and name the full-queue policy, await `spawn_blocking`. A production use
of a banned form needs a site `#[expect(clippy::disallowed_methods, reason = "owner: …; bound: …")]`.
Tests spawn freely. Core's [Concurrency](https://github.com/dekopon-agents/dekopon/blob/main/AGENTS.md#concurrency)
section has the full pairs.
