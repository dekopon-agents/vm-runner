# Session shutdown smoke

On 2026-11-21 at 07:13 UTC, this smoke passed on source commit
3d88e6240ad35ff4d6f4e21831b38438da3d17de with vm-runner 0.6.0, Rust 1.98.1, and
x86_64 Linux.

```sh
cargo test --all-features --locked --lib \
  jail::api::tests::session_shutdown_drops_the_job_and_reaps_its_guest_process_without_resending \
  -- --exact --nocapture
```

The authenticated jail endpoint sent one exec with a 1,200,000 ms guest deadline.
A local relay forwarded the frame to the production guest handler, which started
a real child process. The job reported running. The jail shutdown path closed the
exchange, the handler reaped the child, and the job returned HTTP 404. The relay
observed one exec and no retries. The test passed in 0.22 s.

The smoke uses a local Unix relay and the guest test working directory. The CI
KVM gate exercises the Firecracker and vsock path.

## Exec follow-up

The command above passed on 2026-11-21T10:14:48Z at source commit
`2df6cbc83f2ec746c5a068d444dd62a4eeaef1b1` with vm-runner 0.6.0, Rust 1.98.1,
and x86_64 Linux. The jail API dispatched one exec to the production guest handler
through a Unix relay. After the test observed the child running, jail shutdown closed
the exchange, reaped the child, and retired the job. The relay observed one exec and
the job endpoint returned HTTP 404.

## Codex guest toolkit smoke

On 2026-11-22T19:04:19Z, the amd64 toolkit smoke passed at source commit
`1770631a34a4636f2cad4af542bd63ddd3928a92` with Docker 28.4.0, Buildx 0.31.0
and Codex CLI 0.171.0. The focused image ID was
`sha256:5ae5c834b010efd6280718135373b606a7fb2a4c6bd5ef21be287f7e4f8f9156`.

From the normal guest context, a temporary Dockerfile omitted the Playwright,
guest-agent and browser smoke steps. The Codex archive installation and the
existing `RUN --network=none` invocation of `toolkit-smoke.sh` ran as in the
committed Dockerfile, using the Cloud proxy CA as a build secret for downloads.

```sh
docker buildx build --platform linux/amd64 --load --progress plain \
  --secret id=proxy_ca,src=/etc/ssl/certs/ca-certificates.crt \
  -f "$context/Dockerfile.toolkit" -t "$image" "$context"
docker run --rm --network=none --user 1000:1000 --workdir /home/jail \
  --entrypoint /usr/bin/env "$image" -i HOME=/home/jail \
  PATH=/usr/local/bin:/usr/bin:/bin codex --version
```

The amd64 archive passed the Dockerfile's SHA-256 check. The full toolkit script
ran with an empty environment except for `HOME` and `PATH` and printed
`codex-cli 0.171.0`. A second invocation in the resulting image printed the same
version after checking that the baked `.codex` directory was empty and had mode
`0700` and owner `1000:1000`. Both upstream release archives also matched their
published SHA-256 digests when downloaded independently.

The full amd64 guest Docker build reached the pinned Playwright browser download
and received HTTP 403 `Domain forbidden` from the Cloud proxy for
`cdn.playwright.dev`. Full guest, ext4 verification and Firecracker boot depend
on the CI jobs.

## Named browser pages and session close

At 2026-11-23T03:34:39Z, the smoke passed in 8.34 seconds at source commit
`34675776b8d66172563c4fec9e89604aab478f2b`. It ran with vm-runner 0.6.0,
Rust 1.98.1, Node 24.21.0, Playwright 1.63.0 and Chromium 154.0.8037.57 on
amd64 Linux. `$browse_smoke` is an executable wrapper for this checkout's
`images/guest/browse` that sets `BROWSE_PLAYWRIGHT` and `BROWSE_CHROMIUM` for
the installed Playwright and Chromium.

```sh
VM_RUNNER_BROWSE_SMOKE="$browse_smoke" cargo test --all-features --locked --lib \
  jail::api::tests::the_jail_api_keeps_named_browser_pages_independent_until_session_delete \
  -- --exact --ignored --nocapture
```

The authenticated controller forwarded seven separate execs to the real jail
HTTP endpoint. The production guest handler ran the real `browse` script
through a local Unix relay using loopback pages. Each named tab retained its
own navigation. The jail received each command once at `/exec`, with no
guest-supplied identity headers. The session DELETE returned 204 after the
Kubernetes test fixture reported the pod absent, and the next list was empty.
The hosted KVM gate exercises the Firecracker and vsock path.
