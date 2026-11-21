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
