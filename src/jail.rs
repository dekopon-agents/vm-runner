use crate::{
    config::{Config, Shape},
    telemetry,
};
use poem::listener::Listener;
use serde_json::json;
use std::{
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    process::Command,
    sync::watch,
    task::JoinSet,
};
use tracing::Instrument;

pub(crate) mod api;
mod client;
pub mod image;
type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
#[derive(Debug, thiserror::Error)]
enum Error {
    #[error("jail requires Linux")]
    LinuxOnly,
    #[error("runtime directory requires fsGroup 1000")]
    RuntimeGroup,
    #[error("jail worker stopped unexpectedly")]
    WorkerStopped,
    #[error("image must have a sha256 digest pin")]
    ImageReference,
    #[error("guest image must contain one bounded rootfs layer and one kernel layer")]
    ImageLayers,
    #[error("image registry is not allowed (ghcr.io only)")]
    RegistryHost,
    #[error("registry {kind}; HTTP status {status:?}")]
    Registry {
        kind: &'static str,
        status: Option<u16>,
    },
    #[error("registry I/O: {0:?}")]
    RegistryIo(std::io::ErrorKind),
    #[error("unknown profile or shape")]
    Profile,
    #[error("jail requires jails.controllerSubject")]
    ControllerSubject,
    #[error("jail netns requires {path}={expected}; set the pod sysctl before startup")]
    Sysctl {
        path: &'static str,
        expected: &'static str,
    },
    #[error("invalid session UUIDv7")]
    Session,
    #[error("command {program} failed: {status}")]
    Command {
        program: &'static str,
        status: std::process::ExitStatus,
    },
    #[error("Firecracker exited: {status}; console: {first_line}")]
    Firecracker {
        status: std::process::ExitStatus,
        first_line: String,
    },
}

async fn phase<T>(
    name: &'static str,
    work: impl std::future::Future<Output = Result<T>>,
) -> Result<T> {
    async {
        let result = work.await;
        record_failure(&result);
        result
    }
    .instrument(tracing::info_span!(
        "vm_runner.boot",
        boot.phase = name,
        error.message = tracing::field::Empty
    ))
    .await
}
fn record_failure<T>(result: &Result<T>) {
    if let Err(error) = result {
        tracing::Span::current().record("error.message", crate::egress::cut(&error.to_string()));
    }
}

async fn command(program: &'static str, args: &[&str]) -> Result<()> {
    let status = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .kill_on_drop(true)
        .status()
        .await?;
    if !status.success() {
        return Err(Error::Command { program, status }.into());
    }
    Ok(())
}
async fn require_sysctl(path: &'static str, expected: &'static str) -> Result<()> {
    if tokio::fs::read_to_string(format!("/proc/sys/net/ipv4/{path}"))
        .await?
        .trim()
        != expected
    {
        return Err(Error::Sysctl { path, expected }.into());
    }
    Ok(())
}
async fn network(work: &Path) -> Result<()> {
    phase("tap", async {
        // Default container proc mounts are read-only; the runtime sets these netns sysctls before exec.
        require_sysctl("ip_forward", "0").await?;
        require_sysctl("conf/all/rp_filter", "1").await?;
        require_sysctl("conf/default/rp_filter", "1").await?;
        command(
            "ip",
            &[
                "tuntap", "add", "tap0", "mode", "tap", "user", "1000", "group", "1000",
            ],
        )
        .await?;
        require_sysctl("conf/tap0/rp_filter", "1").await
    })
    .await?;
    phase("nftables", async {
        let rules = work.join("network.nft");
        tokio::fs::write(&rules, include_bytes!("jail/network.nft")).await?;
        let status = Command::new("nft")
            .arg("-f")
            .arg(rules)
            .kill_on_drop(true)
            .status()
            .await?;
        if !status.success() {
            return Err(Error::Command {
                program: "nft",
                status,
            }
            .into());
        }
        Ok(())
    })
    .await?;
    phase("tap.enable", async {
        command("ip", &["addr", "add", "10.0.2.1/30", "dev", "tap0"]).await?;
        command("ip", &["link", "set", "tap0", "up"]).await
    })
    .await
}

fn vm_config(image: &Path, work: &Path, shape: &Shape) -> serde_json::Value {
    let limiter = |bytes_per_second: u64| json!({"bandwidth": {"size": bytes_per_second, "refill_time": 1000}});
    let net = limiter(u64::from(shape.net_mbps.get()) * 1_000_000 / 8);
    json!({
        "boot-source": {"kernel_image_path": image.join("vmlinux"), "boot_args": "console=ttyS0 reboot=k panic=1 init=/sbin/vm-init ro"},
        "drives": [
            {"drive_id": "rootfs", "path_on_host": image.join("rootfs.ext4"), "is_root_device": true, "is_read_only": true},
            {"drive_id": "ca", "path_on_host": work.join("ca.pem"), "is_root_device": false, "is_read_only": true},
            {"drive_id": "scratch", "path_on_host": work.join("scratch.ext4"), "is_root_device": false, "is_read_only": false, "rate_limiter": limiter(u64::from(shape.disk_mbps.get()) * 1_000_000)}
        ],
        "network-interfaces": [{"iface_id": "eth0", "host_dev_name": "tap0", "rx_rate_limiter": net, "tx_rate_limiter": net}],
        "vsock": {"guest_cid": 3, "uds_path": work.join("guest.sock")},
        "machine-config": {"vcpu_count": shape.vcpus.get(), "mem_size_mib": shape.memory.get()}
    })
}
async fn ca_drive(path: &Path, pem: &str) -> Result<()> {
    let mut bytes = pem.as_bytes().to_vec();
    bytes.resize(bytes.len().div_ceil(4096) * 4096, 0);
    shared_file(path, &bytes).await?;
    Ok(())
}
async fn shared_file(path: &Path, bytes: &[u8]) -> Result<tokio::fs::File> {
    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o660)
        .open(path)
        .await?;
    file.set_permissions(std::fs::Permissions::from_mode(0o660))
        .await?;
    file.write_all(bytes).await?;
    file.flush().await?;
    Ok(file)
}
fn firecracker_command(kvm_gid: u32, tun_gid: u32, tun_mode: u32) -> Command {
    let mut groups = vec![1000];
    for gid in [
        Some(kvm_gid),
        (tun_mode & 0o006 != 0o006).then_some(tun_gid),
    ]
    .into_iter()
    .flatten()
    {
        if !groups.contains(&gid) {
            groups.push(gid);
        }
    }
    let mut command = Command::new("setpriv");
    command
        .args(["--reuid", "1000", "--regid", "1000", "--groups"])
        .arg(
            groups
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(","),
        )
        .args(["--inh-caps=-all", "--no-new-privs", "--", "firecracker"]);
    command
}
async fn firecracker_exit(status: std::process::ExitStatus, work: &Path) -> Error {
    let line = async {
        let file = tokio::fs::File::open(work.join("console/serial.log")).await?;
        let mut bytes = Vec::new();
        // C2 caps trace attributes at 4096 bytes; one extra byte preserves the truncation marker.
        BufReader::new(file.take(4097))
            .read_until(b'\n', &mut bytes)
            .await?;
        Ok::<_, std::io::Error>(crate::egress::cut(
            String::from_utf8_lossy(&bytes).trim_end(),
        ))
    }
    .await;
    Error::Firecracker {
        status,
        first_line: line.unwrap_or_else(|error| format!("unavailable: {error}")),
    }
}
async fn launch(
    image: &Path,
    work: &Path,
    shape: &Shape,
    pem: &str,
) -> Result<tokio::process::Child> {
    let (config, console) = phase("drives", async {
        ca_drive(&work.join("ca.pem"), pem).await?;
        let scratch = work.join("scratch.ext4");
        let file = shared_file(&scratch, &[]).await?;
        file.set_len(u64::from(shape.disk.get()) * 1024 * 1024)
            .await?;
        drop(file);
        let status = Command::new("mkfs.ext4")
            .args(["-q", "-F", "-O", "^orphan_file"])
            .arg(scratch)
            .kill_on_drop(true)
            .status()
            .await?;
        if !status.success() {
            return Err(Error::Command {
                program: "mkfs.ext4",
                status,
            }
            .into());
        }
        let config = work.join("vm.json");
        shared_file(
            &config,
            &serde_json::to_vec(&vm_config(image, work, shape))?,
        )
        .await?;
        // Kubernetes mounts a separately bounded emptyDir here; direct jail runs create it.
        tokio::fs::create_dir_all(work.join("console")).await?;
        let console = shared_file(&work.join("console/serial.log"), &[])
            .await?
            .into_std()
            .await;
        Ok((config, console))
    })
    .await?;
    phase("vmm.spawn", async {
        let kvm = tokio::fs::metadata("/dev/kvm").await?;
        let tun = tokio::fs::metadata("/dev/net/tun").await?;
        Ok(firecracker_command(kvm.gid(), tun.gid(), tun.mode())
            .arg("--api-sock")
            .arg(work.join("firecracker.sock"))
            .arg("--config-file")
            .arg(config)
            .args(["--level", "Info", "--log-path", "/dev/stderr"])
            .stdin(Stdio::null())
            .stdout(Stdio::from(console.try_clone()?))
            .stderr(Stdio::from(console))
            .kill_on_drop(true)
            .spawn()?)
    })
    .await
}

pub async fn run(config: Config, profile: &str, session: &str) -> Result<()> {
    if !cfg!(target_os = "linux") {
        return Err(Error::LinuxOnly.into());
    }
    if uuid::Uuid::parse_str(session)?.get_version_num() != 7 {
        return Err(Error::Session.into());
    }
    let controller_subject = config
        .jails
        .ok_or(Error::ControllerSubject)?
        .controller_subject;
    let selected = config
        .profiles
        .0
        .into_iter()
        .find(|(name, _)| name == profile)
        .ok_or(Error::Profile)?
        .1;
    let shape = config
        .shapes
        .0
        .into_iter()
        .find(|(name, _)| name == &selected.shape)
        .ok_or(Error::Profile)?
        .1;
    let provider = telemetry::init_jail(
        config.telemetry.as_ref(),
        profile,
        &selected.shape,
        Some(session),
    )
    .await?;
    let runtime = tokio::runtime::Handle::current();
    let dispatch = tracing::dispatcher::get_default(Clone::clone);
    // One joined lifecycle worker owns the VMM and synchronous span exports through shutdown.
    let lifecycle = async move {
        let (image, work, guest, endpoint, requests, state, acceptor) =
            phase("initialize", async {
                let image = image::directory(Path::new("/images"), &selected.image)?;
                let work = PathBuf::from("/run/vm-runner");
                if tokio::fs::metadata(&work).await?.gid() != 1000 {
                    return Err(Error::RuntimeGroup.into());
                }
                tokio::fs::set_permissions(&work, std::fs::Permissions::from_mode(0o2770)).await?;
                let guest = Arc::new(client::Guest::new(work.join("guest.sock")));
                let (endpoint, requests, state) =
                    api::endpoint(config.auth, controller_subject, Arc::clone(&guest)).await?;
                let acceptor = poem::listener::TcpListener::bind("0.0.0.0:8080")
                    .into_acceptor()
                    .await?;
                Ok((image, work, guest, endpoint, requests, state, acceptor))
            })
            .await?;
        let (stop, stopping) = watch::channel(false);
        let mut workers = JoinSet::new();
        let handle = tokio::runtime::Handle::current();
        let dispatch = tracing::dispatcher::get_default(Clone::clone);
        let api_stop = stopping.clone();
        // The lifecycle joins exactly the gateway and API workers after stopping the VM.
        workers.spawn_blocking(move || {
            tracing::dispatcher::with_default(&dispatch, || {
                handle.block_on(async {
                    poem::Server::new_with_acceptor(acceptor)
                        .run_with_graceful_shutdown(
                            endpoint,
                            stopped(api_stop),
                            Some(Duration::from_secs(45)),
                        )
                        .await?;
                    Ok(())
                })
            })
        });
        let mut vm = None;
        let result = async {
            let (ca, pem) = phase("ca", async { crate::egress::Ca::new() }).await?;
            network(&work).await?;
            let gateway =
                phase("gateway", crate::egress::Gateway::bind(selected.egress, ca)).await?;
            let handle = tokio::runtime::Handle::current();
            let dispatch = tracing::dispatcher::get_default(Clone::clone);
            workers.spawn_blocking(move || {
                tracing::dispatcher::with_default(&dispatch, || {
                    handle.block_on(gateway.serve(stopped(stopping)))
                })
            });
            let shutdown = crate::shutdown_signal();
            tokio::pin!(shutdown);
            let child = tokio::select! {
                child = launch(&image, &work, &shape, &pem) => child?,
                _ = &mut shutdown => return Ok(()),
            };
            let pid = child.id();
            vm = Some(child);
            let child = vm.as_mut().ok_or(Error::WorkerStopped)?;
            let ready = phase("ready", async {
                tokio::select! {
                    result = guest.ready() => { result?; Ok(true) },
                    _ = &mut shutdown => Ok(false),
                    status = child.wait() => Err(firecracker_exit(status?, &work).await.into()),
                    worker = workers.join_next() => Err(worker_error(worker)),
                }
            })
            .await?;
            if !ready {
                return Ok(());
            }
            state.mark_ready();
            tracing::info!(pid, "jail ready");
            tokio::select! {
                _ = &mut shutdown => Ok(()),
                status = child.wait() => Err(firecracker_exit(status?, &work).await.into()),
                worker = workers.join_next() => Err(worker_error(worker)),
            }
        }
        .await;
        let stopped_vm = match vm.as_mut() {
            Some(child) => stop_vm(child).await,
            None => Ok(()),
        };
        stop.send_replace(true);
        let mut drained = Ok(());
        while let Some(worker) = workers.join_next().await {
            match worker {
                Ok(Ok(())) => (),
                other => drained = Err(worker_error(Some(other))),
            }
        }
        requests.drain().await?;
        state.drain().await?;
        result.and(stopped_vm).and(drained)
    };
    let result = tokio::task::spawn_blocking(move || {
        tracing::dispatcher::with_default(&dispatch, || runtime.block_on(lifecycle))
    })
    .await;
    tokio::task::spawn_blocking(move || provider.shutdown()).await??;
    result?
}

async fn stopped(mut signal: watch::Receiver<bool>) {
    if !*signal.borrow_and_update() {
        let _closed = signal.changed().await;
    }
}
fn worker_error(
    worker: Option<std::result::Result<Result<()>, tokio::task::JoinError>>,
) -> Box<dyn std::error::Error + Send + Sync> {
    match worker {
        Some(Ok(Err(error))) => error,
        Some(Err(error)) => error.into(),
        _ => Error::WorkerStopped.into(),
    }
}
async fn stop_vm(child: &mut tokio::process::Child) -> Result<()> {
    if child.try_wait()?.is_none() {
        let pid = child.id().ok_or(Error::WorkerStopped)?;
        // Without CAP_KILL the root launcher must signal through the VMM's own UID.
        let status = Command::new("/bin/sh")
            .args(["-c", "kill -KILL \"$1\"", "stop-vmm", &pid.to_string()])
            .uid(1000)
            .gid(1000)
            .stdin(Stdio::null())
            .kill_on_drop(true)
            .status()
            .await?;
        if !status.success() {
            return Err(Error::Command {
                program: "stop-vmm",
                status,
            }
            .into());
        }
        child.wait().await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn setpriv_uses_device_groups_without_duplicates_and_cannot_gain_privileges() {
        for (kvm, tun, mode, groups) in [
            (993, 994, 0o666, "1000,993"),
            (993, 994, 0o660, "1000,993,994"),
            (993, 994, 0o664, "1000,993,994"),
            (993, 993, 0o660, "1000,993"),
            (1000, 1000, 0o660, "1000"),
        ] {
            let command = firecracker_command(kvm, tun, mode);
            assert_eq!(command.as_std().get_program(), "setpriv");
            assert_eq!(
                command.as_std().get_args().collect::<Vec<_>>(),
                [
                    "--reuid",
                    "1000",
                    "--regid",
                    "1000",
                    "--groups",
                    groups,
                    "--inh-caps=-all",
                    "--no-new-privs",
                    "--",
                    "firecracker",
                ]
            );
        }
    }
    #[tokio::test]
    async fn preboot_vmm_exit_spans_the_first_console_line_once_with_its_status() {
        use opentelemetry::trace::TracerProvider;
        use tracing::instrument::WithSubscriber;
        use tracing_subscriber::layer::SubscriberExt;
        let exporter = opentelemetry_sdk::trace::InMemorySpanExporter::default();
        let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let subscriber = tracing_subscriber::registry()
            .with(tracing_opentelemetry::layer().with_tracer(provider.tracer("vmm-exit")));
        let work = tempfile::tempdir().unwrap();
        tokio::fs::create_dir(work.path().join("console"))
            .await
            .unwrap();
        let console = work.path().join("console/serial.log");
        let status = Command::new("/bin/sh")
            .args(["-c", "printf 'KVM EACCES\\nsecond line\\n' >&2; exit 1"])
            .stderr(Stdio::from(std::fs::File::create(&console).unwrap()))
            .status()
            .await
            .unwrap();
        let error = phase::<()>("ready", async {
            Err(firecracker_exit(status, work.path()).await.into())
        })
        .with_subscriber(subscriber)
        .await
        .unwrap_err();
        assert!(
            matches!(error.downcast_ref::<Error>(), Some(Error::Firecracker { status, first_line }) if status.code() == Some(1) && first_line == "KVM EACCES")
        );
        let spans = exporter.get_finished_spans().unwrap();
        assert_eq!(spans.len(), 1);
        assert_eq!(
            crate::tests::span_attribute(&spans[0], "boot.phase"),
            Some(&"ready".into())
        );
        assert_eq!(
            crate::tests::span_attribute(&spans[0], "error.message"),
            Some(&error.to_string().into())
        );
        assert!(spans[0].events.is_empty());
        tokio::fs::write(&console, "x".repeat(8192)).await.unwrap();
        let Error::Firecracker { first_line, .. } = firecracker_exit(status, work.path()).await
        else {
            panic!("wrong cause")
        };
        assert_eq!(first_line, crate::egress::cut(&"x".repeat(8192)));
        tokio::fs::remove_file(console).await.unwrap();
        assert!(
            matches!(firecracker_exit(status, work.path()).await, Error::Firecracker { status, .. } if status.code() == Some(1))
        );
    }
    #[tokio::test]
    async fn ca_drive_preserves_the_pem_and_zero_pads_to_four_kib() {
        let dir = tempfile::tempdir().unwrap();
        let (_ca, pem) = crate::egress::Ca::new().unwrap();
        let path = dir.path().join("ca.pem");
        ca_drive(&path, &pem).await.unwrap();
        let bytes = tokio::fs::read(path).await.unwrap();
        assert_eq!(bytes.len() % 4096, 0);
        assert_eq!(&bytes[..pem.len()], pem.as_bytes());
        assert!(bytes[pem.len()..].iter().all(|&byte| byte == 0));
    }
    #[tokio::test(start_paused = true)]
    async fn preboot_failures_retain_typed_causes_and_record_each_cause_once() {
        use tracing::instrument::WithSubscriber;
        use tracing_subscriber::layer::SubscriberExt;
        let exporter = opentelemetry_sdk::trace::InMemorySpanExporter::default();
        let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        use opentelemetry::trace::TracerProvider;
        let subscriber = tracing_subscriber::registry()
            .with(tracing_opentelemetry::layer().with_tracer(provider.tracer("preboot")));
        async {
            for name in ["tap", "nftables", "drives"] {
                let error = phase(name, command("/bin/sh", &["-c", "exit 7"])).await.unwrap_err();
                assert!(matches!(error.downcast_ref::<Error>(), Some(Error::Command { status, .. }) if status.code() == Some(7)));
            }
            let cache = tempfile::tempdir().unwrap();
            assert!(matches!(image::fetch(&format!("evil.example/test@sha256:{}", "a".repeat(64)), cache.path()).await.unwrap_err().downcast_ref::<Error>(), Some(Error::RegistryHost)));
            let socket = cache.path().join("silent.sock");
            let _listener = tokio::net::UnixListener::bind(&socket).unwrap();
            let guest = client::Guest::new(socket);
            let error = phase("ready", async { Ok(guest.ready().await?) }).await.unwrap_err();
            assert!(matches!(error.downcast_ref::<client::Error>(), Some(client::Error::Deadline)));
        }.with_subscriber(subscriber).await;
        let spans = exporter.get_finished_spans().unwrap();
        assert_eq!(spans.len(), 5);
        for (span, name) in spans
            .iter()
            .zip(["tap", "nftables", "drives", "fetch", "ready"])
        {
            assert_eq!(span.name, "vm_runner.boot");
            assert_eq!(
                crate::tests::span_attribute(span, "boot.phase"),
                Some(&opentelemetry::Value::from(name))
            );
            assert!(crate::tests::span_attribute(span, "error.message").is_some());
            assert!(
                span.events.is_empty(),
                "failure is recorded once, not also logged as events"
            );
        }
    }
    #[test]
    fn firecracker_rate_limits_use_si_units_and_shape_defaults() {
        let shape: Shape =
            serde_json::from_value(json!({"vcpus":1,"memoryMiB":1024,"diskMiB":4096})).unwrap();
        assert_eq!(shape.disk_mbps.get(), 100);
        assert_eq!(shape.net_mbps.get(), 200);
        let shape: Shape = serde_json::from_value(
            json!({"vcpus":1,"memoryMiB":1024,"diskMiB":4096,"diskMBps":7,"netMbps":9}),
        )
        .unwrap();
        let value = vm_config(
            Path::new("/images/test"),
            Path::new("/run/vm-runner"),
            &shape,
        );
        assert_eq!(
            value["drives"][2]["rate_limiter"],
            json!({"bandwidth":{"size":7_000_000,"refill_time":1000}})
        );
        for direction in ["rx_rate_limiter", "tx_rate_limiter"] {
            assert_eq!(
                value["network-interfaces"][0][direction],
                json!({"bandwidth":{"size":1_125_000,"refill_time":1000}})
            );
        }
        assert!(
            serde_json::from_value::<Shape>(
                json!({"vcpus":1,"memoryMiB":1024,"diskMiB":4096,"diskMBps":0})
            )
            .is_err()
        );
    }
    #[test]
    fn firecracker_uses_the_shape_and_ordered_read_only_drives() {
        let shape: Shape =
            serde_json::from_value(json!({"vcpus":2,"memoryMiB":1024,"diskMiB":4096})).unwrap();
        let value = vm_config(
            Path::new("/images/test"),
            Path::new("/run/vm-runner"),
            &shape,
        );
        assert_eq!(
            value["machine-config"],
            json!({"vcpu_count":2,"mem_size_mib":1024})
        );
        assert_eq!(
            value["drives"]
                .as_array()
                .unwrap()
                .iter()
                .map(|d| (
                    d["drive_id"].as_str().unwrap(),
                    d["is_read_only"].as_bool().unwrap()
                ))
                .collect::<Vec<_>>(),
            [("rootfs", true), ("ca", true), ("scratch", false)]
        );
        assert_eq!(value["vsock"]["uds_path"], "/run/vm-runner/guest.sock");
        assert_eq!(
            value["boot-source"]["boot_args"],
            "console=ttyS0 reboot=k panic=1 init=/sbin/vm-init ro"
        );
    }
}
