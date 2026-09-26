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
use tokio::{io::AsyncWriteExt, process::Command, sync::watch, task::JoinSet};
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
    #[error("unknown profile or shape")]
    Profile,
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
    #[error("Firecracker exited: {0}")]
    Firecracker(std::process::ExitStatus),
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
    require_sysctl("conf/tap0/rp_filter", "1").await?;
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
    command("ip", &["addr", "add", "10.0.2.1/30", "dev", "tap0"]).await?;
    command("ip", &["link", "set", "tap0", "up"]).await
}

fn vm_config(image: &Path, work: &Path, shape: &Shape) -> serde_json::Value {
    json!({
        "boot-source": {"kernel_image_path": image.join("vmlinux"), "boot_args": "console=ttyS0 reboot=k panic=1 init=/sbin/vm-init ro"},
        "drives": [
            {"drive_id": "rootfs", "path_on_host": image.join("rootfs.ext4"), "is_root_device": true, "is_read_only": true},
            {"drive_id": "ca", "path_on_host": work.join("ca.pem"), "is_root_device": false, "is_read_only": true},
            {"drive_id": "scratch", "path_on_host": work.join("scratch.ext4"), "is_root_device": false, "is_read_only": false}
        ],
        "network-interfaces": [{"iface_id": "eth0", "host_dev_name": "tap0"}],
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
async fn launch(
    image: &Path,
    work: &Path,
    shape: &Shape,
    pem: &str,
) -> Result<tokio::process::Child> {
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
    let console = shared_file(&work.join("serial.log"), &[])
        .await?
        .into_std()
        .await;
    Ok(Command::new("firecracker")
        .arg("--api-sock")
        .arg(work.join("firecracker.sock"))
        .arg("--config-file")
        .arg(config)
        .args(["--level", "Info", "--log-path", "/dev/stderr"])
        .stdin(Stdio::null())
        .stdout(Stdio::from(console.try_clone()?))
        .stderr(Stdio::from(console))
        .uid(1000)
        .gid(1000)
        .kill_on_drop(true)
        .spawn()?)
}

pub async fn run(config: Config, profile: &str, session: &str) -> Result<()> {
    if !cfg!(target_os = "linux") {
        return Err(Error::LinuxOnly.into());
    }
    if uuid::Uuid::parse_str(session)?.get_version_num() != 7 {
        return Err(Error::Session.into());
    }
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
    let image = image::directory(Path::new("/images"), &selected.image)?;
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
    let result = tokio::task::spawn_blocking(move || tracing::dispatcher::with_default(&dispatch, || runtime.block_on(async {
        let work = PathBuf::from("/run/vm-runner");
        if tokio::fs::metadata(&work).await?.gid() != 1000 { return Err(Error::RuntimeGroup.into()); }
        tokio::fs::set_permissions(&work, std::fs::Permissions::from_mode(0o2770)).await?;
        let guest = Arc::new(client::Guest::new(work.join("guest.sock")));
        let (endpoint, requests, state) = api::endpoint(config.auth, Arc::clone(&guest)).await?;
        let acceptor = poem::listener::TcpListener::bind("0.0.0.0:8080").into_acceptor().await?;
        let (ca, pem) = crate::egress::Ca::new()?;
        network(&work).await?;
        let gateway = crate::egress::Gateway::bind(selected.egress, ca).await?;
        let (stop, stopping) = watch::channel(false);
        let mut workers = JoinSet::new();
        let handle = tokio::runtime::Handle::current();
        let dispatch = tracing::dispatcher::get_default(Clone::clone);
        let egress_stop = stopping.clone();
        // The lifecycle joins exactly the gateway and API workers after stopping the VM.
        workers.spawn_blocking(move || tracing::dispatcher::with_default(&dispatch, || handle.block_on(gateway.serve(stopped(egress_stop)))));
        let mut vm = None;
        let result = async {
            let shutdown = crate::shutdown_signal();
            tokio::pin!(shutdown);
            let boot = tracing::info_span!("vm_runner.boot");
            let child = tokio::select! {
                child = launch(&image, &work, &shape, &pem).instrument(boot.clone()) => child?,
                _ = &mut shutdown => return Ok(()),
            };
            let pid = child.id();
            vm = Some(child);
            let child = vm.as_mut().ok_or(Error::WorkerStopped)?;
            tokio::select! {
                result = guest.ready().instrument(boot) => result?,
                _ = &mut shutdown => return Ok(()),
                status = child.wait() => return Err(Error::Firecracker(status?).into()),
                worker = workers.join_next() => return Err(worker_error(worker)),
            }
            let handle = tokio::runtime::Handle::current();
            let dispatch = tracing::dispatcher::get_default(Clone::clone);
            workers.spawn_blocking(move || tracing::dispatcher::with_default(&dispatch, || handle.block_on(async {
                poem::Server::new_with_acceptor(acceptor).run_with_graceful_shutdown(endpoint, stopped(stopping), Some(Duration::from_secs(45))).await?;
                Ok(())
            })));
            tracing::info!(pid, "jail ready");
            tokio::select! {
                _ = &mut shutdown => Ok(()),
                status = child.wait() => Err(Error::Firecracker(status?).into()),
                worker = workers.join_next() => Err(worker_error(worker)),
            }
        }.await;
        let stopped_vm = match vm.as_mut() { Some(child) => stop_vm(child).await, None => Ok(()) };
        stop.send_replace(true);
        let mut drained = Ok(());
        while let Some(worker) = workers.join_next().await {
            match worker { Ok(Ok(())) => (), other => drained = Err(worker_error(Some(other))) }
        }
        requests.drain().await?;
        state.drain().await?;
        result.and(stopped_vm).and(drained)
    }))).await;
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
