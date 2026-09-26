use crate::{
    config::{Config, Shape},
    telemetry,
};
use serde_json::json;
use std::{
    path::{Path, PathBuf},
    process::Stdio,
};
use tokio::process::Command;
use tracing::Instrument;

pub mod image;
type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
#[derive(Debug, thiserror::Error)]
enum Error {
    #[error("jail requires Linux")]
    LinuxOnly,
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
    command("ip", &["tuntap", "add", "tap0", "mode", "tap"]).await?;
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
    tokio::fs::write(path, bytes).await?;
    Ok(())
}
async fn launch(
    image: &Path,
    work: &Path,
    shape: &Shape,
    pem: &str,
) -> Result<tokio::process::Child> {
    ca_drive(&work.join("ca.pem"), pem).await?;
    let scratch = work.join("scratch.ext4");
    let file = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&scratch)
        .await?;
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
    tokio::fs::write(&config, serde_json::to_vec(&vm_config(image, work, shape))?).await?;
    Ok(Command::new("firecracker")
        .arg("--api-sock")
        .arg(work.join("firecracker.sock"))
        .arg("--config-file")
        .arg(config)
        .args(["--level", "Info", "--log-path", "/dev/stdout"])
        .stdin(Stdio::null())
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
        tokio::fs::create_dir_all(&work).await?;
        let (_ca, pem) = crate::egress::Ca::new()?;
        network(&work).await?;
        let mut child = launch(&image, &work, &shape, &pem).instrument(tracing::info_span!("vm_runner.boot")).await?;
        tokio::select! {
            result = child.wait() => Err(Error::Firecracker(result?).into()),
            _ = crate::shutdown_signal() => { child.kill().await?; Ok::<_, Box<dyn std::error::Error + Send + Sync>>(()) },
        }
    }))).await;
    tokio::task::spawn_blocking(move || provider.shutdown()).await??;
    result?
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
