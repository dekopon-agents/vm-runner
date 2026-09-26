#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used)]
use std::{process::Stdio, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::Command,
};

#[tokio::test]
async fn isolated_jail_boots_with_kvm_and_stops_on_sigterm() {
    let config = tempfile::NamedTempFile::new().unwrap();
    let image = std::env::var("KVM_GUEST_IMAGE").unwrap();
    let mut value: serde_json::Value =
        serde_yaml_ng::from_str(include_str!("../examples/vm-runner.yaml")).unwrap();
    value["profiles"]["travel"]["image"] = image.into();
    tokio::fs::write(config.path(), serde_yaml_ng::to_string(&value).unwrap())
        .await
        .unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_vm-runnerd"))
        .args(["jail", "--config"])
        .arg(config.path())
        .args([
            "--profile",
            "travel",
            "--session",
            "01960000-0000-7000-8000-000000000001",
        ])
        .env(
            "OTEL_RESOURCE_ATTRIBUTES",
            "vm_runner.subject=system:serviceaccount:test:controller",
        )
        .stdout(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let outcome = tokio::time::timeout(Duration::from_secs(60), async {
        while let Some(line) = lines.next_line().await.unwrap() {
            println!("{line}");
            // The pinned kernel emits this only after mounting the root drive and starting init.
            if line.contains("Run /sbin/vm-init as init process") {
                for (path, expected) in [
                    ("ip_forward", "0"),
                    ("conf/all/rp_filter", "1"),
                    ("conf/tap0/rp_filter", "1"),
                ] {
                    assert_eq!(
                        tokio::fs::read_to_string(format!("/proc/sys/net/ipv4/{path}"))
                            .await
                            .unwrap()
                            .trim(),
                        expected
                    );
                }
                let nft = Command::new("nft")
                    .args(["list", "table", "inet", "vm_runner"])
                    .output()
                    .await
                    .unwrap();
                assert!(nft.status.success());
                let rules = String::from_utf8(nft.stdout).unwrap();
                assert_eq!(rules.matches("ip saddr 10.0.2.2").count(), 3);
                assert!(rules.contains("iifname \"tap0\" counter packets"));
                let api = reqwest::Client::builder()
                    .unix_socket("/run/vm-runner/firecracker.sock")
                    .build()
                    .unwrap();
                let state: serde_json::Value = api
                    .get("http://localhost/")
                    .send()
                    .await
                    .unwrap()
                    .error_for_status()
                    .unwrap()
                    .json()
                    .await
                    .unwrap();
                assert_eq!(state["state"], "Running");
                return true;
            }
        }
        false
    })
    .await;
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(child.id().unwrap() as i32),
        nix::sys::signal::Signal::SIGTERM,
    )
    .unwrap();
    let status = tokio::time::timeout(Duration::from_secs(15), child.wait())
        .await
        .unwrap()
        .unwrap();
    assert!(status.success());
    assert!(outcome.unwrap(), "guest exited before init started");
}
