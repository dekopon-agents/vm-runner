#![allow(clippy::unwrap_used, clippy::disallowed_methods)]

#[test]
fn bad_gateway_values_are_refused_with_every_configuration_conflict_reported() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.yaml");
    std::fs::write(
        &path,
        r#"
listen: 127.0.0.1:0
auth: {issuers: [], subjects: []}
shapes: {}
profiles:
  test:
    shape: absent
    image: test
    browser: headless
    idleSeconds: 2
    maxSeconds: 1
    egress: {allow: [], dns: runner}
quotas: {default: {maxSessions: 1}, subjects: {}}
"#,
    )
    .unwrap();
    for address in [
        "0.0.0.0",
        "255.255.255.255",
        "224.0.0.1",
        "239.255.255.255",
        "127.0.0.1",
        "127.4.3.2",
    ] {
        assert!(matches!(
            vm_runner::egress::validate_gateway(address.parse().unwrap()),
            Err(vm_runner::egress::InvalidGateway { .. })
        ));
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_vm-runnerd"))
            .args(["egress", "--config"])
            .arg(&path)
            .args(["--profile", "test", "--gateway", address, "--ca-out"])
            .arg(dir.path().join("ca"))
            .output()
            .unwrap();
        assert!(!output.status.success());
        let stderr = String::from_utf8(output.stderr).unwrap();
        for conflict in [
            "unknown shape in profile: test",
            "idleSeconds and maxSeconds must be at least 60, with idleSeconds <= maxSeconds: test",
            "empty allow list: test",
            &format!("invalid --gateway {address}:"),
        ] {
            assert!(stderr.contains(conflict), "{stderr}");
        }
        assert!(!dir.path().join("ca").exists());
    }
    assert!(vm_runner::egress::validate_gateway("10.0.2.1".parse().unwrap()).is_ok());
}
