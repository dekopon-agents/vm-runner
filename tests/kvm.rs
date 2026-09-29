#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used)]
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use serde_json::{Value, json};
use std::{os::unix::fs::MetadataExt, process::Stdio, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::Command,
};

#[tokio::test]
async fn jail_vmm_has_no_new_privileges_and_confined_identity_and_egress() {
    let kvm = tokio::fs::metadata("/dev/kvm").await.unwrap();
    let tun = tokio::fs::metadata("/dev/net/tun").await.unwrap();
    for (path, device) in [("/dev/kvm", &kvm), ("/dev/net/tun", &tun)] {
        println!(
            "device {path} mode={:o} uid={} gid={}",
            device.mode() & 0o777,
            device.uid(),
            device.gid()
        );
    }
    assert_eq!(kvm.mode() & 0o777, 0o660);
    assert_eq!(kvm.uid(), 0);
    assert_ne!(kvm.gid(), 0);
    assert_ne!(kvm.gid(), 1000);
    assert_eq!(tun.mode() & 0o777, 0o666);
    let key = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING).unwrap();
    let point = key.public_key().as_ref();
    let jwks = json!({"keys":[{"kty":"EC","crv":"P-256","kid":"kvm","alg":"ES256","x":B64.encode(&point[1..33]),"y":B64.encode(&point[33..])}]}).to_string();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let issuer = format!("http://{}", listener.local_addr().unwrap());
    let mut peers = tokio::task::JoinSet::new();
    peers.spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let body = jwks.clone();
            let service =
                hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                    assert_eq!(req.uri().path(), "/openid/v1/jwks");
                    let body = http_body_util::Full::new(hyper::body::Bytes::from(body.clone()));
                    async move { Ok::<_, std::convert::Infallible>(hyper::Response::new(body)) }
                });
            hyper::server::conn::http1::Builder::new()
                .keep_alive(false)
                .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                .await
                .unwrap();
        }
    });
    let now = jsonwebtoken::get_current_timestamp();
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
    header.kid = Some("kvm".into());
    let token = jsonwebtoken::encode(&header, &json!({"iss":issuer,"sub":"system:serviceaccount:test:controller","aud":["vm-runner-jail"],"exp":now+300,"iat":now,"nbf":now}), &jsonwebtoken::EncodingKey::from_ec_der(key.to_pkcs8v1().unwrap().as_ref())).unwrap();
    let config = tempfile::NamedTempFile::new().unwrap();
    let mut value: Value =
        serde_yaml_ng::from_str(include_str!("../examples/vm-runner.yaml")).unwrap();
    value["profiles"]["travel"]["image"] = std::env::var("KVM_GUEST_IMAGE").unwrap().into();
    value["profiles"]["travel"]["egress"]["allow"] = json!(["example.com"]);
    value["auth"]["issuers"] = json!([{"issuer":issuer}]);
    value["jails"] = json!({
        "namespace":"test", "image":format!("vm-runner@sha256:{}", "a".repeat(64)), "imageCacheHostPath":"/images",
        "controllerAudience":"vm-runner-jail", "controllerSubject":"system:serviceaccount:test:controller",
        "tokenFile":"/unused"
    });
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
    let (ready, received_ready) = tokio::sync::oneshot::channel();
    peers.spawn(async move {
        let mut ready = Some(ready);
        while let Some(line) = lines.next_line().await.unwrap() {
            println!("{line}");
            let record: Value = serde_json::from_str(&line).expect("jail stdout must remain JSON");
            if record["fields"]["message"] == "jail ready" {
                ready
                    .take()
                    .unwrap()
                    .send(record["fields"]["process.pid"].as_u64().unwrap())
                    .unwrap();
            }
        }
    });
    let outcome = tokio::time::timeout(Duration::from_secs(90), async {
        let pid = received_ready.await.expect("jail exited before ready");
        let status = tokio::fs::read_to_string(format!("/proc/{pid}/status")).await.unwrap();
        for field in ["Uid:", "Gid:"] {
            assert_eq!(status.lines().find(|line| line.starts_with(field)).unwrap().split_whitespace().skip(1).collect::<Vec<_>>(), ["1000"; 4]);
        }
        println!("{status}");
        let mut groups = status.lines().find(|line| line.starts_with("Groups:")).unwrap().split_whitespace().skip(1).map(|gid| gid.parse::<u32>().unwrap()).collect::<Vec<_>>();
        groups.sort_unstable();
        let mut expected = [1000, kvm.gid()];
        expected.sort_unstable();
        assert_eq!(groups, expected);
        for field in ["CapEff:", "CapPrm:", "CapInh:", "CapAmb:"] {
            let value = status.lines().find(|line| line.starts_with(field)).unwrap().split_once(':').unwrap().1.trim();
            assert_eq!(u64::from_str_radix(value, 16).unwrap(), 0, "{field}");
        }
        assert_eq!(status.lines().find(|line| line.starts_with("NoNewPrivs:")).unwrap().split_once(':').unwrap().1.trim(), "1");
        for path in ["ip_forward", "conf/all/rp_filter", "conf/default/rp_filter", "conf/tap0/rp_filter"] {
            assert_eq!(tokio::fs::read_to_string(format!("/proc/sys/net/ipv4/{path}")).await.unwrap().trim(), if path == "ip_forward" { "0" } else { "1" });
        }
        let api = reqwest::Client::builder().timeout(Duration::from_secs(30)).build().unwrap();
        assert_eq!(api.get("http://127.0.0.1:8080/healthz").bearer_auth(&token).send().await.unwrap().status(), 200);
        let result = exec(&api, &token, "node -e \"require('node:dns').resolve4('example.com',(e,a)=>{if(e||JSON.stringify(a)!=='[\\\"10.0.2.1\\\"]')process.exit(1)})\" && curl --fail --http1.1 --max-time 15 https://example.com").await;
        assert!(result["stdout"].as_str().unwrap().contains("Example Domain"));
        assert!(!tokio::fs::try_exists("/usr/bin/curl").await.unwrap());
        exec(&api, &token, "mkdir -p /artifacts/nested; printf hello > /artifacts/nested/test.txt").await;
        let files: Value = api.get("http://127.0.0.1:8080/artifacts").bearer_auth(&token).send().await.unwrap().error_for_status().unwrap().json().await.unwrap();
        assert_eq!(files[0]["path"], "nested/test.txt");
        assert_eq!(files[0]["bytes"], 5);
        let response = api.get("http://127.0.0.1:8080/artifacts/nested%2Ftest.txt").bearer_auth(&token).header("Range", "bytes=1-3").send().await.unwrap();
        assert_eq!(response.status(), 206);
        assert_eq!(response.headers()["content-range"], "bytes 1-3/5");
        assert_eq!(response.headers()["sha256"], "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
        assert_eq!(response.text().await.unwrap(), "ell");
        let vmm = reqwest::Client::builder().unix_socket("/run/vm-runner/firecracker.sock").build().unwrap();
        let config: Value = vmm.get("http://localhost/vm/config").send().await.unwrap().error_for_status().unwrap().json().await.unwrap();
        // Post-boot config enumerates the device manager's HashMap, not boot drive order.
        let scratch = config["drives"].as_array().unwrap().iter().find(|drive| drive["drive_id"] == "scratch").expect("scratch drive missing from live config");
        assert_eq!(scratch["rate_limiter"]["bandwidth"]["size"], 100_000_000);
        let nic = config["network-interfaces"].as_array().unwrap().iter().find(|nic| nic["iface_id"] == "eth0").expect("eth0 missing from live config");
        for direction in ["rx_rate_limiter", "tx_rate_limiter"] {
            assert_eq!(nic[direction]["bandwidth"]["size"], 25_000_000);
        }
        let probe = tokio::net::UdpSocket::bind("0.0.0.0:0").await.unwrap();
        probe.connect("1.1.1.1:80").await.unwrap();
        let pod = probe.local_addr().unwrap().ip();
        let addresses = Command::new("ip").args(["-j", "-6", "address", "show", "tap0"]).output().await.unwrap();
        assert!(addresses.status.success());
        let addresses: Value = serde_json::from_slice(&addresses.stdout).unwrap();
        let fe80 = addresses[0]["addr_info"].as_array().unwrap().iter().find(|a| a["scope"] == "link").unwrap()["local"].as_str().unwrap();
        let before = dropped().await;
        let script = format!("set -eu; for url in 'http://{pod}' 'http://{pod}:8080/healthz' 'http://10.0.2.1:22' 'http://1.1.1.1' 'http://[{fe80}%25eth0]'; do code=0; curl --silent --show-error --noproxy '*' --output /dev/null --max-time 3 \"$url\" || code=$?; case $code in 7|28) :;; *) exit 1;; esac; done; echo NEGATIVE_OK");
        assert_eq!(exec(&api, &token, &script).await["stdout"], "NEGATIVE_OK\n");
        assert!(dropped().await > before, "negative packets must reach tap0's actual nft drop rule");
        assert!(tokio::fs::read_to_string("/run/vm-runner/console/serial.log").await.unwrap().contains("Run /sbin/vm-init as init process"));
        pid
    }).await;
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(child.id().unwrap() as i32),
        nix::sys::signal::Signal::SIGTERM,
    )
    .unwrap();
    let status = tokio::time::timeout(Duration::from_secs(45), child.wait())
        .await
        .unwrap()
        .unwrap();
    peers.abort_all();
    while let Some(result) = peers.join_next().await {
        if let Err(error) = result {
            assert!(error.is_cancelled());
        }
    }
    assert!(status.success());
    let pid = outcome.unwrap();
    assert!(
        !tokio::fs::try_exists(format!("/proc/{pid}")).await.unwrap(),
        "VMM must be reaped before daemon exit"
    );
}
async fn exec(api: &reqwest::Client, token: &str, script: &str) -> Value {
    let response = api
        .post("http://127.0.0.1:8080/exec")
        .bearer_auth(token)
        .json(&json!({"argv":["/bin/sh","-c",script],"deadlineMs":25000}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let result: Value = response.json().await.unwrap();
    assert_eq!(result["outcome"], "executed", "{result}");
    assert_eq!(result["exitCode"], 0, "{result}");
    result
}
async fn dropped() -> u64 {
    let output = Command::new("nft")
        .args(["-j", "list", "chain", "inet", "vm_runner", "input"])
        .output()
        .await
        .unwrap();
    assert!(output.status.success());
    let rules: Value = serde_json::from_slice(&output.stdout).unwrap();
    rules["nftables"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|item| item["rule"]["expr"].as_array())
        .flat_map(|expr| expr.iter())
        .filter_map(|expr| expr["counter"]["packets"].as_u64())
        .sum()
}
