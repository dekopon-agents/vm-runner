#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used)]
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use serde_json::{Value, json};
use std::{os::unix::fs::PermissionsExt, process::Stdio, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::Command,
};

#[tokio::test]
async fn jail_vmm_has_no_new_privileges_and_confined_identity_and_egress() {
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
                    .send(record["fields"]["pid"].as_u64().unwrap())
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
        for field in ["Groups:", "CapEff:"] {
            let value = status.lines().find(|line| line.starts_with(field)).unwrap().split_once(':').unwrap().1.trim();
            if field == "Groups:" { assert!(value.is_empty()); } else { assert_eq!(u64::from_str_radix(value, 16).unwrap(), 0); }
        }
        assert_eq!(status.lines().find(|line| line.starts_with("NoNewPrivs:")).unwrap().split_once(':').unwrap().1.trim(), "1");
        for path in ["/dev/kvm", "/dev/net/tun"] {
            let mode = tokio::fs::metadata(path).await.unwrap().permissions().mode() & 0o777;
            println!("device {path} mode={mode:o}");
            assert_eq!(mode, 0o666);
        }
        for path in ["ip_forward", "conf/all/rp_filter", "conf/default/rp_filter", "conf/tap0/rp_filter"] {
            assert_eq!(tokio::fs::read_to_string(format!("/proc/sys/net/ipv4/{path}")).await.unwrap().trim(), if path == "ip_forward" { "0" } else { "1" });
        }
        let api = reqwest::Client::builder().timeout(Duration::from_secs(30)).build().unwrap();
        assert_eq!(api.get("http://127.0.0.1:8080/healthz").bearer_auth(&token).send().await.unwrap().status(), 200);
        let result = exec(&api, &token, "node -e \"require('node:dns').resolve4('example.com',(e,a)=>{if(e||JSON.stringify(a)!=='[\\\"10.0.2.1\\\"]')process.exit(1)})\" && curl --fail --http1.1 --max-time 15 https://example.com").await;
        assert!(result["stdout"].as_str().unwrap().contains("Example Domain"));
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
