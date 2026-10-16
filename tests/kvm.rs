#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::disallowed_methods)]
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
    let pr_guest = std::env::var("KVM_PR_GUEST").as_deref() == Ok("1");
    if pr_guest {
        value["shapes"]["proof-1c512m"] = json!({"vcpus":1,"memoryMiB":512,"diskMiB":4096});
        value["profiles"]["travel"]["shape"] = json!("proof-1c512m");
    }
    value["auth"]["issuers"] = json!([{"issuer":issuer}]);
    let (models, received_models) = model_upstream().await;
    peers.spawn(models);
    value["jails"] = json!({
        "namespace":"test", "image":format!("vm-runner@sha256:{}", "a".repeat(64)), "imageCacheHostPath":"/images",
        "controllerAudience":"vm-runner-jail", "controllerSubject":"system:serviceaccount:test:controller",
        "tokenFile":"/unused",
        "models":{"upstream":format!("https://localhost:{}", received_models.port), "clientCertSecret":"unused", "subject":"test:kvm-vm"}
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
    let outcome = tokio::time::timeout(Duration::from_secs(450), async {
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
        let api = reqwest::Client::builder().timeout(Duration::from_secs(180)).build().unwrap();
        assert_eq!(api.get("http://127.0.0.1:8080/healthz").bearer_auth(&token).send().await.unwrap().status(), 200);
        let result = exec(&api, &token, "node -e \"require('node:dns').resolve4('example.com',(e,a)=>{if(e||JSON.stringify(a)!=='[\\\"10.0.2.1\\\"]')process.exit(1)})\" && curl --fail --http1.1 --max-time 15 https://example.com").await;
        assert!(result["stdout"].as_str().unwrap().contains("Example Domain"));
        assert!(!tokio::fs::try_exists("/usr/bin/curl").await.unwrap());
        // The guest's forged subject is replaced by the jail's, over mTLS, outside the allowlist.
        let result = exec(&api, &token, "curl --fail --silent --show-error --http1.1 --max-time 15 -H 'x-dekopon-vm-subject: test:forged' -H 'content-type: application/json' -d '{\"model\":\"claude-opus\"}' https://models.vm.internal/v1/messages").await;
        assert_eq!(result["stdout"], "model");
        let seen = received_models.requests.lock().await.recv().await.unwrap();
        assert_eq!((seen.path.as_str(), seen.subjects.as_slice(), seen.model.as_str(), seen.admitted), ("/v1/messages", ["test:kvm-vm".to_owned()].as_slice(), "claude-opus", true));
        assert_eq!(received_models.upstream_calls(), 1);
        if pr_guest {
            assert_eq!(exec(&api, &token, "cat /proc/sys/vm/overcommit_memory").await["stdout"], "1\n", "V8's x64 CodeRange reservation exceeds the 512 MiB guest's RAM; heuristic overcommit refuses it");
            let pre_pi_script = "browse open about:blank";
            let attempt = tokio::time::timeout(Duration::from_secs(20), api.post("http://127.0.0.1:8080/exec")
                .bearer_auth(&token)
                .json(&json!({"argv":["/bin/sh","-c",pre_pi_script],"deadlineMs":25000}))
                .send()).await;
            let pre_pi_ready = match attempt {
                Ok(Ok(response)) => {
                    let status = response.status();
                    let body: Value = response.json().await.unwrap_or_default();
                    println!("pre-pi browse open about:blank (HTTP {status}): {body}");
                    status == 200 && body["outcome"] == "executed" && body["exitCode"] == 0
                }
                Ok(Err(error)) => { println!("pre-pi browse open about:blank transport error: {error}"); false }
                Err(_) => { println!("pre-pi browse open about:blank timed out after 20 s"); false }
            };
            if !pre_pi_ready {
                browser_diagnostic(&api, &token).await;
                stderr_probe_on_failure(&api, &token, "about:blank").await;
            }
            assert!(pre_pi_ready, "browse must work before the pi child call");
            let result = exec(&api, &token, "pi --no-session --no-tools --no-mcp --provider vm-proxy --model sol --print 'Reply CANNED_SOL_OK exactly'").await;
            println!("child stdout: {}", result["stdout"]);
            assert!(result["stdout"].as_str().unwrap().contains("CANNED_SOL_OK"));
            let seen = received_models.requests.lock().await.recv().await.unwrap();
            assert_eq!((seen.path.as_str(), seen.subjects.as_slice(), seen.model.as_str(), seen.admitted), ("/v1/responses", ["test:kvm-vm".to_owned()].as_slice(), "sol", true));
            assert_eq!(seen.authorization.as_deref(), Some("Bearer guest-no-credential"), "child must send only the baked non-secret key");
            assert_eq!(received_models.upstream_calls(), 2);
        }
        let denied = exec(&api, &token, "curl --silent --show-error --http1.1 --max-time 15 -w '\\n%{http_code}' -H 'authorization: Bearer guest-no-credential' -H 'content-type: application/json' -d '{\"model\":\"unlisted\",\"stream\":true,\"input\":\"deny\"}' https://models.vm.internal/v1/responses").await;
        let (body, status) = denied["stdout"].as_str().unwrap().rsplit_once('\n').unwrap();
        assert_eq!(status, "403");
        assert_eq!(serde_json::from_str::<Value>(body).unwrap()["error"]["code"], "permission_denied");
        let seen = received_models.requests.lock().await.recv().await.unwrap();
        assert_eq!((seen.path.as_str(), seen.subjects.as_slice(), seen.model.as_str(), seen.admitted), ("/v1/responses", ["test:kvm-vm".to_owned()].as_slice(), "unlisted", false));
        assert_eq!(received_models.upstream_calls(), if pr_guest { 2 } else { 1 }, "a model outside the subject's grant must make zero upstream calls");
        assert!(received_models.requests.lock().await.try_recv().is_err());
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
        if pr_guest {
        exec(&api, &token, "browse open 'data:text/html,<title>CDP proof</title><body style=\"background:#174b72;color:white\"><p>CDP proof without heading</p></body>'").await;
        assert_eq!(exec(&api, &token, "browse eval \"document.querySelector('h1') === null\"").await["stdout"], "true\n", "proof tab must have no heading");
        // A failed encoder must leave the artifact namespace untouched.
        let failure = succeeded(exec_job(&api, &token, "set -eu; d=$(mktemp -d /home/jail/failed-encode.XXXXXX); printf '#!/bin/sh\\neval \"out=\\${$#}\"\\nprintf junk > \"$out\"\\necho FORCED_ENCODER_FAILURE >&2\\nexit 42\\n' > \"$d/ffmpeg\"; chmod +x \"$d/ffmpeg\"; code=0; PATH=\"$d:/usr/local/bin:/usr/bin:/bin\" record-cdp rejected || code=$?; rm -rf \"$d\"; test \"$code\" -ne 0; echo ENCODE_FAILED").await);
        assert_capture_seconds(&failure);
        assert_eq!(exec(&api, &token, "browse eval \"typeof window.recordTimer === 'number' && document.querySelector('[data-cdp-recording]') === null\"").await["stdout"], "true\n", "record-cdp must remove its frame counter after capture");
        assert!(failure["stdout"].as_str().unwrap().contains("CDP_FRAME_ELAPSED_MS="), "capture must complete before forced encoder failure: {failure}");
        assert_eq!(failure["stdout"].as_str().unwrap().lines().last(), Some("ENCODE_FAILED"));
        assert!(failure["stderr"].as_str().unwrap().contains("FORCED_ENCODER_FAILURE"), "the encode, not capture, must be the failing step: {failure}");
        let files = list_artifacts(&api, &token).await;
        assert!(!files.iter().any(|f| f["path"].as_str().unwrap().contains("rejected")));

        // Record the most recently opened tab and compare every observed artifact to final content.
        let runner = api.clone();
        let bearer = token.clone();
        let mut recording = tokio::spawn(async move { succeeded(exec_job(&runner, &bearer, "record-cdp proof").await) });
        let mut polls = 0;
        let mut sampled = Vec::new();
        let result = loop {
            tokio::select! {
                biased;
                result = &mut recording => break result.unwrap(),
                _ = tokio::time::sleep(Duration::from_millis(200)) => {
                    let files = list_artifacts(&api, &token).await;
                    sampled.extend(entries(&files));
                    polls += 1;
                }
            }
        };
        assert!(polls > 1, "artifact listing must be sampled during capture and encode");
        println!("encode stdout: {}", result["stdout"]);
        assert_capture_seconds(&result);
        assert!(result["stdout"].as_str().unwrap().contains("published /artifacts/proof.mp4"));
        let files = list_artifacts(&api, &token).await;
        assert!(samples_match_final(&sampled, &files), "observed partial or unpublished proof entry: {sampled:?}; final: {files:?}");
        let movie = files.iter().find(|f| f["path"] == "proof.mp4").unwrap();
        let png = files.iter().find(|f| f["path"] == "proof.png").unwrap();
        let movie_bytes = read_artifact(&api, &token, movie).await;
        let png_bytes = read_artifact(&api, &token, png).await;
        let dir = tempfile::tempdir().unwrap();
        let mp4_path = dir.path().join("proof.mp4");
        let png_path = dir.path().join("proof.png");
        tokio::fs::write(&mp4_path, &movie_bytes).await.unwrap();
        tokio::fs::write(&png_path, &png_bytes).await.unwrap();
        let probe = Command::new("ffprobe").args(["-v", "error", "-show_entries", "stream=codec_name,width,height:format=duration,size", "-of", "json"]).arg(&mp4_path).output().await.unwrap();
        assert!(probe.status.success());
        let measured: Value = serde_json::from_slice(&probe.stdout).unwrap();
        println!("MP4 actual bytes={} sha256={} ffprobe={measured}", movie_bytes.len(), movie["sha256"]);
        assert_eq!(measured["streams"][0]["codec_name"], "h264");
        assert_eq!(measured["streams"][0]["width"], 1280);
        assert_eq!(measured["streams"][0]["height"], 720);
        assert!((measured["format"]["duration"].as_str().unwrap().parse::<f64>().unwrap() - 30.0).abs() < 0.1);
        assert_eq!(measured["format"]["size"].as_str().unwrap().parse::<usize>().unwrap(), movie_bytes.len());
        assert!(movie_bytes.len() <= 8 * 1024 * 1024, "MP4 must fit the attachment limit");
        let first = decoded_rgb(&mp4_path).await;
        let preview = decoded_rgb(&png_path).await;
        assert_eq!(first.len(), 1280 * 720 * 3);
        assert_eq!(first.len(), preview.len());
        let error: u64 = first.iter().zip(&preview).map(|(a, b)| u64::from(a.abs_diff(*b))).sum();
        println!("first-frame RGB absolute error sum={error}, pixels={}", first.len());
        assert!(error / (first.len() as u64) < 12, "PNG must match the first video frame despite lossy H.264");
        let prior_hash = movie["sha256"].clone();
        let duplicate = exec_job(&api, &token, "record-cdp proof").await;
        assert_capture_seconds(&duplicate);
        assert_eq!(duplicate["outcome"], "executed");
        assert_ne!(duplicate["exitCode"], 0, "existing artifact must not be overwritten");
        assert!(duplicate["stderr"].as_str().unwrap().contains("FileExistsError"), "the existing name, not capture, must cause refusal: {duplicate}");
        let after = list_artifacts(&api, &token).await;
        assert_eq!(after.iter().find(|f| f["path"] == "proof.mp4").unwrap()["sha256"], prior_hash);
        assert_eq!(read_artifact(&api, &token, after.iter().find(|f| f["path"] == "proof.mp4").unwrap()).await, movie_bytes);
        }
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
    succeeded(exec_raw(api, token, script).await)
}
fn succeeded(result: Value) -> Value {
    assert_eq!(result["outcome"], "executed", "{result}");
    assert_eq!(result["exitCode"], 0, "{result}");
    result
}
fn entries(files: &[Value]) -> Vec<(String, u64, String)> {
    files
        .iter()
        .map(|file| {
            (
                file["path"].as_str().unwrap().to_owned(),
                file["bytes"].as_u64().unwrap(),
                file["sha256"].as_str().unwrap().to_owned(),
            )
        })
        .collect()
}
fn samples_match_final(samples: &[(String, u64, String)], final_files: &[Value]) -> bool {
    let final_entries = entries(final_files);
    samples.iter().all(|sample| final_entries.contains(sample))
}
#[test]
fn sampled_listing_rejects_partial_or_hidden_entries() {
    let final_files = [json!({"path":"proof.mp4","bytes":10,"sha256":"final"})];
    assert!(samples_match_final(
        &[("proof.mp4".into(), 10, "final".into())],
        &final_files
    ));
    assert!(!samples_match_final(
        &[("proof.mp4".into(), 5, "partial".into())],
        &final_files
    ));
    assert!(!samples_match_final(
        &[(".proof.tmp".into(), 5, "partial".into())],
        &final_files
    ));
}
fn valid_frame_cadence(frames: &[u64]) -> bool {
    frames.len() == 30
        && frames[0] >= 1000
        && frames[29] >= 29_000
        && frames
            .windows(2)
            .all(|pair| pair[1].checked_sub(pair[0]).is_some_and(|gap| gap >= 500))
}
#[test]
fn frame_cadence_rejects_bursts_and_missing_span() {
    let good: Vec<u64> = (1..=30).map(|n| n * 1000).collect();
    assert!(valid_frame_cadence(&good));
    let burst: Vec<u64> = (0..30).map(|n| 30_000 + n * 10).collect();
    assert!(!valid_frame_cadence(&burst));
    assert!(!valid_frame_cadence(&good[..29]));
    let too_short: Vec<u64> = (1..=30).map(|n| n * 500).collect();
    assert!(!valid_frame_cadence(&too_short));
}
fn assert_capture_seconds(result: &Value) {
    let frames: Vec<u64> = result["stdout"]
        .as_str()
        .unwrap()
        .lines()
        .find_map(|line| line.strip_prefix("CDP_FRAME_ELAPSED_MS="))
        .expect("record-cdp must report accepted frame timestamps")
        .split(',')
        .map(|ms| ms.parse().unwrap())
        .collect();
    assert!(
        valid_frame_cadence(&frames),
        "30 spaced frames must span capture: {frames:?}"
    );
    let elapsed: u64 = result["stdout"]
        .as_str()
        .unwrap()
        .lines()
        .find_map(|line| line.strip_prefix("CDP_CAPTURE_ELAPSED_MS="))
        .expect("record-cdp must report wall-clock capture time")
        .parse()
        .unwrap();
    assert!(
        elapsed >= 30_000,
        "30 frames must span at least 30 seconds: {elapsed}ms"
    );
}
async fn submit(api: &reqwest::Client, token: &str, script: &str) -> reqwest::Response {
    api.post("http://127.0.0.1:8080/exec")
        .bearer_auth(token)
        .json(&json!({"argv":["/bin/sh","-c",script],"deadlineMs":25000}))
        .send()
        .await
        .unwrap()
}
async fn exec_raw(api: &reqwest::Client, token: &str, script: &str) -> Value {
    let response = submit(api, token, script).await;
    assert_eq!(response.status(), 200);
    response.json().await.unwrap()
}
async fn exec_job(api: &reqwest::Client, token: &str, script: &str) -> Value {
    let response = submit(api, token, script).await;
    let status = response.status();
    let pending: Value = response.json().await.unwrap();
    assert_eq!(
        status, 202,
        "a 30-second recording must outlive the 25-second response deadline: {pending}"
    );
    assert_eq!(pending["outcome"], "unknown", "{pending}");
    let job = format!(
        "http://127.0.0.1:8080/jobs/{}",
        pending["jobId"].as_str().unwrap()
    );
    tokio::time::timeout(Duration::from_secs(120), async {
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let response = api.get(&job).bearer_auth(token).send().await.unwrap();
            assert_eq!(response.status(), 200, "job outcome must be known");
            let view: Value = response.json().await.unwrap();
            if view["state"] != "running" {
                println!("{script}: job {job} finished: {}", view["outcome"]);
                return view;
            }
        }
    })
    .await
    .expect("job did not finish within 120 s of its 202")
}
async fn stderr_probe_on_failure(api: &reqwest::Client, token: &str, url: &str) {
    let script = format!(
        "browse reset; printf '#!/bin/sh\\nexec /usr/local/bin/chromium \"$@\" 2>>/tmp/chromium.stderr\\n' > /tmp/chromium-logged; chmod +x /tmp/chromium-logged; BROWSE_CHROMIUM=/tmp/chromium-logged timeout 8 browse open '{url}'; echo '== chromium stderr'; tail -c 8000 /tmp/chromium.stderr"
    );
    let attempt = tokio::time::timeout(
        Duration::from_secs(20),
        api.post("http://127.0.0.1:8080/exec")
            .bearer_auth(token)
            .json(&json!({"argv":["/bin/sh","-c",script],"deadlineMs":25000}))
            .send(),
    )
    .await;
    match attempt {
        Ok(Ok(response)) => {
            let status = response.status();
            let body: Value = response.json().await.unwrap_or_default();
            println!("failure-only Chromium stderr probe (HTTP {status}): {body}");
        }
        Ok(Err(error)) => println!("failure-only Chromium stderr probe transport error: {error}"),
        Err(_) => println!("failure-only Chromium stderr probe timed out after 20 s"),
    }
}
const BROWSER_DIAGNOSTIC: &str = r#"
echo '== memory'
grep -E '^(MemTotal|MemFree|MemAvailable|Cached|Shmem|AnonPages|CommitLimit|Committed_AS):' /proc/meminfo
echo "overcommit_memory=$(cat /proc/sys/vm/overcommit_memory) overcommit_ratio=$(cat /proc/sys/vm/overcommit_ratio)"
grep -E '^Max (address space|data size)' /proc/self/limits
grep -E '^(oom_kill|pgmajfault) ' /proc/vmstat
df -k /tmp /dev/shm
echo '== targets'
curl -s --max-time 3 http://127.0.0.1:9222/json/list
echo
echo '== connectOverCDP with DEBUG=pw:protocol'
DEBUG=pw:protocol timeout 12 node -e 'require("/opt/playwright/node_modules/playwright").chromium.connectOverCDP("http://127.0.0.1:9222",{timeout:8000}).then(b=>{console.log("CDP_DIAG connected pages="+b.contexts()[0].pages().length);process.exit(0)},e=>{console.log("CDP_DIAG "+e.message);process.exit(1)})' 2>&1 | tail -c 8000
echo '== processes: pid state ppid rss_kB cpu_s cmd type'
for d in /proc/[0-9]*; do
  s=$(sed 's/^.*) //' "$d/stat" 2>/dev/null) || continue
  c=$(tr '\0' ' ' < "$d/cmdline" 2>/dev/null | cut -c1-48)
  t=$(tr '\0' '\n' < "$d/cmdline" 2>/dev/null | grep -m1 -- '^--type=')
  echo "${d#/proc/} $(echo "$s" | awk '{print $1, $2, $22*4, ($12+$13)/100}') $c $t"
done
echo '== chrome threads: comm:state, then tid:wchan'
for d in /proc/[0-9]*; do
  grep -qa chrome "$d/cmdline" 2>/dev/null || continue
  echo "pid ${d#/proc/}: $(awk '{sub(/^[^(]*\(/, ""); n = index($0, ") "); printf " %s:%s", substr($0, 1, n - 1), substr($0, n + 2, 1)}' "$d"/task/*/stat | cut -c1-1500)"
  echo "  $(grep -H . "$d"/task/*/wchan 2>/dev/null | sed 's|.*/task/||; s|/wchan:|:|' | tr '\n' ' ' | cut -c1-1500)"
done
"#;
async fn browser_diagnostic(api: &reqwest::Client, token: &str) {
    let response = submit(api, token, BROWSER_DIAGNOSTIC).await;
    let status = response.status();
    let mut view: Value = response.json().await.unwrap_or_default();
    if status == 202 {
        let job = format!(
            "http://127.0.0.1:8080/jobs/{}",
            view["jobId"].as_str().unwrap_or_default()
        );
        for _ in 0..60 {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let Ok(response) = api.get(&job).bearer_auth(token).send().await else {
                break;
            };
            view = response.json().await.unwrap_or_default();
            if view["state"] != "running" {
                break;
            }
        }
    }
    println!(
        "browser diagnostic (HTTP {status}, outcome {}):\n{}\n== diagnostic stderr\n{}",
        view["outcome"],
        view["stdout"].as_str().unwrap_or_default(),
        view["stderr"].as_str().unwrap_or_default()
    );
    let console = tokio::fs::read_to_string("/run/vm-runner/console/serial.log")
        .await
        .unwrap_or_default();
    let flagged: Vec<&str> = console
        .lines()
        .filter(|line| {
            let line = line.to_ascii_lowercase();
            [
                "oom",
                "out of memory",
                "killed process",
                "segfault",
                "traps:",
                "blocked for more than",
            ]
            .iter()
            .any(|needle| line.contains(needle))
        })
        .collect();
    println!(
        "guest console flagged lines ({}):\n{}",
        flagged.len(),
        flagged[flagged.len().saturating_sub(80)..].join("\n")
    );
    let lines: Vec<&str> = console.lines().collect();
    println!(
        "guest console tail:\n{}",
        lines[lines.len().saturating_sub(30)..].join("\n")
    );
}
async fn list_artifacts(api: &reqwest::Client, token: &str) -> Vec<Value> {
    api.get("http://127.0.0.1:8080/artifacts")
        .bearer_auth(token)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap()
}
async fn read_artifact(api: &reqwest::Client, token: &str, listed: &Value) -> Vec<u8> {
    let path = listed["path"].as_str().unwrap();
    let response = api
        .get(format!("http://127.0.0.1:8080/artifacts/{path}"))
        .bearer_auth(token)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    assert_eq!(
        response.headers()["sha256"],
        listed["sha256"].as_str().unwrap()
    );
    let bytes = response.bytes().await.unwrap().to_vec();
    assert_eq!(bytes.len() as u64, listed["bytes"].as_u64().unwrap());
    let hash = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &bytes);
    let hex = hash
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    assert_eq!(hex, listed["sha256"]);
    println!("artifact {path} bytes={} sha256={hex}", bytes.len());
    bytes
}
async fn decoded_rgb(path: &std::path::Path) -> Vec<u8> {
    let output = Command::new("ffmpeg")
        .args(["-v", "error", "-i"])
        .arg(path)
        .args(["-frames:v", "1", "-f", "rawvideo", "-pix_fmt", "rgb24", "-"])
        .output()
        .await
        .unwrap();
    assert!(
        output.status.success(),
        "ffmpeg: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}
async fn dropped() -> u64 {
    let output = Command::new("nft")
        .args(["-j", "list", "counters", "table", "inet", "vm_runner"])
        .output()
        .await
        .unwrap();
    assert!(output.status.success());
    let counters: Value = serde_json::from_slice(&output.stdout).unwrap();
    counters["nftables"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["counter"]["name"] == "input_drop")
        .and_then(|entry| entry["counter"]["packets"].as_u64())
        .unwrap()
}
struct Arrival {
    path: String,
    subjects: Vec<String>,
    model: String,
    authorization: Option<String>,
    admitted: bool,
}
struct ModelUpstream {
    port: u16,
    requests: tokio::sync::Mutex<tokio::sync::mpsc::Receiver<Arrival>>,
    upstream: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}
impl ModelUpstream {
    fn upstream_calls(&self) -> usize {
        self.upstream.load(std::sync::atomic::Ordering::SeqCst)
    }
}
const GUESTS: &[(&str, &[(&str, &str)])] = &[(
    "test:kvm-vm",
    &[("sol", "/v1/responses"), ("claude-opus", "/v1/messages")],
)];
/// dekopon-gatewayd's side of the contract: TLS that requires a client certificate from the test CA,
/// which the jail reads from `/models-tls` like the controller-mounted Secret, then the model
/// proxy's grant check on the jail-asserted subject before anything reaches a model upstream.
async fn model_upstream() -> (
    impl std::future::Future<Output = ()> + Send + 'static,
    ModelUpstream,
) {
    use tokio_rustls::rustls::{
        self, RootCertStore, ServerConfig,
        pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
    };
    let mut ca = rcgen::CertificateParams::default();
    ca.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let ca_pem = ca.self_signed(&ca_key).unwrap().pem();
    let issuer = rcgen::Issuer::new(ca, ca_key);
    let leaf = |name: &str, usage| {
        let mut params = rcgen::CertificateParams::new(vec![name.to_owned()]).unwrap();
        params.extended_key_usages = vec![usage];
        let key = rcgen::KeyPair::generate().unwrap();
        (
            params.signed_by(&key, &issuer).unwrap().pem(),
            key.serialize_pem(),
        )
    };
    let (client_cert, client_key) =
        leaf("vm-runner-jail", rcgen::ExtendedKeyUsagePurpose::ClientAuth);
    tokio::fs::create_dir_all("/models-tls").await.unwrap();
    for (name, contents) in [
        ("tls.crt", &client_cert),
        ("tls.key", &client_key),
        ("ca.crt", &ca_pem),
    ] {
        let path = std::path::Path::new("/models-tls").join(name);
        tokio::fs::write(&path, contents).await.unwrap();
        tokio::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o400))
            .await
            .unwrap();
    }
    let (server_cert, server_key) = leaf("localhost", rcgen::ExtendedKeyUsagePurpose::ServerAuth);
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from_pem_slice(ca_pem.as_bytes()).unwrap())
        .unwrap();
    let provider = std::sync::Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        std::sync::Arc::new(roots),
        std::sync::Arc::clone(&provider),
    )
    .build()
    .unwrap();
    let config = std::sync::Arc::new(
        ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_client_cert_verifier(verifier)
            .with_single_cert(
                vec![CertificateDer::from_pem_slice(server_cert.as_bytes()).unwrap()],
                PrivateKeyDer::from_pem_slice(server_key.as_bytes()).unwrap(),
            )
            .unwrap(),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (sender, requests) = tokio::sync::mpsc::channel(4);
    let upstream = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let calls = std::sync::Arc::clone(&upstream);
    let serve = async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let Ok(tls) = tokio_rustls::TlsAcceptor::from(std::sync::Arc::clone(&config))
                .accept(stream)
                .await
            else {
                continue;
            };
            let sender = sender.clone();
            let calls = std::sync::Arc::clone(&calls);
            let service = hyper::service::service_fn(
                move |req: hyper::Request<hyper::body::Incoming>| {
                    let subjects: Vec<String> = req
                        .headers()
                        .get_all("x-dekopon-vm-subject")
                        .iter()
                        .map(|v| v.to_str().unwrap().to_owned())
                        .collect();
                    let path = req.uri().to_string();
                    let authorization = req
                        .headers()
                        .get("authorization")
                        .map(|v| v.to_str().unwrap().to_owned());
                    let sender = sender.clone();
                    let calls = std::sync::Arc::clone(&calls);
                    async move {
                        let body = http_body_util::BodyExt::collect(req.into_body())
                            .await
                            .unwrap()
                            .to_bytes();
                        let model = serde_json::from_slice::<Value>(&body)
                            .ok()
                            .and_then(|body| body["model"].as_str().map(str::to_owned))
                            .unwrap_or_default();
                        let admitted = GUESTS.iter().any(|(subject, grant)| {
                            subjects == [*subject]
                                && grant.contains(&(model.as_str(), path.as_str()))
                        });
                        sender
                            .send(Arrival {
                                path: path.clone(),
                                subjects,
                                model,
                                authorization,
                                admitted,
                            })
                            .await
                            .unwrap();
                        let response = if !admitted {
                            hyper::Response::builder()
                                .status(403)
                                .header("content-type", "application/json")
                                .body(http_body_util::Full::new(hyper::body::Bytes::from_static(
                                    br#"{"error":{"message":"sandbox: this agent may only call its configured models.","type":"invalid_request_error","param":null,"code":"permission_denied"}}"#,
                                )))
                                .unwrap()
                        } else if path == "/v1/responses" {
                            calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            let body = include_bytes!("../images/guest/pi/response.sse");
                            hyper::Response::builder()
                                .header("content-type", "text/event-stream")
                                .body(http_body_util::Full::new(hyper::body::Bytes::from_static(
                                    body,
                                )))
                                .unwrap()
                        } else {
                            calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            hyper::Response::new(http_body_util::Full::new(
                                hyper::body::Bytes::from_static(b"model"),
                            ))
                        };
                        Ok::<_, std::convert::Infallible>(response)
                    }
                },
            );
            let _closed = hyper::server::conn::http1::Builder::new()
                .keep_alive(false)
                .serve_connection(hyper_util::rt::TokioIo::new(tls), service)
                .await;
        }
    };
    (
        serve,
        ModelUpstream {
            port,
            requests: tokio::sync::Mutex::new(requests),
            upstream,
        },
    )
}
