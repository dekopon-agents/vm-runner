#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::disallowed_methods)]

use http_body_util::{BodyExt, Empty};
use hyper::{
    Request, Response,
    body::{Bytes, Incoming},
    service::service_fn,
};
use hyper_util::rt::TokioIo;
use std::{
    convert::Infallible,
    io::BufRead,
    process::{Child, Command, Stdio},
    sync::Arc,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{Semaphore, oneshot},
};

struct Daemon(Child);
impl Drop for Daemon {
    fn drop(&mut self) {
        // Also reap on assertion failure or the test's deadlock watchdog.
        if self.0.try_wait().unwrap().is_none() {
            self.0.kill().unwrap();
        }
        self.0.wait().unwrap();
    }
}

#[tokio::test]
async fn sigterm_and_sigint_drain_both_roles_before_telemetry_shutdown() {
    // A watchdog only: all ordering below comes from socket and channel acknowledgements.
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        for role in ["egress", "serve"] {
            for signal in ["-TERM", "-INT"] {
                let collector = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let endpoint = collector.local_addr().unwrap();
                let port = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let address = port.local_addr().unwrap();
                drop(port);
                let dir = tempfile::tempdir().unwrap();
                let config = dir.path().join("config.yaml");
                std::fs::write(&config, format!(r#"
listen: {address}
auth: {{issuers: [], subjects: []}}
shapes:
  small: {{vcpus: 1, memoryMiB: 128, diskMiB: 128}}
profiles:
  test:
    shape: small
    image: test@sha256:abc
    browser: headless
    idleSeconds: 60
    maxSeconds: 120
    egress: {{allow: [localhost], dns: runner}}
quotas: {{default: {{maxSessions: 1}}, subjects: {{}}}}
telemetry:
  otlp: {{protocol: http, endpoint: 'http://{endpoint}/v1/traces'}}
"#)).unwrap();
                let mut command = Command::new(env!("CARGO_BIN_EXE_vm-runnerd"));
                command.args([role, "--config"]).arg(&config)
                    .env("OTEL_RESOURCE_ATTRIBUTES", "vm_runner.session_id=01995000-0000-7000-8000-000000000001,vm_runner.subject=system:serviceaccount:test:runner")
                    .stdout(Stdio::piped()).stderr(Stdio::inherit());
                if role == "egress" {
                    command.args(["--profile", "test", "--listen", &address.to_string(), "--ca-out"])
                        .arg(dir.path().join("ca"));
                }
                let mut daemon = Daemon(command.spawn().unwrap());
                let stdout = daemon.0.stdout.take().unwrap();
                let (signalled, acknowledgement) = oneshot::channel();
                let (listening, ready) = oneshot::channel();
                let logs = std::thread::spawn(move || {
                    let mut signalled = Some(signalled);
                    let mut listening = Some(listening);
                    for line in std::io::BufReader::new(stdout).lines() {
                        let line = line.unwrap();
                        if line.contains("\"message\":\"listening\"") {
                            listening.take().unwrap().send(()).unwrap();
                        }
                        if line.contains("shutdown signal received; draining requests") {
                            signalled.take().unwrap().send(()).unwrap();
                        }
                    }
                });
                ready.await.unwrap();
                let mut stream = TcpStream::connect(address).await.unwrap();
                let request = if role == "egress" {
                    "GET http://denied.invalid/ HTTP/1.1\r\nHost: denied.invalid\r\nConnection: close\r\n\r\n"
                } else {
                    "GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
                };
                stream.write_all(request.as_bytes()).await.unwrap();
                let (received, exported) = oneshot::channel();
                let release = Arc::new(Semaphore::new(0));
                let held = Arc::clone(&release);
                let receiver = tokio::spawn(async move {
                    let (socket, _) = collector.accept().await.unwrap();
                    let received = std::sync::Mutex::new(Some(received));
                    hyper::server::conn::http1::Builder::new().keep_alive(false)
                        .serve_connection(TokioIo::new(socket), service_fn(|req: Request<Incoming>| {
                            let received = received.lock().unwrap().take().unwrap();
                            let held = Arc::clone(&held);
                            async move {
                                assert_eq!(req.uri().path(), "/v1/traces");
                                let body = req.into_body().collect().await.unwrap().to_bytes();
                                received.send(body).unwrap();
                                let _permit = held.acquire().await.unwrap();
                                Ok::<_, Infallible>(Response::new(Empty::<Bytes>::new()))
                            }
                        })).await.unwrap();
                });
                let body = exported.await.unwrap();
                let name = if role == "egress" { "egress.request" } else { "vm_runner.request" };
                assert!(body.windows(name.len()).any(|bytes| bytes == name.as_bytes()));
                assert!(Command::new("kill").args([signal, &daemon.0.id().to_string()]).status().unwrap().success());
                acknowledgement.await.unwrap();
                assert!(daemon.0.try_wait().unwrap().is_none(), "must drain the blocked span export");
                release.add_permits(1);
                receiver.await.unwrap();
                let mut response = String::new();
                stream.read_to_string(&mut response).await.unwrap();
                assert!(response.starts_with(if role == "egress" { "HTTP/1.1 403 " } else { "HTTP/1.1 200 " }), "{response}");
                let status = tokio::task::spawn_blocking(move || daemon.0.wait().unwrap()).await.unwrap();
                assert!(status.success(), "{role} did not drain and shut telemetry down: {status}");
                logs.join().unwrap();
            }
        }
    }).await.unwrap();
}
