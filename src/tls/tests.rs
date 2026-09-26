use super::*;
use crate::tests::{Fixture, span_attribute, trace_exporter};
use futures_util::FutureExt;
use poem::listener::Acceptor;
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
use std::{net::SocketAddr, sync::Arc};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::{TlsConnector, rustls};

struct Authority {
    issuer: Issuer<'static, KeyPair>,
    root: CertificateDer<'static>,
}
impl Authority {
    fn new() -> Self {
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let key = KeyPair::generate().unwrap();
        let root = params.self_signed(&key).unwrap().der().clone();
        Self {
            issuer: Issuer::new(params, key),
            root,
        }
    }
    fn pair(&self) -> Pair {
        let key = KeyPair::generate().unwrap();
        let cert = CertificateParams::new(vec!["localhost".into()])
            .unwrap()
            .signed_by(&key, &self.issuer)
            .unwrap();
        Pair {
            cert: cert.pem().into_bytes(),
            key: key.serialize_pem().into_bytes(),
        }
    }
    fn connector(&self, version: &'static rustls::SupportedProtocolVersion) -> TlsConnector {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(self.root.clone()).unwrap();
        let config =
            rustls::ClientConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
                .with_protocol_versions(&[version])
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth();
        TlsConnector::from(Arc::new(config))
    }
}
async fn write_pair(dir: &std::path::Path, pair: &Pair) -> Files {
    tokio::fs::create_dir_all(dir).await.unwrap();
    let files = Files {
        cert_file: dir.join("tls.crt"),
        key_file: dir.join("tls.key"),
    };
    tokio::fs::write(&files.cert_file, &pair.cert)
        .await
        .unwrap();
    tokio::fs::write(&files.key_file, &pair.key).await.unwrap();
    files
}
async fn health(address: SocketAddr, connector: &TlsConnector, pair: &Pair) {
    health_stream(
        tokio::net::TcpStream::connect(address).await.unwrap(),
        connector,
        pair,
    )
    .await;
}
async fn health_stream(tcp: tokio::net::TcpStream, connector: &TlsConnector, pair: &Pair) {
    let mut stream = connector
        .connect("localhost".try_into().unwrap(), tcp)
        .await
        .unwrap();
    assert_eq!(
        stream.get_ref().1.peer_certificates().unwrap()[0],
        CertificateDer::from_pem_slice(&pair.cert).unwrap()
    );
    stream
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).await.unwrap();
    assert!(response.starts_with("HTTP/1.1 200"));
    assert!(response.ends_with("ok"));
}

#[tokio::test]
async fn controller_tls_trusts_test_ca_serves_health_and_refuses_plaintext() {
    let ca = Authority::new();
    let pair = ca.pair();
    let dir = tempfile::tempdir().unwrap();
    let mut fixture = Fixture::new().await;
    fixture.config.listen = "127.0.0.1:0".parse().unwrap();
    fixture.config.tls = Some(write_pair(dir.path(), &pair).await);
    let acceptor = fixture
        .config
        .controller_listener()
        .await
        .unwrap()
        .into_acceptor()
        .await
        .unwrap();
    let address = *acceptor.local_addr()[0].as_socket_addr().unwrap();
    let queued = tokio::net::TcpStream::connect(address).await.unwrap();
    let (endpoint, requests) = crate::app(fixture.config).await.unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(
        poem::Server::new_with_acceptor(acceptor).run_with_graceful_shutdown(
            endpoint,
            async {
                stopped.await.unwrap();
            },
            None,
        ),
    );
    health_stream(queued, &ca.connector(&rustls::version::TLS12), &pair).await;
    health(address, &ca.connector(&rustls::version::TLS13), &pair).await;
    let response = reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap()
        .get(format!("http://{address}/healthz"))
        .send()
        .await;
    assert!(response.unwrap_err().is_request());
    stop.send(()).unwrap();
    server.await.unwrap().unwrap();
    requests.drain().await.unwrap();
    fixture.tasks.shutdown().await;
}

#[tokio::test]
async fn cert_manager_symlink_rotation_updates_new_handshakes() {
    let ca = Authority::new();
    let first = ca.pair();
    let second = ca.pair();
    let dir = tempfile::tempdir().unwrap();
    write_pair(&dir.path().join("one"), &first).await;
    write_pair(&dir.path().join("two"), &second).await;
    let current = dir.path().join("current");
    tokio::fs::symlink("one", &current).await.unwrap();
    let files = Files {
        cert_file: current.join("tls.crt"),
        key_file: current.join("tls.key"),
    };
    let pair = files.read().await.unwrap();
    let initial = pair.config().unwrap();
    let (published, mut updates) = tokio::sync::mpsc::channel(4);
    let stream = files
        .updates(pair, initial)
        .inspect(move |_| published.try_send(()).unwrap());
    let acceptor = ready_listener(TcpListener::bind("127.0.0.1:0".parse().unwrap()), stream)
        .into_acceptor()
        .await
        .unwrap();
    let address = *acceptor.local_addr()[0].as_socket_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(
        poem::Server::new_with_acceptor(acceptor).run_with_graceful_shutdown(
            poem_openapi::OpenApiService::new(crate::Health(None), "tls", "test"),
            async {
                stopped.await.unwrap();
            },
            None,
        ),
    );
    updates.recv().await.unwrap();
    let connector = ca.connector(&rustls::version::TLS13);
    health(address, &connector, &first).await;
    tokio::fs::symlink("two", dir.path().join("next"))
        .await
        .unwrap();
    tokio::fs::rename(dir.path().join("next"), current)
        .await
        .unwrap();
    tokio::time::pause();
    tokio::time::advance(POLL).await;
    tokio::time::resume();
    updates.recv().await.unwrap();
    health(address, &connector, &second).await;
    stop.send(()).unwrap();
    server.await.unwrap().unwrap();
}

#[tokio::test]
async fn startup_gate_holds_queued_tcp_until_initial_config_is_consumed() {
    let (ready, waiting) = tokio::sync::oneshot::channel();
    let mut acceptor = Gated {
        inner: TcpListener::bind("127.0.0.1:0"),
        ready: Some(waiting),
    }
    .into_acceptor()
    .await
    .unwrap();
    let address = *acceptor.local_addr()[0].as_socket_addr().unwrap();
    let queued = tokio::net::TcpStream::connect(address).await.unwrap();
    assert!(acceptor.accept().now_or_never().is_none());
    ready.send(()).unwrap();
    let (_, _, peer, _) = acceptor.accept().await.unwrap();
    assert_eq!(peer.as_socket_addr(), Some(&queued.local_addr().unwrap()));
}

#[tokio::test]
async fn invalid_startup_pair_is_a_configuration_conflict() {
    let ca = Authority::new();
    let mut pair = ca.pair();
    pair.key = ca.pair().key;
    let dir = tempfile::tempdir().unwrap();
    let mut config: Config =
        serde_yaml_ng::from_str(include_str!("../../examples/vm-runner.yaml")).unwrap();
    config.tls = Some(write_pair(dir.path(), &pair).await);
    assert!(matches!(
        config.controller_listener().await,
        Err(Conflict::Tls(Error::Pair))
    ));
    tokio::fs::write(&config.tls.as_ref().unwrap().key_file, b"not a private key")
        .await
        .unwrap();
    assert!(matches!(
        config.controller_listener().await,
        Err(Conflict::Tls(Error::KeyPem))
    ));
}

#[tokio::test]
async fn failed_reload_retains_pair_spans_cause_and_recovers_after_key_rotation() {
    let exporter = trace_exporter();
    let ca = Authority::new();
    let first = ca.pair();
    let second = ca.pair();
    let dir = tempfile::tempdir().unwrap();
    let files = write_pair(dir.path(), &first).await;
    let mut reload = Reload {
        files,
        pair: first,
        refreshed: Instant::now(),
    };
    tokio::fs::write(&reload.files.cert_file, &second.cert)
        .await
        .unwrap();
    assert!(reload.poll().await.is_none());
    assert_ne!(reload.pair.cert, second.cert);
    assert!(reload.pair.config().is_ok());
    let spans = exporter.get_finished_spans().unwrap();
    let span = spans
        .iter()
        .find(|span| span.name == "vm_runner.tls.reload")
        .unwrap();
    assert_eq!(
        span_attribute(span, "error"),
        Some(&"invalid TLS certificate/key pair".into())
    );
    tokio::fs::write(&reload.files.key_file, &second.key)
        .await
        .unwrap();
    assert!(reload.poll().await.is_some());
    assert!(reload.pair == second);
}

#[tokio::test]
async fn unchanged_files_are_revalidated_every_ten_minutes() {
    let pair = Authority::new().pair();
    let dir = tempfile::tempdir().unwrap();
    let files = write_pair(dir.path(), &pair).await;
    let mut reload = Reload {
        files,
        pair,
        refreshed: Instant::now(),
    };
    assert!(reload.poll().await.is_none());
    tokio::time::pause();
    tokio::time::advance(REFRESH).await;
    assert!(reload.poll().await.is_some());
    assert!(reload.poll().await.is_none());
}

#[tokio::test]
async fn absent_tls_keeps_controller_http() {
    let mut fixture = Fixture::new().await;
    fixture.config.listen = "127.0.0.1:0".parse().unwrap();
    assert!(fixture.config.tls.is_none());
    let acceptor = fixture
        .config
        .controller_listener()
        .await
        .unwrap()
        .into_acceptor()
        .await
        .unwrap();
    let address = *acceptor.local_addr()[0].as_socket_addr().unwrap();
    let (endpoint, requests) = crate::app(fixture.config).await.unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(
        poem::Server::new_with_acceptor(acceptor).run_with_graceful_shutdown(
            endpoint,
            async {
                stopped.await.unwrap();
            },
            None,
        ),
    );
    let response = reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap()
        .get(format!("http://{address}/healthz"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(response.text().await.unwrap(), "ok");
    stop.send(()).unwrap();
    server.await.unwrap().unwrap();
    requests.drain().await.unwrap();
    fixture.tasks.shutdown().await;
}
