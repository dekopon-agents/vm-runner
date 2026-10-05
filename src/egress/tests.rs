use super::*;
#[path = "gateway_tests.rs"]
mod gateway_tests;
use crate::tests::span_attribute;
use opentelemetry::{KeyValue, trace::TracerProvider};
use opentelemetry_sdk::{
    logs::{InMemoryLogExporter, SdkLoggerProvider, in_memory_exporter::LogDataWithResource},
    trace::{InMemorySpanExporter, SdkTracerProvider, SpanData},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use tokio_rustls::{
    TlsAcceptor,
    rustls::pki_types::{CertificateDer, pem::PemObject},
};
use tracing::instrument::WithSubscriber;
use tracing_subscriber::layer::SubscriberExt;

struct Proxy {
    addr: SocketAddr,
    tls: Arc<ClientConfig>,
    exporter: InMemorySpanExporter,
    logs: Arc<std::fs::File>,
    provider: SdkTracerProvider,
    log_exporter: InMemoryLogExporter,
    log_provider: SdkLoggerProvider,
    stop: tokio::sync::oneshot::Sender<()>,
    task: tokio::task::JoinHandle<Result<(), Error>>,
}
fn local_egress() -> Egress {
    serde_yaml_ng::from_str(
        "allow: [localhost]\ndns: runner\nallowPrivate: [127.0.0.0/8, '::1/128']",
    )
    .unwrap()
}
impl Proxy {
    async fn new(roots: RootCertStore) -> Self {
        Self::configured(roots, local_egress()).await
    }
    async fn configured(roots: RootCertStore, egress: Egress) -> Self {
        Self::configured_with_omit(roots, egress, Default::default()).await
    }
    async fn drip(roots: RootCertStore) -> Self {
        let exporter = InMemorySpanExporter::default();
        Self::with_listeners(
            roots,
            local_egress(),
            exporter.clone(),
            exporter,
            None,
            Default::default(),
            Some("info,egress.exchange=info,egress.connect=info,egress.dns=info,egress.drop=info"),
        )
        .await
    }
    async fn configured_with_omit(
        roots: RootCertStore,
        egress: Egress,
        omit: crate::config::Omit,
    ) -> Self {
        let exporter = InMemorySpanExporter::default();
        Self::with_listeners(roots, egress, exporter.clone(), exporter, None, omit, None).await
    }
    async fn with_listeners(
        roots: RootCertStore,
        egress: Egress,
        exporter: InMemorySpanExporter,
        processor_exporter: impl opentelemetry_sdk::trace::SpanExporter + 'static,
        listeners: Option<gateway::Listeners>,
        omit: crate::config::Omit,
        filter: Option<&str>,
    ) -> Self {
        let (ca, pem) = Ca::new().unwrap();
        let mut trust = RootCertStore::empty();
        trust
            .add(CertificateDer::from_pem_slice(pem.as_bytes()).unwrap())
            .unwrap();
        let listeners = match listeners {
            Some(listeners) => listeners,
            None => TcpListener::bind("127.0.0.1:0").await.unwrap().into(),
        };
        let addr = listeners
            .explicit
            .as_ref()
            .or(listeners.http.as_ref())
            .unwrap()
            .local_addr()
            .unwrap();
        let provider = SdkTracerProvider::builder()
            .with_simple_exporter(processor_exporter)
            .build();
        let logs = Arc::new(tempfile::tempfile().unwrap());
        let log_exporter = InMemoryLogExporter::default();
        let log_provider = SdkLoggerProvider::builder()
            .with_simple_exporter(log_exporter.clone())
            .build();
        let subscriber = tracing_subscriber::registry()
            .with(
                tracing_subscriber::fmt::layer()
                    .json()
                    .with_writer(Arc::clone(&logs))
                    .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE),
            )
            .with(tracing_opentelemetry::layer().with_tracer(provider.tracer("egress-test")))
            .with(
                opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge::new(
                    &log_provider,
                ),
            )
            .with(filter.map(tracing_subscriber::EnvFilter::new));
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let engine = Arc::new(Engine {
            ca,
            egress,
            tls: client_config(roots).unwrap(),
            omit,
            rollups: Arc::new(Mutex::new(Rollups::new())),
        });
        let task = tokio::spawn(
            engine
                .serve(listeners, async {
                    stopped.await.unwrap();
                })
                .with_subscriber(subscriber),
        );
        Self {
            addr,
            tls: client_config(trust).unwrap(),
            exporter,
            logs,
            provider,
            log_exporter,
            log_provider,
            stop,
            task,
        }
    }
    async fn tunnel(&self, port: u16) -> TcpStream {
        let mut stream = TcpStream::connect(self.addr).await.unwrap();
        stream
            .write_all(
                format!("CONNECT localhost:{port} HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n")
                    .as_bytes(),
            )
            .await
            .unwrap();
        let mut response = Vec::new();
        while !response.ends_with(b"\r\n\r\n") {
            response.push(stream.read_u8().await.unwrap());
        }
        assert!(response.starts_with(b"HTTP/1.1 200 "));
        stream
    }
    async fn finish(self) -> Vec<SpanData> {
        self.finish_with_logs().await.0
    }
    async fn finish_with_logs(self) -> (Vec<SpanData>, Vec<LogDataWithResource>) {
        self.stop.send(()).unwrap();
        self.task.await.unwrap().unwrap();
        let spans = self.exporter.get_finished_spans().unwrap();
        for span in &spans {
            for kv in &span.attributes {
                assert!(span_attribute(span, kv.key.as_str()).is_some());
            }
            if span.name == "egress.request" {
                assert_ne!(
                    span_attribute(span, "http.response.status_code"),
                    Some(&0_i64.into())
                );
                for key in ["egress.exchange.outcome", "egress.decision"] {
                    assert!(
                        span_attribute(span, key).is_some(),
                        "missing {key}: {span:?}"
                    );
                }
            }
        }
        let logs = self.log_exporter.get_emitted_logs().unwrap();
        self.provider.shutdown().unwrap();
        self.log_provider.shutdown().unwrap();
        (spans, logs)
    }
}
async fn exchange(mut stream: impl AsyncRead + AsyncWrite + Unpin, request: &str) -> (u16, String) {
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).await.unwrap();
    let (headers, body) = response.split_once("\r\n\r\n").unwrap();
    (
        headers.split_whitespace().nth(1).unwrap().parse().unwrap(),
        body.to_owned(),
    )
}
fn attribute(span: &SpanData, key: &str, value: &str) -> bool {
    span_attribute(span, key) == Some(&opentelemetry::Value::from(value.to_owned()))
}
fn log_int(log: &LogDataWithResource, key: &str) -> Option<i64> {
    log.record.attributes_iter().find_map(|(name, value)| {
        if name.as_str() != key {
            return None;
        }
        match value {
            opentelemetry::logs::AnyValue::Int(n) => Some(*n),
            _ => None,
        }
    })
}
async fn upstream(listener: TcpListener, tls: Option<Arc<ServerConfig>>) -> hyper::HeaderMap {
    let (stream, _) = listener.accept().await.unwrap();
    let stream: Stream = if let Some(config) = tls {
        Box::new(TlsAcceptor::from(config).accept(stream).await.unwrap())
    } else {
        Box::new(stream)
    };
    let headers = Arc::new(Mutex::new(None));
    let received = Arc::clone(&headers);
    hyper::server::conn::http1::Builder::new()
        .keep_alive(false)
        .serve_connection(
            TokioIo::new(stream),
            service_fn(move |req: Request<Incoming>| {
                *received.lock().unwrap() = Some(req.headers().clone());
                async {
                    Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"upstream"))))
                }
            }),
        )
        .await
        .unwrap();
    headers.lock().unwrap().take().unwrap()
}
#[tokio::test]
async fn allowed_https_strips_trace_headers_and_exports_exactly_one_final_status() {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let server = ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![cert.cert.der().clone()],
        PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
    )
    .unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(cert.cert.der().clone()).unwrap();
    let proxy = Proxy::new(roots).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let peer = tokio::spawn(upstream(listener, Some(Arc::new(server))));
    let tunnel = proxy.tunnel(port).await;
    let tls = TlsConnector::from(Arc::clone(&proxy.tls))
        .connect(ServerName::try_from("localhost").unwrap(), tunnel)
        .await
        .unwrap();
    let (status, body) = exchange(tls, &format!("GET /proof HTTP/1.1\r\nHost: localhost:{port}\r\ntraceparent: 00-11111111111111111111111111111111-2222222222222222-01\r\ntracestate: vendor=value\r\nConnection: close\r\n\r\n")).await;
    assert_eq!((status, body.as_str()), (200, "upstream"));
    let received = peer.await.unwrap();
    assert!(!received.contains_key("traceparent"));
    assert!(!received.contains_key("tracestate"));
    let spans = proxy.finish().await;
    let request = spans
        .iter()
        .find(|s| attribute(s, "http.request.method", "GET"))
        .unwrap();
    for (key, value) in [
        ("url.scheme", "https"),
        ("url.path", "/proof"),
        ("server.address", "localhost"),
        ("egress.decision", "allowed"),
    ] {
        assert!(attribute(request, key, value));
    }
    assert_eq!(
        span_attribute(request, "http.response.status_code"),
        Some(&200_i64.into())
    );
    assert_eq!(
        span_attribute(request, "server.port"),
        Some(&i64::from(port).into())
    );
    assert!(attribute(request, "egress.exchange.outcome", "completed"));
    assert_eq!(request.name, "egress.request");
    assert_eq!(
        request.parent_span_id,
        opentelemetry::trace::SpanId::INVALID
    );
    assert_ne!(
        request.span_context.trace_id().to_string(),
        "11111111111111111111111111111111"
    );
    let connects: Vec<_> = spans
        .iter()
        .filter(|s| s.name == "egress.connect")
        .collect();
    assert_eq!(connects.len(), 1);
    assert_eq!(
        span_attribute(connects[0], "server.port"),
        Some(&i64::from(port).into())
    );
    for key in [
        "egress.connect.dns_ms",
        "egress.connect.tcp_ms",
        "egress.connect.tls_ms",
    ] {
        assert!(
            matches!(
                span_attribute(connects[0], key),
                Some(opentelemetry::Value::I64(_))
            ),
            "{key}"
        );
    }
}
#[tokio::test]
async fn disallowed_plain_host_gets_exact_refusal_and_span_without_connecting() {
    let proxy = Proxy::new(RootCertStore::empty()).await;
    let stream = TcpStream::connect(proxy.addr).await.unwrap();
    assert_eq!(exchange(stream, "GET http://denied.invalid/ HTTP/1.1\r\nHost: denied.invalid\r\nConnection: close\r\n\r\n").await, (403, "egress refused: denied.invalid".into()));
    let (spans, logs) = proxy.finish_with_logs().await;
    assert!(
        logs.iter()
            .any(|log| log.record.event_name() == Some("egress.refused"))
    );
    assert!(
        !logs
            .iter()
            .any(|log| log.record.event_name() == Some("egress.exchange.failed"))
    );
    assert!(
        spans
            .iter()
            .any(|s| attribute(s, "egress.decision", "refused:not_allowed"))
    );
    assert!(!spans.iter().any(|s| s.name == "egress.connect"));
}
#[tokio::test]
async fn denied_head_and_get_close_as_one_refusal_each() {
    for (method, body) in [("HEAD", ""), ("GET", "egress refused: denied.invalid")] {
        let proxy = Proxy::new(RootCertStore::empty()).await;
        let stream = TcpStream::connect(proxy.addr).await.unwrap();
        let request = format!(
            "{method} http://denied.invalid/ HTTP/1.1\r\nHost: denied.invalid\r\nConnection: close\r\n\r\n"
        );
        assert_eq!(exchange(stream, &request).await, (403, body.into()));
        let (spans, logs) = proxy.finish_with_logs().await;
        let refusals: Vec<_> = logs
            .iter()
            .filter(|l| l.record.event_name() == Some("egress.refused"))
            .collect();
        assert_eq!(refusals.len(), 1);
        assert_eq!(log_int(refusals[0], "egress.refused.count"), Some(1));
        assert!(format!("{refusals:?}").contains("refused:not_allowed"));
        assert!(format!("{refusals:?}").contains("denied.invalid"));
        assert!(
            !logs
                .iter()
                .any(|l| l.record.event_name() == Some("egress.exchange.failed"))
        );
        let requests: Vec<_> = spans
            .iter()
            .filter(|s| s.name == "egress.request")
            .collect();
        assert_eq!(requests.len(), 1);
        let s = requests[0];
        assert!(attribute(s, "egress.decision", "refused:not_allowed"));
        assert!(attribute(s, "egress.exchange.outcome", "refused"));
        assert!(attribute(s, "server.address", "denied.invalid"));
        assert!(span_attribute(s, "egress.exchange.phase").is_none());
        assert_eq!(
            span_attribute(s, "http.response.body.size"),
            Some(&(body.len() as i64).into())
        );
    }
}
#[tokio::test]
async fn telemetry_keeps_public_url_components_without_credentials() {
    use std::io::{Read, Seek};
    let proxy = Proxy::new(RootCertStore::empty()).await;
    let mut logs = proxy.logs.try_clone().unwrap();
    let stream = TcpStream::connect(proxy.addr).await.unwrap();
    assert_eq!(exchange(stream, "GET http://sentinel-user:sentinel-password@denied.invalid/path?access_token=sentinel-token&api-key=sentinel-api&x-api-key=sentinel-xapi&q=public HTTP/1.1\r\nHost: denied.invalid\r\nConnection: close\r\n\r\n").await.0, 403);
    let spans = proxy.finish().await;
    let request = spans
        .iter()
        .find(|s| attribute(s, "url.path", "/path"))
        .unwrap();
    assert!(attribute(request, "url.scheme", "http"));
    let keys = span_attribute(request, "url.query.keys").unwrap();
    let values = span_attribute(request, "url.query.values").unwrap();
    assert_eq!(
        keys.to_string(),
        r#"["access_token","api-key","x-api-key","q"]"#
    );
    assert_eq!(
        values.to_string(),
        r#"["[redacted]","[redacted]","[redacted]","public"]"#
    );
    assert!(!format!("{spans:?}").contains("sentinel"));
    logs.rewind().unwrap();
    let mut text = String::new();
    logs.read_to_string(&mut text).unwrap();
    assert!(text.contains("egress.request"));
    assert!(!text.contains("sentinel"));
}
#[tokio::test]
async fn invalid_explicit_ports_are_not_defaulted() {
    let proxy = Proxy::new(RootCertStore::empty()).await;
    let stream = TcpStream::connect(proxy.addr).await.unwrap();
    assert_eq!(
        exchange(
            stream,
            "CONNECT localhost:65536 HTTP/1.1\r\nHost: localhost:443\r\nConnection: close\r\n\r\n"
        )
        .await
        .0,
        403
    );
    let spans = proxy.finish().await;
    assert!(
        spans
            .iter()
            .any(|s| attribute(s, "egress.decision", "refused:host_mismatch"))
    );
    assert!(!spans.iter().any(|s| s.name == "egress.connect"));
}
#[tokio::test]
async fn tls_host_must_agree_with_sni_and_connect_authority() {
    let proxy = Proxy::new(RootCertStore::empty()).await;
    for (sni, host) in [
        ("localhost", "other.invalid"),
        ("other.invalid", "localhost"),
    ] {
        let tunnel = proxy.tunnel(443).await;
        let tls = TlsConnector::from(Arc::clone(&proxy.tls))
            .connect(ServerName::try_from(sni.to_owned()).unwrap(), tunnel)
            .await
            .unwrap();
        assert_eq!(
            exchange(
                tls,
                &format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n")
            )
            .await,
            (403, "egress refused: localhost".into())
        );
    }
    let spans = proxy.finish().await;
    assert_eq!(
        spans
            .iter()
            .filter(|s| attribute(s, "egress.decision", "refused:host_mismatch"))
            .count(),
        2
    );
    assert!(!spans.iter().any(|s| s.name == "egress.connect"));
}
#[tokio::test]
async fn connect_post_is_parsed_and_stripped_or_refused_by_inner_host() {
    let proxy = Proxy::new(RootCertStore::empty()).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let peer = tokio::spawn(upstream(listener, None));
    for (host, status) in [("other.invalid", 403), ("localhost", 200)] {
        let tunnel = proxy.tunnel(port).await;
        assert_eq!(exchange(tunnel, &format!("POST / HTTP/1.1\r\nHost: {host}:{port}\r\nContent-Length: 0\r\ntraceparent: sentinel\r\ntracestate: sentinel\r\nConnection: close\r\n\r\n")).await.0, status);
    }
    let received = peer.await.unwrap();
    assert!(!received.contains_key("traceparent"));
    assert!(!received.contains_key("tracestate"));
    let spans = proxy.finish().await;
    assert!(
        spans
            .iter()
            .any(|s| attribute(s, "egress.decision", "refused:host_mismatch"))
    );
    assert_eq!(
        spans.iter().filter(|s| s.name == "egress.connect").count(),
        1
    );
}
#[tokio::test]
async fn plain_http_preserves_validated_host_and_streams_bodies() {
    let proxy = Proxy::new(RootCertStore::empty()).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let peer = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        hyper::server::conn::http1::Builder::new()
            .keep_alive(false)
            .serve_connection(
                TokioIo::new(stream),
                service_fn(|req: Request<Incoming>| async move {
                    assert_eq!(req.headers()[header::HOST], format!("LOCALHOST:0{port}"));
                    assert!(!req.headers().contains_key("traceparent"));
                    let length = req.headers()[header::CONTENT_LENGTH].clone();
                    let mut response = Response::new(req.into_body());
                    response
                        .headers_mut()
                        .insert(header::CONTENT_LENGTH, length);
                    response.headers_mut().insert(
                        header::CONTENT_TYPE,
                        hyper::http::HeaderValue::from_static("text/plain"),
                    );
                    Ok::<_, Infallible>(response)
                }),
            )
            .await
            .unwrap();
    });
    let payload = "x".repeat(70000);
    let stream = TcpStream::connect(proxy.addr).await.unwrap();
    let response = exchange(stream, &format!("POST http://localhost:{port}/echo HTTP/1.1\r\nHost: LOCALHOST:0{port}\r\ntraceparent: sentinel\r\nContent-Length: {}\r\nContent-Type: text/plain\r\nConnection: close, Host\r\n\r\n{payload}", payload.len())).await;
    assert_eq!(response, (200, payload));
    peer.await.unwrap();
    let (spans, logs) = proxy.finish_with_logs().await;
    let request = spans
        .iter()
        .find(|span| attribute(span, "http.request.method", "POST"))
        .unwrap();
    assert_eq!(
        span_attribute(request, "http.request.body.size"),
        Some(&70_000_i64.into())
    );
    assert_eq!(
        span_attribute(request, "http.response.body.size"),
        Some(&70_000_i64.into())
    );
    for key in ["http.request.body.head", "http.response.body.head"] {
        let head = span_attribute(request, key).unwrap().to_string();
        assert!(head.starts_with(&"x".repeat(4000)), "{key}: {head}");
        assert!(head.ends_with("…[truncated]"));
        assert!(head.len() <= 4096);
    }
    let totals = logs
        .iter()
        .find(|log| log.record.event_name() == Some("egress.exchange.rollup"))
        .unwrap();
    assert_eq!(log_int(totals, "http.request.body.size.sum"), Some(70_000));
    assert_eq!(log_int(totals, "http.response.body.size.sum"), Some(70_000));
}
#[tokio::test]
async fn non_http_tunnel_bytes_close_with_protocol_refusal() {
    let proxy = Proxy::new(RootCertStore::empty()).await;
    let mut stream = proxy.tunnel(443).await;
    stream.write_all(b"\x01garbage").await.unwrap();
    assert_eq!(stream.read(&mut [0; 1]).await.unwrap(), 0);
    drop(stream);
    let spans = proxy.finish().await;
    let refusal = spans
        .iter()
        .find(|s| attribute(s, "egress.exchange.outcome", "protocol-error"))
        .unwrap();
    assert!(attribute(refusal, "server.address", "localhost"));
    assert!(!spans.iter().any(|s| s.name == "egress.connect"));
}
#[tokio::test]
async fn failed_tls_handshake_records_known_sni() {
    let proxy = Proxy::new(RootCertStore::empty()).await;
    let stream = TcpStream::connect(proxy.addr).await.unwrap();
    let error = TlsConnector::from(client_config(RootCertStore::empty()).unwrap())
        .connect(ServerName::try_from("evil.invalid").unwrap(), stream)
        .await
        .unwrap_err();
    assert!(
        matches!(
            error
                .get_ref()
                .and_then(|inner| inner.downcast_ref::<rustls::Error>()),
            Some(rustls::Error::InvalidCertificate(
                rustls::CertificateError::UnknownIssuer
            ))
        ),
        "{error:?}"
    );
    let spans = proxy.finish().await;
    let refusals: Vec<_> = spans
        .iter()
        .filter(|s| attribute(s, "egress.exchange.outcome", "certificate-rejected"))
        .collect();
    assert_eq!(refusals.len(), 1);
    assert!(attribute(refusals[0], "server.address", "evil.invalid"));
    assert!(span_attribute(refusals[0], "http.response.status_code").is_none());
}
#[tokio::test]
async fn truncated_upstream_body_is_body_error_after_the_streamed_bytes() {
    let proxy = Proxy::new(RootCertStore::empty()).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (headers_seen, release) = tokio::sync::oneshot::channel();
    let peer = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            request.push(stream.read_u8().await.unwrap());
        }
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\npartial")
            .await
            .unwrap();
        release.await.unwrap();
        stream.shutdown().await.unwrap();
    });
    let mut stream = TcpStream::connect(proxy.addr).await.unwrap();
    stream.write_all(format!("GET http://localhost:{port}/ HTTP/1.1\r\nHost: localhost:{port}\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
    let mut response = Vec::new();
    while !response.ends_with(b"partial") {
        response.push(stream.read_u8().await.unwrap());
    }
    headers_seen.send(()).unwrap();
    stream.read_to_end(&mut response).await.unwrap();
    assert!(response.starts_with(b"HTTP/1.1 200 "));
    peer.await.unwrap();
    let spans = proxy.finish().await;
    let requests: Vec<_> = spans
        .iter()
        .filter(|s| s.name == "egress.request")
        .collect();
    assert_eq!(requests.len(), 1, "{requests:?}");
    assert!(attribute(requests[0], "egress.decision", "allowed"));
    assert!(
        attribute(requests[0], "egress.exchange.outcome", "body-error"),
        "{requests:?}"
    );
    assert!(attribute(
        requests[0],
        "egress.exchange.phase",
        "response-body"
    ));
    assert_eq!(
        span_attribute(requests[0], "http.response.body.size"),
        Some(&7_i64.into())
    );
}
#[tokio::test]
async fn truncated_guest_post_is_request_body_error_with_one_failure_log() {
    let proxy = Proxy::new(RootCertStore::empty()).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let peer = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        hyper::server::conn::http1::Builder::new()
            .keep_alive(false)
            .serve_connection(
                TokioIo::new(stream),
                service_fn(|req: Request<Incoming>| async move {
                    // Do not answer until the forwarded body is read to completion.
                    let _body = req.into_body().collect().await;
                    Ok::<_, Infallible>(Response::new(Full::new(Bytes::new())))
                }),
            )
            .await
            .unwrap();
    });
    let mut guest = TcpStream::connect(proxy.addr).await.unwrap();
    guest.write_all(format!("POST http://localhost:{port}/ HTTP/1.1\r\nHost: localhost:{port}\r\nContent-Length: 20\r\nConnection: close\r\n\r\npartial").as_bytes()).await.unwrap();
    guest.shutdown().await.unwrap();
    let mut response = Vec::new();
    guest.read_to_end(&mut response).await.unwrap();
    peer.await.unwrap();
    let (_spans, logs) = proxy.finish_with_logs().await;
    let failures: Vec<_> = logs
        .iter()
        .filter(|log| log.record.event_name() == Some("egress.exchange.failed"))
        .collect();
    assert_eq!(failures.len(), 1, "{failures:?}");
    let failure = failures[0];
    assert!(
        failure
            .record
            .attributes_iter()
            .any(|(key, value)| key.as_str() == "egress.exchange.outcome"
                && value == &opentelemetry::logs::AnyValue::from("body-error")),
        "{failure:?}"
    );
    assert!(
        failure
            .record
            .attributes_iter()
            .any(|(key, value)| key.as_str() == "egress.exchange.phase"
                && value == &opentelemetry::logs::AnyValue::from("request-body")),
        "{failure:?}"
    );
    assert!(failure.record.attributes_iter().any(|(key, value)| key.as_str() == "error" && matches!(value, opentelemetry::logs::AnyValue::String(text) if !text.as_str().is_empty())), "{failure:?}");
}
#[tokio::test]
async fn client_cancellation_after_response_bytes_records_abandoned_response_body() {
    let proxy = Proxy::new(RootCertStore::empty()).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let peer = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            request.push(stream.read_u8().await.unwrap());
        }
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\npartial")
            .await
            .unwrap();
        let disconnected =
            tokio::time::timeout(Duration::from_secs(2), stream.read(&mut [0; 1])).await;
        stream.shutdown().await.unwrap();
        matches!(disconnected, Ok(Ok(0)))
    });
    let mut client = TcpStream::connect(proxy.addr).await.unwrap();
    client.write_all(format!("GET http://localhost:{port}/ HTTP/1.1\r\nHost: localhost:{port}\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
    let mut response = Vec::new();
    while !response.ends_with(b"partial") {
        response.push(client.read_u8().await.unwrap());
    }
    drop(client);
    let disconnected = peer.await.unwrap();
    let spans = proxy.finish().await;
    assert!(
        disconnected,
        "downstream cancellation left the upstream socket open"
    );
    let request = spans
        .iter()
        .find(|span| attribute(span, "http.request.method", "GET"))
        .unwrap();
    assert!(
        attribute(request, "egress.exchange.outcome", "abandoned"),
        "{request:?}"
    );
    assert!(attribute(request, "egress.exchange.phase", "response-body"));
    assert_eq!(
        span_attribute(request, "http.response.body.size"),
        Some(&7_i64.into())
    );
}
#[tokio::test]
async fn cancelled_upstream_request_exports_abandoned_without_a_status() {
    let exporter = InMemorySpanExporter::default();
    let provider = SdkTracerProvider::builder()
        .with_simple_exporter(exporter.clone())
        .build();
    let subscriber = tracing_subscriber::registry()
        .with(tracing_opentelemetry::layer().with_tracer(provider.tracer("cancel-test")));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (seen, received) = tokio::sync::oneshot::channel();
    let peer = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            request.push(stream.read_u8().await.unwrap());
        }
        seen.send(()).unwrap();
        // Hold the response until cancellation drops the proxy's upstream socket.
        assert_eq!(stream.read(&mut [0; 1]).await.unwrap(), 0);
    });
    async {
        let engine = Engine {
            ca: Ca::new().unwrap().0,
            egress: local_egress(),
            tls: client_config(RootCertStore::empty()).unwrap(),
            omit: Default::default(),
            rollups: Arc::new(Mutex::new(Rollups::new())),
        };
        let (mut client, stream) = tokio::io::duplex(4096);
        client.write_all(format!("GET http://localhost:{port}/ HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n").as_bytes()).await.unwrap();
        let mut record = ConnectionRecord::default();
        let mut connection = Box::pin(engine.connection(Box::new(stream), &mut record));
        tokio::select! {
            result = &mut connection => panic!("connection finished before cancellation: {result:?}"),
            result = received => result.unwrap(),
        }
        // A deadline cancels by dropping this same future; no clock is needed.
        drop(connection);
        assert!(record.request.get());
        record.failed(&engine.rollups);
        assert_eq!(client.read(&mut [0; 1]).await.unwrap(), 0);
    }
    .with_subscriber(subscriber)
    .await;
    peer.await.unwrap();
    let spans = exporter.get_finished_spans().unwrap();
    let requests: Vec<_> = spans
        .iter()
        .filter(|s| s.name == "egress.request")
        .collect();
    assert_eq!(requests.len(), 1, "{requests:?}");
    assert!(attribute(requests[0], "egress.decision", "allowed"));
    assert!(span_attribute(requests[0], "http.response.status_code").is_none());
    assert!(attribute(
        requests[0],
        "egress.exchange.outcome",
        "abandoned"
    ));
    provider.shutdown().unwrap();
}
#[tokio::test]
async fn fragmented_client_hello_waits_for_remainder_and_is_classified_as_tls() {
    let mut client = rustls::ClientConnection::new(
        client_config(RootCertStore::empty()).unwrap(),
        ServerName::try_from("localhost").unwrap(),
    )
    .unwrap();
    let mut hello = Vec::new();
    client.write_tls(&mut hello).unwrap();
    let (mut writer, reader) = tokio::io::duplex(65536);
    writer.write_all(&hello[..1]).await.unwrap();
    let classified = classify(Box::new(reader));
    tokio::pin!(classified);
    std::future::poll_fn(|cx| {
        assert!(classified.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    writer.write_all(&hello[1..]).await.unwrap();
    let Classified::Tls(start) = classified.await.unwrap() else {
        panic!("ClientHello was not intercepted")
    };
    assert_eq!(start.client_hello().server_name(), Some("localhost"));
    let (ca, _) = Ca::new().unwrap();
    let server = start.into_stream(ca.server("localhost").unwrap());
    tokio::pin!(server);
    std::future::poll_fn(|cx| {
        assert!(server.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    assert_eq!(writer.read_u8().await.unwrap(), 0x16);
}
#[test]
fn request_trailers_cannot_reintroduce_trace_headers() {
    let mut trailers = hyper::HeaderMap::new();
    trailers.insert("traceparent", "sentinel".parse().unwrap());
    trailers.insert("tracestate", "sentinel".parse().unwrap());
    trailers.insert("x-checksum", "kept".parse().unwrap());
    let frame = strip_trailers(Frame::trailers(trailers));
    let trailers = frame.trailers_ref().unwrap();
    assert!(!trailers.contains_key("traceparent"));
    assert!(!trailers.contains_key("tracestate"));
    assert_eq!(trailers["x-checksum"], "kept");
}
#[tokio::test]
async fn allowed_name_resolving_to_loopback_is_refused_and_spanned_before_connect() {
    let mut egress = local_egress();
    egress.allow_private.clear();
    let proxy = Proxy::configured(RootCertStore::empty(), egress).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let stream = TcpStream::connect(proxy.addr).await.unwrap();
    assert_eq!(exchange(stream, &format!("GET http://localhost:{port}/ HTTP/1.1\r\nHost: localhost:{port}\r\nConnection: close\r\n\r\n")).await,
        (403, "egress refused: localhost".into()));
    std::future::poll_fn(|cx| {
        assert!(listener.poll_accept(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    let spans = proxy.finish().await;
    let request = spans.iter().find(|s| s.name == "egress.request").unwrap();
    assert!(attribute(request, "egress.decision", "refused:address"));
    assert!(attribute(request, "server.address", "localhost"));
    assert_eq!(
        span_attribute(request, "http.response.status_code"),
        Some(&403_i64.into())
    );
}
#[test]
fn address_policy_rejects_non_global_answers_including_mapped_and_mixed_addresses() {
    for text in [
        "0.0.0.0",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
        "127.0.0.1",
        "169.254.169.254",
        "100.64.0.1",
        "224.0.0.1",
        "255.255.255.255",
        "192.0.2.1",
        "198.18.0.1",
        "240.0.0.1",
        "::",
        "::1",
        "fd00::1",
        "fe80::1",
        "ff0e::1",
        "::ffff:127.0.0.1",
        "::ffff:169.254.169.254",
        "2001:db8::1",
        "2002:7f00:1::1",
        "64:ff9b::7f00:1",
        "100::1",
        "3fff::1",
        "fec0::1",
    ] {
        let address = SocketAddr::new(text.parse().unwrap(), 80);
        assert!(
            matches!(vetted_addresses(&[address], &[]), Err(AddressRefused)),
            "{text}"
        );
    }
    let public: Vec<SocketAddr> = ["1.1.1.1:80", "[2606:4700:4700::1111]:80"]
        .map(|a| a.parse().unwrap())
        .into();
    assert_eq!(vetted_addresses(&public, &[]).unwrap(), public);
    assert!(matches!(
        vetted_addresses(&[public[0], "127.0.0.1:80".parse().unwrap()], &[]),
        Err(AddressRefused)
    ));
    assert!(matches!(vetted_addresses(&[], &[]), Err(AddressRefused)));
}
#[test]
fn private_cidr_exception_is_narrow_and_applies_to_vetted_socket_addresses() {
    let exceptions = [
        "127.0.0.1/32".parse().unwrap(),
        "169.254.169.254/32".parse().unwrap(),
        "::1/128".parse().unwrap(),
    ];
    for text in [
        "127.0.0.1:80",
        "169.254.169.254:80",
        "[::1]:80",
        "[::ffff:127.0.0.1]:80",
    ] {
        let address = [text.parse().unwrap()];
        assert_eq!(vetted_addresses(&address, &exceptions).unwrap(), address);
    }
    assert!(matches!(
        vetted_addresses(&["127.0.0.2:80".parse().unwrap()], &exceptions),
        Err(AddressRefused)
    ));
}
#[test]
fn egress_defaults_match_browser_limits_and_invalid_settings_fail_at_parse_boundary() {
    let egress: Egress = serde_yaml_ng::from_str("allow: [localhost]\ndns: runner").unwrap();
    assert!(egress.allow_private.is_empty());
    assert_eq!(egress.idle_seconds.get(), 90);
    assert_eq!(egress.max_connection_seconds.get(), 1800);
    assert_eq!(egress.max_connections.get(), 128);
    for invalid in [
        "allowPrivate: [bad-cidr]",
        "idleSeconds: 0",
        "maxConnectionSeconds: 0",
        "maxConnections: 0",
        "unknown: 1",
    ] {
        assert!(
            serde_yaml_ng::from_str::<Egress>(&format!(
                "allow: [localhost]\ndns: runner\n{invalid}"
            ))
            .is_err(),
            "{invalid}"
        );
    }
}
async fn poll_pending(mut future: Pin<&mut impl Future<Output = Result<(), Error>>>) {
    std::future::poll_fn(|cx| {
        assert!(future.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
}
#[tokio::test(start_paused = true)]
async fn idle_connection_closes_only_after_inactivity_and_reads_reset_the_deadline() {
    let engine = Engine {
        ca: Ca::new().unwrap().0,
        egress: local_egress(),
        tls: client_config(RootCertStore::empty()).unwrap(),
        omit: Default::default(),
        rollups: Arc::new(Mutex::new(Rollups::new())),
    };
    let (mut client, stream) = tokio::io::duplex(4096);
    let mut record = ConnectionRecord::default();
    let mut connection = Box::pin(engine.bounded_connection(
        Box::new(stream),
        &mut record,
        Instant::now(),
        gateway::Protocol::Http,
    ));
    poll_pending(connection.as_mut()).await;
    tokio::time::advance(Duration::from_secs(80)).await;
    client.write_all(b"G").await.unwrap();
    poll_pending(connection.as_mut()).await;
    tokio::time::advance(Duration::from_secs(80)).await;
    poll_pending(connection.as_mut()).await;
    tokio::time::advance(Duration::from_secs(10)).await;
    let error = connection.await.unwrap_err();
    assert!(matches!(
        error.downcast_ref::<ConnectionTimeout>(),
        Some(ConnectionTimeout::Idle)
    ));
    assert_eq!(client.read(&mut [0; 1]).await.unwrap(), 0);
}
#[tokio::test(start_paused = true)]
async fn maximum_lifetime_closes_even_an_active_connection() {
    let mut egress = local_egress();
    egress.max_connection_seconds = 180.try_into().unwrap();
    let engine = Engine {
        ca: Ca::new().unwrap().0,
        egress,
        tls: client_config(RootCertStore::empty()).unwrap(),
        omit: Default::default(),
        rollups: Arc::new(Mutex::new(Rollups::new())),
    };
    let (mut client, stream) = tokio::io::duplex(4096);
    let mut record = ConnectionRecord::default();
    let mut connection = Box::pin(engine.bounded_connection(
        Box::new(stream),
        &mut record,
        Instant::now(),
        gateway::Protocol::Http,
    ));
    poll_pending(connection.as_mut()).await;
    for byte in [b"G", b"E"] {
        tokio::time::advance(Duration::from_secs(80)).await;
        client.write_all(byte).await.unwrap();
        poll_pending(connection.as_mut()).await;
    }
    tokio::time::advance(Duration::from_secs(20)).await;
    let error = connection.await.unwrap_err();
    assert!(matches!(
        error.downcast_ref::<ConnectionTimeout>(),
        Some(ConnectionTimeout::Lifetime)
    ));
    assert_eq!(client.read(&mut [0; 1]).await.unwrap(), 0);
}
#[tokio::test]
async fn connection_cap_closes_the_next_socket_and_exports_a_refusal() {
    let mut egress = local_egress();
    egress.max_connections = 1.try_into().unwrap();
    let proxy = Proxy::configured(RootCertStore::empty(), egress).await;
    let first = proxy.tunnel(443).await;
    let mut excess = TcpStream::connect(proxy.addr).await.unwrap();
    assert_eq!(excess.read(&mut [0; 1]).await.unwrap(), 0);
    drop(first);
    let (_, logs) = proxy.finish_with_logs().await;
    let refusals: Vec<_> = logs
        .iter()
        .filter(|log| {
            log.record.event_name() == Some("egress.refused")
                && log_int(log, "egress.refused.count").is_some()
        })
        .collect();
    assert_eq!(refusals.len(), 1);
    assert_eq!(log_int(refusals[0], "egress.refused.count"), Some(1));
}
#[test]
fn span_attribute_assertions_reject_duplicate_values_of_any_type() {
    let exporter = InMemorySpanExporter::default();
    let provider = SdkTracerProvider::builder()
        .with_simple_exporter(exporter.clone())
        .build();
    let subscriber = tracing_subscriber::registry()
        .with(tracing_opentelemetry::layer().with_tracer(provider.tracer("duplicate-test")));
    tracing::subscriber::with_default(subscriber, || {
        let mut exchange = Exchange::new(
            "localhost",
            Some(80),
            "GET",
            "http://localhost/",
            &[],
            Arc::new(Mutex::new(Rollups::new())),
        );
        exchange.status(StatusCode::OK);
        let Recorded = exchange.finish(Outcome::Completed, None);
    });
    let original = exporter.get_finished_spans().unwrap().pop().unwrap();
    for duplicate in [
        KeyValue::new("egress.decision", "allowed"),
        KeyValue::new("egress.decision", "refused:address"),
        KeyValue::new("http.response.status_code", 0_i64),
        KeyValue::new("server.address", "localhost"),
    ] {
        let mut span = original.clone();
        let key = duplicate.key.clone();
        span.attributes.push(duplicate);
        assert!(std::panic::catch_unwind(|| span_attribute(&span, key.as_str())).is_err());
    }
    provider.shutdown().unwrap();
}
#[tokio::test]
async fn dropped_refusal_keeps_decision_and_emits_once() {
    let spans = InMemorySpanExporter::default();
    let provider = SdkTracerProvider::builder()
        .with_simple_exporter(spans.clone())
        .build();
    let logs = InMemoryLogExporter::default();
    let logger = SdkLoggerProvider::builder()
        .with_simple_exporter(logs.clone())
        .build();
    let subscriber = tracing_subscriber::registry()
        .with(tracing_opentelemetry::layer().with_tracer(provider.tracer("dropped-refusal")))
        .with(opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge::new(&logger));
    tracing::subscriber::with_default(subscriber, || {
        let mut exchange = Exchange::new(
            "denied.invalid",
            Some(80),
            "GET",
            "http://denied.invalid/",
            &[],
            Arc::new(Mutex::new(Rollups::new())),
        );
        exchange.refuse(Refusal::NotAllowed);
        exchange.refuse(Refusal::NotAllowed); // decision-time emission is idempotent
        drop(exchange);
    });
    let refusals: Vec<_> = logs
        .get_emitted_logs()
        .unwrap()
        .into_iter()
        .filter(|l| l.record.event_name() == Some("egress.refused"))
        .collect();
    assert_eq!(refusals.len(), 1);
    assert_eq!(log_int(&refusals[0], "egress.refused.count"), Some(1));
    assert!(
        !logs
            .get_emitted_logs()
            .unwrap()
            .iter()
            .any(|l| l.record.event_name() == Some("egress.exchange.failed"))
    );
    let recorded = spans.get_finished_spans().unwrap();
    assert_eq!(recorded.len(), 1);
    assert!(attribute(
        &recorded[0],
        "egress.decision",
        "refused:not_allowed"
    ));
    assert!(attribute(
        &recorded[0],
        "egress.exchange.outcome",
        "refused"
    ));
    assert!(span_attribute(&recorded[0], "egress.exchange.phase").is_none());
    provider.shutdown().unwrap();
    logger.shutdown().unwrap();
}
#[tokio::test]
async fn failed_and_empty_dns_answers_have_distinct_single_refusal_decisions() {
    let exporter = InMemorySpanExporter::default();
    let provider = SdkTracerProvider::builder()
        .with_simple_exporter(exporter.clone())
        .build();
    let subscriber = tracing_subscriber::registry()
        .with(tracing_opentelemetry::layer().with_tracer(provider.tracer("dns-test")));
    tracing::subscriber::with_default(subscriber, || {
        for (answer, decision) in [
            (
                Err(std::io::Error::other("resolver unavailable")),
                "refused:dns",
            ),
            (Ok(Vec::<SocketAddr>::new().into_iter()), "refused:address"),
        ] {
            let error = resolved_addresses(answer, &[]).unwrap_err();
            assert_eq!(error.is::<DnsFailed>(), decision == "refused:dns");
            assert_eq!(error.is::<AddressRefused>(), decision == "refused:address");
            let mut exchange = Exchange::new(
                "allowed.invalid",
                Some(80),
                "GET",
                "http://allowed.invalid/",
                &[],
                Arc::new(Mutex::new(Rollups::new())),
            );
            exchange.status(StatusCode::FORBIDDEN);
            let reason = if error.is::<DnsFailed>() {
                Refusal::Dns
            } else {
                Refusal::Address
            };
            assert_eq!(reason.decision(), decision);
            let Recorded = exchange.finish(Outcome::Refused(reason), None);
        }
    });
    let spans = exporter.get_finished_spans().unwrap();
    assert_eq!(spans.len(), 2);
    for (span, decision) in spans.iter().zip(["refused:dns", "refused:address"]) {
        assert!(attribute(span, "egress.decision", decision));
        assert!(attribute(span, "server.address", "allowed.invalid"));
        assert_eq!(
            span_attribute(span, "http.response.status_code"),
            Some(&403_i64.into())
        );
    }
    provider.shutdown().unwrap();
}
#[tokio::test]
async fn connection_cap_counts_all_refused_sockets_before_shutdown() {
    let mut egress = local_egress();
    egress.max_connections = 1.try_into().unwrap();
    let proxy = Proxy::configured(RootCertStore::empty(), egress).await;
    let first = proxy.tunnel(443).await;
    for _ in 0..3 {
        let mut excess = TcpStream::connect(proxy.addr).await.unwrap();
        assert_eq!(excess.read(&mut [0; 1]).await.unwrap(), 0);
    }
    drop(first);
    let (_, logs) = proxy.finish_with_logs().await;
    let refusals: Vec<_> = logs
        .iter()
        .filter(|log| log.record.event_name() == Some("egress.refused"))
        .filter_map(|log| log_int(log, "egress.refused.count"))
        .collect();
    assert_eq!(refusals.iter().sum::<i64>(), 3);
    assert!(refusals.len() <= 2);
}
#[test]
fn worker_unwind_records_one_abandoned_exchange() {
    let exporter = InMemorySpanExporter::default();
    let provider = SdkTracerProvider::builder()
        .with_simple_exporter(exporter.clone())
        .build();
    let subscriber = tracing_subscriber::registry()
        .with(tracing_opentelemetry::layer().with_tracer(provider.tracer("worker-unwind")));
    tracing::subscriber::with_default(subscriber, || {
        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut exchange = Exchange::new(
                "localhost",
                Some(80),
                "GET",
                "http://localhost/",
                &[],
                Arc::new(Mutex::new(Rollups::new())),
            );
            exchange.status(StatusCode::OK);
            exchange.phase(Phase::ResponseBody);
            panic!("worker unwound");
        }));
        assert!(unwound.is_err());
    });
    let spans = exporter.get_finished_spans().unwrap();
    assert_eq!(spans.len(), 1);
    assert!(attribute(&spans[0], "egress.exchange.outcome", "abandoned"));
    assert!(attribute(
        &spans[0],
        "egress.exchange.phase",
        "response-body"
    ));
    provider.shutdown().unwrap();
}
#[tokio::test]
async fn drip_keeps_failure_and_rollup_logs_without_an_exchange_span() {
    let proxy = Proxy::drip(RootCertStore::empty()).await;
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = upstream.local_addr().unwrap().port();
    let peer = tokio::spawn(async move {
        drop(upstream.accept().await.unwrap());
    });
    let stream = TcpStream::connect(proxy.addr).await.unwrap();
    assert_eq!(exchange(stream, &format!("GET http://localhost:{port}/ HTTP/1.1\r\nHost: localhost:{port}\r\nConnection: close\r\n\r\n")).await.0, 502);
    peer.await.unwrap();
    let (spans, logs) = proxy.finish_with_logs().await;
    assert!(!spans.iter().any(|span| span.name == "egress.request"));
    let failed = logs
        .iter()
        .find(|log| log.record.event_name() == Some("egress.exchange.failed"))
        .unwrap();
    assert_eq!(log_int(failed, "http.response.status_code"), Some(502));
    assert!(
        failed
            .record
            .attributes_iter()
            .any(|(name, value)| name.as_str() == "egress.exchange.outcome"
                && value == &opentelemetry::logs::AnyValue::from("upstream-failed"))
    );
    let rollup = logs
        .iter()
        .find(|log| log.record.event_name() == Some("egress.exchange.rollup"))
        .unwrap();
    assert_eq!(log_int(rollup, "egress.exchange.count"), Some(1));
    assert_eq!(log_int(rollup, "egress.exchange.error.count"), Some(1));
}
#[tokio::test]
async fn connect_is_its_own_completed_tunnel_record_without_zero_status() {
    let proxy = Proxy::new(RootCertStore::empty()).await;
    drop(proxy.tunnel(443).await);
    let (spans, logs) = proxy.finish_with_logs().await;
    let tunnel = spans
        .iter()
        .find(|s| attribute(s, "http.request.method", "CONNECT"))
        .unwrap();
    assert!(attribute(tunnel, "egress.exchange.outcome", "tunnel"));
    assert_eq!(
        span_attribute(tunnel, "http.response.status_code"),
        Some(&200_i64.into())
    );
    assert!(
        spans
            .iter()
            .all(|s| span_attribute(s, "http.response.status_code") != Some(&0_i64.into()))
    );
    assert_eq!(
        logs.iter()
            .filter(|log| log.record.event_name() == Some("egress.exchange.rollup"))
            .filter_map(|log| log_int(log, "egress.exchange.count"))
            .sum::<i64>(),
        1
    );
}
#[tokio::test]
async fn client_error_completes_and_emits_a_failure_log() {
    let proxy = Proxy::new(RootCertStore::empty()).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let peer = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        hyper::server::conn::http1::Builder::new()
            .keep_alive(false)
            .serve_connection(
                TokioIo::new(stream),
                service_fn(|_: Request<Incoming>| async {
                    Ok::<_, Infallible>(
                        Response::builder()
                            .status(404)
                            .header("set-cookie", "sentinel-cookie")
                            .header("content-type", "text/plain")
                            .body(Full::new(Bytes::new()))
                            .unwrap(),
                    )
                }),
            )
            .await
            .unwrap();
    });
    let stream = TcpStream::connect(proxy.addr).await.unwrap();
    assert_eq!(exchange(stream, &format!("GET http://localhost:{port}/missing HTTP/1.1\r\nHost: localhost:{port}\r\nConnection: close\r\n\r\n")).await.0, 404);
    peer.await.unwrap();
    let (spans, logs) = proxy.finish_with_logs().await;
    let request = spans
        .iter()
        .find(|s| attribute(s, "http.request.method", "GET"))
        .unwrap();
    assert!(attribute(request, "egress.exchange.outcome", "completed"));
    assert!(attribute(
        request,
        "http.response.header.content_type",
        "text/plain"
    ));
    assert!(
        span_attribute(request, "http.response.header.names")
            .unwrap()
            .to_string()
            .contains("set-cookie")
    );
    assert!(
        span_attribute(request, "http.response.header.values")
            .unwrap()
            .to_string()
            .contains("[redacted]")
    );
    assert!(!format!("{spans:?}{logs:?}").contains("sentinel"));
    assert_eq!(
        span_attribute(request, "http.response.body.size"),
        Some(&0_i64.into())
    );
    let failed = logs
        .iter()
        .find(|log| log.record.event_name() == Some("egress.exchange.failed"))
        .unwrap();
    assert_eq!(log_int(failed, "http.response.status_code"), Some(404));
    assert!(
        failed
            .record
            .attributes_iter()
            .any(|(key, value)| key.as_str() == "egress.exchange.outcome"
                && value == &opentelemetry::logs::AnyValue::from("completed"))
    );
}
#[tokio::test]
async fn sixty_fifth_exchange_key_folds_into_star_without_losing_counts() {
    let proxy = Proxy::new(RootCertStore::empty()).await;
    for n in 0..65 {
        let host = format!("denied-{n}.invalid");
        let stream = TcpStream::connect(proxy.addr).await.unwrap();
        assert_eq!(
            exchange(
                stream,
                &format!(
                    "GET http://{host}/ HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
                )
            )
            .await
            .0,
            403
        );
    }
    let (spans, logs) = proxy.finish_with_logs().await;
    assert_eq!(
        spans.iter().filter(|s| s.name == "egress.request").count(),
        65
    );
    let rows: Vec<_> = logs
        .iter()
        .filter(|log| log.record.event_name() == Some("egress.exchange.rollup"))
        .collect();
    assert_eq!(rows.len(), 64);
    assert_eq!(
        rows.iter()
            .filter_map(|row| log_int(row, "egress.exchange.count"))
            .sum::<i64>(),
        65
    );
    assert!(rows.iter().any(|row| {
        row.record.attributes_iter().any(|(key, value)| {
            key.as_str() == "server.address" && value == &opentelemetry::logs::AnyValue::from("*")
        })
    }));
}
#[tokio::test]
async fn omitted_and_credential_pairs_keep_parallel_arrays_aligned_without_secrets() {
    let omit = serde_yaml_ng::from_str("headers: ['x-drop*']\nqueryKeys: ['drop*']").unwrap();
    let proxy = Proxy::configured_with_omit(RootCertStore::empty(), local_egress(), omit).await;
    let stream = TcpStream::connect(proxy.addr).await.unwrap();
    assert_eq!(exchange(stream, "GET http://denied.invalid/a?drop-one=sentinel-omitted&access_token=sentinel-token&q=public HTTP/1.1\r\nHost: denied.invalid\r\nAuthorization: Bearer sentinel-secret\r\nCookie: sentinel-cookie\r\nX-Drop-One: sentinel-omitted\r\nConnection: close\r\n\r\n").await.0, 403);
    let (spans, logs) = proxy.finish_with_logs().await;
    let request = spans
        .iter()
        .find(|s| attribute(s, "url.path", "/a"))
        .unwrap();
    assert_eq!(
        span_attribute(request, "url.query.keys")
            .unwrap()
            .to_string(),
        r#"["access_token","q"]"#
    );
    assert_eq!(
        span_attribute(request, "url.query.values")
            .unwrap()
            .to_string(),
        r#"["[redacted]","public"]"#
    );
    let names = span_attribute(request, "http.request.header.names")
        .unwrap()
        .to_string();
    let values = span_attribute(request, "http.request.header.values")
        .unwrap()
        .to_string();
    assert!(names.contains("authorization") && names.contains("cookie"));
    assert!(!names.contains("x-drop"));
    assert!(values.contains("[redacted]"));
    assert!(!format!("{spans:?}{logs:?}").contains("sentinel"));
    assert!(
        logs.iter()
            .filter(|log| log.record.event_name() == Some("egress.exchange.noise"))
            .all(|log| !format!("{log:?}").contains("drop"))
    );
}
#[tokio::test]
async fn query_noise_only_inspects_first_sixty_four_pairs() {
    let proxy = Proxy::new(RootCertStore::empty()).await;
    let query = (0..70)
        .map(|n| format!("q{n}=v"))
        .collect::<Vec<_>>()
        .join("&");
    let stream = TcpStream::connect(proxy.addr).await.unwrap();
    assert_eq!(exchange(stream, &format!("GET http://denied.invalid/?{query} HTTP/1.1\r\nHost: denied.invalid\r\nConnection: close\r\n\r\n")).await.0, 403);
    let (_, logs) = proxy.finish_with_logs().await;
    let noise: Vec<_> = logs
        .iter()
        .filter(|l| l.record.event_name() == Some("egress.exchange.noise"))
        .filter(|l| {
            l.record.attributes_iter().any(|(k, v)| {
                k.as_str() == "egress.noise.kind"
                    && v == &opentelemetry::logs::AnyValue::from("query-key")
            })
        })
        .collect();
    assert_eq!(
        noise
            .iter()
            .filter_map(|l| log_int(l, "egress.noise.value.count"))
            .sum::<i64>(),
        64
    );
    assert!(!format!("{noise:?}").contains("q69"));
}
#[test]
fn suffix_allowlist_respects_label_boundaries_and_attributes_are_byte_bounded() {
    let allow = vec!["*.example.com".into()];
    assert!(allowed("A.Example.Com.", &allow));
    assert!(!allowed("example.com", &allow));
    assert!(!allowed("badexample.com", &allow));
    let value = cut(&"é".repeat(3000));
    assert!(value.len() <= 4096);
    assert!(value.ends_with("…[truncated]"));
}

#[test]
fn minted_leaf_names_its_host_and_chains_to_a_distinct_ca_subject() {
    let (ca, pem) = Ca::new().unwrap();
    let (leaf, _) = ca.leaf("www.example.com").unwrap();
    let (_, ca_der) = x509_parser::pem::parse_x509_pem(pem.as_bytes()).unwrap();
    let ca_cert = ca_der.parse_x509().unwrap();
    let (_, leaf_cert) = x509_parser::parse_x509_certificate(&leaf).unwrap();
    assert_eq!(leaf_cert.issuer(), ca_cert.subject());
    assert_ne!(leaf_cert.subject(), leaf_cert.issuer());
    let eku = leaf_cert.extended_key_usage().unwrap().unwrap().value;
    assert!(eku.server_auth);
}
