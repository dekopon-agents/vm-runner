use super::*;
use opentelemetry::{KeyValue, trace::TracerProvider};
use opentelemetry_sdk::trace::{InMemorySpanExporter, SdkTracerProvider, SpanData};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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
    stop: tokio::sync::oneshot::Sender<()>,
    task: tokio::task::JoinHandle<Result<(), Error>>,
}
impl Proxy {
    async fn new(roots: RootCertStore) -> Self {
        let (ca, pem) = Ca::new().unwrap();
        let mut trust = RootCertStore::empty();
        trust
            .add(CertificateDer::from_pem_slice(pem.as_bytes()).unwrap())
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let exporter = InMemorySpanExporter::default();
        let provider = SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let logs = Arc::new(tempfile::tempfile().unwrap());
        let subscriber = tracing_subscriber::registry()
            .with(
                tracing_subscriber::fmt::layer()
                    .json()
                    .with_writer(Arc::clone(&logs))
                    .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE),
            )
            .with(tracing_opentelemetry::layer().with_tracer(provider.tracer("egress-test")));
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let engine = Arc::new(Engine {
            ca,
            allow: vec!["localhost".into()],
            tls: client_config(roots).unwrap(),
        });
        let task = tokio::spawn(
            engine
                .serve(listener, async {
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
        self.stop.send(()).unwrap();
        self.task.await.unwrap().unwrap();
        let spans = self.exporter.get_finished_spans().unwrap();
        self.provider.shutdown().unwrap();
        spans
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
    span.attributes
        .contains(&KeyValue::new(key.to_owned(), value.to_owned()))
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
async fn allowed_https_uses_injected_root_strips_trace_headers_and_exports_request() {
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
        ("url.full", format!("https://localhost:{port}/proof")),
        ("server.address", "localhost".into()),
        ("egress.decision", "allowed".into()),
    ] {
        assert!(attribute(request, key, &value));
    }
    assert!(
        request
            .attributes
            .contains(&KeyValue::new("http.response.status_code", 200_i64))
    );
    assert_eq!(request.name, "egress.request");
    assert_eq!(
        request.parent_span_id,
        opentelemetry::trace::SpanId::INVALID
    );
    assert_ne!(
        request.span_context.trace_id().to_string(),
        "11111111111111111111111111111111"
    );
    assert_eq!(
        spans.iter().filter(|s| s.name == "egress.connect").count(),
        1
    );
}
#[tokio::test]
async fn disallowed_plain_host_gets_exact_refusal_and_span_without_connecting() {
    let proxy = Proxy::new(RootCertStore::empty()).await;
    let stream = TcpStream::connect(proxy.addr).await.unwrap();
    assert_eq!(exchange(stream, "GET http://denied.invalid/ HTTP/1.1\r\nHost: denied.invalid\r\nConnection: close\r\n\r\n").await, (403, "egress refused: denied.invalid".into()));
    let spans = proxy.finish().await;
    assert!(
        spans
            .iter()
            .any(|s| attribute(s, "egress.decision", "refused:not_allowed"))
    );
    assert!(!spans.iter().any(|s| s.name == "egress.connect"));
}
#[tokio::test]
async fn telemetry_keeps_public_url_components_without_credentials() {
    use std::io::{Read, Seek};
    let proxy = Proxy::new(RootCertStore::empty()).await;
    let mut logs = proxy.logs.try_clone().unwrap();
    let stream = TcpStream::connect(proxy.addr).await.unwrap();
    assert_eq!(exchange(stream, "GET http://sentinel-user:sentinel-password@denied.invalid/path?access_token=sentinel-token&api-key=sentinel-api&x-api-key=sentinel-xapi&q=public HTTP/1.1\r\nHost: denied.invalid\r\nConnection: close\r\n\r\n").await.0, 403);
    let spans = proxy.finish().await;
    assert!(spans.iter().any(|s| attribute(
        s,
        "url.full",
        "http://denied.invalid/path?access_token=%5Bredacted%5D&api-key=%5Bredacted%5D&x-api-key=%5Bredacted%5D&q=public"
    )));
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
async fn plain_http_streams_request_and_response_bodies() {
    let proxy = Proxy::new(RootCertStore::empty()).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let peer = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        hyper::server::conn::http1::Builder::new()
            .keep_alive(false)
            .serve_connection(
                TokioIo::new(stream),
                service_fn(|req: Request<Incoming>| async {
                    assert!(!req.headers().contains_key("traceparent"));
                    let length = req.headers()[header::CONTENT_LENGTH].clone();
                    let mut response = Response::new(req.into_body());
                    response
                        .headers_mut()
                        .insert(header::CONTENT_LENGTH, length);
                    Ok::<_, Infallible>(response)
                }),
            )
            .await
            .unwrap();
    });
    let payload = "x".repeat(70000);
    let stream = TcpStream::connect(proxy.addr).await.unwrap();
    let response = exchange(stream, &format!("POST http://localhost:{port}/echo HTTP/1.1\r\nHost: localhost:{port}\r\ntraceparent: sentinel\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}", payload.len())).await;
    assert_eq!(response, (200, payload));
    peer.await.unwrap();
    proxy.finish().await;
}
#[tokio::test]
async fn non_http_tunnel_bytes_close_with_protocol_refusal() {
    let proxy = Proxy::new(RootCertStore::empty()).await;
    let mut stream = proxy.tunnel(443).await;
    stream.write_all(b"\x01garbage").await.unwrap();
    assert_eq!(stream.read(&mut [0; 1]).await.unwrap(), 0);
    drop(stream);
    let spans = proxy.finish().await;
    assert!(
        spans
            .iter()
            .any(|s| attribute(s, "egress.decision", "refused:protocol"))
    );
    assert!(!spans.iter().any(|s| s.name == "egress.connect"));
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
