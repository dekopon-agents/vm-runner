use super::*;
use hickory_proto::{
    op::{Message, MessageType, OpCode, Query, ResponseCode},
    rr::{Name, RData, RecordType, rdata::A},
};
use std::net::Ipv4Addr;
use tokio::net::UdpSocket;

struct Gateway {
    proxy: Proxy,
    dns: SocketAddr,
    https: SocketAddr,
    udp: SocketAddr,
}
impl Gateway {
    async fn new(egress: Egress) -> Self {
        Self::with_peers(egress, [IpAddr::V4(Ipv4Addr::LOCALHOST)].into()).await
    }
    async fn with_peers(egress: Egress, dns_peers: std::collections::HashSet<IpAddr>) -> Self {
        Self::with_models(egress, dns_peers, None).await
    }
    async fn with_models(
        egress: Egress,
        dns_peers: std::collections::HashSet<IpAddr>,
        models: Option<models::Route>,
    ) -> Self {
        let http = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let https = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let https_addr = https.local_addr().unwrap();
        let dns = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dns_addr = dns.local_addr().unwrap();
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_addr = udp.local_addr().unwrap();
        let listeners = gateway::Listeners {
            explicit: None,
            http: Some(http),
            https: Some(https),
            dns: Some((dns, Ipv4Addr::LOCALHOST)),
            udp: Some((udp, Ipv4Addr::LOCALHOST)),
            dns_peers,
        };
        let exporter = InMemorySpanExporter::default();
        let proxy = Proxy::with_listeners(
            RootCertStore::empty(),
            egress,
            exporter.clone(),
            exporter,
            Some(listeners),
            Default::default(),
            None,
            models,
        )
        .await;
        Self {
            proxy,
            dns: dns_addr,
            https: https_addr,
            udp: udp_addr,
        }
    }
}
fn query(name: &str, kind: RecordType) -> Vec<u8> {
    let mut query = Message::new(42, MessageType::Query, OpCode::Query);
    query.metadata.recursion_desired = true;
    query.add_query(Query::query(Name::from_ascii(name).unwrap(), kind));
    query.to_vec().unwrap()
}
async fn tcp_query(stream: &mut TcpStream, packet: &[u8]) -> Message {
    stream
        .write_u16(packet.len().try_into().unwrap())
        .await
        .unwrap();
    stream.write_all(packet).await.unwrap();
    let length = stream.read_u16().await.unwrap();
    let mut response = vec![0; length.into()];
    stream.read_exact(&mut response).await.unwrap();
    Message::from_vec(&response).unwrap()
}
#[tokio::test]
async fn dns_udp_and_tcp_answer_only_allowed_address_questions_and_span_each_once() {
    let gateway = Gateway::new(local_egress()).await;
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut tcp = TcpStream::connect(gateway.dns).await.unwrap();
    let cases = [
        (
            "LOCALHOST.",
            RecordType::A,
            ResponseCode::NoError,
            "allowed",
        ),
        (
            "localhost.",
            RecordType::AAAA,
            ResponseCode::NoError,
            "allowed",
        ),
        (
            "denied.invalid.",
            RecordType::A,
            ResponseCode::NXDomain,
            "refused:host",
        ),
        (
            "localhost.",
            RecordType::MX,
            ResponseCode::NXDomain,
            "refused:type",
        ),
    ];
    for (name, kind, code, _) in cases {
        let packet = query(name, kind);
        socket.send_to(&packet, gateway.udp).await.unwrap();
        let mut received = [0; 1024];
        let (length, _) = socket.recv_from(&mut received).await.unwrap();
        assert!(length <= 512);
        let udp = Message::from_vec(&received[..length]).unwrap();
        let tcp = tcp_query(&mut tcp, &packet).await;
        assert_eq!(udp, tcp);
        assert_eq!(udp.id, 42);
        assert_eq!(udp.response_code, code);
        assert!(!udp.truncation);
        assert!(!udp.recursion_available);
        if kind == RecordType::A && code == ResponseCode::NoError {
            assert_eq!(udp.answers.len(), 1);
            assert_eq!(udp.answers[0].ttl, 30);
            assert_eq!(udp.answers[0].data, RData::A(A(Ipv4Addr::LOCALHOST)));
        } else {
            assert!(udp.answers.is_empty());
        }
    }
    drop(tcp);
    let (spans, logs) = gateway.proxy.finish_with_logs().await;
    assert_eq!(spans.len(), cases.len() * 2);
    assert_eq!(
        logs.iter()
            .filter(|log| log.record.event_name() == Some("egress.dns.rollup"))
            .filter_map(|log| log_int(log, "egress.dns.count"))
            .sum::<i64>(),
        i64::try_from(cases.len() * 2).unwrap()
    );
    assert_eq!(
        logs.iter()
            .filter(|log| log.record.event_name() == Some("egress.dns.rollup"))
            .filter_map(|log| log_int(log, "egress.dns.refused.count"))
            .sum::<i64>(),
        4
    );
    assert_eq!(
        logs.iter()
            .filter(|log| log.record.event_name() == Some("egress.refused"))
            .count(),
        4
    );
    for (name, kind, _, decision) in cases {
        let matching: Vec<_> = spans
            .iter()
            .filter(|s| {
                s.name == "egress.dns"
                    && attribute(s, "dns.question.name", name)
                    && attribute(s, "dns.question.type", &kind.to_string())
            })
            .collect();
        assert_eq!(matching.len(), 2, "{spans:?}");
        for span in matching {
            assert!(attribute(span, "egress.decision", decision));
        }
    }
}
#[tokio::test]
async fn gateway_ports_classify_http_tls_and_refuse_non_protocol_streams() {
    let mut egress = local_egress();
    egress.allow_private.clear();
    let gateway = Gateway::new(egress).await;
    for address in [gateway.proxy.addr, gateway.https] {
        let stream = TcpStream::connect(address).await.unwrap();
        assert_eq!(
            exchange(
                stream,
                "GET /plain HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
            )
            .await,
            (403, "egress refused: localhost".into())
        );
        let stream = TcpStream::connect(address).await.unwrap();
        let tls = TlsConnector::from(Arc::clone(&gateway.proxy.tls))
            .connect(ServerName::try_from("localhost").unwrap(), stream)
            .await
            .unwrap();
        assert_eq!(
            exchange(
                tls,
                "GET /tls HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
            )
            .await,
            (403, "egress refused: localhost".into())
        );
        let mut stream = TcpStream::connect(address).await.unwrap();
        stream.write_all(b"\x01not HTTP or TLS").await.unwrap();
        assert_eq!(stream.read(&mut [0; 1]).await.unwrap(), 0);
    }
    let spans = gateway.proxy.finish().await;
    for (scheme, path) in [("http", "/plain"), ("https", "/tls")] {
        let requests: Vec<_> = spans
            .iter()
            .filter(|s| attribute(s, "url.scheme", scheme) && attribute(s, "url.path", path))
            .collect();
        assert_eq!(requests.len(), 2);
        for request in requests {
            assert!(attribute(request, "egress.decision", "refused:address"));
        }
    }
    assert_eq!(
        spans
            .iter()
            .filter(|s| attribute(s, "egress.exchange.outcome", "protocol-error"))
            .count(),
        2
    );
}
#[tokio::test]
async fn gateway_origin_form_forwards_by_host_and_strips_trace_context() {
    let gateway = Gateway::new(local_egress()).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let peer = tokio::spawn(upstream(listener, None));
    let stream = TcpStream::connect(gateway.proxy.addr).await.unwrap();
    assert_eq!(exchange(stream, &format!("GET / HTTP/1.1\r\nHost: localhost:{port}\r\ntraceparent: sentinel\r\ntracestate: sentinel\r\nConnection: close\r\n\r\n")).await,
        (200, "upstream".into()));
    let received = peer.await.unwrap();
    assert!(!received.contains_key("traceparent"));
    assert!(!received.contains_key("tracestate"));
    let spans = gateway.proxy.finish().await;
    assert!(
        spans
            .iter()
            .any(|s| attribute(s, "egress.decision", "allowed"))
    );
}
#[tokio::test]
async fn readiness_log_keeps_the_bound_address_for_explicit_and_gateway_launchers() {
    use std::io::{Read, Seek};
    for proxy in [
        Proxy::new(RootCertStore::empty()).await,
        Gateway::new(local_egress()).await.proxy,
    ] {
        let mut logs = proxy.logs.try_clone().unwrap();
        let address = proxy.addr;
        proxy.finish().await;
        logs.rewind().unwrap();
        let mut text = String::new();
        logs.read_to_string(&mut text).unwrap();
        let records: Vec<serde_json::Value> = text
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .filter(|record: &serde_json::Value| record["fields"]["message"] == "listening")
            .collect();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["fields"]["addr"], address.to_string());
    }
}
#[tokio::test]
async fn tcp_dns_shares_the_http_connection_cap_but_udp_needs_no_connection_slot() {
    let mut egress = local_egress();
    egress.max_connections = 1.try_into().unwrap();
    let gateway = Gateway::new(egress).await;
    let mut first = TcpStream::connect(gateway.dns).await.unwrap();
    let packet = query("localhost.", RecordType::A);
    assert_eq!(tcp_query(&mut first, &packet).await.answers.len(), 1);
    for address in [gateway.dns, gateway.proxy.addr, gateway.https] {
        let mut excess = TcpStream::connect(address).await.unwrap();
        assert_eq!(excess.read(&mut [0; 1]).await.unwrap(), 0);
    }
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    udp.send_to(&packet, gateway.udp).await.unwrap();
    let mut response = [0; 512];
    let (length, _) = udp.recv_from(&mut response).await.unwrap();
    assert_eq!(
        Message::from_vec(&response[..length])
            .unwrap()
            .answers
            .len(),
        1
    );
    drop(first);
    let (_, logs) = gateway.proxy.finish_with_logs().await;
    let refused: i64 = logs
        .iter()
        .filter(|log| log.record.event_name() == Some("egress.refused"))
        .filter_map(|log| log_int(log, "egress.refused.count"))
        .sum();
    assert_eq!(refused, 3);
}

#[tokio::test]
async fn reset_tcp_dns_connections_do_not_stop_dns_or_http_service() {
    let gateway = Gateway::new(local_egress()).await;
    for _ in 0..8 {
        let reset = TcpStream::connect(gateway.dns).await.unwrap();
        #[expect(
            deprecated,
            reason = "zero linger injects an immediate TCP reset without blocking on close"
        )]
        reset.set_linger(Some(Duration::ZERO)).unwrap();
        drop(reset);
        let mut dns = TcpStream::connect(gateway.dns).await.unwrap();
        assert_eq!(
            tcp_query(&mut dns, &query("localhost.", RecordType::A))
                .await
                .answers
                .len(),
            1
        );
        let http = TcpStream::connect(gateway.proxy.addr).await.unwrap();
        assert_eq!(
            exchange(
                http,
                "GET / HTTP/1.1\r\nHost: denied.invalid\r\nConnection: close\r\n\r\n"
            )
            .await,
            (403, "egress refused: denied.invalid".into())
        );
    }
    let spans = gateway.proxy.finish().await;
    assert_eq!(
        spans
            .iter()
            .filter(|s| s.name == "egress.dns" && attribute(s, "egress.decision", "allowed"))
            .count(),
        8
    );
    assert_eq!(
        spans
            .iter()
            .filter(|s| s.name == "egress.request"
                && attribute(s, "egress.decision", "refused:not_allowed"))
            .count(),
        8
    );
}

type ReceivedDatagram = std::io::Result<(Vec<u8>, SocketAddr)>;
struct DatagramScript {
    received: Mutex<std::collections::VecDeque<ReceivedDatagram>>,
    send_errors: Mutex<std::collections::VecDeque<std::io::Error>>,
    sent: Mutex<Vec<(Vec<u8>, SocketAddr)>>,
    stop: watch::Sender<bool>,
}
impl gateway::Datagram for &DatagramScript {
    async fn recv_from(&self, packet: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        let next = self.received.lock().unwrap().pop_front();
        if let Some(next) = next {
            let (bytes, peer) = next?;
            packet[..bytes.len()].copy_from_slice(&bytes);
            return Ok((bytes.len(), peer));
        }
        self.stop.send_replace(true);
        std::future::pending().await
    }
    async fn send_to(&self, packet: &[u8], peer: SocketAddr) -> std::io::Result<usize> {
        if let Some(error) = self.send_errors.lock().unwrap().pop_front() {
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
            return Err(error);
        }
        self.sent.lock().unwrap().push((packet.to_vec(), peer));
        Ok(packet.len())
    }
}
async fn datagram_fault_keeps_serving(port_zero: bool, receive_error: bool) {
    let engine = Engine {
        ca: Ca::new().unwrap().0,
        egress: local_egress(),
        tls: client_config(RootCertStore::empty()).unwrap(),
        omit: Default::default(),
        rollups: Arc::new(Mutex::new(Rollups::new())),
        models: None,
    };
    let exporter = InMemorySpanExporter::default();
    let provider = SdkTracerProvider::builder()
        .with_simple_exporter(exporter.clone())
        .build();
    let subscriber = tracing_subscriber::registry()
        .with(tracing_opentelemetry::layer().with_tracer(provider.tracer("dns-fault")));
    let (stop, stopped) = watch::channel(false);
    let peer = SocketAddr::from((Ipv4Addr::LOCALHOST, 1234));
    let mut first = query("localhost.", RecordType::A);
    first[..2].copy_from_slice(&41_u16.to_be_bytes());
    let first = if receive_error {
        Err(std::io::Error::from_raw_os_error(22))
    } else {
        Ok((
            first,
            if port_zero {
                SocketAddr::new(peer.ip(), 0)
            } else {
                peer
            },
        ))
    };
    let script = DatagramScript {
        received: Mutex::new([first, Ok((query("localhost.", RecordType::A), peer))].into()),
        send_errors: Mutex::new(if port_zero || receive_error {
            [].into()
        } else {
            [std::io::Error::from_raw_os_error(22)].into()
        }),
        sent: Mutex::new(Vec::new()),
        stop,
    };
    gateway::udp(
        &engine,
        &script,
        Ipv4Addr::LOCALHOST,
        &[peer.ip()].into(),
        stopped,
    )
    .with_subscriber(subscriber)
    .await
    .unwrap();
    let sent = script.sent.lock().unwrap();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].1, peer);
    let response = Message::from_vec(&sent[0].0).unwrap();
    assert_eq!(response.id, 42);
    assert_eq!(response.answers.len(), 1);
    let spans = exporter.get_finished_spans().unwrap();
    assert_eq!(spans.len(), 2);
    assert!(spans.iter().all(|s| s.name == "egress.dns"));
    assert!(attribute(
        &spans[0],
        "egress.decision",
        if port_zero {
            "refused:address"
        } else if receive_error {
            "refused:protocol"
        } else {
            "allowed"
        }
    ));
    assert!(attribute(&spans[1], "egress.decision", "allowed"));
    provider.shutdown().unwrap();
}
#[tokio::test]
async fn port_zero_datagram_is_dropped_and_the_stub_serves_the_next_query() {
    datagram_fault_keeps_serving(true, false).await;
}
#[tokio::test]
async fn einval_send_is_per_datagram_and_the_stub_serves_the_next_query() {
    datagram_fault_keeps_serving(false, false).await;
}
#[tokio::test]
async fn receive_error_is_per_datagram_and_the_stub_serves_the_next_query() {
    datagram_fault_keeps_serving(false, true).await;
}
fn assert_protocol_span(spans: &[SpanData]) {
    assert_eq!(spans.len(), 1, "{spans:?}");
    assert_eq!(spans[0].name, "egress.dns");
    for (key, value) in [
        ("dns.question.name", ""),
        ("dns.question.type", ""),
        ("egress.decision", "refused:protocol"),
    ] {
        assert!(attribute(&spans[0], key, value), "{spans:?}");
    }
}
#[tokio::test]
async fn formerr_and_qr_packets_each_emit_exactly_one_protocol_refusal() {
    let empty = Message::new(43, MessageType::Query, OpCode::Query);
    let mut multiple = empty.clone();
    multiple.add_query(Query::query(
        Name::from_ascii("localhost.").unwrap(),
        RecordType::A,
    ));
    multiple.add_query(Query::query(
        Name::from_ascii("localhost.").unwrap(),
        RecordType::AAAA,
    ));
    let mut update = multiple.clone();
    update.metadata.op_code = OpCode::Update;
    update.queries.truncate(1);
    let mut qr = update.clone();
    qr.metadata.op_code = OpCode::Query;
    qr.metadata.message_type = MessageType::Response;
    for packet in [empty, multiple, update, qr] {
        for tcp in [false, true] {
            let gateway = Gateway::new(local_egress()).await;
            let bytes = packet.to_vec().unwrap();
            let dropped = packet.message_type == MessageType::Response;
            if tcp {
                let mut stream = TcpStream::connect(gateway.dns).await.unwrap();
                if dropped {
                    stream
                        .write_u16(bytes.len().try_into().unwrap())
                        .await
                        .unwrap();
                    stream.write_all(&bytes).await.unwrap();
                    stream.shutdown().await.unwrap();
                    assert_eq!(stream.read(&mut [0; 1]).await.unwrap(), 0);
                } else {
                    assert_eq!(
                        tcp_query(&mut stream, &bytes).await.response_code,
                        ResponseCode::FormErr
                    );
                }
            } else {
                let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                socket.send_to(&bytes, gateway.udp).await.unwrap();
                let mut received = [0; 512];
                let response = tokio::time::timeout(
                    Duration::from_millis(100),
                    socket.recv_from(&mut received),
                )
                .await;
                if dropped {
                    assert!(response.is_err(), "QR=1 must never be answered");
                } else {
                    let (length, _) = response.unwrap().unwrap();
                    assert_eq!(
                        Message::from_vec(&received[..length])
                            .unwrap()
                            .response_code,
                        ResponseCode::FormErr
                    );
                }
            }
            assert_protocol_span(&gateway.proxy.finish().await);
        }
    }
}
#[tokio::test]
async fn tcp_garbage_zero_length_and_partial_frames_each_emit_one_protocol_refusal() {
    for bytes in [
        b"GET / HTTP/1.1\r\n\r\n".as_slice(),
        b"\x00\x00",
        b"\x00\x03bad",
        b"\x00",
    ] {
        let gateway = Gateway::new(local_egress()).await;
        let mut stream = TcpStream::connect(gateway.dns).await.unwrap();
        stream.write_all(bytes).await.unwrap();
        stream.shutdown().await.unwrap();
        assert_eq!(stream.read(&mut [0; 1]).await.unwrap(), 0);
        assert_protocol_span(&gateway.proxy.finish().await);
    }
}
#[tokio::test]
async fn punycode_allow_entries_match_dns_and_http_and_remain_ascii_in_spans() {
    let name = "xn--80ak6aa92e.com";
    let mut egress = local_egress();
    egress.allow = vec![name.into()];
    let gateway = Gateway::new(egress).await;
    let mut dns = TcpStream::connect(gateway.dns).await.unwrap();
    let reply = tcp_query(&mut dns, &query(&format!("{name}."), RecordType::A)).await;
    assert_eq!(reply.response_code, ResponseCode::NoError);
    assert_eq!(reply.answers.len(), 1);
    drop(dns);
    // CONNECT's HTTP allow-check requires no external lookup or upstream connection.
    let mut http = TcpStream::connect(gateway.proxy.addr).await.unwrap();
    http.write_all(format!("CONNECT {name}:443 HTTP/1.1\r\nHost: {name}:443\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut response = Vec::new();
    while !response.ends_with(b"\r\n\r\n") {
        response.push(http.read_u8().await.unwrap());
    }
    assert!(response.starts_with(b"HTTP/1.1 200 "));
    drop(http);
    let spans = gateway.proxy.finish().await;
    let dns = spans.iter().find(|s| s.name == "egress.dns").unwrap();
    assert!(attribute(dns, "dns.question.name", &format!("{name}.")));
    assert!(attribute(dns, "egress.decision", "allowed"));
    let http = spans
        .iter()
        .find(|s| attribute(s, "http.request.method", "CONNECT"))
        .unwrap();
    assert!(attribute(http, "server.address", name));
    assert!(attribute(http, "egress.decision", "allowed"));
}
#[tokio::test]
async fn off_gateway_subnet_peers_get_no_udp_or_tcp_answer() {
    let peers = gateway::subnet_peers(Ipv4Addr::new(10, 0, 2, 1));
    assert_eq!(
        peers,
        [
            IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 2, 2))
        ]
        .into()
    );
    let gateway = Gateway::with_peers(local_egress(), peers).await;
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket
        .send_to(&query("localhost.", RecordType::A), gateway.udp)
        .await
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(100), socket.recv_from(&mut [0; 512]))
            .await
            .is_err()
    );
    let mut stream = TcpStream::connect(gateway.dns).await.unwrap();
    assert_eq!(stream.read(&mut [0; 1]).await.unwrap(), 0);
    let spans = gateway.proxy.finish().await;
    assert_eq!(spans.len(), 2);
    assert!(
        spans
            .iter()
            .all(|s| s.name == "egress.dns" && attribute(s, "egress.decision", "refused:address"))
    );
}
#[tokio::test(start_paused = true)]
async fn tcp_dns_idle_closes_at_ten_seconds_and_activity_resets_the_deadline() {
    let engine = Engine {
        ca: Ca::new().unwrap().0,
        egress: local_egress(),
        tls: client_config(RootCertStore::empty()).unwrap(),
        omit: Default::default(),
        rollups: Arc::new(Mutex::new(Rollups::new())),
        models: None,
    };
    let exporter = InMemorySpanExporter::default();
    let provider = SdkTracerProvider::builder()
        .with_simple_exporter(exporter.clone())
        .build();
    let subscriber = tracing::Dispatch::new(
        tracing_subscriber::registry()
            .with(tracing_opentelemetry::layer().with_tracer(provider.tracer("dns-idle"))),
    );
    for active in [false, true] {
        let (mut client, stream) = tokio::io::duplex(4096);
        let mut record = ConnectionRecord::default();
        let mut connection = Box::pin(
            engine
                .bounded_connection(
                    Box::new(stream),
                    &mut record,
                    Instant::now(),
                    gateway::Protocol::Dns(Ipv4Addr::LOCALHOST),
                )
                .with_subscriber(subscriber.clone()),
        );
        poll_pending(connection.as_mut()).await;
        if active {
            tokio::time::advance(Duration::from_secs(9)).await;
            client.write_all(b"\x00").await.unwrap();
            poll_pending(connection.as_mut()).await;
        }
        tokio::time::advance(Duration::from_secs(9)).await;
        poll_pending(connection.as_mut()).await;
        tokio::time::advance(Duration::from_secs(1)).await;
        let error = connection.await.unwrap_err();
        assert!(matches!(
            error.downcast_ref::<ConnectionTimeout>(),
            Some(ConnectionTimeout::Idle)
        ));
        assert_eq!(client.read(&mut [0; 1]).await.unwrap(), 0);
    }
    assert_protocol_span(&exporter.get_finished_spans().unwrap());
    provider.shutdown().unwrap();
}

struct ModelPki {
    issuer: rcgen::Issuer<'static, KeyPair>,
    ca: String,
}
impl ModelPki {
    fn new() -> Self {
        let mut params = rcgen::CertificateParams::default();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "test homelab-ca");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let key = KeyPair::generate().unwrap();
        let ca = params.self_signed(&key).unwrap().pem();
        Self {
            issuer: rcgen::Issuer::new(params, key),
            ca,
        }
    }
    fn leaf(&self, san: rcgen::SanType, usage: rcgen::ExtendedKeyUsagePurpose) -> (String, String) {
        let mut params = rcgen::CertificateParams::default();
        params.subject_alt_names = vec![san];
        params.extended_key_usages = vec![usage];
        let key = KeyPair::generate().unwrap();
        let cert = params.signed_by(&key, &self.issuer).unwrap();
        (cert.pem(), key.serialize_pem())
    }
    fn client(&self, dir: &std::path::Path) -> Vec<u8> {
        let (cert, key) = self.leaf(
            rcgen::SanType::URI(
                "spiffe://homelab/ns/vm-runner/sa/vm-runner-jail"
                    .try_into()
                    .unwrap(),
            ),
            rcgen::ExtendedKeyUsagePurpose::ClientAuth,
        );
        std::fs::write(dir.join("tls.crt"), &cert).unwrap();
        std::fs::write(dir.join("tls.key"), key).unwrap();
        std::fs::write(dir.join("ca.crt"), &self.ca).unwrap();
        CertificateDer::from_pem_slice(cert.as_bytes())
            .unwrap()
            .to_vec()
    }
    /// dekopon-gatewayd's side of the contract: a client certificate chained to the CA is required.
    fn server(&self) -> Arc<ServerConfig> {
        let (cert, key) = self.leaf(
            rcgen::SanType::DnsName("localhost".try_into().unwrap()),
            rcgen::ExtendedKeyUsagePurpose::ServerAuth,
        );
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from_pem_slice(self.ca.as_bytes()).unwrap())
            .unwrap();
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::clone(&provider),
        )
        .build()
        .unwrap();
        Arc::new(
            ServerConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_client_cert_verifier(verifier)
                .with_single_cert(
                    vec![CertificateDer::from_pem_slice(cert.as_bytes()).unwrap()],
                    rustls::pki_types::PrivateKeyDer::from_pem_slice(key.as_bytes()).unwrap(),
                )
                .unwrap(),
        )
    }
}
struct ModelRequest {
    path: String,
    headers: hyper::HeaderMap,
    client_cert: Vec<u8>,
}
async fn model_upstream(
    listener: TcpListener,
    server: Arc<ServerConfig>,
    count: usize,
) -> Vec<ModelRequest> {
    let mut received = Vec::new();
    for _ in 0..count {
        let (stream, _) = listener.accept().await.unwrap();
        let tls = tokio_rustls::TlsAcceptor::from(Arc::clone(&server))
            .accept(stream)
            .await
            .unwrap();
        let client_cert = tls.get_ref().1.peer_certificates().unwrap()[0].to_vec();
        let seen = Arc::new(Mutex::new(None));
        let record = Arc::clone(&seen);
        hyper::server::conn::http1::Builder::new()
            .keep_alive(false)
            .serve_connection(
                TokioIo::new(tls),
                service_fn(move |req: Request<Incoming>| {
                    *record.lock().unwrap() = Some((req.uri().to_string(), req.headers().clone()));
                    async {
                        Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"model"))))
                    }
                }),
            )
            .await
            .unwrap();
        let (path, headers) = seen.lock().unwrap().take().unwrap();
        received.push(ModelRequest {
            path,
            headers,
            client_cert,
        });
    }
    received
}
const FORGED: &str =
    "x-dekopon-vm-subject: dekopon:forged\r\nX-Dekopon-VM-Subject: dekopon:forged-too\r\n";
#[tokio::test]
async fn models_route_answers_dns_and_forwards_sni_host_and_connect_over_mtls_with_one_subject() {
    let pki = ModelPki::new();
    let dir = tempfile::tempdir().unwrap();
    let first = pki.client(dir.path());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    // The fourth request runs after the client certificate rotates on disk.
    let peer = tokio::spawn(model_upstream(listener, pki.server(), 4));
    let route = models::Route::new(
        &format!("https://localhost:{port}"),
        "dekopon:gylmar-vm",
        dir.path().to_owned(),
    )
    .unwrap();
    let mut egress = local_egress();
    // The route must not depend on the allowlist or on the private-address exception.
    egress.allow_private.clear();
    let gateway = Gateway::with_models(
        egress,
        [IpAddr::V4(Ipv4Addr::LOCALHOST)].into(),
        Some(route),
    )
    .await;

    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket
        .send_to(&query("Models.VM.Internal.", RecordType::A), gateway.udp)
        .await
        .unwrap();
    let mut received = [0; 512];
    let (length, _) = socket.recv_from(&mut received).await.unwrap();
    let answer = Message::from_vec(&received[..length]).unwrap();
    assert_eq!(answer.response_code, ResponseCode::NoError);
    assert_eq!(answer.answers[0].data, RData::A(A(Ipv4Addr::LOCALHOST)));

    let request = |path: &str| {
        format!(
            "POST {path} HTTP/1.1\r\nHost: models.vm.internal\r\n{FORGED}authorization: Bearer vm\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}"
        )
    };
    // SNI on the gateway's :443.
    let stream = TcpStream::connect(gateway.https).await.unwrap();
    let tls = TlsConnector::from(Arc::clone(&gateway.proxy.tls))
        .connect(ServerName::try_from(models::HOST).unwrap(), stream)
        .await
        .unwrap();
    assert_eq!(
        exchange(tls, &request("/v1/messages")).await,
        (200, "model".into())
    );
    // Origin-form Host on :80.
    let stream = TcpStream::connect(gateway.proxy.addr).await.unwrap();
    assert_eq!(
        exchange(stream, &request("/v1/responses")).await,
        (200, "model".into())
    );
    // CONNECT, then TLS inside the tunnel.
    let mut stream = TcpStream::connect(gateway.proxy.addr).await.unwrap();
    stream
        .write_all(
            b"CONNECT models.vm.internal:443 HTTP/1.1\r\nHost: models.vm.internal:443\r\n\r\n",
        )
        .await
        .unwrap();
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        head.push(stream.read_u8().await.unwrap());
    }
    assert!(head.starts_with(b"HTTP/1.1 200 "));
    let tls = TlsConnector::from(Arc::clone(&gateway.proxy.tls))
        .connect(ServerName::try_from(models::HOST).unwrap(), stream)
        .await
        .unwrap();
    assert_eq!(
        exchange(tls, &request("/v1/chat/completions")).await,
        (200, "model".into())
    );
    // cert-manager rotates the Secret; the next connection presents the new pair.
    let second = pki.client(dir.path());
    let stream = TcpStream::connect(gateway.proxy.addr).await.unwrap();
    assert_eq!(
        exchange(stream, &request("/v1/messages/count_tokens")).await,
        (200, "model".into())
    );

    let received = peer.await.unwrap();
    let paths: Vec<_> = received.iter().map(|r| r.path.as_str()).collect();
    assert_eq!(
        paths,
        [
            "/v1/messages",
            "/v1/responses",
            "/v1/chat/completions",
            "/v1/messages/count_tokens"
        ]
    );
    for request in &received {
        let subjects: Vec<_> = request
            .headers
            .get_all(models::SUBJECT_HEADER)
            .iter()
            .collect();
        assert_eq!(subjects, ["dekopon:gylmar-vm"]);
        assert_eq!(request.headers[header::HOST], format!("localhost:{port}"));
        // The guest's token is left for dekopon-gatewayd to drop; the jail adds no credential.
        assert_eq!(request.headers[header::AUTHORIZATION], "Bearer vm");
    }
    assert!(received[..3].iter().all(|r| r.client_cert == first));
    assert_eq!(received[3].client_cert, second);
    assert_ne!(first, second);

    let spans = gateway.proxy.finish().await;
    // Four forwarded requests plus the CONNECT envelope.
    assert_eq!(
        spans
            .iter()
            .filter(|s| s.name == "egress.request" && attribute(s, "egress.decision", "allowed"))
            .count(),
        5
    );
    assert_eq!(
        spans.iter().filter(|s| s.name == "egress.connect").count(),
        4
    );
}
#[tokio::test]
async fn models_name_is_refused_without_a_route_and_its_header_never_leaves_for_other_hosts() {
    let gateway = Gateway::new(local_egress()).await;
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket
        .send_to(&query("models.vm.internal.", RecordType::A), gateway.udp)
        .await
        .unwrap();
    let mut received = [0; 512];
    let (length, _) = socket.recv_from(&mut received).await.unwrap();
    assert_eq!(
        Message::from_vec(&received[..length])
            .unwrap()
            .response_code,
        ResponseCode::NXDomain
    );
    let stream = TcpStream::connect(gateway.proxy.addr).await.unwrap();
    assert_eq!(
        exchange(
            stream,
            "GET / HTTP/1.1\r\nHost: models.vm.internal\r\nConnection: close\r\n\r\n"
        )
        .await,
        (403, "egress refused: models.vm.internal".into())
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let peer = tokio::spawn(upstream(listener, None));
    let stream = TcpStream::connect(gateway.proxy.addr).await.unwrap();
    assert_eq!(
        exchange(
            stream,
            &format!(
                "GET / HTTP/1.1\r\nHost: localhost:{port}\r\n{FORGED}Connection: close\r\n\r\n"
            )
        )
        .await
        .0,
        200
    );
    assert!(!peer.await.unwrap().contains_key(models::SUBJECT_HEADER));
    let spans = gateway.proxy.finish().await;
    assert!(
        spans
            .iter()
            .any(|s| attribute(s, "egress.decision", "refused:not_allowed"))
    );
}
#[test]
fn models_upstream_is_an_https_origin_and_subject_is_namespace_name() {
    assert_eq!(
        models::upstream("https://dekopon.dekopon.svc.cluster.local:9090").unwrap(),
        (
            "dekopon.dekopon.svc.cluster.local".into(),
            ServerName::try_from("dekopon.dekopon.svc.cluster.local").unwrap(),
            9090
        )
    );
    assert_eq!(models::upstream("https://dekopon").unwrap().2, 443);
    // An IPv6 literal keeps its brackets in the authority but not in the TLS server name.
    assert_eq!(
        models::upstream("https://[::1]:9090").unwrap(),
        (
            "[::1]".into(),
            ServerName::IpAddress(std::net::Ipv6Addr::LOCALHOST.into()),
            9090
        )
    );
    assert!(models::Route::new("https://[::1]:9090", "dekopon:gylmar-vm", "/".into()).is_ok());
    for invalid in [
        "http://dekopon:9090",
        "https://dekopon:9090/v1",
        "https://user@dekopon:9090",
        "https://dekopon:9090/?q",
        "dekopon:9090",
    ] {
        assert!(models::upstream(invalid).is_err(), "{invalid}");
    }
    assert!(models::subject("dekopon:gylmar-vm").is_ok());
    for invalid in [
        "system:serviceaccount:dekopon:gylmar-vm",
        "dekopon:",
        "*:x",
        "x",
    ] {
        assert!(models::subject(invalid).is_err(), "{invalid}");
    }
}
