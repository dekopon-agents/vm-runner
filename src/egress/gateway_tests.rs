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
        };
        let exporter = InMemorySpanExporter::default();
        let proxy = Proxy::with_listeners(
            RootCertStore::empty(),
            egress,
            exporter.clone(),
            exporter,
            Some(listeners),
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
    let spans = gateway.proxy.finish().await;
    assert_eq!(spans.len(), cases.len() * 2);
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
    for url in ["http://localhost/plain", "https://localhost/tls"] {
        let requests: Vec<_> = spans
            .iter()
            .filter(|s| attribute(s, "url.full", url))
            .collect();
        assert_eq!(requests.len(), 2);
        for request in requests {
            assert!(attribute(request, "egress.decision", "refused:address"));
        }
    }
    assert_eq!(
        spans
            .iter()
            .filter(|s| attribute(s, "egress.decision", "refused:protocol"))
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
    let spans = gateway.proxy.finish().await;
    let refused: i64 = spans
        .iter()
        .filter(|s| attribute(s, "egress.decision", "refused:connections"))
        .map(|s| match span_attribute(s, "count").unwrap() {
            opentelemetry::Value::I64(n) => *n,
            other => panic!("{other:?}"),
        })
        .sum();
    assert_eq!(refused, 3);
}
