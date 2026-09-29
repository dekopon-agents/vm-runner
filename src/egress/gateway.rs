use super::{Engine, Error, Stream, allowed, cut};
use hickory_proto::{
    op::{Message, MessageType, OpCode, ResponseCode},
    rr::{DNSClass, RData, Record, RecordType, rdata::A},
};
use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::watch,
};

#[derive(Clone, Copy)]
pub(super) enum Protocol {
    Http,
    Dns(Ipv4Addr),
}
pub(super) struct Listeners {
    pub(super) explicit: Option<TcpListener>,
    pub(super) http: Option<TcpListener>,
    pub(super) https: Option<TcpListener>,
    pub(super) dns: Option<(TcpListener, Ipv4Addr)>,
    pub(super) udp: Option<(UdpSocket, Ipv4Addr)>,
    pub(super) dns_peers: HashSet<IpAddr>,
}
impl From<TcpListener> for Listeners {
    fn from(listener: TcpListener) -> Self {
        Self {
            explicit: Some(listener),
            http: None,
            https: None,
            dns: None,
            udp: None,
            dns_peers: HashSet::new(),
        }
    }
}
pub(super) fn subnet_peers(gateway: Ipv4Addr) -> HashSet<IpAddr> {
    let network = u32::from(gateway) & !3;
    // Only usable host addresses in the gateway's /30, never network or broadcast.
    [1, 2]
        .map(|host| IpAddr::V4(Ipv4Addr::from(network | host)))
        .into()
}
impl Listeners {
    pub(super) async fn bind(
        explicit: Option<SocketAddr>,
        gateway: Option<Ipv4Addr>,
    ) -> Result<Self, Error> {
        if explicit.is_none() && gateway.is_none() {
            return Err(super::RefusalError.into());
        }
        if let Some(address) = gateway {
            super::validate_gateway(address)?;
        }
        let mut listeners = Self {
            explicit: match explicit {
                Some(address) => Some(TcpListener::bind(address).await?),
                None => None,
            },
            http: None,
            https: None,
            dns: None,
            udp: None,
            dns_peers: gateway.map(subnet_peers).unwrap_or_default(),
        };
        if let Some(address) = gateway {
            listeners.udp = Some((UdpSocket::bind((address, 53)).await?, address));
            listeners.dns = Some((TcpListener::bind((address, 53)).await?, address));
            listeners.http = Some(TcpListener::bind((address, 80)).await?);
            listeners.https = Some(TcpListener::bind((address, 443)).await?);
        }
        Ok(listeners)
    }
    pub(super) async fn accept(&self) -> std::io::Result<(TcpStream, SocketAddr, Protocol)> {
        async fn accept(
            listener: Option<&TcpListener>,
        ) -> std::io::Result<(TcpStream, SocketAddr)> {
            match listener {
                Some(listener) => listener.accept().await,
                None => std::future::pending().await,
            }
        }
        tokio::select! {
            stream = accept(self.explicit.as_ref()) => stream.map(|(s, peer)| (s, peer, Protocol::Http)),
            stream = accept(self.http.as_ref()) => stream.map(|(s, peer)| (s, peer, Protocol::Http)),
            stream = accept(self.https.as_ref()) => stream.map(|(s, peer)| (s, peer, Protocol::Http)),
            stream = async {
                match &self.dns {
                    Some((listener, address)) => listener.accept().await.map(|(s, peer)| (s, peer, Protocol::Dns(*address))),
                    None => std::future::pending().await,
                }
            } => stream,
        }
    }
}
pub(super) enum Decision {
    Allowed,
    Host,
    Type,
    Protocol,
    Address,
}
impl Decision {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::Host => "refused:host",
            Self::Type => "refused:type",
            Self::Protocol => "refused:protocol",
            Self::Address => "refused:address",
        }
    }
}
pub(super) fn refusal(engine: &Engine, decision: Decision, name: &str) {
    if let Ok(mut rollups) = engine.rollups.lock() {
        rollups.dns(name, true);
    }
    let _span = tracing::debug_span!(target: crate::config::Category::EgressDns.target(), parent: None, "egress.dns",
        telemetry.detail = crate::telemetry::detail!(crate::config::Category::EgressDns), dns.question.name = %cut(name), dns.question.type = "", egress.decision = decision.as_str());
    tracing::info!(name: "egress.refused", target: crate::config::Category::EgressDrop.target(), {
        telemetry.detail = crate::telemetry::detail!(crate::config::Category::EgressDrop),
        dns.question.name = %cut(name), egress.decision = decision.as_str(), egress.refused.count = 1_i64,
    }, "egress.refused");
}
fn answer(engine: &Engine, packet: &[u8], gateway: Ipv4Addr) -> Result<Option<Vec<u8>>, Error> {
    let query = match Message::from_vec(packet) {
        Ok(query) => query,
        Err(error) => {
            refusal(engine, Decision::Protocol, "");
            return Err(error.into());
        }
    };
    let mut reply = Message::response(query.id, query.op_code);
    reply.metadata.recursion_desired = query.recursion_desired;
    if query.message_type != MessageType::Query
        || query.op_code != OpCode::Query
        || query.queries.len() != 1
    {
        refusal(engine, Decision::Protocol, "");
        if query.message_type != MessageType::Query {
            return Ok(None);
        }
        reply.metadata.response_code = ResponseCode::FormErr;
        return Ok(Some(reply.to_vec()?));
    }
    for question in &query.queries {
        let name = question.name().to_ascii();
        let kind = question.query_type();
        let decision = if !allowed(&name, &engine.egress.allow) {
            Decision::Host
        } else if question.query_class() != DNSClass::IN
            || !matches!(kind, RecordType::A | RecordType::AAAA)
        {
            Decision::Type
        } else {
            Decision::Allowed
        };
        if let Ok(mut rollups) = engine.rollups.lock() {
            rollups.dns(&name, !matches!(decision, Decision::Allowed));
        }
        if !matches!(decision, Decision::Allowed) {
            tracing::info!(name: "egress.refused", target: crate::config::Category::EgressDrop.target(), {
                telemetry.detail = crate::telemetry::detail!(crate::config::Category::EgressDrop),
                dns.question.name = %cut(&name), egress.decision = decision.as_str(), egress.refused.count = 1_i64,
            }, "egress.refused");
        }
        let span = tracing::debug_span!(target: crate::config::Category::EgressDns.target(), parent: None, "egress.dns",
            telemetry.detail = crate::telemetry::detail!(crate::config::Category::EgressDns), dns.question.name = %cut(&name), dns.question.type = %kind,
            egress.decision = decision.as_str());
        reply.add_query(question.clone());
        if !matches!(decision, Decision::Allowed) {
            reply.metadata.response_code = ResponseCode::NXDomain;
        } else if kind == RecordType::A {
            reply.add_answer(Record::from_rdata(
                question.name().clone(),
                30,
                RData::A(A(gateway)),
            ));
        }
        drop(span);
    }
    Ok(Some(reply.to_vec()?))
}
fn udp_reply(engine: &Engine, packet: &[u8], gateway: Ipv4Addr) -> Result<Option<Vec<u8>>, Error> {
    let Some(response) = answer(engine, packet, gateway)? else {
        return Ok(None);
    };
    if response.len() <= 512 {
        return Ok(Some(response));
    }
    Ok(Some(Message::from_vec(&response)?.truncate().to_vec()?))
}
// Keep the per-datagram error boundary testable without privileged raw sockets.
pub(super) trait Datagram {
    async fn recv_from(&self, packet: &mut [u8]) -> std::io::Result<(usize, SocketAddr)>;
    async fn send_to(&self, packet: &[u8], peer: SocketAddr) -> std::io::Result<usize>;
}
impl Datagram for UdpSocket {
    async fn recv_from(&self, packet: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        self.recv_from(packet).await
    }
    async fn send_to(&self, packet: &[u8], peer: SocketAddr) -> std::io::Result<usize> {
        self.send_to(packet, peer).await
    }
}
pub(super) async fn udp(
    engine: &Engine,
    socket: impl Datagram,
    gateway: Ipv4Addr,
    peers: &HashSet<IpAddr>,
    mut stop: watch::Receiver<bool>,
) -> Result<(), Error> {
    let mut packet = [0; 65535];
    loop {
        let received = tokio::select! {
            biased;
            _ = stop.changed() => return Ok(()),
            received = socket.recv_from(&mut packet) => received,
        };
        let (length, peer) = match received {
            Ok(received) => received,
            Err(error) => {
                tracing::warn!(name: "egress.dns.receive_failed", target: crate::config::Category::EgressDns.target(), {
                    telemetry.detail = crate::telemetry::detail!(crate::config::Category::EgressDns), %error,
                }, "egress DNS receive failed");
                refusal(engine, Decision::Protocol, "");
                // A broken socket must not spin; shutdown still interrupts retries.
                tokio::select! {
                    _ = stop.changed() => return Ok(()),
                    _ = tokio::time::sleep(Duration::from_millis(10)) => (),
                }
                continue;
            }
        };
        if peer.port() == 0 || !peers.contains(&peer.ip()) {
            refusal(engine, Decision::Address, "");
            continue;
        }
        match udp_reply(engine, &packet[..length], gateway) {
            Ok(Some(response)) => {
                // The query already emitted its one DNS span, including on send failure.
                if let Err(error) = socket.send_to(&response, peer).await {
                    tracing::warn!(name: "egress.dns.send_failed", target: crate::config::Category::EgressDns.target(), {
                        telemetry.detail = crate::telemetry::detail!(crate::config::Category::EgressDns), %error, %peer,
                    }, "egress DNS send failed");
                }
            }
            Ok(None) => (),
            Err(error) => {
                tracing::warn!(name: "egress.dns.datagram_refused", target: crate::config::Category::EgressDns.target(), {
                telemetry.detail = crate::telemetry::detail!(crate::config::Category::EgressDns), %error,
            }, "egress DNS datagram refused")
            }
        }
    }
}
struct PartialFrame<'a>(bool, &'a Engine);
impl Drop for PartialFrame<'_> {
    fn drop(&mut self) {
        if self.0 {
            refusal(self.1, Decision::Protocol, "");
        }
    }
}
async fn read_frame(engine: &Engine, stream: &mut Stream) -> std::io::Result<Option<Vec<u8>>> {
    let mut prefix = [0; 2];
    match stream.read(&mut prefix[..1]).await {
        Ok(0) => return Ok(None),
        Ok(_) => (),
        Err(error) => {
            refusal(engine, Decision::Protocol, "");
            return Err(error);
        }
    }
    // Partial frames are also refused once if the connection's idle/lifetime gate cancels us.
    let mut partial = PartialFrame(true, engine);
    stream.read_exact(&mut prefix[1..]).await?;
    let mut packet = vec![0; usize::from(u16::from_be_bytes(prefix))];
    stream.read_exact(&mut packet).await?;
    partial.0 = false;
    Ok(Some(packet))
}
pub(super) async fn tcp(
    engine: &Engine,
    mut stream: Stream,
    gateway: Ipv4Addr,
) -> Result<(), Error> {
    loop {
        let Some(packet) = read_frame(engine, &mut stream).await? else {
            return Ok(());
        };
        if let Some(response) = answer(engine, &packet, gateway)? {
            stream.write_u16(u16::try_from(response.len())?).await?;
            stream.write_all(&response).await?;
        }
    }
}
