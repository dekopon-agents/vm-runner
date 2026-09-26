use super::{Engine, Error, Stream, allowed, cut};
use hickory_proto::{
    op::{Message, MessageType, OpCode, ResponseCode},
    rr::{DNSClass, RData, Record, RecordType, rdata::A},
};
use std::net::{Ipv4Addr, SocketAddr};
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
}
impl From<TcpListener> for Listeners {
    fn from(listener: TcpListener) -> Self {
        Self {
            explicit: Some(listener),
            http: None,
            https: None,
            dns: None,
            udp: None,
        }
    }
}
impl Listeners {
    pub(super) async fn bind(
        explicit: Option<SocketAddr>,
        gateway: Option<Ipv4Addr>,
    ) -> Result<Self, Error> {
        if explicit.is_none() && gateway.is_none() {
            return Err(super::RefusalError.into());
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
        };
        if let Some(address) = gateway {
            listeners.udp = Some((UdpSocket::bind((address, 53)).await?, address));
            listeners.dns = Some((TcpListener::bind((address, 53)).await?, address));
            listeners.http = Some(TcpListener::bind((address, 80)).await?);
            listeners.https = Some(TcpListener::bind((address, 443)).await?);
        }
        Ok(listeners)
    }
    pub(super) async fn accept(&self) -> std::io::Result<(TcpStream, Protocol)> {
        async fn accept(listener: Option<&TcpListener>) -> std::io::Result<TcpStream> {
            match listener {
                Some(listener) => listener.accept().await.map(|(stream, _)| stream),
                None => std::future::pending().await,
            }
        }
        tokio::select! {
            stream = accept(self.explicit.as_ref()) => stream.map(|s| (s, Protocol::Http)),
            stream = accept(self.http.as_ref()) => stream.map(|s| (s, Protocol::Http)),
            stream = accept(self.https.as_ref()) => stream.map(|s| (s, Protocol::Http)),
            stream = async {
                match &self.dns {
                    Some((listener, address)) => listener.accept().await.map(|(s, _)| (s, Protocol::Dns(*address))),
                    None => std::future::pending().await,
                }
            } => stream,
        }
    }
}
enum Decision {
    Allowed,
    Host,
    Type,
}
impl Decision {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::Host => "refused:host",
            Self::Type => "refused:type",
        }
    }
}
fn answer(engine: &Engine, packet: &[u8], gateway: Ipv4Addr) -> Result<Vec<u8>, Error> {
    let query = Message::from_vec(packet)?;
    let mut reply = Message::response(query.id, query.op_code);
    reply.metadata.recursion_desired = query.recursion_desired;
    if query.message_type != MessageType::Query
        || query.op_code != OpCode::Query
        || query.queries.len() != 1
    {
        reply.metadata.response_code = ResponseCode::FormErr;
        return Ok(reply.to_vec()?);
    }
    for question in &query.queries {
        let name = question.name().to_utf8();
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
        let span = tracing::info_span!(parent: None, "egress.dns",
            dns.question.name = %cut(&name), dns.question.type = %kind,
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
    Ok(reply.to_vec()?)
}
fn udp_reply(engine: &Engine, packet: &[u8], gateway: Ipv4Addr) -> Result<Vec<u8>, Error> {
    let response = answer(engine, packet, gateway)?;
    if response.len() <= 512 {
        return Ok(response);
    }
    Ok(Message::from_vec(&response)?.truncate().to_vec()?)
}
pub(super) async fn udp(
    engine: &Engine,
    socket: UdpSocket,
    gateway: Ipv4Addr,
    mut stop: watch::Receiver<bool>,
) -> Result<(), Error> {
    let mut packet = [0; 65535];
    loop {
        let (length, peer) = tokio::select! {
            biased;
            _ = stop.changed() => return Ok(()),
            received = socket.recv_from(&mut packet) => received?,
        };
        match udp_reply(engine, &packet[..length], gateway) {
            Ok(response) => {
                socket.send_to(&response, peer).await?;
            }
            Err(error) => tracing::debug!(%error, "egress DNS datagram refused"),
        }
    }
}
pub(super) async fn tcp(
    engine: &Engine,
    mut stream: Stream,
    gateway: Ipv4Addr,
) -> Result<(), Error> {
    loop {
        let length = match stream.read_u16().await {
            Ok(length) => usize::from(length),
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        let mut packet = vec![0; length];
        stream.read_exact(&mut packet).await?;
        let response = answer(engine, &packet, gateway)?;
        stream.write_u16(u16::try_from(response.len())?).await?;
        stream.write_all(&response).await?;
    }
}
