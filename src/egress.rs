use crate::{
    config::{Config, Egress},
    telemetry,
};
use http_body_util::{BodyExt, Full, combinators::UnsyncBoxBody};
use hyper::{
    Request, Response, StatusCode, Uri,
    body::{Body, Bytes, Frame, Incoming},
    header,
    service::service_fn,
};
use hyper_util::rt::TokioIo;
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
use std::{
    cell::Cell,
    convert::Infallible,
    future::Future,
    net::{IpAddr, SocketAddr},
    path::Path,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader},
    net::TcpStream,
    sync::watch,
    time::Instant,
};
use tokio_rustls::{
    LazyConfigAcceptor, TlsConnector,
    rustls::{
        self, ClientConfig, RootCertStore, ServerConfig,
        pki_types::{PrivatePkcs8KeyDer, ServerName},
    },
};
use tracing::Instrument;

mod gateway;
mod observability;

type Error = Box<dyn std::error::Error + Send + Sync>;
type HttpBody = UnsyncBoxBody<Bytes, Error>;
trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}
type Stream = Box<dyn Io>;
type RequestBody =
    http_body_util::combinators::MapFrame<Incoming, fn(Frame<Bytes>) -> Frame<Bytes>>;
type Driver = hyper::client::conn::http1::Connection<TokioIo<Stream>, RequestBody>;

pub(crate) struct Ca {
    issuer: Issuer<'static, KeyPair>,
}
impl Ca {
    pub(crate) fn new() -> Result<(Self, String), Error> {
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "vm-runner egress CA");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        let key = KeyPair::generate()?;
        let pem = params.self_signed(&key)?.pem();
        Ok((
            Self {
                issuer: Issuer::new(params, key),
            },
            pem,
        ))
    }
    fn server(&self, host: &str) -> Result<Arc<ServerConfig>, Error> {
        let (cert, key) = self.leaf(host)?;
        let config = ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(
            vec![cert],
            PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
        )?;
        Ok(Arc::new(config))
    }
    fn leaf(
        &self,
        host: &str,
    ) -> Result<(rustls::pki_types::CertificateDer<'static>, KeyPair), Error> {
        let key = KeyPair::generate()?;
        let mut params = CertificateParams::new(vec![host.to_owned()])?;
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, host);
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        let cert = params.signed_by(&key, &self.issuer)?;
        Ok((cert.der().clone(), key))
    }
}
enum Classified {
    Tls(Box<tokio_rustls::StartHandshake<BufReader<Stream>>>),
    Http(BufReader<Stream>),
    Refuse,
}
async fn classify(stream: Stream) -> Result<Classified, Error> {
    let mut buffered = BufReader::new(stream);
    match buffered.fill_buf().await?.first().copied() {
        Some(0x16) => Ok(Classified::Tls(Box::new(
            LazyConfigAcceptor::new(rustls::server::Acceptor::default(), buffered).await?,
        ))),
        Some(b'A'..=b'Z') => Ok(Classified::Http(buffered)),
        _ => Ok(Classified::Refuse),
    }
}
struct Engine {
    ca: Ca,
    egress: Egress,
    tls: Arc<ClientConfig>,
}
#[derive(Clone)]
struct Tunnel {
    authority: hyper::http::uri::Authority,
    sni: Option<String>,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Refusal {
    HostMismatch,
    NotAllowed,
    Protocol,
    Address,
    Dns,
    Connections,
}
impl Refusal {
    fn decision(self) -> &'static str {
        match self {
            Self::HostMismatch => "refused:host_mismatch",
            Self::NotAllowed => "refused:not_allowed",
            Self::Protocol => "refused:protocol",
            Self::Address => "refused:address",
            Self::Dns => "refused:dns",
            Self::Connections => "refused:connections",
        }
    }
}
pub(crate) fn cut(value: &str) -> String {
    const MARKER: &str = "…[truncated]";
    if value.len() <= 4096 {
        return value.to_owned();
    }
    let mut end = 4096 - MARKER.len();
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}{MARKER}", &value[..end])
}
fn safe_url(value: &str) -> String {
    let Ok(mut url) = url::Url::parse(value) else {
        return String::new();
    };
    if !matches!(url.scheme(), "http" | "https") || !url.has_host() {
        return String::new();
    }
    let _username = url.set_username("");
    let _password = url.set_password(None);
    let query: Vec<_> = url
        .query_pairs()
        .map(|(key, value)| {
            let lower = key.to_ascii_lowercase().replace(['-', '_'], "");
            let secret = ["token", "password", "secret", "signature", "credential"]
                .iter()
                .any(|part| lower.contains(part))
                || matches!(
                    lower.as_str(),
                    "key" | "apikey" | "xapikey" | "auth" | "authorization" | "code" | "sig"
                );
            (
                key.into_owned(),
                if secret {
                    "[redacted]".into()
                } else {
                    value.into_owned()
                },
            )
        })
        .collect();
    if url.query().is_some() {
        url.query_pairs_mut().clear().extend_pairs(query);
    }
    cut(url.as_str())
}
struct RequestSpan {
    span: tracing::Span,
    status: i64,
    decision: &'static str,
}
impl Drop for RequestSpan {
    fn drop(&mut self) {
        // Finalize once even when the connection deadline cancels forwarding.
        self.span.record("http.response.status_code", self.status);
        self.span.record("egress.decision", self.decision);
    }
}
fn span(method: &str, url: &str, host: &str) -> RequestSpan {
    RequestSpan {
        span: tracing::debug_span!(target: crate::config::Category::EgressExchange.target(), parent: None, "egress.request",
            telemetry.detail = crate::telemetry::detail!(crate::config::Category::EgressExchange),
            http.request.method = %cut(method), url.full = %safe_url(url), server.address = %cut(host),
            http.response.status_code = tracing::field::Empty, egress.decision = tracing::field::Empty, count = tracing::field::Empty),
        status: 0,
        decision: "allowed",
    }
}
fn protocol_refusal(host: Option<&str>) {
    let mut span = span("", "", host.unwrap_or(""));
    span.decision = Refusal::Protocol.decision();
}
fn forward_response(
    result: Result<Response<HttpBody>, Error>,
    span: &mut RequestSpan,
    host: &str,
) -> Response<HttpBody> {
    match result {
        Ok(response) => response,
        Err(error) if error.is::<AddressRefused>() || error.is::<DnsFailed>() => {
            span.decision = if error.is::<DnsFailed>() {
                Refusal::Dns.decision()
            } else {
                Refusal::Address.decision()
            };
            reply(StatusCode::FORBIDDEN, format!("egress refused: {host}"))
        }
        Err(error) => {
            tracing::warn!(name: "egress.exchange.failed", target: crate::config::Category::EgressExchange.target(), {
                telemetry.detail = crate::telemetry::detail!(crate::config::Category::EgressExchange), %error,
            }, "egress upstream failed");
            reply(StatusCode::BAD_GATEWAY, String::new())
        }
    }
}
fn reply(status: StatusCode, body: String) -> Response<HttpBody> {
    let mut response = Response::new(
        Full::new(Bytes::from(body))
            .map_err(|never: Infallible| match never {})
            .boxed_unsync(),
    );
    *response.status_mut() = status;
    response
}
fn same_host(a: &str, b: &str) -> bool {
    a.trim_end_matches('.')
        .eq_ignore_ascii_case(b.trim_end_matches('.'))
}
fn allowed(host: &str, allow: &[String]) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    allow.iter().any(|pattern| {
        let pattern = pattern.trim_end_matches('.').to_ascii_lowercase();
        match pattern.strip_prefix("*.") {
            Some(suffix) => host
                .strip_suffix(suffix)
                .is_some_and(|prefix| prefix.ends_with('.') && prefix.len() > 1),
            None => host == pattern,
        }
    })
}
fn port(authority: &hyper::http::uri::Authority, default: u16) -> Result<u16, Refusal> {
    let host_port = authority.as_str().rsplit('@').next().unwrap_or("");
    match host_port.strip_prefix(authority.host()) {
        Some("") => Ok(default),
        Some(suffix) => suffix
            .strip_prefix(':')
            .filter(|p| p.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|p| p.parse().ok())
            .ok_or(Refusal::HostMismatch),
        None => Err(Refusal::HostMismatch),
    }
}
#[expect(
    clippy::map_err_ignore,
    reason = "refusal reason replaces potentially sensitive URI diagnostics"
)]
fn destination(
    req: &Request<Incoming>,
    tunnel: Option<&Tunnel>,
    allow: &[String],
) -> Result<Uri, Refusal> {
    let connect = req.method() == hyper::Method::CONNECT;
    if connect && tunnel.is_some() {
        return Err(Refusal::Protocol);
    }
    let mut hosts = req.headers().get_all(header::HOST).iter();
    let host = hosts
        .next()
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.parse::<hyper::http::uri::Authority>().ok())
        .ok_or(Refusal::HostMismatch)?;
    let authority = req
        .uri()
        .authority()
        .or_else(|| tunnel.map(|t| &t.authority))
        .unwrap_or(&host);
    let scheme = if connect {
        "https"
    } else {
        req.uri()
            .scheme_str()
            .unwrap_or(if tunnel.is_some_and(|t| t.sni.is_some()) {
                "https"
            } else {
                "http"
            })
    };
    if !matches!(scheme, "http" | "https") {
        return Err(Refusal::Protocol);
    }
    let default = if scheme == "https" { 443 } else { 80 };
    let destination_port = port(authority, default)?;
    if hosts.next().is_some()
        || !same_host(host.host(), authority.host())
        || port(&host, default)? != destination_port
        || tunnel.is_some_and(|t| {
            !same_host(authority.host(), t.authority.host())
                || port(&t.authority, default) != Ok(destination_port)
                || t.sni
                    .as_ref()
                    .is_some_and(|s| !same_host(s, authority.host()))
        })
    {
        return Err(Refusal::HostMismatch);
    }
    if !allowed(authority.host(), allow) {
        return Err(Refusal::NotAllowed);
    }
    Uri::builder()
        .scheme(scheme)
        .authority(format!("{}:{destination_port}", authority.host()))
        .path_and_query(req.uri().path_and_query().map_or("/", |p| p.as_str()))
        .build()
        .map_err(|_| Refusal::Protocol)
}
fn strip(headers: &mut hyper::HeaderMap) {
    let named: Vec<_> = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|v| v.trim().to_owned())
        .collect();
    for name in named {
        headers.remove(name);
    }
    for name in [
        "traceparent",
        "tracestate",
        "connection",
        "proxy-connection",
        "proxy-authorization",
        "keep-alive",
        "upgrade",
        "te",
        "trailer",
        "transfer-encoding",
    ] {
        headers.remove(name);
    }
}
fn strip_trailers(mut frame: Frame<Bytes>) -> Frame<Bytes> {
    if let Some(trailers) = frame.trailers_mut() {
        strip(trailers);
    }
    frame
}
struct ForwardBody {
    incoming: Incoming,
    driver: Driver,
    done: bool,
}
impl Body for ForwardBody {
    type Data = Bytes;
    type Error = Error;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Error>>> {
        if !self.done {
            match Pin::new(&mut self.driver).poll(cx) {
                Poll::Ready(Ok(())) => self.done = true,
                Poll::Ready(Err(error)) => {
                    self.done = true;
                    return Poll::Ready(Some(Err(error.into())));
                }
                Poll::Pending => (),
            }
        }
        Pin::new(&mut self.incoming)
            .poll_frame(cx)
            .map(|frame| frame.map(|result| result.map_err(Into::into)))
    }
    fn is_end_stream(&self) -> bool {
        self.incoming.is_end_stream()
    }
    fn size_hint(&self) -> hyper::body::SizeHint {
        self.incoming.size_hint()
    }
}
impl Engine {
    async fn connect(&self, uri: &Uri) -> Result<Stream, Error> {
        let host = uri.host().ok_or(RefusalError)?;
        let tls = uri.scheme_str() == Some("https");
        let port = uri.port_u16().unwrap_or(if tls { 443 } else { 80 });
        async {
            let addresses = resolved_addresses(
                tokio::net::lookup_host((host.trim_matches(['[', ']']), port)).await,
                &self.egress.allow_private,
            )?;
            let tcp = TcpStream::connect(addresses.as_slice()).await?;
            if tls {
                Ok::<Stream, Error>(Box::new(
                    TlsConnector::from(Arc::clone(&self.tls))
                        .connect(ServerName::try_from(host.to_owned())?, tcp)
                        .await?,
                ))
            } else {
                Ok::<Stream, Error>(Box::new(tcp))
            }
        }
        .instrument(
            tracing::debug_span!(target: crate::config::Category::EgressConnect.target(), "egress.connect",
                telemetry.detail = crate::telemetry::detail!(crate::config::Category::EgressConnect),
                server.address = %cut(host), server.port = i64::from(port)),
        )
        .await
    }
    async fn forward(
        &self,
        mut req: Request<Incoming>,
        uri: Uri,
    ) -> Result<Response<HttpBody>, Error> {
        let stream = self.connect(&uri).await?;
        let (mut sender, mut driver) =
            hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
        // Preserve the validated wire value even if Connection nominates Host.
        let host = req.headers().get(header::HOST).ok_or(RefusalError)?.clone();
        strip(req.headers_mut());
        req.headers_mut().insert(header::HOST, host);
        req.headers_mut().insert(
            header::CONNECTION,
            hyper::http::HeaderValue::from_static("close"),
        );
        *req.uri_mut() = uri.path_and_query().ok_or(RefusalError)?.as_str().parse()?;
        let mut done = false;
        let response = {
            let sent =
                sender.send_request(req.map(|body| {
                    body.map_frame(strip_trailers as fn(Frame<Bytes>) -> Frame<Bytes>)
                }));
            tokio::pin!(sent);
            std::future::poll_fn(|cx| {
                let progress = Pin::new(&mut driver).poll(cx);
                done = progress.is_ready();
                match sent.as_mut().poll(cx) {
                    Poll::Ready(result) => Poll::Ready(result.map_err(Error::from)),
                    Poll::Pending => match progress {
                        Poll::Ready(Err(error)) => Poll::Ready(Err(error.into())),
                        Poll::Ready(Ok(())) => Poll::Ready(Err(RefusalError.into())),
                        Poll::Pending => Poll::Pending,
                    },
                }
            })
            .await?
        };
        let (mut parts, incoming) = response.into_parts();
        strip(&mut parts.headers);
        Ok(Response::from_parts(
            parts,
            ForwardBody {
                incoming,
                driver,
                done,
            }
            .boxed_unsync(),
        ))
    }
    async fn request(
        &self,
        req: Request<Incoming>,
        tunnel: Option<&Tunnel>,
        upgrade: &Mutex<Option<Tunnel>>,
        recorded: &Cell<bool>,
    ) -> Result<Response<HttpBody>, Infallible> {
        recorded.set(true);
        let header_host = req
            .headers()
            .get(header::HOST)
            .and_then(|h| h.to_str().ok())
            .and_then(|h| h.parse::<hyper::http::uri::Authority>().ok());
        let host = req
            .uri()
            .host()
            .or_else(|| tunnel.map(|t| t.authority.host()))
            .or_else(|| header_host.as_ref().map(|h| h.host()))
            .unwrap_or("");
        let host = host.to_owned();
        let url = if req.method() == hyper::Method::CONNECT {
            format!("https://{}/", req.uri())
        } else if req.uri().scheme().is_some() {
            req.uri().to_string()
        } else if let Some(t) = tunnel {
            format!(
                "{}://{}{}",
                if t.sni.is_some() { "https" } else { "http" },
                t.authority,
                req.uri()
            )
        } else if let Some(authority) = &header_host {
            format!("http://{authority}{}", req.uri())
        } else {
            req.uri().to_string()
        };
        let mut span = span(req.method().as_str(), &url, &host);
        let decision = destination(&req, tunnel, &self.egress.allow);
        let response = match decision {
            Err(reason) => {
                span.decision = reason.decision();
                reply(StatusCode::FORBIDDEN, format!("egress refused: {host}"))
            }
            Ok(uri) => {
                if req.method() == hyper::Method::CONNECT {
                    match upgrade.lock() {
                        Ok(mut slot) => {
                            *slot = uri.authority().cloned().map(|authority| Tunnel {
                                authority,
                                sni: None,
                            });
                            reply(StatusCode::OK, String::new())
                        }
                        Err(error) => {
                            tracing::error!(name: "egress.exchange.lock_poisoned", target: crate::config::Category::EgressExchange.target(), {
                                telemetry.detail = crate::telemetry::detail!(crate::config::Category::EgressExchange), %error,
                            }, "egress upgrade lock poisoned");
                            reply(StatusCode::INTERNAL_SERVER_ERROR, String::new())
                        }
                    }
                } else {
                    let result = self.forward(req, uri).instrument(span.span.clone()).await;
                    forward_response(result, &mut span, &host)
                }
            }
        };
        span.status = i64::from(response.status().as_u16());
        Ok(response)
    }
    async fn connection(
        &self,
        mut stream: Stream,
        record: &mut ConnectionRecord,
    ) -> Result<(), Error> {
        let mut tunnel: Option<Tunnel> = None;
        loop {
            stream = match classify(stream).await {
                Ok(Classified::Tls(start)) => {
                    let sni = start
                        .client_hello()
                        .server_name()
                        .ok_or(RefusalError)?
                        .to_owned();
                    record.host = Some(sni.clone());
                    let server = self.ca.server(&sni)?;
                    if let Some(t) = &mut tunnel {
                        t.sni = Some(sni);
                    } else {
                        tunnel = Some(Tunnel {
                            authority: format!("{sni}:443").parse()?,
                            sni: Some(sni),
                        });
                    }
                    Box::new(start.into_stream(server).await?)
                }
                Ok(Classified::Http(buffered)) => Box::new(buffered),
                Ok(Classified::Refuse) => {
                    protocol_refusal(record.host.as_deref());
                    return Ok(());
                }
                Err(error) => return Err(error),
            };
            let upgrade = Mutex::new(None);
            let service =
                service_fn(|req| self.request(req, tunnel.as_ref(), &upgrade, &record.request));
            let parts = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .without_shutdown()
                .await;
            let parts = match parts {
                Ok(parts) => parts,
                Err(error) => return Err(error.into()),
            };
            stream = Box::new(Buffered {
                prefix: parts.read_buf,
                stream: parts.io.into_inner(),
            });
            let next = upgrade.into_inner()?;
            let Some(next) = next else {
                stream.shutdown().await?;
                return Ok(());
            };
            record.host = Some(next.authority.host().to_owned());
            // CONNECT's envelope is complete; the inner byte stream has its own gate.
            record.request.set(false);
            tunnel = Some(next);
        }
    }
    async fn bounded_connection(
        &self,
        stream: Stream,
        record: &mut ConnectionRecord,
        started: Instant,
        protocol: gateway::Protocol,
    ) -> Result<(), Error> {
        let (activity, mut changed) = watch::channel(started);
        let stream = Box::new(ActiveStream { stream, activity });
        let idle = match protocol {
            gateway::Protocol::Http => Duration::from_secs(self.egress.idle_seconds.get().into()),
            gateway::Protocol::Dns(_) => Duration::from_secs(10),
        };
        let lifetime = Duration::from_secs(self.egress.max_connection_seconds.get().into());
        let idle_timeout = async {
            loop {
                let deadline = *changed.borrow_and_update() + idle;
                tokio::select! {
                    biased;
                    result = changed.changed() => { if result.is_err() { return; } }
                    _ = tokio::time::sleep_until(deadline) => return,
                }
            }
        };
        tokio::select! {
            biased;
            _ = tokio::time::sleep_until(started + lifetime) => Err(ConnectionTimeout::Lifetime.into()),
            _ = idle_timeout => Err(ConnectionTimeout::Idle.into()),
            result = async {
                match protocol {
                    gateway::Protocol::Http => self.connection(stream, record).await,
                    gateway::Protocol::Dns(address) => gateway::tcp(self, stream, address).await,
                }
            } => result,
        }
    }
    async fn serve(
        self: Arc<Self>,
        mut listeners: gateway::Listeners,
        stop: impl Future<Output = ()>,
    ) -> Result<(), Error> {
        if let Some(listener) = listeners.explicit.as_ref().or(listeners.http.as_ref()) {
            let depth = crate::telemetry::detail!(crate::config::Category::VmLifecycle);
            tracing::info!(name: "vm_runner.boot.egress_listening", target: crate::config::Category::VmLifecycle.target(), {
                telemetry.detail = depth,
                addr = %listener.local_addr()?,
            }, "listening");
        }
        let (dns_stop, stopped) = watch::channel(false);
        let mut dns_worker = listeners.udp.take().map(|(socket, address)| {
            let peers = listeners.dns_peers.clone();
            let engine = Arc::clone(&self);
            let runtime = tokio::runtime::Handle::current();
            let dispatch = tracing::dispatcher::get_default(Clone::clone);
            // One sequential UDP worker owns its fixed packet buffer and drains before shutdown.
            tokio::task::spawn_blocking(move || {
                tracing::dispatcher::with_default(&dispatch, || {
                    runtime.block_on(gateway::udp(&engine, socket, address, &peers, stopped))
                })
            })
        });
        let mut workers = tokio::task::JoinSet::new();
        let (refusals, refused) = watch::channel(0_i64);
        let runtime = tokio::runtime::Handle::current();
        let dispatch = tracing::dispatcher::get_default(Clone::clone);
        // One worker coalesces counts, rather than queueing a task/span per refused socket.
        let refusal_worker = tokio::task::spawn_blocking(move || {
            tracing::dispatcher::with_default(&dispatch, || {
                runtime.block_on(connection_refusals(refused));
            });
        });
        tokio::pin!(stop);
        let outcome = loop {
            tokio::select! {
                biased;
                _ = &mut stop => break Ok(()),
                result = async {
                    match &mut dns_worker {
                        Some(worker) => worker.await,
                        None => std::future::pending().await,
                    }
                } => {
                    dns_worker = None;
                    break match result {
                        Ok(result) => result,
                        Err(error) => Err(error.into()),
                    };
                }
                result = workers.join_next(), if !workers.is_empty() => { if let Some(Err(error)) = result { break Err(Error::from(error)); } }
                accepted = listeners.accept() => {
                    let (stream, peer, protocol) = match accepted {
                        Ok(accepted) => accepted,
                        Err(error) => {
                            tracing::warn!(name: "egress.connect.accept_failed", target: crate::config::Category::EgressConnect.target(), {
                                telemetry.detail = crate::telemetry::detail!(crate::config::Category::EgressConnect), %error,
                            }, "egress accept failed");
                            continue;
                        }
                    };
                    if matches!(protocol, gateway::Protocol::Dns(_))
                        && !listeners.dns_peers.contains(&peer.ip())
                    {
                        gateway::refusal("refused:address");
                        continue;
                    }
                    let engine = Arc::clone(&self);
                    let runtime = tokio::runtime::Handle::current();
                    let dispatch = tracing::dispatcher::get_default(Clone::clone);
                    if workers.len() >= self.egress.max_connections.get() as usize {
                        drop(stream);
                        refusals.send_modify(|count| *count += 1);
                        continue;
                    }
                    let started = Instant::now();
                    // The capped JoinSet owns each stream and its synchronous span exports until drained.
                    workers.spawn_blocking(move || tracing::dispatcher::with_default(&dispatch, || {
                        let mut record = ConnectionRecord::default();
                        if let Err(error) = runtime.block_on(engine.bounded_connection(Box::new(stream), &mut record, started, protocol)) {
                            if matches!(protocol, gateway::Protocol::Http) { record.failed(); }
                            tracing::warn!(name: "egress.connect.failed", target: crate::config::Category::EgressConnect.target(), {
                                telemetry.detail = crate::telemetry::detail!(crate::config::Category::EgressConnect), %error,
                            }, "egress connection failed");
                        }
                    }));
                }
            }
        };
        drop(refusals);
        dns_stop.send_replace(true);
        let mut outcome = outcome;
        if let Some(worker) = dns_worker {
            match worker.await {
                Ok(Ok(())) => (),
                Ok(Err(error)) => outcome = Err(error),
                Err(error) => outcome = Err(error.into()),
            }
        }
        while let Some(result) = workers.join_next().await {
            if let Err(error) = result {
                outcome = Err(error.into());
            }
        }
        if let Err(error) = refusal_worker.await {
            outcome = Err(error.into());
        }
        outcome
    }
}
async fn connection_refusals(mut refused: watch::Receiver<i64>) {
    let mut exported = 0;
    while refused.changed().await.is_ok() {
        // At most one span per second; a slow exporter only grows the coalesced count.
        tokio::time::sleep(Duration::from_secs(1)).await;
        let total = *refused.borrow_and_update();
        let mut span = span("", "", "");
        span.decision = Refusal::Connections.decision();
        span.span.record("count", total - exported);
        exported = total;
    }
}
#[derive(Debug, thiserror::Error)]
#[error("egress DNS resolution failed: {0}")]
struct DnsFailed(#[source] std::io::Error);
fn resolved_addresses(
    result: std::io::Result<impl Iterator<Item = SocketAddr>>,
    exceptions: &[ipnet::IpNet],
) -> Result<Vec<SocketAddr>, Error> {
    let addresses: Vec<_> = result.map_err(DnsFailed)?.collect();
    vetted_addresses(&addresses, exceptions)?;
    Ok(addresses)
}
#[derive(Debug, thiserror::Error)]
#[error("egress address refused")]
struct AddressRefused;
fn vetted_addresses<'a>(
    addresses: &'a [SocketAddr],
    exceptions: &[ipnet::IpNet],
) -> Result<&'a [SocketAddr], AddressRefused> {
    if addresses.is_empty()
        || addresses.iter().any(|address| {
            let ip = address.ip().to_canonical();
            !(global_unicast(ip)
                || exceptions
                    .iter()
                    .any(|cidr| cidr.contains(&ip) || cidr.contains(&address.ip())))
        })
    {
        return Err(AddressRefused);
    }
    Ok(addresses)
}
fn global_unicast(ip: IpAddr) -> bool {
    // Stable Rust lacks is_global (rust-lang/rust#27709); exclude IANA special-purpose ranges explicitly.
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, c, d] = ip.octets();
            !(ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_documentation()
                || a == 0
                || a >= 224
                || (a == 100 && (64..=127).contains(&b))
                || (a == 198 && (18..=19).contains(&b))
                || (a == 192 && b == 0 && c == 0 && !matches!(d, 9 | 10))
                || (a == 192 && b == 88 && c == 99))
        }
        IpAddr::V6(ip) => {
            let s = ip.segments();
            let protocol_exception = matches!(
                s,
                [0x2001, 1, 0, 0, 0, 0, 0, 1..=3]
                    | [0x2001, 3, ..]
                    | [0x2001, 4, 0x112, ..]
                    | [0x2001, 0x20..=0x3f, ..]
            );
            !(ip.is_unspecified()
                || ip.is_loopback()
                || ip.is_multicast()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
                || matches!(
                    s,
                    [0, 0, 0, 0, 0, 0, ..]
                        | [0x64, 0xff9b, 1, ..]
                        | [0x100, 0, 0, 0, ..]
                        | [0x100, 0, 0, 1, ..]
                        | [0x2002, ..]
                        | [0x2001, 0xdb8, ..]
                        | [0x3fff, 0..=0x0fff, ..]
                        | [0x5f00, ..]
                        | [0xfec0..=0xfeff, ..]
                )
                || (s[0] == 0x2001 && s[1] < 0x200 && !protocol_exception)
                || (matches!(s, [0x64, 0xff9b, 0, 0, 0, 0, ..])
                    && !global_unicast(IpAddr::V4(std::net::Ipv4Addr::from(
                        (u32::from(s[6]) << 16) | u32::from(s[7]),
                    )))))
        }
    }
}
#[derive(Debug, thiserror::Error)]
enum ConnectionTimeout {
    #[error("egress idle timeout")]
    Idle,
    #[error("egress maximum lifetime")]
    Lifetime,
}
struct ActiveStream {
    stream: Stream,
    activity: watch::Sender<Instant>,
}
impl AsyncRead for ActiveStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut self.stream).poll_read(cx, buf);
        if matches!(result, Poll::Ready(Ok(()))) && buf.filled().len() > before {
            self.activity.send_replace(Instant::now());
        }
        result
    }
}
impl AsyncWrite for ActiveStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let result = Pin::new(&mut self.stream).poll_write(cx, buf);
        if matches!(result, Poll::Ready(Ok(n)) if n > 0) {
            self.activity.send_replace(Instant::now());
        }
        result
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}
#[derive(Default)]
struct ConnectionRecord {
    host: Option<String>,
    // HTTP/1 requests and this connection's classifier are driven by one worker.
    request: Cell<bool>,
}
impl ConnectionRecord {
    fn failed(&self) {
        if !self.request.get() {
            protocol_refusal(self.host.as_deref());
        }
    }
}
struct Buffered {
    prefix: Bytes,
    stream: Stream,
}
impl AsyncRead for Buffered {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if !self.prefix.is_empty() {
            let n = buf.remaining().min(self.prefix.len());
            buf.put_slice(&self.prefix.split_to(n));
            Poll::Ready(Ok(()))
        } else {
            Pin::new(&mut self.stream).poll_read(cx, buf)
        }
    }
}
impl AsyncWrite for Buffered {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}
#[derive(Debug, thiserror::Error)]
#[error("invalid egress transport")]
struct RefusalError;
fn client_config(roots: RootCertStore) -> Result<Arc<ClientConfig>, rustls::Error> {
    Ok(Arc::new(
        ClientConfig::builder_with_provider(
            Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
        )
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth(),
    ))
}
#[derive(Debug, thiserror::Error)]
#[error(
    "invalid --gateway {0}: unspecified, broadcast, multicast and loopback addresses are forbidden"
)]
pub struct InvalidGateway(std::net::Ipv4Addr);

pub fn validate_gateway(address: std::net::Ipv4Addr) -> Result<(), InvalidGateway> {
    if address.is_unspecified()
        || address.is_broadcast()
        || address.is_multicast()
        || address.is_loopback()
    {
        Err(InvalidGateway(address))
    } else {
        Ok(())
    }
}

pub(crate) struct Gateway {
    engine: Arc<Engine>,
    listeners: gateway::Listeners,
}
impl Gateway {
    pub(crate) async fn bind(egress: Egress, ca: Ca) -> Result<Self, Error> {
        let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Ok(Self {
            engine: Arc::new(Engine {
                ca,
                egress,
                tls: client_config(roots)?,
            }),
            listeners: gateway::Listeners::bind(None, Some(std::net::Ipv4Addr::new(10, 0, 2, 1)))
                .await?,
        })
    }
    pub(crate) async fn serve(self, stop: impl Future<Output = ()>) -> Result<(), Error> {
        self.engine.serve(self.listeners, stop).await
    }
}

pub async fn run(
    config: Config,
    profile: &str,
    listen: Option<SocketAddr>,
    gateway: Option<std::net::Ipv4Addr>,
    ca_out: &Path,
) -> Result<(), Error> {
    let selected = config
        .profiles
        .0
        .iter()
        .find(|(name, _)| name == profile)
        .ok_or(RefusalError)?;
    let provider =
        telemetry::init_jail(config.telemetry.as_ref(), profile, &selected.1.shape, None).await?;
    let result = async {
        let (ca, pem) = Ca::new()?;
        tokio::fs::create_dir_all(ca_out).await?;
        tokio::fs::write(ca_out.join("ca.pem"), pem).await?;
        let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let engine = Arc::new(Engine {
            ca,
            egress: selected.1.egress.clone(),
            tls: client_config(roots)?,
        });
        engine
            .serve(
                gateway::Listeners::bind(listen, gateway).await?,
                crate::shutdown_signal(),
            )
            .await
    }
    .await;
    tokio::task::spawn_blocking(move || provider.shutdown()).await??;
    result
}
#[cfg(test)]
mod tests;
