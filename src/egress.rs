use crate::{config::Config, telemetry};
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
    net::SocketAddr,
    path::Path,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
};
use tokio_rustls::{
    LazyConfigAcceptor, TlsConnector,
    rustls::{
        self, ClientConfig, RootCertStore, ServerConfig,
        pki_types::{PrivatePkcs8KeyDer, ServerName},
    },
};
use tracing::Instrument;

type Error = Box<dyn std::error::Error + Send + Sync>;
type HttpBody = UnsyncBoxBody<Bytes, Error>;
trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}
type Stream = Box<dyn Io>;
type RequestBody =
    http_body_util::combinators::MapFrame<Incoming, fn(Frame<Bytes>) -> Frame<Bytes>>;
type Driver = hyper::client::conn::http1::Connection<TokioIo<Stream>, RequestBody>;

struct Ca {
    issuer: Issuer<'static, KeyPair>,
}
impl Ca {
    fn new() -> Result<(Self, String), Error> {
        let mut params = CertificateParams::default();
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
        let key = KeyPair::generate()?;
        let cert = CertificateParams::new(vec![host.to_owned()])?.signed_by(&key, &self.issuer)?;
        let config = ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
        )?;
        Ok(Arc::new(config))
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
    allow: Vec<String>,
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
}
impl Refusal {
    fn decision(self) -> &'static str {
        match self {
            Self::HostMismatch => "refused:host_mismatch",
            Self::NotAllowed => "refused:not_allowed",
            Self::Protocol => "refused:protocol",
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
}
impl Drop for RequestSpan {
    fn drop(&mut self) {
        // Finalize once even when the connection deadline cancels forwarding.
        self.span.record("http.response.status_code", self.status);
    }
}
fn span(method: &str, url: &str, host: &str) -> RequestSpan {
    RequestSpan {
        span: tracing::info_span!(parent: None, "egress.request", http.request.method = %cut(method), url.full = %safe_url(url), server.address = %cut(host), http.response.status_code = tracing::field::Empty, egress.decision = tracing::field::Empty),
        status: 0,
    }
}
fn protocol_refusal(host: Option<&str>) {
    let span = span("", "", host.unwrap_or(""));
    span.span
        .record("egress.decision", Refusal::Protocol.decision());
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
    let authority = req
        .uri()
        .authority()
        .or_else(|| tunnel.map(|t| &t.authority))
        .ok_or(Refusal::HostMismatch)?;
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
    let mut hosts = req.headers().get_all(header::HOST).iter();
    let host = hosts
        .next()
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.parse::<hyper::http::uri::Authority>().ok())
        .ok_or(Refusal::HostMismatch)?;
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
            let tcp = TcpStream::connect((host.trim_matches(['[', ']']), port)).await?;
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
            tracing::info_span!("egress.connect", server.address = %cut(host), server.port = port),
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
        let host = req
            .uri()
            .host()
            .or_else(|| tunnel.map(|t| t.authority.host()))
            .unwrap_or("");
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
        } else {
            req.uri().to_string()
        };
        let mut span = span(req.method().as_str(), &url, host);
        let decision = destination(&req, tunnel, &self.allow);
        let response = match decision {
            Err(reason) => {
                span.span.record("egress.decision", reason.decision());
                reply(StatusCode::FORBIDDEN, format!("egress refused: {host}"))
            }
            Ok(uri) => {
                span.span.record("egress.decision", "allowed");
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
                            tracing::error!(%error, "egress upgrade lock poisoned");
                            reply(StatusCode::INTERNAL_SERVER_ERROR, String::new())
                        }
                    }
                } else {
                    match self.forward(req, uri).instrument(span.span.clone()).await {
                        Ok(response) => response,
                        Err(error) => {
                            tracing::warn!(%error, "egress upstream failed");
                            reply(StatusCode::BAD_GATEWAY, String::new())
                        }
                    }
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
    async fn serve(
        self: Arc<Self>,
        listener: TcpListener,
        stop: impl Future<Output = ()>,
    ) -> Result<(), Error> {
        tracing::info!(addr = %listener.local_addr()?, "listening");
        let mut workers = tokio::task::JoinSet::new();
        tokio::pin!(stop);
        let outcome = loop {
            tokio::select! {
                _ = &mut stop => break Ok(()),
                result = workers.join_next(), if !workers.is_empty() => { if let Some(Err(error)) = result { break Err(Error::from(error)); } }
                accepted = listener.accept(), if workers.len() < 16 => {
                    let (stream, _) = match accepted {
                        Ok(accepted) => accepted,
                        Err(error) => {
                            tracing::warn!(%error, "egress accept failed");
                            continue;
                        }
                    };
                    let engine = Arc::clone(&self);
                    let runtime = tokio::runtime::Handle::current();
                    let dispatch = tracing::dispatcher::get_default(Clone::clone);
                    // Each of 16 owned workers drives its stream and synchronous span exports off Tokio.
                    workers.spawn_blocking(move || tracing::dispatcher::with_default(&dispatch, || {
                        let mut record = ConnectionRecord::default();
                        let result = runtime.block_on(tokio::time::timeout(Duration::from_secs(60), engine.connection(Box::new(stream), &mut record)));
                        match result {
                            Ok(Ok(())) => (),
                            Ok(Err(error)) => { record.failed(); tracing::warn!(%error, "egress connection failed"); }
                            Err(error) => { record.failed(); tracing::warn!(%error, "egress connection deadline"); }
                        }
                    }));
                }
            }
        };
        let mut outcome = outcome;
        while let Some(result) = workers.join_next().await {
            if let Err(error) = result {
                outcome = Err(error.into());
            }
        }
        outcome
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
pub async fn run(
    config: Config,
    profile: &str,
    listen: SocketAddr,
    ca_out: &Path,
) -> Result<(), Error> {
    let selected = config
        .profiles
        .0
        .iter()
        .find(|(name, _)| name == profile)
        .ok_or(RefusalError)?;
    let provider =
        telemetry::init_jail(config.telemetry.as_ref(), profile, &selected.1.shape).await?;
    let result = async {
        let (ca, pem) = Ca::new()?;
        tokio::fs::create_dir_all(ca_out).await?;
        tokio::fs::write(ca_out.join("ca.pem"), pem).await?;
        let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let engine = Arc::new(Engine {
            ca,
            allow: selected.1.egress.allow.clone(),
            tls: client_config(roots)?,
        });
        engine
            .serve(TcpListener::bind(listen).await?, crate::shutdown_signal())
            .await
    }
    .await;
    tokio::task::spawn_blocking(move || provider.shutdown()).await??;
    result
}
#[cfg(test)]
mod tests;
