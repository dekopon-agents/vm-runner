use crate::config::{Config, Conflict};
use futures_util::{Stream, StreamExt, stream};
use poem::{
    http::uri::Scheme,
    listener::{Acceptor, BoxListener, Listener, RustlsCertificate, RustlsConfig, TcpListener},
    web::{LocalAddr, RemoteAddr},
};
use serde::Deserialize;
use std::{io, path::PathBuf, time::Duration};
use tokio::time::{Instant, MissedTickBehavior};
use tokio_rustls::rustls::{
    crypto::aws_lc_rs,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
    sign::CertifiedKey,
};

const POLL: Duration = Duration::from_secs(1);
const REFRESH: Duration = Duration::from_secs(600);

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct Files {
    cert_file: PathBuf,
    key_file: PathBuf,
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("cannot read tls.certFile: {0}")]
    CertificateFile(io::ErrorKind),
    #[error("cannot read tls.keyFile: {0}")]
    KeyFile(io::ErrorKind),
    #[error("invalid TLS certificate PEM")]
    CertificatePem,
    #[error("invalid TLS private key PEM")]
    KeyPem,
    #[error("invalid TLS certificate/key pair")]
    Pair,
}

#[derive(PartialEq, Eq)]
struct Pair {
    cert: Vec<u8>,
    key: Vec<u8>,
}
impl Pair {
    fn config(&self) -> Result<RustlsConfig, Error> {
        let certs = CertificateDer::pem_slice_iter(&self.cert)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_invalid_pem| Error::CertificatePem)?;
        let key = PrivateKeyDer::from_pem_slice(&self.key).map_err(|_invalid_pem| Error::KeyPem)?;
        // Poem parses the key but does not check that it matches the leaf certificate.
        CertifiedKey::from_der(certs, key, &aws_lc_rs::default_provider())
            .and_then(|key| key.keys_match())
            .map_err(|_invalid_pair| Error::Pair)?;
        Ok(RustlsConfig::new().fallback(
            RustlsCertificate::new()
                .cert(self.cert.clone())
                .key(self.key.clone()),
        ))
    }
}
impl Files {
    async fn read(&self) -> Result<Pair, Error> {
        Ok(Pair {
            cert: tokio::fs::read(&self.cert_file)
                .await
                .map_err(|error| Error::CertificateFile(error.kind()))?,
            key: tokio::fs::read(&self.key_file)
                .await
                .map_err(|error| Error::KeyFile(error.kind()))?,
        })
    }

    fn updates(self, pair: Pair, initial: RustlsConfig) -> impl Stream<Item = RustlsConfig> + Send {
        let mut interval = tokio::time::interval_at(Instant::now() + POLL, POLL);
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let reload = Reload {
            files: self,
            pair,
            refreshed: Instant::now(),
        };
        stream::unfold(
            (reload, Some(initial), interval),
            |(mut reload, initial, mut interval)| async move {
                if let Some(initial) = initial {
                    return Some((initial, (reload, None, interval)));
                }
                loop {
                    interval.tick().await;
                    if let Some(config) = reload.poll().await {
                        return Some((config, (reload, None, interval)));
                    }
                }
            },
        )
    }
}

struct Reload {
    files: Files,
    pair: Pair,
    refreshed: Instant,
}
impl Reload {
    async fn poll(&mut self) -> Option<RustlsConfig> {
        let result = match self.files.read().await {
            Ok(pair) if pair == self.pair && self.refreshed.elapsed() < REFRESH => return None,
            Ok(pair) => pair.config().map(|config| (pair, config)),
            Err(error) => Err(error),
        };
        match result {
            Ok((pair, config)) => {
                self.pair = pair;
                self.refreshed = Instant::now();
                Some(config)
            }
            Err(error) => {
                tracing::warn_span!("vm_runner.tls.reload", error = %error)
                    .in_scope(|| tracing::warn!("retaining previous TLS certificate/key pair"));
                None
            }
        }
    }
}

struct Gated<T> {
    inner: T,
    ready: Option<tokio::sync::oneshot::Receiver<()>>,
}
impl<L: Listener> Listener for Gated<L> {
    type Acceptor = Gated<L::Acceptor>;
    async fn into_acceptor(self) -> io::Result<Self::Acceptor> {
        Ok(Gated {
            inner: self.inner.into_acceptor().await?,
            ready: self.ready,
        })
    }
}
impl<A: Acceptor> Acceptor for Gated<A> {
    type Io = A::Io;
    fn local_addr(&self) -> Vec<LocalAddr> {
        self.inner.local_addr()
    }
    async fn accept(&mut self) -> io::Result<(Self::Io, LocalAddr, RemoteAddr, Scheme)> {
        if let Some(ready) = &mut self.ready {
            ready.await.map_err(io::Error::other)?;
            self.ready = None;
        }
        self.inner.accept().await
    }
}
fn ready_listener(
    listener: TcpListener<std::net::SocketAddr>,
    configs: impl Stream<Item = RustlsConfig> + Send + 'static,
) -> impl Listener {
    let (ready, waiting) = tokio::sync::oneshot::channel();
    let mut ready = Some(ready);
    let configs = configs.inspect(move |_| {
        // Poem installs this item synchronously before polling TCP acceptance again.
        if let Some(ready) = ready.take() {
            let _closed_listener = ready.send(());
        }
    });
    Gated {
        inner: listener,
        ready: Some(waiting),
    }
    .rustls(configs)
}

impl Config {
    pub async fn controller_listener(&self) -> Result<BoxListener, Conflict> {
        let listener = TcpListener::bind(self.listen);
        let Some(files) = &self.tls else {
            return Ok(listener.boxed());
        };
        let pair = files.read().await.map_err(Conflict::Tls)?;
        let initial = pair.config().map_err(Conflict::Tls)?;
        Ok(ready_listener(listener, files.clone().updates(pair, initial)).boxed())
    }
}

#[cfg(all(test, unix))]
mod tests;
