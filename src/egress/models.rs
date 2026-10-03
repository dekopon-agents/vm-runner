//! The guest route to dekopon-gatewayd's model proxy: `models.vm.internal` bypasses the allowlist and
//! forwards over mTLS to one configured upstream, asserting the VM's subject in a header the
//! guest can never set.
use super::{Error, Stream, same_host};
use std::{path::PathBuf, sync::Arc};
use tokio::net::TcpStream;
use tokio_rustls::{
    TlsConnector,
    rustls::{
        self, ClientConfig, RootCertStore,
        pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject},
    },
};
use tracing::Instrument;

/// The name guests address; the DNS stub answers it with the gateway address.
pub(crate) const HOST: &str = "models.vm.internal";
/// Set by the jail on every routed request; any copy the guest sent is stripped first.
pub(crate) const SUBJECT_HEADER: &str = "x-dekopon-vm-subject";
/// Where the controller mounts the jail client-certificate Secret (`tls.crt`, `tls.key`,
/// `ca.crt`), 0400 so the VMM's uid cannot read it.
pub(crate) const TLS_DIR: &str = "/models-tls";

#[derive(Debug, thiserror::Error)]
pub(crate) enum InvalidRoute {
    #[error("models.upstream must be an https origin with a host and no path, query or userinfo")]
    Upstream,
    #[error("models.subject must be a namespace:name service account")]
    Subject,
}

pub(crate) struct Route {
    server: ServerName<'static>,
    port: u16,
    authority: hyper::header::HeaderValue,
    subject: hyper::header::HeaderValue,
    dir: PathBuf,
}
/// `https://host[:port]` with nothing else; the guest's path is forwarded unchanged. Returns the
/// host as written (IPv6 bracketed, for the authority), its TLS server name and the port.
pub(crate) fn upstream(value: &str) -> Result<(String, ServerName<'static>, u16), InvalidRoute> {
    let url = url::Url::parse(value).map_err(|_invalid| InvalidRoute::Upstream)?;
    match (url.scheme(), url.host_str(), url.port_or_known_default()) {
        ("https", Some(host), Some(port))
            if url.username().is_empty()
                && url.password().is_none()
                && url.path() == "/"
                && url.query().is_none()
                && url.fragment().is_none() =>
        {
            let server = ServerName::try_from(host.trim_matches(['[', ']']).to_owned())
                .map_err(|_invalid| InvalidRoute::Upstream)?;
            Ok((host.to_owned(), server, port))
        }
        _ => Err(InvalidRoute::Upstream),
    }
}
/// The design's guest subject is `namespace:name`, the service-account subject without the
/// `system:serviceaccount:` prefix.
pub(crate) fn subject(value: &str) -> Result<&str, InvalidRoute> {
    match value.split(':').collect::<Vec<_>>().as_slice() {
        [ns, name] if !ns.is_empty() && !name.is_empty() && !value.contains('*') => Ok(value),
        _ => Err(InvalidRoute::Subject),
    }
}
impl Route {
    pub(crate) fn new(upstream: &str, subject: &str, dir: PathBuf) -> Result<Self, Error> {
        let (host, server, port) = self::upstream(upstream)?;
        Ok(Self {
            authority: format!("{host}:{port}").parse()?,
            subject: self::subject(subject)?.parse()?,
            server,
            port,
            dir,
        })
    }
    pub(super) fn addressed(host: &str) -> bool {
        same_host(host, HOST)
    }
    pub(super) fn authority(&self) -> hyper::header::HeaderValue {
        self.authority.clone()
    }
    pub(super) fn subject(&self) -> hyper::header::HeaderValue {
        self.subject.clone()
    }
    /// Rereads the mounted Secret on every connection so cert-manager rotation needs no restart.
    async fn client_config(&self) -> Result<Arc<ClientConfig>, Error> {
        let cert = tokio::fs::read(self.dir.join("tls.crt")).await?;
        let key = tokio::fs::read(self.dir.join("tls.key")).await?;
        let ca = tokio::fs::read(self.dir.join("ca.crt")).await?;
        let mut roots = RootCertStore::empty();
        for cert in CertificateDer::pem_slice_iter(&ca) {
            roots.add(cert?)?;
        }
        let chain = CertificateDer::pem_slice_iter(&cert).collect::<Result<Vec<_>, _>>()?;
        Ok(Arc::new(
            ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::aws_lc_rs::default_provider(),
            ))
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots)
            .with_client_auth_cert(chain, PrivateKeyDer::from_pem_slice(&key)?)?,
        ))
    }
    /// The one upstream outside the allowlist: cluster-internal, so address vetting is skipped.
    pub(super) async fn connect(&self) -> Result<Stream, Error> {
        async {
            let config = self.client_config().await?;
            let tcp = TcpStream::connect((&*self.server.to_str(), self.port)).await?;
            let tls = TlsConnector::from(config)
                .connect(self.server.clone(), tcp)
                .await?;
            Ok::<Stream, Error>(Box::new(tls))
        }
        .instrument(tracing::info_span!("egress.connect",
            server.address = %super::cut(&self.server.to_str()), server.port = self.port))
        .await
    }
}
