use crate::config::{Protocol, Telemetry};
use opentelemetry::{KeyValue, trace::TracerProvider};
use opentelemetry_otlp::{WithExportConfig, WithHttpConfig, WithTonicConfig};
use opentelemetry_sdk::{
    Resource,
    trace::{Sampler, SdkTracerProvider},
};
use std::{collections::HashMap, time::Duration};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Debug, thiserror::Error)]
#[error(
    "could not initialize telemetry (check endpoint, CA, headers file and jail resource attributes)"
)]
pub struct SetupError;

#[expect(
    clippy::map_err_ignore,
    reason = "exporter setup errors can contain secret header values"
)]
async fn build_provider(
    config: Option<&Telemetry>,
    jail: Vec<KeyValue>,
) -> Result<SdkTracerProvider, SetupError> {
    let role = if jail.is_empty() {
        "controller"
    } else {
        "jail"
    };
    let resource = Resource::builder_empty()
        .with_attributes([
            KeyValue::new("service.name", "vm-runner"),
            KeyValue::new("service.version", env!("CARGO_PKG_VERSION")),
            KeyValue::new("vm_runner.role", role),
            KeyValue::new("dekopon.source", "runner"),
        ])
        .with_attributes(jail)
        .build();
    let mut builder = SdkTracerProvider::builder()
        .with_resource(resource)
        .with_sampler(Sampler::AlwaysOn);
    if let Some(config) = config {
        let c = &config.otlp;
        let mut headers = HashMap::new();
        if let Some(path) = &c.headers_file {
            for line in tokio::fs::read_to_string(path)
                .await
                .map_err(|_| SetupError)?
                .lines()
            {
                let (key, value) = line.split_once(':').ok_or(SetupError)?;
                headers.insert(key.trim().to_owned(), value.trim().to_owned());
            }
        }
        let ca = match &c.ca_bundle_file {
            Some(path) => Some(tokio::fs::read(path).await.map_err(|_| SetupError)?),
            None => None,
        };
        let exporter = match c.protocol {
            Protocol::Grpc => {
                let mut metadata = tonic::metadata::MetadataMap::new();
                for (key, value) in headers {
                    let key = key
                        .parse::<tonic::metadata::MetadataKey<tonic::metadata::Ascii>>()
                        .map_err(|_| SetupError)?;
                    let mut value = value
                        .parse::<tonic::metadata::MetadataValue<tonic::metadata::Ascii>>()
                        .map_err(|_| SetupError)?;
                    value.set_sensitive(true);
                    metadata.insert(key, value);
                }
                let mut tls = tonic::transport::ClientTlsConfig::new().with_webpki_roots();
                if let Some(ca) = ca {
                    tls = tls.ca_certificate(tonic::transport::Certificate::from_pem(ca));
                }
                opentelemetry_otlp::SpanExporter::builder()
                    .with_tonic()
                    .with_endpoint(&c.endpoint)
                    .with_timeout(Duration::from_secs(10))
                    .with_metadata(metadata)
                    .with_tls_config(tls)
                    .build()
                    .map_err(|_| SetupError)?
            }
            Protocol::Http => {
                let mut sensitive = reqwest::header::HeaderMap::new();
                for (key, value) in headers {
                    let key = reqwest::header::HeaderName::from_bytes(key.as_bytes())
                        .map_err(|_| SetupError)?;
                    let mut value =
                        reqwest::header::HeaderValue::from_str(&value).map_err(|_| SetupError)?;
                    value.set_sensitive(true);
                    sensitive.insert(key, value);
                }
                let mut client = reqwest::Client::builder()
                    .default_headers(sensitive)
                    .timeout(Duration::from_secs(10))
                    .redirect(reqwest::redirect::Policy::none());
                if let Some(ca) = ca {
                    client = client.add_root_certificate(
                        reqwest::Certificate::from_pem(&ca).map_err(|_| SetupError)?,
                    );
                }
                opentelemetry_otlp::SpanExporter::builder()
                    .with_http()
                    .with_endpoint(&c.endpoint)
                    .with_protocol(opentelemetry_otlp::Protocol::HttpBinary)
                    .with_http_client(client.build().map_err(|_| SetupError)?)
                    .build()
                    .map_err(|_| SetupError)?
            }
        };
        builder = builder.with_simple_exporter(exporter);
    }
    Ok(builder.build())
}
pub async fn init(config: Option<&Telemetry>) -> Result<SdkTracerProvider, SetupError> {
    install(provider(config).await?)
}
pub(crate) async fn provider(config: Option<&Telemetry>) -> Result<SdkTracerProvider, SetupError> {
    build_provider(config, Vec::new()).await
}
#[expect(
    clippy::map_err_ignore,
    reason = "environment and identity parsing errors must not echo launcher values"
)]
pub(crate) async fn init_jail(
    config: Option<&Telemetry>,
    profile: &str,
    shape: &str,
    session: Option<&str>,
) -> Result<SdkTracerProvider, SetupError> {
    let attributes = std::env::var("OTEL_RESOURCE_ATTRIBUTES").map_err(|_| SetupError)?;
    let get = |key| {
        attributes
            .split(',')
            .filter_map(|pair| pair.split_once('='))
            .find(|(k, _)| *k == key)
            .map(|(_, v)| v)
    };
    let session = session
        .or_else(|| get("vm_runner.session_id"))
        .ok_or(SetupError)?;
    let subject = get("vm_runner.subject").ok_or(SetupError)?;
    if uuid::Uuid::parse_str(session)
        .map_err(|_| SetupError)?
        .get_version_num()
        != 7
        || !crate::config::service_account(subject)
    {
        return Err(SetupError);
    }
    install(
        build_provider(
            config,
            vec![
                KeyValue::new("vm_runner.session_id", session.to_owned()),
                KeyValue::new("vm_runner.subject", crate::egress::cut(subject)),
                KeyValue::new("vm_runner.profile", crate::egress::cut(profile)),
                KeyValue::new("vm_runner.shape", crate::egress::cut(shape)),
            ],
        )
        .await?,
    )
}
#[expect(
    clippy::map_err_ignore,
    reason = "subscriber setup errors need no credential-bearing diagnostics"
)]
fn install(provider: SdkTracerProvider) -> Result<SdkTracerProvider, SetupError> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::filter::LevelFilter::INFO)
        .with(
            tracing_subscriber::fmt::layer()
                .json()
                .with_writer(std::io::stdout)
                .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE),
        )
        .with(tracing_opentelemetry::layer().with_tracer(provider.tracer("vm-runner")))
        .try_init()
        .map_err(|_| SetupError)?;
    Ok(provider)
}

pub(crate) struct Headers<'a>(pub &'a poem::http::HeaderMap);
impl opentelemetry::propagation::Extractor for Headers<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key)?.to_str().ok()
    }
    fn keys(&self) -> Vec<&str> {
        self.0.keys().map(|k| k.as_str()).collect()
    }
}
