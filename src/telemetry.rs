use crate::config::{Category, Detail, DetailConfig, Otlp, Protocol, Telemetry};
use opentelemetry::{KeyValue, trace::TracerProvider};
use opentelemetry_otlp::{WithExportConfig, WithHttpConfig, WithTonicConfig};
use opentelemetry_sdk::{
    Resource,
    logs::{BatchConfigBuilder as LogBatchConfigBuilder, BatchLogProcessor, SdkLoggerProvider},
    trace::{BatchConfigBuilder, BatchSpanProcessor, Sampler, SdkTracerProvider},
};
use std::{collections::HashMap, time::Duration};
use tracing_subscriber::{Layer, layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Debug, thiserror::Error)]
#[error(
    "could not initialize telemetry (check endpoint, CA, headers file and jail resource attributes)"
)]
pub struct SetupError;

#[derive(Debug)]
pub struct Providers(Option<Exporters>);
#[derive(Debug)]
struct Exporters {
    tracer: SdkTracerProvider,
    logger: SdkLoggerProvider,
}
impl Providers {
    pub fn shutdown(self) -> opentelemetry_sdk::error::OTelSdkResult {
        let Some(exporters) = self.0 else {
            return Ok(());
        };
        let logs = exporters.logger.shutdown();
        let traces = exporters.tracer.shutdown();
        logs.and(traces)
    }
    #[cfg(test)]
    pub(crate) fn tracer(&self, name: &'static str) -> Option<opentelemetry_sdk::trace::SdkTracer> {
        self.0
            .as_ref()
            .map(|exporters| exporters.tracer.tracer(name))
    }
}
impl Detail {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Drip => "drip",
            Self::Standard => "standard",
            Self::Full => "full",
        }
    }
}

macro_rules! detail {
    ($category:expr) => {{
        // Probe INFO last so per-layer filters do not retain a failed DEBUG probe for this record.
        let levels = [
            ($crate::config::Detail::Full, tracing::enabled!(target: $category.target(), tracing::Level::TRACE)),
            ($crate::config::Detail::Standard, tracing::enabled!(target: $category.target(), tracing::Level::DEBUG)),
            ($crate::config::Detail::Drip, tracing::enabled!(target: $category.target(), tracing::Level::INFO)),
        ];
        levels.into_iter().find(|(_, enabled)| *enabled)
            .map_or($crate::config::Detail::Drip, |(detail, _)| detail).label()
    }};
}
pub(crate) use detail;

#[expect(
    clippy::map_err_ignore,
    reason = "exporter setup errors can contain secret header values"
)]
async fn build_provider(
    config: Option<&Telemetry>,
    jail: Vec<KeyValue>,
) -> Result<Providers, SetupError> {
    let Some(config) = config else {
        return Ok(Providers(None));
    };
    let Some(c) = config.otlp.as_ref() else {
        return Ok(Providers(None));
    };
    let role = if jail.is_empty() {
        "controller"
    } else {
        "jail"
    };
    let resource = Resource::builder_empty()
        .with_attributes([
            KeyValue::new("service.name", "vm-runner"),
            KeyValue::new("service.version", env!("CARGO_PKG_VERSION")),
            KeyValue::new("service.instance.id", uuid::Uuid::new_v4().to_string()),
            KeyValue::new("vm_runner.role", role),
            KeyValue::new("dekopon.source", "runner"),
        ])
        .with_attributes(jail)
        .build();
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
    let c = c.clone();
    let (spans, logs) = tokio::task::spawn_blocking(move || exporters(&c, headers, ca))
        .await
        .map_err(|_| SetupError)??;
    let queue = if Category::ALL
        .iter()
        .any(|category| config.detail.level(*category) == Detail::Full)
    {
        64
    } else {
        512
    };
    let tracer = SdkTracerProvider::builder()
        .with_resource(resource.clone())
        .with_sampler(Sampler::AlwaysOn)
        .with_span_processor(
            BatchSpanProcessor::builder(spans)
                .with_batch_config(
                    BatchConfigBuilder::default()
                        .with_max_queue_size(queue)
                        .with_max_export_batch_size(64)
                        .build(),
                )
                .build(),
        )
        .build();
    let logger = SdkLoggerProvider::builder()
        .with_resource(resource)
        .with_log_processor(
            BatchLogProcessor::builder(logs)
                .with_batch_config(
                    LogBatchConfigBuilder::default()
                        .with_max_queue_size(512)
                        .with_max_export_batch_size(128)
                        .build(),
                )
                .build(),
        )
        .build();
    Ok(Providers(Some(Exporters { tracer, logger })))
}
#[expect(
    clippy::map_err_ignore,
    reason = "exporter setup errors can contain secret header values"
)]
fn exporters(
    c: &Otlp,
    headers: HashMap<String, String>,
    ca: Option<Vec<u8>>,
) -> Result<
    (
        opentelemetry_otlp::SpanExporter,
        opentelemetry_otlp::LogExporter,
    ),
    SetupError,
> {
    match c.protocol {
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
            let span = opentelemetry_otlp::SpanExporter::builder()
                .with_tonic()
                .with_endpoint(&c.endpoint)
                .with_timeout(Duration::from_secs(10))
                .with_metadata(metadata.clone())
                .with_tls_config(tls.clone())
                .build()
                .map_err(|_| SetupError)?;
            let log = opentelemetry_otlp::LogExporter::builder()
                .with_tonic()
                .with_endpoint(&c.endpoint)
                .with_timeout(Duration::from_secs(10))
                .with_metadata(metadata)
                .with_tls_config(tls)
                .build()
                .map_err(|_| SetupError)?;
            Ok((span, log))
        }
        Protocol::Http => {
            let logs_url = c
                .endpoint
                .strip_suffix("/v1/traces")
                .ok_or(SetupError)?
                .to_owned()
                + "/v1/logs";
            let mut sensitive = reqwest::header::HeaderMap::new();
            for (key, value) in headers {
                let key = reqwest::header::HeaderName::from_bytes(key.as_bytes())
                    .map_err(|_| SetupError)?;
                let mut value =
                    reqwest::header::HeaderValue::from_str(&value).map_err(|_| SetupError)?;
                value.set_sensitive(true);
                sensitive.insert(key, value);
            }
            let mut client = reqwest::blocking::Client::builder()
                .default_headers(sensitive)
                .timeout(Duration::from_secs(10))
                .redirect(reqwest::redirect::Policy::none());
            if let Some(ca) = ca {
                client = client.add_root_certificate(
                    reqwest::Certificate::from_pem(&ca).map_err(|_| SetupError)?,
                );
            }
            let client = client.build().map_err(|_| SetupError)?;
            let span = opentelemetry_otlp::SpanExporter::builder()
                .with_http()
                .with_endpoint(&c.endpoint)
                .with_protocol(opentelemetry_otlp::Protocol::HttpBinary)
                .with_http_client(client.clone())
                .build()
                .map_err(|_| SetupError)?;
            let log = opentelemetry_otlp::LogExporter::builder()
                .with_http()
                .with_endpoint(logs_url)
                .with_protocol(opentelemetry_otlp::Protocol::HttpBinary)
                .with_http_client(client)
                .build()
                .map_err(|_| SetupError)?;
            Ok((span, log))
        }
    }
}
pub async fn init(config: Option<&Telemetry>) -> Result<Providers, SetupError> {
    let detail = config.map_or_else(DetailConfig::default, |c| c.detail.clone());
    install(provider(config).await?, &detail)
}
pub(crate) async fn provider(config: Option<&Telemetry>) -> Result<Providers, SetupError> {
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
) -> Result<Providers, SetupError> {
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
    let detail = config.map_or_else(DetailConfig::default, |c| c.detail.clone());
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
        &detail,
    )
}
#[expect(
    clippy::map_err_ignore,
    reason = "subscriber setup errors need no credential-bearing diagnostics"
)]
fn install(providers: Providers, detail: &DetailConfig) -> Result<Providers, SetupError> {
    let filter = detail.filter();
    let traces = providers.0.as_ref().map(|exporters| {
        tracing_opentelemetry::layer()
            .with_tracer(exporters.tracer.tracer("vm-runner"))
            .with_filter(tracing_subscriber::EnvFilter::new(&filter))
    });
    let logs = providers.0.as_ref().map(|exporters| {
        opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge::new(&exporters.logger)
            .with_filter(tracing_subscriber::EnvFilter::new(&filter))
    });
    tracing_subscriber::registry()
        .with(traces)
        .with(logs)
        .with(
            tracing_subscriber::fmt::layer()
                .json()
                .with_writer(std::io::stdout)
                .with_filter(tracing_subscriber::filter::LevelFilter::INFO),
        )
        .try_init()
        .map_err(|_| SetupError)?;
    Ok(providers)
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
