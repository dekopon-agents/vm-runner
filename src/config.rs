use serde::{
    Deserialize, Deserializer,
    de::{MapAccess, Visitor},
};
use std::{
    collections::{BTreeMap, HashSet},
    fmt,
    net::SocketAddr,
    num::NonZeroU32,
    path::{Path, PathBuf},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Config {
    pub listen: SocketAddr,
    pub(crate) tls: Option<crate::tls::Files>,
    pub(crate) auth: Auth,
    pub(crate) shapes: Names<Shape>,
    pub(crate) profiles: Names<Profile>,
    pub(crate) quotas: Quotas,
    pub telemetry: Option<Telemetry>,
    pub(crate) jails: Option<Jails>,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Auth {
    #[serde(default = "audience")]
    pub audience: String,
    pub issuers: Vec<Issuer>,
    pub subjects: Vec<String>,
}
fn audience() -> String {
    "vm-runner".into()
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct Issuer {
    pub issuer: String,
    pub ca_file: Option<PathBuf>,
    pub token_file: Option<PathBuf>,
}
#[derive(Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct Shape {
    pub vcpus: NonZeroU32,
    #[serde(rename = "memoryMiB")]
    pub memory: NonZeroU32,
    #[serde(rename = "diskMiB")]
    pub disk: NonZeroU32,
    #[serde(default = "disk_rate", rename = "diskMBps")]
    pub disk_mbps: NonZeroU32,
    #[serde(default = "net_rate", rename = "netMbps")]
    pub net_mbps: NonZeroU32,
}
fn disk_rate() -> NonZeroU32 {
    const { NonZeroU32::new(100).expect("nonzero default") }
}
fn net_rate() -> NonZeroU32 {
    const { NonZeroU32::new(200).expect("nonzero default") }
}
#[derive(Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct Profile {
    pub shape: String,
    pub image: String,
    #[serde(rename = "browser")]
    _browser: Browser,
    pub idle_seconds: u64,
    pub max_seconds: u64,
    pub egress: Egress,
}
#[derive(Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
enum Browser {
    Headless,
    Headful,
}
#[derive(Clone, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct Egress {
    pub allow: Vec<String>,
    #[serde(default)]
    pub allow_private: Vec<ipnet::IpNet>,
    #[serde(default = "egress_idle")]
    pub idle_seconds: NonZeroU32,
    #[serde(default = "egress_lifetime")]
    pub max_connection_seconds: NonZeroU32,
    #[serde(default = "egress_connections")]
    pub max_connections: NonZeroU32,
    #[serde(rename = "dns")]
    _dns: Dns,
}
fn egress_idle() -> NonZeroU32 {
    const { NonZeroU32::new(90).expect("nonzero default") }
}
fn egress_lifetime() -> NonZeroU32 {
    const { NonZeroU32::new(1800).expect("nonzero default") }
}
// One worker and one DNS lookup per connection, plus refusal export and spare work,
// must fit Tokio's default 512 blocking threads: 2 * 255 + 2 = 512.
const MAX_EGRESS_CONNECTIONS: u32 = 255;
fn egress_connections() -> NonZeroU32 {
    const { NonZeroU32::new(128).expect("nonzero default") }
}
#[derive(Clone, Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
enum Dns {
    Runner,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Quotas {
    pub default: Quota,
    pub subjects: Names<Quota>,
}
#[derive(Clone, Copy, Deserialize, poem_openapi::Object)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct Quota {
    #[oai(rename = "maxSessions")]
    pub max_sessions: u32,
}
#[derive(Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct Telemetry {
    #[serde(default)]
    pub(crate) otlp: Option<Otlp>,
    #[serde(default)]
    pub(crate) detail: DetailConfig,
    #[serde(default)]
    pub(crate) omit: Omit,
}
#[derive(Clone, Copy, Debug, Default, Deserialize, serde::Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Detail {
    Drip,
    #[default]
    Standard,
    Full,
}
impl Detail {
    pub(crate) const fn filter(self) -> &'static str {
        match self {
            Self::Drip => "info",
            Self::Standard => "debug",
            Self::Full => "trace",
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Category {
    VmLifecycle,
    VmExec,
    VmResources,
    EgressExchange,
    EgressDns,
    EgressConnect,
    EgressDrop,
    Telemetry,
}
impl Category {
    pub(crate) const ALL: [Self; 8] = [
        Self::VmLifecycle,
        Self::VmExec,
        Self::VmResources,
        Self::EgressExchange,
        Self::EgressDns,
        Self::EgressConnect,
        Self::EgressDrop,
        Self::Telemetry,
    ];
    pub(crate) const fn target(self) -> &'static str {
        match self {
            Self::VmLifecycle => "vm.lifecycle",
            Self::VmExec => "vm.exec",
            Self::VmResources => "vm.resources",
            Self::EgressExchange => "egress.exchange",
            Self::EgressDns => "egress.dns",
            Self::EgressConnect => "egress.connect",
            Self::EgressDrop => "egress.drop",
            Self::Telemetry => "telemetry",
        }
    }
}
#[derive(Clone, Debug, Default, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DetailConfig {
    #[serde(default)]
    pub default: Detail,
    #[serde(default, deserialize_with = "categories")]
    pub categories: BTreeMap<String, Detail>,
}
fn categories<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<BTreeMap<String, Detail>, D::Error> {
    let entries = BTreeMap::<String, Detail>::deserialize(deserializer)?;
    let unknown: Vec<_> = entries
        .keys()
        .filter(|key| {
            !Category::ALL
                .iter()
                .any(|category| category.target() == key.as_str())
        })
        .cloned()
        .collect();
    if !unknown.is_empty() {
        return Err(serde::de::Error::custom(format!(
            "unknown telemetry categories: {}",
            unknown.join(", ")
        )));
    }
    Ok(entries)
}
impl DetailConfig {
    pub(crate) fn level(&self, category: Category) -> Detail {
        self.categories
            .get(category.target())
            .copied()
            .unwrap_or(self.default)
    }
    pub(crate) fn filter(&self) -> String {
        let mut filter = String::from("info");
        for category in Category::ALL {
            filter.push_str(&format!(
                ",{}={}",
                category.target(),
                self.level(category).filter()
            ));
        }
        filter.push_str(",hyper=off,tonic=off,h2=off,reqwest=off,opentelemetry=off");
        filter
    }
}
#[derive(Clone, Default, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct Omit {
    #[serde(default)]
    pub headers: Vec<OmitName>,
    #[serde(default)]
    pub query_keys: Vec<OmitName>,
}
#[derive(Clone, serde::Serialize)]
#[serde(transparent)]
pub(crate) struct OmitName(String);
impl<'de> Deserialize<'de> for OmitName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let name = String::deserialize(deserializer)?;
        if name.is_empty()
            || name.chars().any(char::is_control)
            || name.trim_end_matches('*').contains('*')
            || name == "*"
        {
            return Err(serde::de::Error::custom(
                "omit name must be nonempty and may have only a trailing *",
            ));
        }
        Ok(Self(name))
    }
}
#[derive(Clone, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct Otlp {
    pub protocol: Protocol,
    pub endpoint: String,
    pub ca_bundle_file: Option<PathBuf>,
    pub headers_file: Option<PathBuf>,
}
#[derive(Clone, Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Protocol {
    Grpc,
    Http,
}
#[derive(Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct Jails {
    pub namespace: String,
    pub image: String,
    pub image_cache_host_path: PathBuf,
    pub controller_audience: String,
    pub controller_subject: String,
    pub token_file: PathBuf,
    // Controller-only scheduling setting; do not copy into the strict jail config.
    #[serde(default, skip_serializing)]
    pub cpu_request_milli: Option<NonZeroU32>,
    #[serde(default = "fetch_timeout")]
    pub fetch_timeout_seconds: u64,
}
fn fetch_timeout() -> u64 {
    15 * 60
}
pub(crate) fn digest_pinned(image: &str) -> bool {
    image.split_once("@sha256:").is_some_and(|(name, hash)| {
        !name.is_empty() && hash.len() == 64 && hash.bytes().all(|c| c.is_ascii_hexdigit())
    })
}
pub(crate) struct Names<T>(pub Vec<(String, T)>);
impl<'de, T: Deserialize<'de>> Deserialize<'de> for Names<T> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Entries<T>(std::marker::PhantomData<T>);
        impl<'de, T: Deserialize<'de>> Visitor<'de> for Entries<T> {
            type Value = Names<T>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("named entries")
            }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
                let mut entries = Vec::new();
                while let Some(entry) = map.next_entry()? {
                    entries.push(entry);
                }
                Ok(Names(entries))
            }
        }
        d.deserialize_map(Entries(std::marker::PhantomData))
    }
}
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum Conflict {
    #[error("duplicate name: {0}")]
    Duplicate(String),
    #[error("unknown shape in profile: {0}")]
    Shape(String),
    #[error("empty allow list: {0}")]
    EmptyAllow(String),
    #[error("malformed egress host pattern: {0}")]
    Wildcard(String),
    #[error("idleSeconds and maxSeconds must be at least 60, with idleSeconds <= maxSeconds: {0}")]
    Lifetime(String),
    #[error("egress.maxConnections exceeds 255 (Tokio blocking-pool budget): {0}")]
    EgressConnections(String),
    #[error("invalid service account subject: {0}")]
    Subject(String),
    #[error("profile image must be pinned to a sha256 digest: {0}")]
    Image(String),
    #[error("invalid jails configuration: {0}")]
    Jails(&'static str),
    #[error("invalid tls configuration: {0}")]
    Tls(crate::tls::Error),
}
pub(crate) fn service_account(s: &str) -> bool {
    matches!(s.split(':').collect::<Vec<_>>().as_slice(), ["system", "serviceaccount", ns, name] if !ns.is_empty() && !name.is_empty() && !s.contains('*'))
}
fn duplicates<'a>(names: impl Iterator<Item = &'a str>, errors: &mut Vec<Conflict>) {
    let mut seen = HashSet::new();
    for name in names {
        if !seen.insert(name) {
            errors.push(Conflict::Duplicate(name.into()));
        }
    }
}
impl Config {
    pub async fn load(path: &Path) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Ok(serde_yaml_ng::from_slice(&tokio::fs::read(path).await?)?)
    }
    pub fn conflicts(&self) -> Vec<Conflict> {
        let mut errors = Vec::new();
        if let Some(jails) = &self.jails {
            if let Some(request) = jails.cpu_request_milli
                && self.profiles.0.iter().any(|(_, profile)| {
                    self.shapes.0.iter().any(|(name, shape)| {
                        name == &profile.shape
                            && u64::from(request.get()) > u64::from(shape.vcpus.get()) * 1000
                    })
                })
            {
                errors.push(Conflict::Jails("cpuRequestMilli"));
            }
            for (valid, field) in [
                (!jails.namespace.is_empty(), "namespace"),
                (digest_pinned(&jails.image), "image"),
                (jails.fetch_timeout_seconds > 0, "fetchTimeoutSeconds"),
                (
                    jails.image_cache_host_path.is_absolute(),
                    "imageCacheHostPath",
                ),
                (jails.token_file.is_absolute(), "tokenFile"),
                (
                    jails.controller_audience == "vm-runner-jail",
                    "controllerAudience",
                ),
                (
                    service_account(&jails.controller_subject),
                    "controllerSubject",
                ),
            ] {
                if !valid {
                    errors.push(Conflict::Jails(field));
                }
            }
        }
        duplicates(self.shapes.0.iter().map(|(n, _)| n.as_str()), &mut errors);
        duplicates(self.profiles.0.iter().map(|(n, _)| n.as_str()), &mut errors);
        duplicates(
            self.quotas.subjects.0.iter().map(|(n, _)| n.as_str()),
            &mut errors,
        );
        duplicates(
            self.auth.issuers.iter().map(|i| i.issuer.as_str()),
            &mut errors,
        );
        duplicates(self.auth.subjects.iter().map(String::as_str), &mut errors);
        for subject in self
            .quotas
            .subjects
            .0
            .iter()
            .map(|(n, _)| n)
            .chain(&self.auth.subjects)
        {
            if !service_account(subject) {
                errors.push(Conflict::Subject(subject.clone()));
            }
        }
        for (name, profile) in &self.profiles.0 {
            if !digest_pinned(&profile.image) {
                errors.push(Conflict::Image(name.clone()));
            }
            if !self.shapes.0.iter().any(|(n, _)| n == &profile.shape) {
                errors.push(Conflict::Shape(name.clone()));
            }
            if profile.idle_seconds < 60
                || profile.max_seconds < 60
                || profile.idle_seconds > profile.max_seconds
            {
                errors.push(Conflict::Lifetime(name.clone()));
            }
            if profile.egress.max_connections.get() > MAX_EGRESS_CONNECTIONS {
                errors.push(Conflict::EgressConnections(name.clone()));
            }
            if profile.egress.allow.is_empty() {
                errors.push(Conflict::EmptyAllow(name.clone()));
            }
            for host in &profile.egress.allow {
                let suffix = host.strip_prefix("*.").unwrap_or(host);
                if suffix.is_empty() || suffix.contains(['*', ':', '/']) || !suffix.is_ascii() {
                    errors.push(Conflict::Wildcard(host.clone()));
                }
            }
        }
        errors
    }
}
