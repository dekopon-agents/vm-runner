use serde::{
    Deserialize, Deserializer,
    de::{MapAccess, Visitor},
};
use std::{
    collections::HashSet,
    fmt,
    net::SocketAddr,
    num::NonZeroU32,
    path::{Path, PathBuf},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Config {
    pub listen: SocketAddr,
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
    pub(crate) otlp: Otlp,
}
#[derive(Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct Otlp {
    pub protocol: Protocol,
    pub endpoint: String,
    pub ca_bundle_file: Option<PathBuf>,
    pub headers_file: Option<PathBuf>,
}
#[derive(Deserialize, serde::Serialize)]
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
    #[error("invalid jails configuration: {0}")]
    Jails(&'static str),
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
            for (valid, field) in [
                (!jails.namespace.is_empty(), "namespace"),
                (!jails.image.trim().is_empty(), "image"),
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
