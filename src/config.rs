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
    shapes: Names<Shape>,
    profiles: Names<Profile>,
    pub(crate) quotas: Quotas,
    pub telemetry: Option<Telemetry>,
}
#[derive(Deserialize)]
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
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct Issuer {
    pub issuer: String,
    pub ca_file: Option<PathBuf>,
    pub token_file: Option<PathBuf>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Shape {
    #[serde(rename = "vcpus")]
    _vcpus: NonZeroU32,
    #[serde(rename = "memoryMiB")]
    _memory: NonZeroU32,
    #[serde(rename = "diskMiB")]
    _disk: NonZeroU32,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Profile {
    shape: String,
    #[serde(rename = "image")]
    _image: String,
    #[serde(rename = "browser")]
    _browser: Browser,
    idle_seconds: u64,
    max_seconds: u64,
    egress: Egress,
}
#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum Browser {
    Headless,
    Headful,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Egress {
    allow: Vec<String>,
    #[serde(rename = "dns")]
    _dns: Dns,
}
#[derive(Deserialize)]
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
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Telemetry {
    pub(crate) otlp: Otlp,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct Otlp {
    pub protocol: Protocol,
    pub endpoint: String,
    pub ca_bundle_file: Option<PathBuf>,
    pub headers_file: Option<PathBuf>,
}
#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Protocol {
    Grpc,
    Http,
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
    #[error("malformed wildcard: {0}")]
    Wildcard(String),
    #[error("idleSeconds exceeds maxSeconds: {0}")]
    Lifetime(String),
    #[error("invalid service account subject: {0}")]
    Subject(String),
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
            if profile.idle_seconds > profile.max_seconds {
                errors.push(Conflict::Lifetime(name.clone()));
            }
            if profile.egress.allow.is_empty() {
                errors.push(Conflict::EmptyAllow(name.clone()));
            }
            for host in &profile.egress.allow {
                let suffix = host.strip_prefix("*.").unwrap_or(host);
                if suffix.is_empty() || suffix.contains('*') {
                    errors.push(Conflict::Wildcard(host.clone()));
                }
            }
        }
        errors
    }
}
