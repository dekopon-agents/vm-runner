use super::{Refusal, cut};
use crate::config::OmitName;
use hyper::StatusCode;
use opentelemetry::{Array, Value};
use std::{
    collections::{BTreeMap, HashSet},
    hash::{Hash, Hasher},
    sync::{Arc, Mutex},
};
use tokio::time::Instant;
use tracing_opentelemetry::OpenTelemetrySpanExt;

#[derive(Clone, Copy)]
pub(super) enum Phase {
    Connect,
    Headers,
    RequestBody,
    ResponseBody,
}
impl Phase {
    pub(super) const fn label(self) -> &'static str {
        match self {
            Self::Connect => "connect",
            Self::Headers => "headers",
            Self::RequestBody => "request-body",
            Self::ResponseBody => "response-body",
        }
    }
}

pub(super) enum Outcome {
    Completed,
    Tunnel,
    Refused(Refusal),
    UpstreamFailed,
    CertificateRejected,
    ProtocolError,
    BodyError(Phase),
    Abandoned(Phase),
}
impl Outcome {
    pub(super) const fn label(&self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Tunnel => "tunnel",
            Self::Refused(_) => "refused",
            Self::UpstreamFailed => "upstream-failed",
            Self::CertificateRejected => "certificate-rejected",
            Self::ProtocolError => "protocol-error",
            Self::BodyError(_) => "body-error",
            Self::Abandoned(_) => "abandoned",
        }
    }
    fn phase(&self) -> Option<&'static str> {
        match self {
            Self::BodyError(phase) | Self::Abandoned(phase) => Some(phase.label()),
            Self::Completed
            | Self::Tunnel
            | Self::Refused(_)
            | Self::UpstreamFailed
            | Self::CertificateRejected
            | Self::ProtocolError => None,
        }
    }
    fn decision(&self) -> &'static str {
        match self {
            Self::Refused(reason) => reason.decision(),
            Self::Completed
            | Self::Tunnel
            | Self::UpstreamFailed
            | Self::CertificateRejected
            | Self::ProtocolError
            | Self::BodyError(_)
            | Self::Abandoned(_) => "allowed",
        }
    }
}

pub(super) struct Exchange {
    data: Option<ExchangeData>,
}
struct ExchangeData {
    span: tracing::Span,
    host: String,
    port: Option<u16>,
    method: String,
    started: Instant,
    phase: Phase,
    status: Option<StatusCode>,
    request: Arc<Mutex<RequestMeasure>>,
    response_bytes: u64,
    response_head: Vec<u8>,
    request_text: bool,
    response_text: bool,
    rollups: Arc<Mutex<Rollups>>,
}
#[derive(Clone, Copy)]
pub(super) enum HeaderSide {
    Request,
    Response,
}
impl HeaderSide {
    const fn content_type(self) -> &'static str {
        match self {
            Self::Request => "http.request.header.content_type",
            Self::Response => "http.response.header.content_type",
        }
    }
    const fn names(self) -> &'static str {
        match self {
            Self::Request => "http.request.header.names",
            Self::Response => "http.response.header.names",
        }
    }
    const fn values(self) -> &'static str {
        match self {
            Self::Request => "http.request.header.values",
            Self::Response => "http.response.header.values",
        }
    }
}
pub(super) struct RequestMeasure {
    pub(super) bytes: u64,
    pub(super) head: Vec<u8>,
}
impl RequestMeasure {
    pub(super) fn new() -> Self {
        Self {
            bytes: 0,
            head: Vec::new(),
        }
    }
    pub(super) fn append(&mut self, bytes: &[u8]) {
        self.bytes = self.bytes.saturating_add(bytes.len() as u64);
        if tracing::enabled!(target: "egress.exchange", tracing::Level::TRACE) {
            let take = (4096 - self.head.len()).min(bytes.len());
            self.head.extend_from_slice(&bytes[..take]);
        }
    }
}
#[must_use]
pub(super) struct Recorded;
impl Exchange {
    pub(super) fn new(
        host: &str,
        port: Option<u16>,
        method: &str,
        url: &str,
        omit_query: &[OmitName],
        rollups: Arc<Mutex<Rollups>>,
    ) -> Self {
        let parsed = url::Url::parse(url)
            .ok()
            .filter(|url| matches!(url.scheme(), "http" | "https"));
        let span = tracing::debug_span!(target: "egress.exchange", parent: None, "egress.request",
            telemetry.detail = crate::telemetry::detail!(crate::config::Category::EgressExchange),
            http.request.method = %cut(method), server.address = %cut(host),
            server.port = port.map(i64::from),
            url.scheme = parsed.as_ref().map(url::Url::scheme),
            url.path = tracing::field::Empty,
            http.response.status_code = tracing::field::Empty,
            egress.decision = tracing::field::Empty,
            egress.exchange.outcome = tracing::field::Empty,
            egress.exchange.phase = tracing::field::Empty,
            egress.exchange.headers_ms = tracing::field::Empty,
            http.request.body.size = tracing::field::Empty,
            http.response.body.size = tracing::field::Empty,
            http.request.header.content_type = tracing::field::Empty,
            http.response.header.content_type = tracing::field::Empty,
            user_agent.original = tracing::field::Empty,
            http.request.body.head = tracing::field::Empty,
            http.response.body.head = tracing::field::Empty);
        if let Some(url) = &parsed
            && let Some(query) = url.query()
            && let Ok(mut totals) = rollups.lock()
        {
            for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
                if !omitted(&key, omit_query) {
                    totals.noise(NoiseKind::QueryKey, &key, value.as_bytes());
                }
            }
        }
        if tracing::enabled!(target: "egress.exchange", tracing::Level::DEBUG)
            && let Some(url) = &parsed
        {
            span.record("url.path", cut_text(url.path(), 1024));
            let pairs = url
                .query_pairs()
                .filter(|(key, _)| !omitted(key, omit_query))
                .take(64)
                .map(|(key, value)| {
                    let value = if redact(&key) {
                        "[redacted]".into()
                    } else {
                        value
                    };
                    (cut_text(&key, 1024), cut_text(&value, 1024))
                })
                .collect::<Vec<_>>();
            let (keys, values): (Vec<_>, Vec<_>) = pairs.into_iter().unzip();
            set_pairs(&span, "url.query.keys", "url.query.values", keys, values);
        }
        Self {
            data: Some(ExchangeData {
                span,
                host: cut(host),
                port,
                method: cut(method),
                started: Instant::now(),
                phase: Phase::Headers,
                status: None,
                request: Arc::new(Mutex::new(RequestMeasure::new())),
                response_bytes: 0,
                response_head: Vec::new(),
                request_text: false,
                response_text: false,
                rollups,
            }),
        }
    }
    pub(super) fn span(&self) -> tracing::Span {
        self.data
            .as_ref()
            .map_or_else(tracing::Span::none, |data| data.span.clone())
    }
    pub(super) fn measure(&self) -> Arc<Mutex<RequestMeasure>> {
        self.data.as_ref().map_or_else(
            || Arc::new(Mutex::new(RequestMeasure::new())),
            |data| Arc::clone(&data.request),
        )
    }
    pub(super) fn headers(
        &mut self,
        headers: &hyper::HeaderMap,
        side: HeaderSide,
        omit: &[OmitName],
    ) {
        if let Some(data) = self.data.as_mut() {
            let text = headers
                .get(hyper::header::CONTENT_TYPE)
                .is_some_and(|content| {
                    content.as_bytes().starts_with(b"text/")
                        || content.as_bytes().starts_with(b"application/json")
                });
            match side {
                HeaderSide::Request => data.request_text = text,
                HeaderSide::Response => data.response_text = text,
            }
        }
        let Some(data) = &self.data else {
            return;
        };
        let standard = tracing::enabled!(target: "egress.exchange", tracing::Level::DEBUG);
        let full = tracing::enabled!(target: "egress.exchange", tracing::Level::TRACE);
        let mut names = Vec::new();
        let mut values = Vec::new();
        for (name, value) in headers {
            let name = name.as_str();
            if omitted(name, omit) {
                continue;
            }
            if let Ok(mut totals) = data.rollups.lock() {
                totals.noise(NoiseKind::Header, name, value.as_bytes());
            }
            if standard && name == "content-type" {
                let content = cut_text(&String::from_utf8_lossy(value.as_bytes()), 1024);
                data.span.record(side.content_type(), content);
            }
            if standard && matches!(side, HeaderSide::Request) && name == "user-agent" {
                data.span.record(
                    "user_agent.original",
                    cut_text(&String::from_utf8_lossy(value.as_bytes()), 1024),
                );
            }
            if full && names.len() < 64 {
                names.push(cut_text(name, 1024));
                values.push(if redact(name) {
                    "[redacted]".into()
                } else {
                    cut_text(&String::from_utf8_lossy(value.as_bytes()), 1024)
                });
            }
        }
        if full {
            set_pairs(&data.span, side.names(), side.values(), names, values);
        }
    }
    pub(super) fn phase(&mut self, phase: Phase) {
        if let Some(data) = self.data.as_mut() {
            data.phase = phase;
        }
    }
    pub(super) fn status(&mut self, status: StatusCode) {
        if let Some(data) = self.data.as_mut() {
            data.status = Some(status);
            data.span.record(
                "egress.exchange.headers_ms",
                i64::try_from(data.started.elapsed().as_millis()).unwrap_or(i64::MAX),
            );
        }
    }
    pub(super) fn response_bytes(&mut self, bytes: &[u8]) {
        if let Some(data) = self.data.as_mut() {
            data.response_bytes = data.response_bytes.saturating_add(bytes.len() as u64);
            if data.response_text
                && tracing::enabled!(target: "egress.exchange", tracing::Level::TRACE)
            {
                let take = (4096 - data.response_head.len()).min(bytes.len());
                data.response_head.extend_from_slice(&bytes[..take]);
            }
        }
    }
    pub(super) fn finish(mut self, outcome: Outcome, error: Option<&str>) -> Recorded {
        if let Some(data) = self.data.take() {
            record(data, outcome, error);
        }
        Recorded
    }
}
impl Drop for Exchange {
    fn drop(&mut self) {
        if let Some(data) = self.data.take() {
            let phase = data.phase;
            record(data, Outcome::Abandoned(phase), None);
        }
    }
}
fn record(data: ExchangeData, outcome: Outcome, error: Option<&str>) {
    let status = data.status.map(|status| i64::from(status.as_u16()));
    let phase = outcome.phase();
    let decision = outcome.decision();
    let label = outcome.label();
    data.span.record("egress.decision", decision);
    data.span.record("egress.exchange.outcome", label);
    if let Some(status) = status {
        data.span.record("http.response.status_code", status);
    }
    if let Some(phase) = phase {
        data.span.record("egress.exchange.phase", phase);
    }
    let request_bytes = data.request.lock().map_or(0, |measure| {
        if data.request_text
            && tracing::enabled!(target: "egress.exchange", tracing::Level::TRACE)
            && !measure.head.is_empty()
        {
            data.span.record(
                "http.request.body.head",
                cut_text(&String::from_utf8_lossy(&measure.head), 4096),
            );
        }
        measure.bytes
    });
    data.span.record(
        "http.request.body.size",
        i64::try_from(request_bytes).unwrap_or(i64::MAX),
    );
    if data.response_text
        && !data.response_head.is_empty()
        && tracing::enabled!(target: "egress.exchange", tracing::Level::TRACE)
    {
        data.span.record(
            "http.response.body.head",
            cut_text(&String::from_utf8_lossy(&data.response_head), 4096),
        );
    }
    data.span.record(
        "http.response.body.size",
        i64::try_from(data.response_bytes).unwrap_or(i64::MAX),
    );
    if let Ok(mut rollups) = data.rollups.lock() {
        rollups.exchange(&data, &outcome);
    }
    if let Outcome::Refused(reason) = outcome {
        tracing::info!(name: "egress.refused", target: "egress.drop", {
            telemetry.detail = crate::telemetry::detail!(crate::config::Category::EgressDrop),
            server.address = %data.host, egress.decision = reason.decision(),
            egress.refused.count = 1_i64,
        }, "egress.refused");
    }
    let failed = match outcome {
        Outcome::Completed => status.is_some_and(|status| status >= 400),
        Outcome::Tunnel | Outcome::Refused(_) => false,
        Outcome::UpstreamFailed
        | Outcome::CertificateRejected
        | Outcome::ProtocolError
        | Outcome::BodyError(_)
        | Outcome::Abandoned(_) => true,
    };
    if failed {
        let error = error.map(|error| cut_text(error, 1024));
        tracing::info!(name: "egress.exchange.failed", target: "egress.exchange", {
            telemetry.detail = crate::telemetry::detail!(crate::config::Category::EgressExchange),
            server.address = %data.host, server.port = data.port.map(i64::from),
            http.request.method = %data.method, http.response.status_code = status,
            egress.exchange.outcome = label, egress.exchange.phase = phase,
            error = error.as_deref(),
        }, "egress.exchange.failed");
    }
}

pub(super) struct Rollups {
    since: Instant,
    exchanges: BTreeMap<(String, u16), ExchangeTotals>,
    connects: BTreeMap<(String, u16), ConnectTotals>,
    dns: BTreeMap<String, DnsTotals>,
    noise: BTreeMap<(NoiseKind, String), NoiseTotals>,
    max_named_noise_keys: usize,
}
#[derive(Default)]
struct ExchangeTotals {
    count: u64,
    errors: u64,
    client_errors: u64,
    server_errors: u64,
    request_bytes: u64,
    response_bytes: u64,
    slowest_ms: u64,
}
#[derive(Default)]
struct ConnectTotals {
    count: u64,
    errors: u64,
}
#[derive(Default)]
struct DnsTotals {
    count: u64,
    refused: u64,
}
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
pub(super) enum NoiseKind {
    Header,
    QueryKey,
}
impl NoiseKind {
    pub(super) const fn label(self) -> &'static str {
        match self {
            Self::Header => "header",
            Self::QueryKey => "query-key",
        }
    }
}
#[derive(Default)]
struct NoiseTotals {
    count: u64,
    bytes: u64,
    hashes: HashSet<u64>,
    many: bool,
}
impl Rollups {
    pub(super) fn new() -> Self {
        Self {
            since: Instant::now(),
            exchanges: BTreeMap::new(),
            connects: BTreeMap::new(),
            dns: BTreeMap::new(),
            noise: BTreeMap::new(),
            max_named_noise_keys: 62,
        }
    }
    fn exchange(&mut self, data: &ExchangeData, outcome: &Outcome) {
        let key = (data.host.clone(), data.port.unwrap_or(0));
        let key = if self.exchanges.contains_key(&key) || self.exchanges.len() < 63 {
            key
        } else {
            ("*".into(), 0)
        };
        let row = self.exchanges.entry(key).or_default();
        row.count += 1;
        let status = data.status.map(|status| status.as_u16());
        row.client_errors += u64::from(status.is_some_and(|status| (400..500).contains(&status)));
        row.server_errors += u64::from(status.is_some_and(|status| status >= 500));
        row.errors += u64::from(
            !matches!(
                outcome,
                Outcome::Completed | Outcome::Tunnel | Outcome::Refused(_)
            ) || status.is_some_and(|status| status >= 400),
        );
        row.request_bytes = row
            .request_bytes
            .saturating_add(data.request.lock().map_or(0, |measure| measure.bytes));
        row.response_bytes = row.response_bytes.saturating_add(data.response_bytes);
        row.slowest_ms = row
            .slowest_ms
            .max(u64::try_from(data.started.elapsed().as_millis()).unwrap_or(u64::MAX));
    }
    pub(super) fn connect(&mut self, host: &str, port: u16, failed: bool) {
        let key = (cut(host), port);
        let key = if self.connects.contains_key(&key) || self.connects.len() < 63 {
            key
        } else {
            ("*".into(), 0)
        };
        let row = self.connects.entry(key).or_default();
        row.count += 1;
        row.errors += u64::from(failed);
    }
    pub(super) fn dns(&mut self, name: &str, refused: bool) {
        let key = cut_text(name, 1024);
        let key = if self.dns.contains_key(&key) || self.dns.len() < 63 {
            key
        } else {
            "*".into()
        };
        let row = self.dns.entry(key).or_default();
        row.count += 1;
        row.refused += u64::from(refused);
    }
    pub(super) fn noise(&mut self, kind: NoiseKind, name: &str, value: &[u8]) {
        let key = (kind, cut_text(&name.to_ascii_lowercase(), 1024));
        let named = self.noise.keys().filter(|(_, name)| name != "*").count();
        let key = if self.noise.contains_key(&key) || named < self.max_named_noise_keys {
            key
        } else {
            (kind, "*".into())
        };
        let row = self.noise.entry(key).or_default();
        row.count += 1;
        row.bytes = row.bytes.saturating_add(value.len() as u64);
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        value.hash(&mut hasher);
        if row.hashes.len() < 257 {
            row.hashes.insert(hasher.finish());
        }
        row.many |= row.hashes.len() > 256;
    }
    pub(super) fn tick(&mut self) -> RollupBatch {
        self.drain(i64::try_from(crate::ROLLUP_INTERVAL.as_millis()).unwrap_or(i64::MAX))
    }
    pub(super) fn flush(&mut self) -> RollupBatch {
        self.drain(i64::try_from(self.since.elapsed().as_millis()).unwrap_or(i64::MAX))
    }
    fn drain(&mut self, interval: i64) -> RollupBatch {
        RollupBatch {
            interval,
            exchanges: std::mem::take(&mut self.exchanges),
            connects: std::mem::take(&mut self.connects),
            dns: std::mem::take(&mut self.dns),
            noise: std::mem::take(&mut self.noise),
        }
        .also_reset(&mut self.since)
    }
}
pub(super) struct RollupBatch {
    interval: i64,
    exchanges: BTreeMap<(String, u16), ExchangeTotals>,
    connects: BTreeMap<(String, u16), ConnectTotals>,
    dns: BTreeMap<String, DnsTotals>,
    noise: BTreeMap<(NoiseKind, String), NoiseTotals>,
}
impl RollupBatch {
    fn also_reset(self, since: &mut Instant) -> Self {
        *since = Instant::now();
        self
    }
    pub(super) fn emit(self) {
        for ((host, port), row) in self.exchanges {
            tracing::info!(name: "egress.exchange.rollup", target: "egress.exchange", {
                telemetry.detail = crate::telemetry::detail!(crate::config::Category::EgressExchange),
                server.address = %host, server.port = i64::from(port), rollup.interval_ms = self.interval,
                egress.exchange.count = i64::try_from(row.count).unwrap_or(i64::MAX),
                egress.exchange.error.count = i64::try_from(row.errors).unwrap_or(i64::MAX),
                egress.exchange.client_error.count = i64::try_from(row.client_errors).unwrap_or(i64::MAX),
                egress.exchange.server_error.count = i64::try_from(row.server_errors).unwrap_or(i64::MAX),
                http.request.body.size.sum = i64::try_from(row.request_bytes).unwrap_or(i64::MAX),
                http.response.body.size.sum = i64::try_from(row.response_bytes).unwrap_or(i64::MAX),
                egress.exchange.slowest_ms = i64::try_from(row.slowest_ms).unwrap_or(i64::MAX),
            }, "egress.exchange.rollup");
        }
        for ((host, port), row) in self.connects {
            tracing::info!(name: "egress.connect.rollup", target: "egress.connect", {
                telemetry.detail = crate::telemetry::detail!(crate::config::Category::EgressConnect),
                server.address = %host, server.port = i64::from(port), rollup.interval_ms = self.interval,
                egress.connect.count = i64::try_from(row.count).unwrap_or(i64::MAX),
                egress.connect.error.count = i64::try_from(row.errors).unwrap_or(i64::MAX),
            }, "egress.connect.rollup");
        }
        for (name, row) in self.dns {
            tracing::info!(name: "egress.dns.rollup", target: "egress.dns", {
                telemetry.detail = crate::telemetry::detail!(crate::config::Category::EgressDns),
                dns.question.name = %name, rollup.interval_ms = self.interval,
                egress.dns.count = i64::try_from(row.count).unwrap_or(i64::MAX),
                egress.dns.refused.count = i64::try_from(row.refused).unwrap_or(i64::MAX),
            }, "egress.dns.rollup");
        }
        for ((kind, name), row) in self.noise {
            tracing::info!(name: "egress.exchange.noise", target: "egress.exchange", {
                telemetry.detail = crate::telemetry::detail!(crate::config::Category::EgressExchange),
                egress.noise.kind = kind.label(), egress.noise.name = %name,
                egress.noise.value.count = i64::try_from(row.count).unwrap_or(i64::MAX),
                egress.noise.value.bytes = i64::try_from(row.bytes).unwrap_or(i64::MAX),
                egress.noise.distinct.count = i64::try_from(row.hashes.len().min(256)).unwrap_or(i64::MAX),
                egress.noise.distinct.many = row.many,
                rollup.interval_ms = self.interval,
            }, "egress.exchange.noise");
        }
    }
}
pub(super) fn omitted(name: &str, patterns: &[OmitName]) -> bool {
    let name = name.to_lowercase();
    patterns.iter().any(|pattern| match pattern {
        OmitName::Exact(exact) => name == *exact,
        OmitName::Prefix(prefix) => name.starts_with(prefix),
    })
}
pub(super) fn redact(name: &str) -> bool {
    let name = name.to_ascii_lowercase().replace(['-', '_'], "");
    [
        "token",
        "password",
        "passwd",
        "pwd",
        "secret",
        "signature",
        "credential",
        "cookie",
        "session",
        "auth",
        "apikey",
    ]
    .iter()
    .any(|part| name.contains(part))
        || name.ends_with("key")
        || matches!(name.as_str(), "code" | "sig" | "state" | "appid")
}
pub(super) fn cut_text(value: &str, max: usize) -> String {
    const MARKER: &str = "…[truncated]";
    if value.len() <= max {
        return value.to_owned();
    }
    let mut end = max.saturating_sub(MARKER.len());
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}{MARKER}", &value[..end])
}
pub(super) fn set_pairs(
    span: &tracing::Span,
    keys_name: &'static str,
    values_name: &'static str,
    keys: Vec<String>,
    values: Vec<String>,
) {
    if !keys.is_empty() {
        span.set_attribute(
            keys_name,
            Value::Array(Array::String(keys.into_iter().map(Into::into).collect())),
        );
        span.set_attribute(
            values_name,
            Value::Array(Array::String(values.into_iter().map(Into::into).collect())),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn credential_names_redact_query_and_header_values() {
        assert!(redact("x_api-key"));
        assert!(redact("authorization"));
        assert!(redact("Set-Cookie"));
        assert!(redact("sortkey"));
        assert!(!redact("public"));
    }
    #[test]
    fn omit_removes_both_name_and_value() {
        assert!(omitted("X-Secret", &[OmitName::Exact("x-secret".into())]));
        assert!(omitted(
            "X-Secret-One",
            &[OmitName::Prefix("x-secret".into())]
        ));
        assert!(!omitted("public", &[OmitName::Prefix("x-secret".into())]));
    }
    #[test]
    fn noise_distinct_values_saturate_at_256() {
        let mut rollups = Rollups::new();
        for n in 0..300_u64 {
            rollups.noise(NoiseKind::Header, "x-item", &n.to_le_bytes());
        }
        let row = rollups.noise.values().next().unwrap();
        assert_eq!(row.hashes.len(), 257);
        assert!(row.many);
    }
}
