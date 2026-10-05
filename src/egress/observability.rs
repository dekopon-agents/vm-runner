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
    response_head: BodyHead,
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
struct BodyHead {
    bytes: Vec<u8>,
    max_bytes: usize,
}
impl BodyHead {
    fn new() -> Self {
        Self {
            bytes: Vec::new(),
            max_bytes: 4096,
        }
    }
    fn append(&mut self, bytes: &[u8]) {
        let take = (self.max_bytes - self.bytes.len()).min(bytes.len());
        self.bytes.extend_from_slice(&bytes[..take]);
    }
    fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}
pub(super) struct RequestMeasure {
    bytes: u64,
    head: BodyHead,
    failed: bool,
}
impl RequestMeasure {
    pub(super) fn new() -> Self {
        Self {
            bytes: 0,
            head: BodyHead::new(),
            failed: false,
        }
    }
    pub(super) const fn fail(&mut self) {
        self.failed = true;
    }
    pub(super) fn append(&mut self, bytes: &[u8]) {
        self.bytes = self.bytes.saturating_add(bytes.len() as u64);
        if tracing::enabled!(target: "egress.exchange", tracing::Level::TRACE) {
            self.head.append(bytes);
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
            span.record("url.path", cut_text(url.path()));
            let mut pairs = ParallelFields::new();
            for (key, value) in url.query_pairs() {
                if pairs.full() {
                    break;
                }
                if omitted(&key, omit_query) {
                    continue;
                }
                let value = if redact(&key) {
                    "[redacted]".into()
                } else {
                    value
                };
                pairs.push(cut_text(&key), cut_text(&value));
            }
            pairs.record(&span, "url.query.keys", "url.query.values");
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
                response_head: BodyHead::new(),
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
    pub(super) fn request_body_failed(&self) -> bool {
        self.data
            .as_ref()
            .is_some_and(|data| data.request.lock().is_ok_and(|measured| measured.failed))
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
                    let kind = content
                        .as_bytes()
                        .iter()
                        .copied()
                        .take_while(|byte| *byte != b';')
                        .map(|byte| byte.to_ascii_lowercase())
                        .collect::<Vec<_>>();
                    kind.starts_with(b"text/")
                        || kind == b"application/json"
                        || kind.ends_with(b"+json")
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
        let mut pairs = ParallelFields::new();
        for (name, value) in headers {
            let name = name.as_str();
            if omitted(name, omit) {
                continue;
            }
            if let Ok(mut totals) = data.rollups.lock() {
                totals.noise(NoiseKind::Header, name, value.as_bytes());
            }
            if standard && name == "content-type" {
                let content = cut_text(&String::from_utf8_lossy(value.as_bytes()));
                data.span.record(side.content_type(), content);
            }
            if standard && matches!(side, HeaderSide::Request) && name == "user-agent" {
                data.span.record(
                    "user_agent.original",
                    cut_text(&String::from_utf8_lossy(value.as_bytes())),
                );
            }
            if full && !pairs.full() {
                let value = if redact(name) {
                    "[redacted]".into()
                } else {
                    cut_text(&String::from_utf8_lossy(value.as_bytes()))
                };
                pairs.push(cut_text(name), value);
            }
        }
        if full {
            pairs.record(&data.span, side.names(), side.values());
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
                data.response_head.append(bytes);
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
                body_head(&measure.head, measure.bytes),
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
            body_head(&data.response_head, data.response_bytes),
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
        let error = error.map(cut_text);
        tracing::info!(name: "egress.exchange.failed", target: "egress.exchange", {
            telemetry.detail = crate::telemetry::detail!(crate::config::Category::EgressExchange),
            server.address = %data.host, server.port = data.port.map(i64::from),
            http.request.method = %data.method, http.response.status_code = status,
            egress.exchange.outcome = label, egress.exchange.phase = phase,
            error = error.as_deref(),
        }, "egress.exchange.failed");
    }
}

pub(super) struct ConnectAttempt<'a> {
    rollups: &'a Mutex<Rollups>,
    host: &'a str,
    port: u16,
    outcome: ConnectOutcome,
}
#[derive(Clone, Copy)]
pub(super) enum ConnectOutcome {
    Abandoned,
    Succeeded,
    Failed,
}
impl<'a> ConnectAttempt<'a> {
    pub(super) fn new(rollups: &'a Mutex<Rollups>, host: &'a str, port: u16) -> Self {
        Self {
            rollups,
            host,
            port,
            outcome: ConnectOutcome::Abandoned,
        }
    }
    pub(super) fn complete(&mut self, outcome: ConnectOutcome) {
        self.outcome = outcome;
    }
}
impl Drop for ConnectAttempt<'_> {
    fn drop(&mut self) {
        if let Ok(mut rollups) = self.rollups.lock() {
            rollups.connect(self.host, self.port, self.outcome);
        }
    }
}

pub(super) struct Rollups {
    since: Instant,
    exchanges: BTreeMap<(String, Option<u16>), ExchangeTotals>,
    connects: BTreeMap<(String, Option<u16>), ConnectTotals>,
    dns: BTreeMap<String, DnsTotals>,
    noise: BTreeMap<(NoiseKind, String), NoiseTotals>,
    max_named_keys: usize,
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
struct NoiseTotals {
    count: u64,
    bytes: u64,
    hashes: HashSet<u64>,
    many: bool,
    max_distinct: usize,
}
impl Default for NoiseTotals {
    fn default() -> Self {
        Self {
            count: 0,
            bytes: 0,
            hashes: HashSet::new(),
            many: false,
            max_distinct: 257,
        }
    }
}
impl NoiseTotals {
    fn observe(&mut self, value: &[u8]) {
        self.count = self.count.saturating_add(1);
        self.bytes = self
            .bytes
            .saturating_add(u64::try_from(value.len()).unwrap_or(u64::MAX));
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        value.hash(&mut hasher);
        if self.hashes.len() < self.max_distinct {
            self.hashes.insert(hasher.finish());
        }
        self.many |= self.hashes.len() >= self.max_distinct;
    }
    fn distinct_count(&self) -> i64 {
        i64::try_from(self.hashes.len().min(self.max_distinct - 1)).unwrap_or(i64::MAX)
    }
}
impl Rollups {
    pub(super) fn new() -> Self {
        Self {
            since: Instant::now(),
            exchanges: BTreeMap::new(),
            connects: BTreeMap::new(),
            dns: BTreeMap::new(),
            noise: BTreeMap::new(),
            max_named_keys: 63,
            max_named_noise_keys: 62,
        }
    }
    fn exchange(&mut self, data: &ExchangeData, outcome: &Outcome) {
        let key = (data.host.clone(), data.port);
        let key = if self.exchanges.contains_key(&key) || self.exchanges.len() < self.max_named_keys
        {
            key
        } else {
            ("*".into(), None)
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
    pub(super) fn connect(&mut self, host: &str, port: u16, outcome: ConnectOutcome) {
        let key = (cut(host), Some(port));
        let key = if self.connects.contains_key(&key) || self.connects.len() < self.max_named_keys {
            key
        } else {
            ("*".into(), None)
        };
        let row = self.connects.entry(key).or_default();
        row.count += 1;
        row.errors += match outcome {
            ConnectOutcome::Abandoned | ConnectOutcome::Failed => 1,
            ConnectOutcome::Succeeded => 0,
        };
    }
    pub(super) fn dns(&mut self, name: &str, refused: bool) {
        let key = cut_text(name);
        let key = if self.dns.contains_key(&key) || self.dns.len() < self.max_named_keys {
            key
        } else {
            "*".into()
        };
        let row = self.dns.entry(key).or_default();
        row.count += 1;
        row.refused += u64::from(refused);
    }
    pub(super) fn noise(&mut self, kind: NoiseKind, name: &str, value: &[u8]) {
        let key = (kind, cut_text(&name.to_ascii_lowercase()));
        let named = self.noise.keys().filter(|(_, name)| name != "*").count();
        let key = if self.noise.contains_key(&key) || named < self.max_named_noise_keys {
            key
        } else {
            (kind, "*".into())
        };
        self.noise.entry(key).or_default().observe(value);
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
    exchanges: BTreeMap<(String, Option<u16>), ExchangeTotals>,
    connects: BTreeMap<(String, Option<u16>), ConnectTotals>,
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
                server.address = %host, server.port = port.map(i64::from), rollup.interval_ms = self.interval,
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
                server.address = %host, server.port = port.map(i64::from), rollup.interval_ms = self.interval,
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
                egress.noise.distinct.count = row.distinct_count(),
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
const TRUNCATION: &str = "…[truncated]";
fn body_head(head: &BodyHead, total: u64) -> String {
    let text = String::from_utf8_lossy(&head.bytes);
    if total > head.bytes.len() as u64 {
        let mut end = text
            .len()
            .min(head.max_bytes.saturating_sub(TRUNCATION.len()));
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}{TRUNCATION}", &text[..end])
    } else {
        cut_at(&text, head.max_bytes)
    }
}
struct TextCut {
    max_bytes: usize,
}
impl TextCut {
    fn new() -> Self {
        Self { max_bytes: 1024 }
    }
    fn apply(&self, value: &str) -> String {
        cut_at(value, self.max_bytes)
    }
}
pub(super) fn cut_text(value: &str) -> String {
    TextCut::new().apply(value)
}
fn cut_at(value: &str, max: usize) -> String {
    if value.len() <= max {
        return value.to_owned();
    }
    let mut end = max.saturating_sub(TRUNCATION.len());
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}{TRUNCATION}", &value[..end])
}
struct ParallelFields {
    keys: Vec<String>,
    values: Vec<String>,
    max_elements: usize,
}
impl ParallelFields {
    fn new() -> Self {
        Self {
            keys: Vec::new(),
            values: Vec::new(),
            max_elements: 64,
        }
    }
    fn full(&self) -> bool {
        self.keys.len() >= self.max_elements
    }
    fn push(&mut self, key: String, value: String) {
        if !self.full() {
            self.keys.push(key);
            self.values.push(value);
        }
    }
    fn record(self, span: &tracing::Span, keys_name: &'static str, values_name: &'static str) {
        if !self.keys.is_empty() {
            span.set_attribute(
                keys_name,
                Value::Array(Array::String(
                    self.keys.into_iter().map(Into::into).collect(),
                )),
            );
            span.set_attribute(
                values_name,
                Value::Array(Array::String(
                    self.values.into_iter().map(Into::into).collect(),
                )),
            );
        }
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
        use opentelemetry::logs::AnyValue;
        use opentelemetry_sdk::logs::{InMemoryLogExporter, SdkLoggerProvider};
        use tracing_subscriber::layer::SubscriberExt;
        let exporter = InMemoryLogExporter::default();
        let provider = SdkLoggerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let dispatch = tracing::Dispatch::new(tracing_subscriber::registry().with(
            opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge::new(&provider),
        ));
        let mut rollups = Rollups::new();
        for n in 0..300_u64 {
            rollups.noise(NoiseKind::Header, "x-item", &n.to_le_bytes());
        }
        let row = rollups.noise.values().next().unwrap();
        assert_eq!(row.hashes.len(), 257);
        assert!(row.many);
        tracing::dispatcher::with_default(&dispatch, || rollups.flush().emit());
        let logs = exporter.get_emitted_logs().unwrap();
        let noise = logs
            .iter()
            .find(|log| log.record.event_name() == Some("egress.exchange.noise"))
            .unwrap();
        assert!(
            noise
                .record
                .attributes_iter()
                .any(|(key, value)| key.as_str() == "egress.noise.distinct.count"
                    && value == &AnyValue::Int(256))
        );
        assert!(
            noise
                .record
                .attributes_iter()
                .any(|(key, value)| key.as_str() == "egress.noise.distinct.many"
                    && value == &AnyValue::Boolean(true))
        );
        assert!(
            noise
                .record
                .attributes_iter()
                .any(|(key, value)| key.as_str() == "egress.noise.value.bytes"
                    && value == &AnyValue::Int(2400))
        );
        provider.shutdown().unwrap();
    }
    #[test]
    fn sixty_fifth_noise_key_folds_both_kinds_without_exceeding_the_map_bound() {
        let mut rollups = Rollups::new();
        for n in 0..63 {
            rollups.noise(NoiseKind::Header, &format!("x-item-{n}"), b"v");
        }
        rollups.noise(NoiseKind::QueryKey, "q", b"query");
        assert_eq!(rollups.noise.len(), 64);
        assert_eq!(rollups.noise.values().map(|row| row.count).sum::<u64>(), 64);
        assert_eq!(rollups.noise.values().map(|row| row.bytes).sum::<u64>(), 68);
        assert_eq!(
            rollups
                .noise
                .get(&(NoiseKind::Header, "*".into()))
                .map(|row| row.count),
            Some(1)
        );
        assert_eq!(
            rollups
                .noise
                .get(&(NoiseKind::QueryKey, "*".into()))
                .map(|row| row.count),
            Some(1)
        );
    }
    #[test]
    fn cancelled_connect_still_contributes_an_error_to_its_rollup() {
        let rollups = Mutex::new(Rollups::new());
        drop(ConnectAttempt::new(&rollups, "localhost", 443));
        let rows = &rollups.lock().unwrap().connects;
        let row = rows.get(&("localhost".to_owned(), Some(443))).unwrap();
        assert_eq!(row.count, 1);
        assert_eq!(row.errors, 1);
    }
    #[tokio::test(start_paused = true)]
    async fn regular_interval_is_sixty_seconds_and_final_interval_is_shorter() {
        let mut rollups = Rollups::new();
        tokio::time::advance(crate::ROLLUP_INTERVAL).await;
        assert_eq!(rollups.tick().interval, 60_000);
        tokio::time::advance(std::time::Duration::from_secs(7)).await;
        assert_eq!(rollups.flush().interval, 7_000);
    }
}
