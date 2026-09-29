use super::{Error, Refusal};
use crate::config::OmitName;
use hyper::StatusCode;
use std::{
    collections::{BTreeMap, HashSet},
    sync::Mutex,
};
use tokio::time::Instant;

#[derive(Clone, Copy)]
pub(super) enum Phase {
    Connect,
    Headers,
    RequestBody,
    ResponseBody,
}
impl Phase {
    pub(super) const fn label(self) -> &'static str {
        todo!()
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
        todo!()
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
    request_bytes: u64,
    response_bytes: u64,
    rollups: std::sync::Arc<Mutex<Rollups>>,
}
#[must_use]
pub(super) struct Recorded;
impl Exchange {
    pub(super) fn new(
        host: &str,
        port: Option<u16>,
        method: &str,
        rollups: std::sync::Arc<Mutex<Rollups>>,
    ) -> Self {
        todo!()
    }
    pub(super) fn phase(&mut self, phase: Phase) {
        todo!()
    }
    pub(super) fn status(&mut self, status: StatusCode) {
        todo!()
    }
    pub(super) fn finish(self, outcome: Outcome, error: Option<&str>) -> Recorded {
        todo!()
    }
}
impl Drop for Exchange {
    fn drop(&mut self) {
        todo!()
    }
}

pub(super) struct Rollups {
    since: Instant,
    exchanges: BTreeMap<(String, u16), ExchangeTotals>,
    noise: BTreeMap<(NoiseKind, String), NoiseTotals>,
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
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
pub(super) enum NoiseKind {
    Header,
    QueryKey,
}
impl NoiseKind {
    pub(super) const fn label(self) -> &'static str {
        todo!()
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
        todo!()
    }
    fn exchange(&mut self, data: &ExchangeData, outcome: &Outcome) {
        todo!()
    }
    pub(super) fn noise(&mut self, kind: NoiseKind, name: &str, value: &[u8]) {
        todo!()
    }
    pub(super) fn flush(&mut self) {
        todo!()
    }
}
pub(super) fn omitted(name: &str, patterns: &[OmitName]) -> bool {
    todo!()
}
pub(super) fn redact(name: &str) -> bool {
    todo!()
}

#[cfg(test)]
mod tests {
    #[test]
    fn cancelled_exchange_has_one_abandoned_end() {
        todo!()
    }
    #[test]
    fn completed_exchange_with_no_body_has_one_end() {
        todo!()
    }
    #[test]
    fn refused_exchange_never_has_zero_status() {
        todo!()
    }
    #[test]
    fn excess_rollup_keys_fold_into_star_with_exact_totals() {
        todo!()
    }
    #[test]
    fn noise_distinct_values_saturate_at_256() {
        todo!()
    }
    #[test]
    fn omit_removes_both_name_and_value() {
        todo!()
    }
    #[test]
    fn credential_names_redact_query_and_header_values() {
        todo!()
    }
}
