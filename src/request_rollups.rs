use crate::{ROLLUP_INTERVAL, config::Category};
use std::collections::BTreeMap;
use tokio::time::Instant;

#[derive(Clone, Copy)]
pub(crate) enum Origin {
    Controller,
    Jail,
}

#[derive(Eq, PartialEq, Ord, PartialOrd)]
struct Key {
    route: String,
    session: Option<String>,
}

#[derive(Default)]
struct Totals {
    count: u64,
    errors: u64,
}

pub(crate) struct RequestRollups {
    since: Instant,
    rows: BTreeMap<Key, Totals>,
    origin: Origin,
    max_named_keys: usize,
}

pub(crate) struct Batch {
    interval_ms: i64,
    rows: BTreeMap<Key, Totals>,
    origin: Origin,
}

impl RequestRollups {
    pub(crate) fn new(origin: Origin) -> Self {
        Self {
            since: Instant::now(),
            rows: BTreeMap::new(),
            origin,
            max_named_keys: 63,
        }
    }

    pub(crate) fn record(&mut self, route: String, path: &str, status: poem::http::StatusCode) {
        let session = match self.origin {
            Origin::Controller if route.starts_with("/v1/sessions/{id}") => path
                .split('/')
                .nth(3)
                .and_then(|id| uuid::Uuid::parse_str(id).ok())
                .map(|id| id.to_string()),
            Origin::Controller | Origin::Jail => None,
        };
        let key = Key { route, session };
        let key = if self.rows.contains_key(&key) || self.rows.len() < self.max_named_keys {
            key
        } else {
            Key {
                route: "*".into(),
                session: None,
            }
        };
        let row = self.rows.entry(key).or_default();
        row.count = row.count.saturating_add(1);
        row.errors = row.errors.saturating_add(u64::from(status.as_u16() >= 400));
    }

    pub(crate) fn tick(&mut self) -> Batch {
        self.drain(i64::try_from(ROLLUP_INTERVAL.as_millis()).unwrap_or(i64::MAX))
    }

    pub(crate) fn flush(&mut self) -> Batch {
        self.drain(i64::try_from(self.since.elapsed().as_millis()).unwrap_or(i64::MAX))
    }

    fn drain(&mut self, interval_ms: i64) -> Batch {
        let batch = Batch {
            interval_ms,
            rows: std::mem::take(&mut self.rows),
            origin: self.origin,
        };
        self.since = Instant::now();
        batch
    }
}

impl Batch {
    pub(crate) fn emit(self) {
        for (key, row) in self.rows {
            let session = match self.origin {
                Origin::Controller => key.session.as_deref(),
                Origin::Jail => None,
            };
            tracing::info!(name: "vm_runner.request.rollup", target: "vm.exec", {
                telemetry.detail = crate::telemetry::detail!(Category::VmExec),
                http.route = %key.route,
                vm_runner.session_id = session,
                rollup.interval_ms = self.interval_ms,
                vm_runner.request.count = i64::try_from(row.count).unwrap_or(i64::MAX),
                vm_runner.request.error.count = i64::try_from(row.errors).unwrap_or(i64::MAX),
            }, "vm_runner.request.rollup");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentelemetry::logs::AnyValue;
    use opentelemetry_sdk::logs::{InMemoryLogExporter, SdkLoggerProvider};
    use tracing_subscriber::layer::SubscriberExt;

    #[test]
    fn request_rollups_fold_the_sixty_fourth_new_route_without_losing_errors() {
        let mut rollups = RequestRollups::new(Origin::Jail);
        for n in 0..65 {
            rollups.record(format!("/route/{n}"), "", poem::http::StatusCode::NOT_FOUND);
        }
        let batch = rollups.flush();
        assert_eq!(batch.rows.len(), 64);
        assert_eq!(batch.rows.values().map(|row| row.count).sum::<u64>(), 65);
        assert_eq!(batch.rows.values().map(|row| row.errors).sum::<u64>(), 65);
        assert_eq!(
            batch
                .rows
                .get(&Key {
                    route: "*".into(),
                    session: None
                })
                .map(|row| row.count),
            Some(2)
        );
    }

    #[test]
    fn controller_request_rollup_carries_only_the_matched_session_coordinate() {
        let exporter = InMemoryLogExporter::default();
        let provider = SdkLoggerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let dispatch = tracing::Dispatch::new(tracing_subscriber::registry().with(
            opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge::new(&provider),
        ));
        let id = "01995000-0000-7000-8000-000000000001";
        let mut rollups = RequestRollups::new(Origin::Controller);
        rollups.record(
            "/v1/sessions/{id}/exec".into(),
            &format!("/v1/sessions/{id}/exec"),
            poem::http::StatusCode::ACCEPTED,
        );
        rollups.record(
            "/v1/sessions/{id}/exec".into(),
            &format!("/v1/sessions/{id}/exec"),
            poem::http::StatusCode::BAD_REQUEST,
        );
        rollups.record(
            "unmatched".into(),
            "/v1/sessions/not-a-uuid/exec",
            poem::http::StatusCode::UNAUTHORIZED,
        );
        tracing::dispatcher::with_default(&dispatch, || rollups.flush().emit());
        let logs = exporter.get_emitted_logs().unwrap();
        let session = logs
            .iter()
            .find(|log| {
                log.record.attributes_iter().any(|(key, value)| {
                    key.as_str() == "http.route"
                        && value == &AnyValue::from("/v1/sessions/{id}/exec")
                })
            })
            .unwrap();
        assert!(
            session
                .record
                .attributes_iter()
                .any(|(key, value)| key.as_str() == "vm_runner.session_id"
                    && value == &AnyValue::from(id))
        );
        assert!(
            session
                .record
                .attributes_iter()
                .any(
                    |(key, value)| key.as_str() == "vm_runner.request.error.count"
                        && value == &AnyValue::Int(1)
                )
        );
        let unmatched = logs
            .iter()
            .find(|log| {
                log.record.attributes_iter().any(|(key, value)| {
                    key.as_str() == "http.route" && value == &AnyValue::from("unmatched")
                })
            })
            .unwrap();
        assert!(
            !unmatched
                .record
                .attributes_iter()
                .any(|(key, _)| key.as_str() == "vm_runner.session_id")
        );
        provider.shutdown().unwrap();
    }
    #[test]
    fn jail_request_rollup_never_sets_session_id_and_keeps_integer_counts() {
        let exporter = InMemoryLogExporter::default();
        let provider = SdkLoggerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let dispatch = tracing::Dispatch::new(tracing_subscriber::registry().with(
            opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge::new(&provider),
        ));
        let mut rollups = RequestRollups::new(Origin::Jail);
        rollups.record(
            "/v1/sessions/{id}/exec".into(),
            "/v1/sessions/01995000-0000-7000-8000-000000000001/exec",
            poem::http::StatusCode::BAD_REQUEST,
        );
        tracing::dispatcher::with_default(&dispatch, || rollups.flush().emit());
        let logs = exporter.get_emitted_logs().unwrap();
        let log = logs
            .iter()
            .find(|log| log.record.event_name() == Some("vm_runner.request.rollup"))
            .unwrap();
        assert!(
            !log.record
                .attributes_iter()
                .any(|(key, _)| key.as_str() == "vm_runner.session_id")
        );
        assert!(log.record.attributes_iter().any(|(key, value)| key.as_str()
            == "vm_runner.request.error.count"
            && value == &AnyValue::Int(1)));
        provider.shutdown().unwrap();
    }
}
