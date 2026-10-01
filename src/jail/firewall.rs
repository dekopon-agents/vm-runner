use crate::{ROLLUP_INTERVAL, config::Category};
use serde::Deserialize;
use std::{io, process::Stdio};
use tokio::{io::AsyncReadExt, process::Command, time::Instant};

#[derive(Clone, Copy, Default)]
struct Counters {
    input: u64,
    forward: u64,
}

#[derive(Deserialize)]
struct NftListing {
    nftables: Vec<NftObject>,
}
#[derive(Deserialize)]
struct NftObject {
    counter: Option<NftCounter>,
}
#[derive(Deserialize)]
struct NftCounter {
    name: String,
    packets: u64,
}

#[derive(Debug, thiserror::Error)]
enum ReadError {
    #[error("nft counter read failed: {kind:?}")]
    Io { kind: io::ErrorKind },
    #[error("nft returned {status}")]
    Status { status: std::process::ExitStatus },
    #[error("nft counter output exceeds limit")]
    TooLarge,
    #[error("invalid nft counter JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("missing nft counter {name}")]
    Missing { name: &'static str },
}

struct NftOutput(Vec<u8>);
impl NftOutput {
    async fn read() -> Result<Self, ReadError> {
        let mut child = Command::new("nft")
            .args(["-j", "list", "counters", "table", "inet", "vm_runner"])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|error| ReadError::Io { kind: error.kind() })?;
        let stdout = child.stdout.take().ok_or(ReadError::Io {
            kind: io::ErrorKind::BrokenPipe,
        })?;
        let mut bytes = Vec::with_capacity(4096);
        stdout
            .take(65_537)
            .read_to_end(&mut bytes)
            .await
            .map_err(|error| ReadError::Io { kind: error.kind() })?;
        if bytes.len() > 65_536 {
            return Err(ReadError::TooLarge);
        }
        let status = child
            .wait()
            .await
            .map_err(|error| ReadError::Io { kind: error.kind() })?;
        if !status.success() {
            return Err(ReadError::Status { status });
        }
        Ok(Self(bytes))
    }

    fn counters(&self) -> Result<Counters, ReadError> {
        let listing: NftListing = serde_json::from_slice(&self.0)?;
        let mut input = None;
        let mut forward = None;
        for entry in listing.nftables {
            if let Some(counter) = entry.counter {
                match counter.name.as_str() {
                    "input_drop" => input = Some(counter.packets),
                    "forward_drop" => forward = Some(counter.packets),
                    _ => (),
                }
            }
        }
        Ok(Counters {
            input: input.ok_or(ReadError::Missing { name: "input_drop" })?,
            forward: forward.ok_or(ReadError::Missing {
                name: "forward_drop",
            })?,
        })
    }
}

#[derive(Clone, Copy)]
pub(super) enum Interval {
    Regular,
    End,
}

pub(super) struct Firewall {
    since: Instant,
    previous: Counters,
    missed: bool,
}
impl Firewall {
    pub(super) fn new() -> Self {
        Self {
            since: Instant::now(),
            previous: Counters::default(),
            missed: false,
        }
    }

    pub(super) async fn sample(&mut self, interval: Interval) {
        match NftOutput::read().await.and_then(|output| output.counters()) {
            Ok(counters) => self.record(counters, interval),
            Err(error) => {
                self.missed = true;
                tracing::warn!(name: "egress.refused.firewall_read_failed", target: "egress.drop", {
                    telemetry.detail = crate::telemetry::detail!(Category::EgressDrop),
                    error = %crate::egress::cut_error(&error.to_string()),
                }, "egress firewall counter read failed");
            }
        }
    }

    fn record(&mut self, counters: Counters, interval: Interval) {
        let input = counters.input.saturating_sub(self.previous.input);
        let forward = counters.forward.saturating_sub(self.previous.forward);
        let interval_ms = match (interval, self.missed) {
            (Interval::Regular, false) => {
                i64::try_from(ROLLUP_INTERVAL.as_millis()).unwrap_or(i64::MAX)
            }
            (Interval::Regular, true) | (Interval::End, _) => {
                i64::try_from(self.since.elapsed().as_millis()).unwrap_or(i64::MAX)
            }
        };
        self.previous = counters;
        self.since = Instant::now();
        self.missed = false;
        if input > 0 || forward > 0 || matches!(interval, Interval::End) {
            tracing::info!(name: "egress.refused.firewall", target: "egress.drop", {
                telemetry.detail = crate::telemetry::detail!(Category::EgressDrop),
                egress.firewall.input_drop.count = i64::try_from(input).unwrap_or(i64::MAX),
                egress.firewall.forward_drop.count = i64::try_from(forward).unwrap_or(i64::MAX),
                rollup.interval_ms = interval_ms,
            }, "egress.refused.firewall");
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
    fn named_firewall_counters_emit_only_moved_deltas_and_a_final_record() {
        let output = NftOutput(
            serde_json::to_vec(&serde_json::json!({"nftables": [
                {"metainfo": {}},
                {"counter": {"name": "input_drop", "packets": 7}},
                {"counter": {"name": "forward_drop", "packets": 3}},
            ]}))
            .unwrap(),
        );
        let current = output.counters().unwrap();
        let exporter = InMemoryLogExporter::default();
        let provider = SdkLoggerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let dispatch = tracing::Dispatch::new(tracing_subscriber::registry().with(
            opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge::new(&provider),
        ));
        tracing::dispatcher::with_default(&dispatch, || {
            let mut firewall = Firewall::new();
            firewall.record(current, Interval::Regular);
            firewall.record(current, Interval::Regular);
            firewall.record(current, Interval::End);
        });
        let logs = exporter.get_emitted_logs().unwrap();
        let records: Vec<_> = logs
            .iter()
            .filter(|log| log.record.event_name() == Some("egress.refused.firewall"))
            .collect();
        assert_eq!(records.len(), 2);
        assert!(
            records[0]
                .record
                .attributes_iter()
                .any(
                    |(key, value)| key.as_str() == "egress.firewall.input_drop.count"
                        && value == &AnyValue::Int(7)
                )
        );
        assert!(
            records[0]
                .record
                .attributes_iter()
                .any(
                    |(key, value)| key.as_str() == "egress.firewall.forward_drop.count"
                        && value == &AnyValue::Int(3)
                )
        );
        assert!(
            records[1]
                .record
                .attributes_iter()
                .any(
                    |(key, value)| key.as_str() == "egress.firewall.input_drop.count"
                        && value == &AnyValue::Int(0)
                )
        );
        provider.shutdown().unwrap();
    }

    #[test]
    fn missing_counter_refuses_to_report_a_partial_delta() {
        let output = NftOutput(
            serde_json::to_vec(&serde_json::json!({"nftables": [
                {"counter": {"name": "input_drop", "packets": 2}},
            ]}))
            .unwrap(),
        );
        assert!(matches!(
            output.counters(),
            Err(ReadError::Missing {
                name: "forward_drop"
            })
        ));
    }
}
