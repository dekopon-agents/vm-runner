use crate::guest::{self, Request};
use serde::de::DeserializeOwned;
use std::{
    path::PathBuf,
    sync::atomic::{AtomicU32, Ordering},
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::UnixStream,
};

const LEGACY_EXEC_DEADLINE_MS: u32 = 600_000;

#[derive(Debug, thiserror::Error)]
pub(super) enum Error {
    #[error("guest transport: {0}")]
    Io(#[from] std::io::Error),
    #[error("guest frame: {0}")]
    Frame(#[from] guest::Error),
    #[error("invalid guest response")]
    Reply(#[from] serde_json::Error),
    #[error("invalid vsock handshake")]
    Handshake,
    #[error("guest exchange deadline")]
    Deadline,
    #[error("unexpected guest exec deadline probe response")]
    ExecDeadlineProbe,
}
pub(super) struct Guest {
    path: PathBuf,
    exec_deadline_ms: AtomicU32,
}
impl Guest {
    pub(super) fn new(path: PathBuf) -> Self {
        Self {
            path,
            exec_deadline_ms: AtomicU32::new(LEGACY_EXEC_DEADLINE_MS),
        }
    }
    pub(super) fn exec_deadline_ms(&self) -> u32 {
        self.exec_deadline_ms.load(Ordering::Relaxed)
    }
    #[expect(
        clippy::map_err_ignore,
        reason = "Elapsed adds no cause; the owning operation records the typed deadline once"
    )]
    pub(super) async fn call<T: DeserializeOwned>(
        &self,
        request: &Request,
        deadline: Duration,
    ) -> Result<T, Error> {
        tokio::time::timeout(deadline, async {
            let mut stream = BufReader::new(UnixStream::connect(&self.path).await?);
            stream.write_all(b"CONNECT 1024\n").await?;
            let mut hello = Vec::new();
            (&mut stream).take(64).read_until(b'\n', &mut hello).await?;
            if !hello.starts_with(b"OK ") || !hello.ends_with(b"\n") {
                return Err(Error::Handshake);
            }
            guest::write_frame(&mut stream, request).await?;
            Ok(serde_json::from_slice(
                &guest::read_frame(&mut stream).await?,
            )?)
        })
        .await
        .map_err(|_| Error::Deadline)?
    }
    #[expect(
        clippy::map_err_ignore,
        reason = "Elapsed adds no cause; the boot phase records the typed deadline once"
    )]
    pub(super) async fn ready(&self) -> Result<(), Error> {
        #[derive(serde::Deserialize)]
        struct Pong {
            ok: bool,
        }
        tokio::time::timeout(Duration::from_secs(30), async {
            let mut probe = tokio::time::interval(Duration::from_millis(100));
            loop {
                probe.tick().await;
                if let Ok(Pong { ok: true }) =
                    self.call(&Request::Ping, Duration::from_secs(1)).await
                {
                    break;
                }
            }
            self.probe_exec_deadline().await
        })
        .await
        .map_err(|_| Error::Deadline)?
    }
    async fn probe_exec_deadline(&self) -> Result<(), Error> {
        #[derive(serde::Deserialize)]
        #[serde(
            tag = "outcome",
            rename_all = "snake_case",
            rename_all_fields = "camelCase"
        )]
        enum Probe {
            Executed { exit_code: i32 },
            NotExecuted { reason: String },
        }
        let request = Request::Exec {
            argv: vec!["/bin/true".into()],
            stdin: None,
            deadline_ms: guest::EXEC_DEADLINE_MS,
            env: None,
            cwd: None,
        };
        let deadline_ms = match self.call(&request, Duration::from_secs(5)).await? {
            Probe::Executed { exit_code: 0 } => guest::EXEC_DEADLINE_MS,
            Probe::NotExecuted { reason } if reason == "invalid_exec" => LEGACY_EXEC_DEADLINE_MS,
            _ => return Err(Error::ExecDeadlineProbe),
        };
        self.exec_deadline_ms.store(deadline_ms, Ordering::Relaxed);
        Ok(())
    }
}
