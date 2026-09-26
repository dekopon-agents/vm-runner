use crate::guest::{self, Request};
use serde::de::DeserializeOwned;
use std::{path::PathBuf, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::UnixStream,
};

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
}
pub(super) struct Guest {
    path: PathBuf,
}
impl Guest {
    pub(super) fn new(path: PathBuf) -> Self {
        Self { path }
    }
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
        .map_err(|elapsed| {
            tracing::warn!(%elapsed, "guest exchange timed out");
            Error::Deadline
        })?
    }
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
                    return;
                }
            }
        })
        .await
        .map_err(|elapsed| {
            tracing::warn!(%elapsed, "guest did not become ready");
            Error::Deadline
        })
    }
}
