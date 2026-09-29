use super::{Guest, State};
use crate::guest::Request;
use base64::{Engine, engine::general_purpose::STANDARD};
use poem::{Body, http::StatusCode};
use poem_openapi::{
    ApiResponse, Object,
    payload::{Binary, Json},
};
use serde::Deserialize;
use std::{
    io,
    path::{Component, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::sync::OwnedSemaphorePermit;
use tracing::Instrument;

#[cfg(test)]
mod tests;
const CHUNK: u32 = 64 * 1024;
#[derive(Deserialize, Object)]
pub(super) struct Artifact {
    path: String,
    bytes: u64,
    sha256: String,
}
#[derive(Deserialize)]
struct Chunk {
    data: String,
    eof: bool,
}
#[derive(Deserialize)]
#[serde(tag = "outcome")]
enum Refusal {
    #[serde(rename = "not_executed")]
    NotExecuted {
        #[serde(rename = "reason")]
        _reason: String,
    },
}
#[derive(Deserialize)]
#[serde(untagged)]
enum Reply<T> {
    Value(T),
    Refused(Refusal),
}
impl<T> Reply<T> {
    fn value(self) -> poem::Result<T> {
        match self {
            Self::Value(value) => Ok(value),
            Self::Refused(Refusal::NotExecuted { .. }) => {
                Err(poem::Error::from_status(StatusCode::FORBIDDEN))
            }
        }
    }
}
fn safe_path(path: &str) -> bool {
    !path.is_empty()
        && std::path::Path::new(path)
            .components()
            .all(|c| matches!(c, Component::Normal(_)))
}
pub(super) async fn list(guest: &Guest) -> poem::Result<Json<Vec<Artifact>>> {
    let files = guest
        .call::<Reply<Vec<Artifact>>>(&Request::List, Duration::from_secs(610))
        .await
        .map_err(poem::error::BadGateway)?
        .value()?;
    if files.iter().any(|file| {
        !safe_path(&file.path)
            || file.sha256.len() != 64
            || !file.sha256.bytes().all(|b| b.is_ascii_hexdigit())
    }) {
        return Err(poem::Error::from_status(StatusCode::BAD_GATEWAY));
    }
    Ok(Json(files))
}
#[derive(ApiResponse)]
pub(super) enum Download {
    #[oai(status = 200)]
    Full(
        Binary<Body>,
        #[oai(header = "sha256")] String,
        #[oai(header = "Content-Length")] u64,
        #[oai(header = "Accept-Ranges")] String,
    ),
    #[oai(status = 206)]
    Partial(
        Binary<Body>,
        #[oai(header = "sha256")] String,
        #[oai(header = "Content-Length")] u64,
        #[oai(header = "Content-Range")] String,
        #[oai(header = "Accept-Ranges")] String,
    ),
    #[oai(status = 416)]
    Unsatisfiable(#[oai(header = "Content-Range")] String),
}
struct Transfer {
    guest: Arc<Guest>,
    path: PathBuf,
    offset: u64,
    end: u64,
    size: u64,
}
impl Transfer {
    async fn next(mut self) -> io::Result<Option<(hyper::body::Bytes, Self)>> {
        if self.offset == self.end {
            return Ok(None);
        }
        let len = (self.end - self.offset).min(CHUNK.into()) as u32;
        let reply = self
            .guest
            .call::<Reply<Chunk>>(
                &Request::Read {
                    path: self.path.clone(),
                    offset: self.offset,
                    len,
                },
                Duration::from_secs(610),
            )
            .await
            .map_err(io::Error::other)?;
        let chunk = reply.value().map_err(io::Error::other)?;
        if chunk.data.len() > (len as usize).div_ceil(3) * 4 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "oversized artifact chunk",
            ));
        }
        let data = STANDARD.decode(chunk.data).map_err(io::Error::other)?;
        if data.len() != len as usize || chunk.eof != (self.offset + u64::from(len) == self.size) {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "artifact changed during read",
            ));
        }
        self.offset += u64::from(len);
        Ok(Some((data.into(), self)))
    }
}
fn stream(state: &State, mut transfer: Transfer, slot: OwnedSemaphorePermit) -> poem::Result<Body> {
    // Reuse the lifecycle's bounded worker owner. Span export runs on its blocking thread,
    // not a Hyper I/O worker. Only one chunk can queue ahead of the HTTP reader.
    let mut jobs = state
        .jobs
        .lock()
        .map_err(|error| poem::error::InternalServerError(io::Error::other(error.to_string())))?;
    while let Some(result) = jobs.workers.try_join_next() {
        result.map_err(poem::error::InternalServerError)?;
    }
    if jobs.workers.len() >= super::JOB_CAP {
        return Err(poem::Error::from_status(StatusCode::SERVICE_UNAVAILABLE));
    }
    let (send, receiver) = tokio::sync::mpsc::channel(1);
    let runtime = tokio::runtime::Handle::current();
    let dispatch = tracing::dispatcher::get_default(Clone::clone);
    let span = tracing::Span::current();
    jobs.workers.spawn_blocking(move || tracing::dispatcher::with_default(&dispatch, || runtime.block_on(async move {
        loop {
            let next = tokio::select! { _ = send.closed() => break, next = transfer.next() => next };
            match next {
                Ok(Some((bytes, next))) => {
                    if send.send(Ok(bytes)).await.is_err() { break; }
                    transfer = next;
                }
                Ok(None) => break,
                Err(error) => {
                    tracing::Span::current().record("error.message", crate::egress::cut(&error.to_string()));
                    let _closed = send.send(Err(error)).await;
                    break;
                }
            }
        }
    }.instrument(span))));
    let stream =
        futures_util::stream::unfold((receiver, slot), |(mut receiver, slot)| async move {
            receiver.recv().await.map(|chunk| (chunk, (receiver, slot)))
        });
    Ok(Body::from_async_read(tokio_util::io::StreamReader::new(
        Box::pin(stream),
    )))
}
pub(super) async fn read(
    state: &State,
    path: String,
    range: Option<String>,
) -> poem::Result<Download> {
    async {
        if !safe_path(&path) {
            return Err(poem::Error::from_status(StatusCode::FORBIDDEN));
        }
        // HTTP admission ends when headers return; these four leases bound streaming bodies until drop.
        let slot = Arc::clone(&state.transfers)
            .try_acquire_owned()
            .map_err(poem::error::ServiceUnavailable)?;
        let file = list(&state.guest)
            .await?
            .0
            .into_iter()
            .find(|f| f.path == path)
            .ok_or_else(|| poem::Error::from_status(StatusCode::NOT_FOUND))?;
        let bytes = range
            .as_deref()
            .and_then(|r| r.split_once('='))
            .filter(|(unit, _)| unit.eq_ignore_ascii_case("bytes"));
        let selected = if let Some((_, range)) = bytes {
            if file.bytes == 0 {
                return Ok(Download::Unsatisfiable("bytes */0".into()));
            }
            match http_range::HttpRange::parse(&format!("bytes={range}"), file.bytes) {
                Ok(ranges) if ranges.len() == 1 => ranges.into_iter().next(),
                Ok(_) => None,
                Err(_invalid) => {
                    return Ok(Download::Unsatisfiable(format!("bytes */{}", file.bytes)));
                }
            }
        } else {
            None
        };
        let (offset, end) = selected
            .as_ref()
            .map_or((0, file.bytes), |r| (r.start, r.start + r.length));
        let body = Binary(stream(
            state,
            Transfer {
                guest: Arc::clone(&state.guest),
                path: path.into(),
                offset,
                end,
                size: file.bytes,
            },
            slot,
        )?);
        Ok(if selected.is_some() {
            Download::Partial(
                body,
                file.sha256,
                end - offset,
                format!("bytes {offset}-{}/{}", end - 1, file.bytes),
                "bytes".into(),
            )
        } else {
            Download::Full(body, file.sha256, file.bytes, "bytes".into())
        })
    }
    .instrument(tracing::info_span!(
        target: crate::config::Category::VmExec.target(), "vm_runner.artifact.read",
        telemetry.detail = crate::telemetry::detail!(crate::config::Category::VmExec),
        error.message = tracing::field::Empty
    ))
    .await
}
