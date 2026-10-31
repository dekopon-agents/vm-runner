use crate::request_rollups::Origin;
use poem::{
    Request,
    http::{Method, StatusCode},
};
use std::{future::Future, sync::Arc, time::Duration};
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore},
    time::Instant,
};

#[derive(Clone, Copy)]
pub(crate) struct JobWait {
    pub(crate) requested_seconds: u32,
    pub(crate) deadline: Instant,
}
impl JobWait {
    pub(crate) fn prepare(request: &mut Request, origin: Origin) -> poem::Result<Option<Self>> {
        let started = Instant::now();
        let prefix = match origin {
            Origin::Controller => "/v1/jobs/",
            Origin::Jail => "/jobs/",
        };
        if request.method() != Method::GET
            || !request
                .uri()
                .path()
                .strip_prefix(prefix)
                .is_some_and(|id| !id.is_empty() && !id.contains('/'))
        {
            return Ok(None);
        }
        let Some(requested_seconds) = Self::preference(request)? else {
            return Ok(None);
        };
        let budget = match origin {
            Origin::Controller => Duration::from_secs(29),
            Origin::Jail => Duration::from_secs(requested_seconds.into()),
        };
        let wait = Self {
            requested_seconds,
            deadline: started + budget,
        };
        request.extensions_mut().insert(wait);
        Ok(Some(wait))
    }
    fn preference(request: &Request) -> poem::Result<Option<u32>> {
        for header in request.headers().get_all("Prefer") {
            let value = header.to_str().map_err(poem::error::BadRequest)?;
            let mut quoted = false;
            let mut escaped = false;
            for preference in value.split(|ch| {
                if escaped {
                    escaped = false;
                    return false;
                }
                match ch {
                    '\\' if quoted => escaped = true,
                    '"' => quoted = !quoted,
                    ',' if !quoted => return true,
                    _ => (),
                }
                false
            }) {
                let preference = preference.split(';').next().unwrap_or_default();
                let (name, value) = preference
                    .split_once('=')
                    .map_or((preference, None), |(name, value)| (name, Some(value)));
                if !name.trim().eq_ignore_ascii_case("wait") {
                    continue;
                }
                let invalid = || {
                    poem::Error::from_string(
                        "Prefer wait must be an integer from 1 to 25",
                        StatusCode::BAD_REQUEST,
                    )
                };
                let value = value.ok_or_else(invalid)?.trim();
                if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                    return Err(invalid());
                }
                let seconds = value.parse::<u32>().map_err(poem::error::BadRequest)?;
                if !(1..=25).contains(&seconds) {
                    return Err(invalid());
                }
                return Ok(Some(seconds));
            }
        }
        Ok(None)
    }
    pub(crate) fn applied(self) -> String {
        format!("wait={}", self.requested_seconds)
    }
    pub(crate) async fn admit(
        wait: Option<Self>,
        admission: Arc<Semaphore>,
    ) -> poem::Result<OwnedSemaphorePermit> {
        match wait {
            Some(_) => admission
                .try_acquire_owned()
                .map_err(poem::error::ServiceUnavailable),
            None => admission
                .acquire_owned()
                .await
                .map_err(poem::error::InternalServerError),
        }
    }
    pub(crate) async fn complete<T>(
        wait: Option<Self>,
        work: impl Future<Output = poem::Result<T>>,
    ) -> poem::Result<T> {
        match wait {
            Some(wait) => tokio::time::timeout_at(wait.deadline, work)
                .await
                .map_err(poem::error::RequestTimeout)?,
            None => work.await,
        }
    }
}
