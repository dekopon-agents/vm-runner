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

#[derive(serde::Deserialize)]
struct Query {
    #[serde(rename = "waitMs")]
    wait_ms: Option<u32>,
}

#[derive(Clone, Copy)]
pub(crate) struct JobWait {
    pub(crate) requested_ms: u32,
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
        let Query { wait_ms } = request.params().map_err(poem::error::BadRequest)?;
        let Some(requested_ms) = wait_ms else {
            return Ok(None);
        };
        if requested_ms > 25000 {
            return Err(poem::Error::from_string(
                "waitMs must be 0–25000",
                StatusCode::BAD_REQUEST,
            ));
        }
        if requested_ms == 0 {
            return Ok(None);
        }
        let budget = match origin {
            Origin::Controller => Duration::from_secs(29),
            Origin::Jail => Duration::from_millis(requested_ms.into()),
        };
        let wait = Self {
            requested_ms,
            deadline: started + budget,
        };
        request.extensions_mut().insert(wait);
        Ok(Some(wait))
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
