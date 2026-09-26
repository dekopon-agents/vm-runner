use super::client::Guest;
use crate::{auth::Authenticator, config::Auth, guest};
use poem::{Endpoint, EndpointExt, IntoResponse, Request, http::StatusCode};
use poem_openapi::{
    ApiResponse, Object, OpenApi, OpenApiService, Union, param::Path, payload::Json,
};
use serde::Deserialize;
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex, atomic::AtomicBool},
    time::Duration,
};
use tokio::{sync::watch, task::JoinSet};
use tracing::Instrument;

mod artifacts;
const JOB_CAP: usize = 64;
#[derive(Object)]
#[oai(rename_all = "camelCase")]
struct ExecInput {
    argv: Vec<String>,
    stdin: Option<String>,
    #[oai(validator(maximum(value = "25000")))]
    deadline_ms: u32,
}
#[derive(Clone, Deserialize, Object)]
#[serde(rename_all = "camelCase")]
#[oai(rename_all = "camelCase")]
struct Executed {
    exit_code: i32,
    stdout: String,
    stderr: String,
    truncated: bool,
}
#[derive(Clone, Deserialize, Object)]
#[oai(rename = "JailNotExecuted")]
struct NotExecuted {
    reason: String,
    #[serde(default)]
    truncated: bool,
}
#[derive(Clone, Deserialize, Union)]
#[serde(tag = "outcome", rename_all = "snake_case")]
#[oai(discriminator_name = "outcome", rename_all = "snake_case")]
enum Terminal {
    Executed(Executed),
    NotExecuted(NotExecuted),
}
impl Terminal {
    fn capped(mut self) -> Self {
        match &mut self {
            Self::Executed(result) => {
                result.truncated |= cap(&mut result.stdout) | cap(&mut result.stderr);
            }
            Self::NotExecuted(result) => result.truncated |= cap(&mut result.reason),
        }
        self
    }
}
fn cap(text: &mut String) -> bool {
    const OUTPUT_CAP: usize = 64 * 1024;
    if text.len() <= OUTPUT_CAP {
        return false;
    }
    text.truncate(text.floor_char_boundary(OUTPUT_CAP));
    text.shrink_to_fit();
    true
}
#[derive(Object)]
#[oai(rename_all = "camelCase")]
struct Unknown {
    outcome: String,
    job_id: String,
}
fn unknown(id: uuid::Uuid) -> Json<Unknown> {
    Json(Unknown {
        outcome: "unknown".into(),
        job_id: id.to_string(),
    })
}
#[derive(Object)]
struct Running {
    state: String,
}
#[derive(Union)]
enum View {
    Running(Running),
    Terminal(Terminal),
}
#[derive(ApiResponse)]
enum ExecResponse {
    #[oai(status = 200)]
    Done(Json<Terminal>),
    #[oai(status = 202)]
    Unknown(Json<Unknown>),
}
#[derive(ApiResponse)]
enum JobResponse {
    #[oai(status = 200)]
    View(Json<View>),
    #[oai(status = 202)]
    Unknown(Json<Unknown>),
}
#[derive(Clone)]
enum Progress {
    Running,
    Done(Arc<Terminal>),
    Unknown,
}
struct Job {
    id: uuid::Uuid,
    progress: watch::Receiver<Progress>,
}
#[derive(Default)]
struct Jobs {
    entries: VecDeque<Job>,
    workers: JoinSet<()>,
}
pub(super) struct State {
    guest: Arc<Guest>,
    ready: Arc<AtomicBool>,
    jobs: Mutex<Jobs>,
    transfers: Arc<tokio::sync::Semaphore>,
}
impl State {
    pub(super) fn mark_ready(&self) {
        self.ready.store(true, std::sync::atomic::Ordering::Release);
    }
    fn submit(&self, input: ExecInput) -> poem::Result<Option<Job>> {
        let mut jobs = self.jobs.lock().map_err(|error| {
            poem::error::InternalServerError(std::io::Error::other(error.to_string()))
        })?;
        while let Some(result) = jobs.workers.try_join_next() {
            result.map_err(poem::error::InternalServerError)?;
        }
        if jobs.workers.len() >= JOB_CAP {
            return Ok(None);
        }
        if jobs.entries.len() == JOB_CAP {
            let Some(index) = jobs
                .entries
                .iter()
                .position(|job| !matches!(*job.progress.borrow(), Progress::Running))
            else {
                return Ok(None);
            };
            jobs.entries.remove(index);
        }
        let id = uuid::Uuid::now_v7();
        let (send, progress) = watch::channel(Progress::Running);
        jobs.entries.push_back(Job {
            id,
            progress: progress.clone(),
        });
        let guest = Arc::clone(&self.guest);
        let runtime = tokio::runtime::Handle::current();
        let dispatch = tracing::dispatcher::get_default(Clone::clone);
        let span = tracing::info_span!("vm_runner.exec");
        // The bounded table owns these workers until shutdown, even after HTTP cancellation.
        jobs.workers.spawn_blocking(move || {
            tracing::dispatcher::with_default(&dispatch, || {
                runtime.block_on(
                    async {
                        let request = guest::Request::Exec {
                            argv: input.argv,
                            stdin: input.stdin,
                            deadline_ms: 600_000,
                            env: None,
                            cwd: None,
                        };
                        let result = match guest
                            .call::<Terminal>(&request, Duration::from_secs(610))
                            .await
                        {
                            Ok(result) => Progress::Done(Arc::new(result.capped())),
                            Err(error) => {
                                tracing::error!(%error, "guest exec outcome unknown");
                                Progress::Unknown
                            }
                        };
                        send.send_replace(result);
                    }
                    .instrument(span),
                )
            })
        });
        Ok(Some(Job { id, progress }))
    }
    pub(super) async fn drain(&self) -> super::Result<()> {
        let mut workers = std::mem::take(
            &mut self
                .jobs
                .lock()
                .map_err(|e| std::io::Error::other(e.to_string()))?
                .workers,
        );
        while let Some(result) = workers.join_next().await {
            result?;
        }
        Ok(())
    }
}
pub(crate) struct Api;
#[OpenApi]
impl Api {
    #[oai(path = "/artifacts", method = "get")]
    async fn artifacts(
        &self,
        state: poem::web::Data<&Arc<State>>,
    ) -> poem::Result<Json<Vec<artifacts::Artifact>>> {
        artifacts::list(&state.guest).await
    }
    #[oai(path = "/artifacts/:path", method = "get")]
    async fn artifact(
        &self,
        state: poem::web::Data<&Arc<State>>,
        path: Path<String>,
        #[oai(name = "Range")] range: poem_openapi::param::Header<Option<String>>,
    ) -> poem::Result<artifacts::Download> {
        artifacts::read(&state, path.0, range.0).await
    }
    #[oai(path = "/exec", method = "post")]
    async fn exec(
        &self,
        state: poem::web::Data<&Arc<State>>,
        Json(input): Json<ExecInput>,
    ) -> poem::Result<ExecResponse> {
        if input.argv.first().is_none_or(String::is_empty) {
            return Err(poem::Error::from_status(StatusCode::BAD_REQUEST));
        }
        let deadline =
            tokio::time::Instant::now() + Duration::from_millis(input.deadline_ms.into());
        let Some(Job { id, mut progress }) = state.submit(input)? else {
            return Ok(ExecResponse::Done(Json(Terminal::NotExecuted(
                NotExecuted {
                    reason: "quota".into(),
                    truncated: false,
                },
            ))));
        };
        let result = tokio::time::timeout_at(deadline, async {
            loop {
                let value = progress.borrow_and_update().clone();
                if !matches!(value, Progress::Running) {
                    return value;
                }
                if progress.changed().await.is_err() {
                    return Progress::Unknown;
                }
            }
        })
        .await;
        Ok(match result {
            Ok(Progress::Done(result)) => ExecResponse::Done(Json((*result).clone())),
            _ => ExecResponse::Unknown(unknown(id)),
        })
    }
    #[oai(path = "/jobs/:id", method = "get")]
    async fn job(
        &self,
        state: poem::web::Data<&Arc<State>>,
        id: Path<String>,
    ) -> poem::Result<JobResponse> {
        async {
            let id = uuid::Uuid::parse_str(&id).map_err(poem::error::BadRequest)?;
            let jobs = state.jobs.lock().map_err(|error| {
                poem::error::InternalServerError(std::io::Error::other(error.to_string()))
            })?;
            let job = jobs
                .entries
                .iter()
                .find(|j| j.id == id)
                .ok_or_else(|| poem::Error::from_status(StatusCode::NOT_FOUND))?;
            Ok(match &*job.progress.borrow() {
                Progress::Running => JobResponse::View(Json(View::Running(Running {
                    state: "running".into(),
                }))),
                Progress::Done(result) => {
                    JobResponse::View(Json(View::Terminal((**result).clone())))
                }
                Progress::Unknown => JobResponse::Unknown(unknown(id)),
            })
        }
        .instrument(tracing::info_span!("vm_runner.job.get"))
        .await
    }
}
pub(super) async fn endpoint(
    mut auth: Auth,
    controller_subject: String,
    guest: Arc<Guest>,
) -> super::Result<(
    impl Endpoint<Output = poem::Response>,
    crate::TracedRequests,
    Arc<State>,
)> {
    auth.audience = "vm-runner-jail".into();
    auth.subjects = vec![controller_subject];
    let auth = Authenticator::new(auth).await?;
    let state = Arc::new(State {
        guest,
        ready: Arc::new(AtomicBool::new(false)),
        jobs: Mutex::new(Jobs::default()),
        transfers: Arc::new(tokio::sync::Semaphore::new(4)),
    });
    let endpoint: poem::endpoint::BoxEndpoint<'static, poem::Response> = OpenApiService::new(
        (crate::Health(Some(Arc::clone(&state.ready))), Api),
        "vm-runner jail",
        env!("CARGO_PKG_VERSION"),
    )
    .data(Arc::clone(&state))
    .boxed();
    let (endpoint, requests) = crate::traced(Authorized { endpoint, auth }, 16);
    Ok((endpoint, requests, state))
}

struct Authorized {
    endpoint: poem::endpoint::BoxEndpoint<'static, poem::Response>,
    auth: Authenticator,
}
impl Endpoint for Authorized {
    type Output = poem::Response;
    async fn call(&self, mut req: Request) -> poem::Result<Self::Output> {
        tokio::time::timeout(Duration::from_secs(40), async {
            if let Err(reason) = self.auth.verify(req.header("Authorization")).await {
                tracing::Span::current().record("vm_runner.auth.reason", reason.as_str());
                return Ok(Json(crate::Refusal {
                    error: "unauthorized".into(),
                    reason,
                })
                .with_status(StatusCode::UNAUTHORIZED)
                .into_response());
            }
            if req.method() == poem::http::Method::POST {
                // Reserve space for the C6 op/env/cwd envelope added to the C4 request.
                let body = req
                    .take_body()
                    .into_bytes_limit(guest::FRAME_CAP - 64)
                    .await?;
                req.set_body(body);
            }
            self.endpoint.call(req).await
        })
        .await
        .map_err(poem::error::RequestTimeout)?
    }
}

#[cfg(test)]
mod tests;
