use super::*;
use poem_openapi::{OpenApi, Union, param::Path};
use serde::{Deserialize, Serialize};
use std::time::Duration;
pub(crate) mod artifacts;

#[derive(Debug, thiserror::Error)]
pub(super) enum Error {
    #[error("session or job not found")]
    NotFound,
    #[error("jail boot failed")]
    Boot,
    #[error("artifact path refused")]
    Forbidden,
    #[error("artifact service unavailable")]
    Unavailable,
    #[error("invalid jail response or configuration")]
    Protocol,
    #[error("invalid projected token")]
    Token,
    #[error("kubernetes request failed (status {0})")]
    Kubernetes(u16),
    #[error("jail returned status {0}")]
    Status(u16),
    #[error("jail transport failed (timeout={timeout}, connect={connect})")]
    Http { timeout: bool, connect: bool },
    #[error("configuration I/O failed ({0:?})")]
    Io(std::io::ErrorKind),
    #[error("JSON decoding failed ({0:?})")]
    Json(serde_json::error::Category),
    #[error("invalid UTF-8")]
    Utf8(#[from] std::str::Utf8Error),
    #[error("invalid pod timestamp")]
    Timestamp(#[from] std::num::TryFromIntError),
    #[error("invalid pod address")]
    Address(std::net::AddrParseError),
    #[error("invalid pod URL")]
    Url(#[from] url::ParseError),
}
impl From<kube::Error> for Error {
    fn from(error: kube::Error) -> Self {
        Self::Kubernetes(match error {
            kube::Error::Api(e) => e.code,
            _ => 0,
        })
    }
}
impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error.kind())
    }
}
impl From<serde_json::Error> for Error {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error.classify())
    }
}
impl From<jsonwebtoken::errors::Error> for Error {
    fn from(_: jsonwebtoken::errors::Error) -> Self {
        Self::Token
    }
}
impl From<reqwest::Error> for Error {
    fn from(e: reqwest::Error) -> Self {
        Self::Http {
            timeout: e.is_timeout(),
            connect: e.is_connect(),
        }
    }
}
#[derive(ApiResponse)]
enum ResponseError {
    #[oai(status = 403)]
    Forbidden(PlainText<String>),
    #[oai(status = 404)]
    NotFound(PlainText<String>),
    #[oai(status = 503)]
    Unavailable(PlainText<String>),
    #[oai(status = 502)]
    Upstream(Json<ExecResult>),
}
impl From<Error> for ResponseError {
    fn from(error: Error) -> Self {
        tracing::warn!(name: "vm_runner.request.failed", target: crate::config::Category::VmExec.target(), {
            telemetry.detail = crate::telemetry::detail!(crate::config::Category::VmExec),
            cause = %error,
        }, "controller operation failed");
        let body = PlainText(error.to_string());
        match error {
            Error::NotFound => Self::NotFound(body),
            Error::Forbidden => Self::Forbidden(body),
            Error::Unavailable => Self::Unavailable(body),
            _ => Self::Upstream(Json(refused(&error.to_string()))),
        }
    }
}
#[derive(Object, Serialize)]
#[serde(rename_all = "camelCase")]
#[oai(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Exec {
    argv: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stdin: Option<String>,
    #[oai(validator(minimum(value = "1000"), maximum(value = "25000")))]
    deadline_ms: u32,
}
#[derive(Object, Deserialize)]
#[serde(rename_all = "camelCase")]
#[oai(rename = "ControllerExecuted", rename_all = "camelCase")]
struct Executed {
    exit_code: i32,
    stdout: String,
    stderr: String,
    truncated: bool,
}
#[derive(Object, Deserialize)]
struct ExecRefused {
    reason: String,
    #[serde(default)]
    truncated: bool,
}
#[derive(Union, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
#[oai(discriminator_name = "outcome", rename_all = "snake_case")]
enum ExecResult {
    Executed(Executed),
    NotExecuted(ExecRefused),
}
#[derive(Object, Deserialize)]
#[serde(rename_all = "camelCase")]
#[oai(rename_all = "camelCase")]
struct Pending {
    outcome: Unknown,
    job_id: String,
}
#[derive(poem_openapi::Enum, Deserialize)]
#[serde(rename_all = "snake_case")]
#[oai(rename = "ControllerUnknown", rename_all = "snake_case")]
enum Unknown {
    Unknown,
}
#[derive(Object, Deserialize)]
#[oai(rename = "ControllerRunning")]
struct Running {
    state: RunningState,
}
#[derive(poem_openapi::Enum, Deserialize)]
#[serde(rename_all = "snake_case")]
#[oai(rename_all = "snake_case")]
enum RunningState {
    Running,
}
#[derive(Union, Deserialize)]
#[serde(untagged)]
enum JobStatus {
    Running(Running),
    Complete(ExecResult),
}
#[derive(ApiResponse)]
#[oai(bad_request_handler = "bad_request")]
enum ExecResponse {
    #[oai(status = 200)]
    Complete(Json<ExecResult>),
    #[oai(status = 202)]
    Pending(Json<Pending>),
    #[oai(status = 401)]
    Unauthorized(Json<crate::Refusal>),
    #[oai(status = 400)]
    Invalid(Json<ExecResult>),
    #[oai(status = 413)]
    TooLarge(Json<ExecResult>),
}
fn refused(reason: &str) -> ExecResult {
    ExecResult::NotExecuted(ExecRefused {
        reason: reason.into(),
        truncated: false,
    })
}
fn bad_request(_: poem::Error) -> ExecResponse {
    ExecResponse::Invalid(Json(refused("invalid exec request")))
}
pub(crate) const BODY_LIMIT: usize = 1_048_576 - 64;
pub(crate) fn oversized() -> poem::Response {
    use poem::IntoResponse;
    ExecResponse::TooLarge(Json(refused("request body too large"))).into_response()
}
#[derive(ApiResponse)]
enum JobResponse {
    #[oai(status = 200)]
    Ok(Json<JobStatus>),
    #[oai(status = 401)]
    Unauthorized(Json<crate::Refusal>),
}
#[derive(Clone)]
pub(super) struct Job {
    pub(super) session: String,
    jail_id: String,
}
fn cap(result: &mut ExecResult) {
    fn text(value: &mut String) -> bool {
        if value.len() <= 65536 {
            return false;
        }
        value.truncate(value.floor_char_boundary(65536));
        true
    }
    match result {
        ExecResult::Executed(r) => r.truncated |= text(&mut r.stdout) | text(&mut r.stderr),
        ExecResult::NotExecuted(r) => r.truncated |= text(&mut r.reason),
    }
}
async fn json<T: serde::de::DeserializeOwned>(mut response: reqwest::Response) -> Result<T, Error> {
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if bytes.len() + chunk.len() > 1_048_576 {
            return Err(Error::Protocol);
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(serde_json::from_slice(&bytes)?)
}
fn checked(response: reqwest::Response, status: u16) -> Result<reqwest::Response, Error> {
    if response.status().as_u16() != status {
        return Err(Error::Status(response.status().as_u16()));
    }
    Ok(response)
}
impl Controller {
    async fn request(
        &self,
        method: reqwest::Method,
        url: url::Url,
    ) -> Result<reqwest::RequestBuilder, Error> {
        let jails = self.config.jails.as_ref().ok_or(Error::Boot)?;
        let bytes = super::pods::read(&jails.token_file).await?;
        let token = std::str::from_utf8(&bytes)?.trim();
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(30))
            .build()?;
        let mut request = client.request(method, url).bearer_auth(token);
        let mut headers = std::collections::HashMap::new();
        use opentelemetry::propagation::TextMapPropagator;
        use tracing_opentelemetry::OpenTelemetrySpanExt;
        opentelemetry_sdk::propagation::TraceContextPropagator::new()
            .inject_context(&tracing::Span::current().context(), &mut headers);
        for (name, value) in headers {
            request = request.header(name, value);
        }
        Ok(request)
    }
    pub(super) async fn send(
        &self,
        method: reqwest::Method,
        url: url::Url,
        exec: Option<&Exec>,
    ) -> Result<reqwest::Response, Error> {
        let mut request = self.request(method, url).await?;
        if let Some(exec) = exec {
            request = request.json(exec);
        }
        Ok(request.send().await?)
    }
    async fn exec(&self, subject: &str, id: &str, exec: &Exec) -> Result<ExecResponse, Error> {
        let (key, session) = self.session(subject, id)?;
        if let Some(stored) = self
            .sessions
            .lock()
            .expect("session registry poisoned")
            .get_mut(&key)
        {
            stored.active = now();
        }
        // Exec admission serializes this check and dispatch; GETs can only remove entries.
        let full = {
            let jobs = self.jobs.lock().expect("job registry poisoned");
            jobs.len() >= 1024 || jobs.values().filter(|job| job.session == id).count() >= 64
        };
        if full {
            return Ok(ExecResponse::Complete(Json(ExecResult::NotExecuted(
                ExecRefused {
                    reason: "job_capacity".into(),
                    truncated: false,
                },
            ))));
        }
        if let Err(error) = self.boot(&key, &session).await {
            if !matches!(error, Error::Boot) {
                return Err(error);
            }
            tracing::warn!(name: "vm_runner.exec.not_started", target: crate::config::Category::VmExec.target(), {
                telemetry.detail = crate::telemetry::detail!(crate::config::Category::VmExec),
                cause = %error,
            }, "exec not started");
            return Ok(ExecResponse::Complete(Json(ExecResult::NotExecuted(
                ExecRefused {
                    reason: "boot_failure".into(),
                    truncated: false,
                },
            ))));
        }
        let (key, session) = self.session(subject, id)?;
        let address = self.target(&key, &session).await?;
        let response = self
            .send(reqwest::Method::POST, address.join("exec")?, Some(exec))
            .await?;
        if response.status().as_u16() == 202 {
            let pending: Pending = json(response).await?;
            if pending.job_id.is_empty() || pending.job_id.len() > 128 {
                return Err(Error::Protocol);
            }
            let job_id = uuid::Uuid::now_v7().to_string();
            let sessions = self.sessions.lock().expect("session registry poisoned");
            sessions
                .get(&key)
                .filter(|s| !s.is_retiring())
                .ok_or(Error::NotFound)?;
            self.jobs.lock().expect("job registry poisoned").insert(
                job_id.clone(),
                Job {
                    session: id.into(),
                    jail_id: pending.job_id,
                },
            );
            Ok(ExecResponse::Pending(Json(Pending {
                outcome: Unknown::Unknown,
                job_id,
            })))
        } else {
            let mut result = json(checked(response, 200)?).await?;
            cap(&mut result);
            Ok(ExecResponse::Complete(Json(result)))
        }
    }
    async fn job(&self, subject: &str, id: &str) -> Result<JobResponse, Error> {
        let job = self
            .jobs
            .lock()
            .expect("job registry poisoned")
            .get(id)
            .cloned()
            .ok_or(Error::NotFound)?;
        let (_, session) = self.session(subject, &job.session)?;
        let pod = self
            .pods
            .get(session.pod.as_ref().ok_or(Error::NotFound)?)
            .await?;
        let mut url = self.address(&pod)?.ok_or(Error::Boot)?;
        url.path_segments_mut()
            .map_err(|()| Error::Protocol)?
            .extend(["jobs", &job.jail_id]);
        let response = self.send(reqwest::Method::GET, url, None).await?;
        if response.status().as_u16() == 404 {
            self.jobs.lock().expect("job registry poisoned").remove(id);
            return Err(Error::NotFound);
        }
        if response.status().as_u16() == 202 {
            let _: Pending = json(response).await?;
            self.jobs.lock().expect("job registry poisoned").remove(id);
            return Ok(JobResponse::Ok(Json(JobStatus::Complete(refused(
                "unknown",
            )))));
        }
        let mut status = json(checked(response, 200)?).await?;
        if let JobStatus::Complete(ref mut result) = status {
            cap(result);
        }
        Ok(JobResponse::Ok(Json(status)))
    }
}
pub(crate) struct Api;
fn controller(state: &crate::State) -> Result<&Arc<Controller>, ResponseError> {
    state
        .controller
        .as_ref()
        .ok_or_else(|| ResponseError::Unavailable(PlainText("jails are not configured".into())))
}
#[OpenApi]
impl Api {
    #[oai(path = "/v1/sessions/:id/exec", method = "post")]
    async fn exec(
        &self,
        request: &poem::Request,
        state: poem::web::Data<&Arc<crate::State>>,
        id: Path<String>,
        body: Json<Exec>,
    ) -> Result<ExecResponse, ResponseError> {
        let subject = match state.authenticate(request).await {
            Ok(s) => s,
            Err(r) => return Ok(ExecResponse::Unauthorized(Json(r))),
        };
        if body.argv.first().is_none_or(String::is_empty) {
            return Ok(ExecResponse::Invalid(Json(refused("invalid exec request"))));
        }
        Ok(controller(&state)?
            .exec(&subject, &id, &body)
            .instrument(tracing::info_span!(
                target: crate::config::Category::VmExec.target(), "vm_runner.exec",
                telemetry.detail = crate::telemetry::detail!(crate::config::Category::VmExec),
                vm_runner.session_id = crate::egress::cut(&id.0)
            ))
            .await?)
    }
    #[oai(path = "/v1/jobs/:jobId", method = "get")]
    async fn job(
        &self,
        request: &poem::Request,
        state: poem::web::Data<&Arc<crate::State>>,
        #[oai(name = "jobId")] job_id: Path<String>,
    ) -> Result<JobResponse, ResponseError> {
        let subject = match state.authenticate(request).await {
            Ok(s) => s,
            Err(r) => return Ok(JobResponse::Unauthorized(Json(r))),
        };
        Ok(controller(&state)?
            .job(&subject, &job_id)
            .instrument(tracing::info_span!(target: crate::config::Category::VmExec.target(), "vm_runner.job.get",
                telemetry.detail = crate::telemetry::detail!(crate::config::Category::VmExec)))
            .await?)
    }
}
#[cfg(test)]
mod tests;
