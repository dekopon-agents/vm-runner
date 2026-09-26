#![cfg_attr(test, allow(clippy::unwrap_used, clippy::disallowed_methods))]
mod auth;
pub mod config;
mod controller;
pub mod egress;
#[cfg(unix)]
pub mod guest;
#[cfg(unix)]
pub mod jail;
pub mod telemetry;
use auth::{Authenticator, Reason};
use config::{Config, Quota};
use opentelemetry::propagation::TextMapPropagator;
use poem::{Endpoint, EndpointExt, IntoResponse, Request};
use poem_openapi::{
    ApiResponse, Object, OpenApi, OpenApiService,
    payload::{Json, PlainText},
};
use tracing::Instrument;
use tracing_opentelemetry::OpenTelemetrySpanExt;

#[derive(Object)]
struct Identity {
    subject: String,
    quota: Quota,
}
#[derive(Object, serde::Serialize)]
pub(crate) struct Refusal {
    error: String,
    reason: Reason,
}
#[derive(ApiResponse)]
enum Whoami {
    #[oai(status = 200)]
    Ok(Json<Identity>),
    #[oai(status = 401)]
    Unauthorized(Json<Refusal>),
}
struct Api;
#[derive(Clone)]
struct Subject(String);
struct State {
    auth: Authenticator,
    config: std::sync::Arc<Config>,
    controller: Option<std::sync::Arc<controller::Controller>>,
}
#[OpenApi]
impl Api {
    #[oai(path = "/v1/sessions", method = "post")]
    async fn create_session(
        &self,
        request: &Request,
        state: poem::web::Data<&std::sync::Arc<State>>,
        body: Json<controller::Create>,
    ) -> poem::Result<controller::Created> {
        let subject = match state.authenticate(request).await {
            Ok(subject) => subject,
            Err(refusal) => return Ok(controller::Created::Unauthorized(Json(refusal))),
        };
        let Some(controller) = state.controller.as_ref() else {
            return Ok(controller::Created::Unavailable(PlainText(
                "jails are not configured",
            )));
        };
        tracing::info_span!("vm_runner.session.create")
            .in_scope(|| controller.create(&subject, body.0))
    }
    #[oai(path = "/healthz", method = "get")]
    async fn healthz(&self) -> PlainText<&'static str> {
        PlainText("ok")
    }
    #[oai(path = "/v1/whoami", method = "get")]
    async fn whoami(
        &self,
        request: &Request,
        state: poem::web::Data<&std::sync::Arc<State>>,
    ) -> Whoami {
        match state.authenticate(request).await {
            Ok(subject) => {
                let quota = state
                    .config
                    .quotas
                    .subjects
                    .0
                    .iter()
                    .find(|(s, _)| s == &subject)
                    .map_or(state.config.quotas.default, |(_, q)| *q);
                Whoami::Ok(Json(Identity { subject, quota }))
            }
            Err(refusal) => Whoami::Unauthorized(Json(refusal)),
        }
    }
}
impl State {
    async fn authenticate(&self, request: &Request) -> Result<String, Refusal> {
        if let Some(subject) = request.extensions().get::<Subject>() {
            return Ok(subject.0.clone());
        }
        self.auth
            .verify(request.header("Authorization"))
            .await
            .map_err(|reason| {
                tracing::Span::current().record("vm_runner.auth.reason", reason.as_str());
                Refusal {
                    error: "unauthorized".into(),
                    reason,
                }
            })
    }
}
fn service() -> OpenApiService<Api, ()> {
    OpenApiService::new(Api, "vm-runner", env!("CARGO_PKG_VERSION"))
}
pub fn openapi() -> String {
    service().spec_yaml()
}
pub struct Requests {
    admission: std::sync::Arc<tokio::sync::Semaphore>,
    // Only shutdown waits on this: a cancelled reap future leaves its blocking worker alive.
    reaper_drain: std::sync::Arc<tokio::sync::Semaphore>,
    controller: Option<std::sync::Arc<controller::Controller>>,
}
impl Requests {
    pub async fn reap(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let Some(controller) = &self.controller else {
            return std::future::pending().await;
        };
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));
        loop {
            interval.tick().await;
            let permit = std::sync::Arc::clone(&self.reaper_drain)
                .acquire_owned()
                .await?;
            let controller = std::sync::Arc::clone(controller);
            let runtime = tokio::runtime::Handle::current();
            let dispatch = tracing::dispatcher::get_default(Clone::clone);
            tokio::task::spawn_blocking(move || {
                let _permit = permit;
                tracing::dispatcher::with_default(&dispatch, || {
                    runtime.block_on(controller.reap(controller::now()))
                })
            })
            .await?;
        }
    }
    // Call after the server stops, before shutting down telemetry.
    pub async fn drain(self) -> Result<(), tokio::sync::AcquireError> {
        let _idle = self.admission.acquire().await?;
        let _reaped = self.reaper_drain.acquire().await?;
        Ok(())
    }
}
fn kube_timeouts(mut config: kube::Config) -> kube::Config {
    config.connect_timeout = Some(std::time::Duration::from_secs(5));
    config.read_timeout = Some(std::time::Duration::from_secs(15));
    config
}
pub async fn app(
    config: Config,
) -> Result<(impl Endpoint, Requests), Box<dyn std::error::Error + Send + Sync>> {
    let config = std::sync::Arc::new(config);
    let controller = if config.jails.is_some() {
        let client = kube::Client::try_from(kube_timeouts(kube::Config::incluster()?))?;
        let config = std::sync::Arc::clone(&config);
        let runtime = tokio::runtime::Handle::current();
        let dispatch = tracing::dispatcher::get_default(Clone::clone);
        Some(std::sync::Arc::new(
            tokio::task::spawn_blocking(move || {
                tracing::dispatcher::with_default(&dispatch, || {
                    runtime.block_on(controller::Controller::new(config, client))
                })
            })
            .await??,
        ))
    } else {
        None
    };
    let state = State {
        auth: Authenticator::new(config.auth.clone()).await?,
        config,
        controller: controller.as_ref().map(std::sync::Arc::clone),
    };
    let admission = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
    let requests = Requests {
        admission: std::sync::Arc::clone(&admission),
        reaper_drain: std::sync::Arc::new(tokio::sync::Semaphore::new(1)),
        controller,
    };
    Ok((endpoint(std::sync::Arc::new(state), admission), requests))
}
fn endpoint(
    state: std::sync::Arc<State>,
    admission: std::sync::Arc<tokio::sync::Semaphore>,
) -> impl Endpoint {
    service()
        .data(std::sync::Arc::clone(&state))
        .around(move |ep, mut req| {
            let state = std::sync::Arc::clone(&state);
            let admission = std::sync::Arc::clone(&admission);
            async move {
                // Admit before creating the span so cancellation cannot queue an unbounded export.
                let permit = admission
                    .acquire_owned()
                    .await
                    .map_err(poem::error::InternalServerError)?;
                let runtime = tokio::runtime::Handle::current();
                let dispatch = tracing::dispatcher::get_default(Clone::clone);
                // The worker owns the entire request so cancellation cannot export on Tokio.
                tokio::task::spawn_blocking(move || {
                    let _permit = permit;
                    tracing::dispatcher::with_default(&dispatch, || {
                        let span = tracing::info_span!(
                            "vm_runner.request",
                            otel.kind = "server",
                            vm_runner.auth.reason = tracing::field::Empty
                        );
                        let parent = opentelemetry_sdk::propagation::TraceContextPropagator::new()
                            .extract(&telemetry::Headers(req.headers()));
                        if let Err(error) = span.set_parent(parent) {
                            tracing::warn!(%error, "could not attach trace parent");
                        }
                        runtime.block_on(
                            async move {
                                if req.uri().path() != "/healthz"
                                    || req.method() != poem::http::Method::GET
                                {
                                    match state.authenticate(&req).await {
                                        Ok(subject) => {
                                            req.extensions_mut().insert(Subject(subject));
                                        }
                                        Err(refusal) => {
                                            return Ok(poem::web::Json(refusal)
                                                .with_status(poem::http::StatusCode::UNAUTHORIZED)
                                                .into_response());
                                        }
                                    }
                                }
                                ep.call(req).await
                            }
                            .instrument(span),
                        )
                    })
                })
                .await
                .map_err(poem::error::InternalServerError)?
            }
        })
}
/// Stop admission on either terminal interruption or pod termination.
/// Callers drain their requests before shutting down (and flushing) telemetry.
pub async fn shutdown_signal() {
    #[cfg(unix)]
    let result = async {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result,
            _ = terminate.recv() => Ok(()),
        }
    }
    .await;
    #[cfg(not(unix))]
    let result = tokio::signal::ctrl_c().await;
    if let Err(error) = result {
        tracing::error!(%error, "signal handler failed");
    }
    tracing::info!("shutdown signal received; draining requests");
}
#[cfg(test)]
mod tests;
