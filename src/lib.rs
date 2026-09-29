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
mod tls;
use auth::{Authenticator, Reason};
use config::{Config, Quota};
use opentelemetry::{propagation::TextMapPropagator, trace::TraceContextExt};
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
        tracing::info_span!(target: crate::config::Category::VmLifecycle.target(), "vm_runner.session.create",
            telemetry.detail = telemetry::detail!(crate::config::Category::VmLifecycle))
        .in_scope(|| controller.create(&subject, body.0))
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
pub(crate) struct Health(pub Option<std::sync::Arc<std::sync::atomic::AtomicBool>>);
#[derive(ApiResponse)]
enum HealthResponse {
    #[oai(status = 200)]
    Ready(PlainText<&'static str>),
    #[oai(status = 503)]
    Starting(PlainText<&'static str>),
}
#[OpenApi]
impl Health {
    #[oai(path = "/healthz", method = "get")]
    async fn healthz(&self) -> HealthResponse {
        if self
            .0
            .as_ref()
            .is_none_or(|ready| ready.load(std::sync::atomic::Ordering::Acquire))
        {
            HealthResponse::Ready(PlainText("ok"))
        } else {
            HealthResponse::Starting(PlainText("starting"))
        }
    }
}
fn service() -> OpenApiService<
    (
        Health,
        Api,
        controller::proxy::Api,
        controller::proxy::artifacts::Api,
    ),
    (),
> {
    OpenApiService::new(
        (
            Health(None),
            Api,
            controller::proxy::Api,
            controller::proxy::artifacts::Api,
        ),
        "vm-runner",
        env!("CARGO_PKG_VERSION"),
    )
}
pub fn openapi() -> String {
    #[cfg(unix)]
    {
        OpenApiService::new(
            (
                Health(None),
                Api,
                controller::proxy::Api,
                controller::proxy::artifacts::Api,
                jail::api::Api,
            ),
            "vm-runner",
            env!("CARGO_PKG_VERSION"),
        )
        .spec_yaml()
    }
    #[cfg(not(unix))]
    {
        service().spec_yaml()
    }
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
        let mut last_health = None;
        loop {
            interval.tick().await;
            let now = std::time::Instant::now();
            if last_health.is_none_or(|last: std::time::Instant| {
                now.duration_since(last) >= controller::ROLLUP_INTERVAL
            }) {
                controller.health();
                last_health = Some(now);
            }
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
        if let Some(controller) = &self.controller {
            let _executed = controller.execution.acquire().await?;
            let _read = controller.reads.acquire().await?;
        }
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
            // Slow C4 operations never own API admission. GETs have their own worker
            // so a cold boot or long exec cannot block job/artifact reads.
            // Poem matches literal path segments before percent-decoding captured parameters.
            let admission = match &state.controller {
                Some(controller)
                    if req.uri().path().starts_with("/v1/sessions/")
                        || req.uri().path().starts_with("/v1/jobs/") =>
                {
                    std::sync::Arc::clone(if req.method() == poem::http::Method::GET {
                        &controller.reads
                    } else {
                        &controller.execution
                    })
                }
                _ => std::sync::Arc::clone(&admission),
            };
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
                        let span = request_span(&req);
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
                                if req.method() == poem::http::Method::POST {
                                    let body = tokio::time::timeout(
                                        std::time::Duration::from_secs(30),
                                        req.take_body()
                                            .into_bytes_limit(controller::proxy::BODY_LIMIT),
                                    )
                                    .await
                                    .map_err(poem::error::RequestTimeout)?;
                                    match body {
                                        Ok(body) => req.set_body(body),
                                        Err(poem::error::ReadBodyError::PayloadTooLarge) => {
                                            return Ok(controller::proxy::oversized());
                                        }
                                        Err(error) => return Err(error.into()),
                                    }
                                }
                                let result = ep.call(req).await;
                                record_route(&result);
                                result
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
#[cfg(unix)]
pub(crate) struct TracedRequests([std::sync::Arc<tokio::sync::Semaphore>; 2], u32);
#[cfg(unix)]
impl TracedRequests {
    pub async fn drain(self) -> Result<(), tokio::sync::AcquireError> {
        let _exec_idle = self.0[0].acquire_many(self.1).await?;
        let _get_idle = self.0[1].acquire_many(self.1).await?;
        Ok(())
    }
}
#[cfg(unix)]
pub(crate) fn traced(
    endpoint: impl Endpoint + 'static,
    capacity: u32,
) -> (impl Endpoint<Output = poem::Response>, TracedRequests) {
    let admission = std::array::from_fn(|_| {
        std::sync::Arc::new(tokio::sync::Semaphore::new(capacity as usize))
    });
    let requests = TracedRequests(admission.each_ref().map(std::sync::Arc::clone), capacity);
    let endpoint = endpoint.map_to_response().around(move |ep, req| {
        let admission =
            std::sync::Arc::clone(&admission[usize::from(req.method() == poem::http::Method::GET)]);
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
                    let span = request_span(&req);
                    runtime.block_on(
                        async move {
                            let result = ep.call(req).await;
                            record_route(&result);
                            result
                        }
                        .instrument(span),
                    )
                })
            })
            .await
            .map_err(poem::error::InternalServerError)?
        }
    });
    (endpoint, requests)
}
enum RequestTrace {
    Health,
    Root,
    Parent(opentelemetry::Context),
}
impl RequestTrace {
    fn from_request(req: &poem::Request) -> Self {
        if req.uri().path() == "/healthz" && req.method() == poem::http::Method::GET {
            return Self::Health;
        }
        let parent = opentelemetry_sdk::propagation::TraceContextPropagator::new()
            .extract(&telemetry::Headers(req.headers()));
        if parent.span().span_context().is_valid() {
            Self::Parent(parent)
        } else {
            Self::Root
        }
    }
    fn span(self) -> tracing::Span {
        match self {
            Self::Health => tracing::Span::none(),
            Self::Root => {
                let depth = telemetry::detail!(crate::config::Category::VmExec);
                tracing::debug_span!(target: crate::config::Category::VmExec.target(), "vm_runner.request",
                otel.kind = "server", http.route = tracing::field::Empty,
                telemetry.detail = depth,
                vm_runner.auth.reason = tracing::field::Empty)
            }
            Self::Parent(parent) => {
                let depth = telemetry::detail!(crate::config::Category::VmExec);
                let span = tracing::info_span!(target: crate::config::Category::VmExec.target(), "vm_runner.request",
                    otel.kind = "server", http.route = tracing::field::Empty,
                    telemetry.detail = depth,
                    vm_runner.auth.reason = tracing::field::Empty);
                if let Err(error) = span.set_parent(parent) {
                    tracing::warn!(name: "vm_runner.request.parent_rejected", target: crate::config::Category::VmExec.target(), {
                        telemetry.detail = depth,
                        %error,
                    }, "could not attach trace parent");
                }
                span
            }
        }
    }
}
fn request_span(req: &poem::Request) -> tracing::Span {
    RequestTrace::from_request(req).span()
}
fn record_route(result: &poem::Result<poem::Response>) {
    let pattern = match result {
        Ok(response) => response.data::<poem::PathPattern>(),
        Err(error) => error.data::<poem::PathPattern>(),
    };
    let route = pattern.map_or_else(
        || "unmatched".to_owned(),
        |p| {
            p.0.split('/')
                .map(|part| {
                    if let Some(param) = part.strip_prefix(':') {
                        format!("{{{param}}}")
                    } else {
                        part.to_owned()
                    }
                })
                .collect::<Vec<_>>()
                .join("/")
        },
    );
    tracing::Span::current().record("http.route", route);
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
        let depth = telemetry::detail!(crate::config::Category::VmExec);
        tracing::error!(name: "vm_runner.shutdown.signal_failed", target: crate::config::Category::VmExec.target(), {
            telemetry.detail = depth, %error,
        }, "signal handler failed");
    }
    let depth = telemetry::detail!(crate::config::Category::VmExec);
    tracing::info!(name: "vm_runner.shutdown.started", target: crate::config::Category::VmExec.target(), {
        telemetry.detail = depth,
    }, "shutdown signal received; draining requests");
}
#[cfg(test)]
mod tests;
