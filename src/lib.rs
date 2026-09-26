#![cfg_attr(test, allow(clippy::unwrap_used, clippy::disallowed_methods))]
mod auth;
pub mod config;
pub mod egress;
pub mod telemetry;
use auth::{Authenticator, Reason};
use config::{Config, Quota, Quotas};
use opentelemetry::propagation::TextMapPropagator;
use poem::{Endpoint, EndpointExt, Request};
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
#[derive(Object)]
struct Refusal {
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
struct State {
    auth: Authenticator,
    quotas: Quotas,
}
#[OpenApi]
impl Api {
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
        match state.auth.verify(request.header("Authorization")).await {
            Ok(subject) => {
                let quota = state
                    .quotas
                    .subjects
                    .0
                    .iter()
                    .find(|(s, _)| s == &subject)
                    .map_or(state.quotas.default, |(_, q)| *q);
                Whoami::Ok(Json(Identity { subject, quota }))
            }
            Err(reason) => {
                tracing::Span::current().record("vm_runner.auth.reason", reason.as_str());
                Whoami::Unauthorized(Json(Refusal {
                    error: "unauthorized".into(),
                    reason,
                }))
            }
        }
    }
}
fn service() -> OpenApiService<Api, ()> {
    OpenApiService::new(Api, "vm-runner", env!("CARGO_PKG_VERSION"))
}
pub fn openapi() -> String {
    service().spec_yaml()
}
pub struct Requests(std::sync::Arc<tokio::sync::Semaphore>);
impl Requests {
    // Call after the server stops, before shutting down telemetry.
    pub async fn drain(self) -> Result<(), tokio::sync::AcquireError> {
        let _idle = self.0.acquire().await?;
        Ok(())
    }
}
pub async fn app(
    config: Config,
) -> Result<(impl Endpoint, Requests), Box<dyn std::error::Error + Send + Sync>> {
    let state = State {
        auth: Authenticator::new(config.auth).await?,
        quotas: config.quotas,
    };
    let admission = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
    let requests = Requests(std::sync::Arc::clone(&admission));
    let endpoint = service()
        .data(std::sync::Arc::new(state))
        .around(move |ep, req| {
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
                        runtime.block_on(ep.call(req).instrument(span))
                    })
                })
                .await
                .map_err(poem::error::InternalServerError)?
            }
        });
    Ok((endpoint, requests))
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
