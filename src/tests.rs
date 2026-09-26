use super::*;
mod controller_resilience;
use aws_lc_rs::{
    encoding::AsDer,
    signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use poem::{http::StatusCode, test::TestClient};
use serde_json::{Value, json};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

pub(crate) struct Fixture {
    pub(crate) config: Config,
    ec: EncodingKey,
    rsa: EncodingKey,
    calls: Arc<AtomicUsize>,
    gate: Arc<tokio::sync::Semaphore>,
    refresh_started: tokio::sync::oneshot::Receiver<()>,
    tasks: tokio::task::JoinSet<()>,
}
impl Fixture {
    pub(crate) async fn new() -> Self {
        let ec = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING).unwrap();
        let rsa = aws_lc_rs::rsa::KeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048).unwrap();
        let point = ec.public_key().as_ref();
        let jwks = json!({"keys": [
            {"kty":"EC", "crv":"P-256", "kid":"ec", "alg":"ES256", "x":B64.encode(&point[1..33]), "y":B64.encode(&point[33..])},
            {"kty":"RSA", "kid":"rsa", "alg":"RS256", "n":B64.encode(rsa.public_key().modulus().big_endian_without_leading_zero()), "e":B64.encode(rsa.public_key().exponent().big_endian_without_leading_zero())}
        ]}).to_string();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let issuer = format!("http://{}", listener.local_addr().unwrap());
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&calls);
        let gate = Arc::new(tokio::sync::Semaphore::new(1));
        let server_gate = Arc::clone(&gate);
        let (started, refresh_started) = tokio::sync::oneshot::channel();
        let mut tasks = tokio::task::JoinSet::new();
        tasks.spawn(async move {
            let mut started = Some(started);
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                if counter.load(Ordering::SeqCst) == 1 {
                    started.take().unwrap().send(()).unwrap();
                }
                let _permit = server_gate.acquire().await.unwrap();
                let body = jwks.clone();
                let counter = Arc::clone(&counter);
                let service = hyper::service::service_fn(
                    move |req: hyper::Request<hyper::body::Incoming>| {
                        assert_eq!(req.uri().path(), "/openid/v1/jwks");
                        counter.fetch_add(1, Ordering::SeqCst);
                        let body =
                            http_body_util::Full::new(hyper::body::Bytes::from(body.clone()));
                        async move { Ok::<_, std::convert::Infallible>(hyper::Response::new(body)) }
                    },
                );
                hyper::server::conn::http1::Builder::new()
                    .keep_alive(false)
                    .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                    .await
                    .unwrap();
            }
        });
        let mut config: Config =
            serde_yaml_ng::from_str(include_str!("../examples/vm-runner.yaml")).unwrap();
        config.auth.issuers = vec![config::Issuer {
            issuer,
            ca_file: None,
            token_file: None,
        }];
        Self {
            config,
            calls,
            gate,
            refresh_started,
            tasks,
            ec: EncodingKey::from_ec_der(ec.to_pkcs8v1().unwrap().as_ref()),
            rsa: EncodingKey::from_rsa_pem(
                format!(
                    "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----",
                    base64::engine::general_purpose::STANDARD
                        .encode(rsa.as_der().unwrap().as_ref())
                )
                .as_bytes(),
            )
            .unwrap(),
        }
    }
    pub(crate) fn claims(&self) -> Value {
        let now = jsonwebtoken::get_current_timestamp();
        json!({"iss":self.config.auth.issuers[0].issuer, "sub":"system:serviceaccount:dekopon:default", "aud":["vm-runner"], "exp":now+300, "iat":now, "nbf":now})
    }
    pub(crate) fn token(&self, claims: &Value, kid: &str) -> String {
        let mut header = Header::new(if kid == "rsa" {
            Algorithm::RS256
        } else {
            Algorithm::ES256
        });
        header.kid = Some(kid.into());
        jsonwebtoken::encode(
            &header,
            claims,
            if kid == "rsa" { &self.rsa } else { &self.ec },
        )
        .unwrap()
    }
}
pub(crate) fn span_attribute<'a>(
    span: &'a opentelemetry_sdk::trace::SpanData,
    key: &str,
) -> Option<&'a opentelemetry::Value> {
    let mut attributes = span.attributes.iter().filter(|kv| kv.key.as_str() == key);
    let value = attributes.next().map(|kv| &kv.value);
    assert!(
        attributes.next().is_none(),
        "duplicate span attribute {key}: {span:?}"
    );
    value
}
#[tokio::test]
async fn session_route_authenticates_and_returns_named_create_or_get_statuses() {
    let mut fixture = Fixture::new().await;
    let token = fixture.token(&fixture.claims(), "ec");
    fixture.config.jails = Some(
        serde_json::from_value(json!({
            "namespace":"jails", "image":"runner", "imageCacheHostPath":"/images",
            "controllerAudience":"vm-runner-jail", "controllerSubject":"system:serviceaccount:test:controller", "tokenFile":"/token"
        }))
        .unwrap(),
    );
    let config = Arc::new(fixture.config);
    let (mock_service, mut mock) = tower_test::mock::pair();
    let (controller, ()) = tokio::join!(
        controller::Controller::new(
            Arc::clone(&config),
            kube::Client::new(mock_service, "jails")
        ),
        async {
            let (_, send) = mock.next_request().await.unwrap();
            send.send_response(hyper::Response::new(kube::client::Body::from(
                json!({"apiVersion":"v1","kind":"PodList","metadata":{},"items":[]})
                    .to_string()
                    .into_bytes(),
            )));
        }
    );
    let state = State {
        auth: Authenticator::new(config.auth.clone()).await.unwrap(),
        config,
        controller: Some(Arc::new(controller.unwrap())),
    };
    let client = TestClient::new(endpoint(
        Arc::new(state),
        Arc::new(tokio::sync::Semaphore::new(1)),
    ));
    let malformed = client
        .post("/v1/sessions")
        .header("Content-Type", "application/json")
        .body("{")
        .send()
        .await;
    malformed.assert_status(StatusCode::UNAUTHORIZED);
    malformed
        .assert_json(json!({"error":"unauthorized", "reason":"malformed"}))
        .await;
    client
        .post("/v1/sessions")
        .body_json(&json!({"profile":"travel"}))
        .send()
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
    for status in [StatusCode::CREATED, StatusCode::OK] {
        let response = client
            .post("/v1/sessions")
            .header("Authorization", format!("Bearer {token}"))
            .body_json(&json!({"profile":"travel"}))
            .send()
            .await;
        response.assert_status(status);
        response
            .json()
            .await
            .value()
            .object()
            .get("name")
            .assert_string("default");
    }
    let response = client
        .post("/v1/sessions")
        .header("Authorization", format!("Bearer {token}"))
        .body_json(&json!({"profile":"other"}))
        .send()
        .await;
    response.assert_status(StatusCode::CONFLICT);
    response
        .assert_json(json!({"error":"session_profile_conflict"}))
        .await;
    let response = client
        .post("/v1/sessions")
        .header("Authorization", format!("Bearer {token}"))
        .body_json(&json!({"profile":"travel", "name":"Bad Name"}))
        .send()
        .await;
    response.assert_status(StatusCode::BAD_REQUEST);
    response
        .assert_json(json!({"outcome":"not_executed", "reason":"bad_name"}))
        .await;
    fixture.tasks.shutdown().await;
}
#[test]
fn config_reports_all_conflicts_together() {
    let yaml = include_str!("../examples/vm-runner.yaml")
        .replace("shape: pw-1c1g", "shape: missing")
        .replace("maxSeconds: 1800", "maxSeconds: 1")
        .replace("maxConnections: 128", "maxConnections: 256");
    let mut config: Config = serde_yaml_ng::from_str(&yaml).unwrap();
    let invalid = ["www.google.com:443", "https://x", "*.bücher.example"];
    config.profiles.0[0]
        .1
        .egress
        .allow
        .extend(invalid.map(String::from));
    let conflicts = config.conflicts();
    for host in invalid {
        assert!(
            conflicts.contains(&config::Conflict::Wildcard(host.into())),
            "{conflicts:?}"
        );
    }
    for expected in [
        config::Conflict::Shape("travel".into()),
        config::Conflict::Lifetime("travel".into()),
        config::Conflict::EgressConnections("travel".into()),
    ] {
        assert!(conflicts.contains(&expected), "{conflicts:?}");
    }
    assert!(serde_yaml_ng::from_str::<Config>(&format!("{yaml}\nunrecognized: true")).is_err());
}
#[test]
fn egress_connection_ceiling_fits_the_default_blocking_pool() {
    for (limit, valid) in [
        (1, true),
        (128, true),
        (255, true),
        (256, false),
        (u32::MAX, false),
    ] {
        let yaml = include_str!("../examples/vm-runner.yaml")
            .replace("maxConnections: 128", &format!("maxConnections: {limit}"));
        let config: Config = serde_yaml_ng::from_str(&yaml).unwrap();
        assert_eq!(
            config
                .conflicts()
                .contains(&config::Conflict::EgressConnections("travel".into())),
            !valid,
            "maxConnections: {limit}"
        );
    }
}
#[test]
fn openapi_file_matches_generated() {
    assert_eq!(openapi(), include_str!("../openapi.yaml"));
}
#[test]
fn openapi_has_no_xml_request_body() {
    assert!(!openapi().contains("application/xml"));
}
#[tokio::test]
async fn valid_rs256_and_es256_tokens_get_subject_quota() {
    let fixture = Fixture::new().await;
    let tokens = [
        fixture.token(&fixture.claims(), "ec"),
        fixture.token(&fixture.claims(), "rsa"),
    ];
    let client = TestClient::new(app(fixture.config).await.unwrap().0);
    client.get("/healthz").send().await.assert_text("ok").await;
    for token in tokens {
        let response = client
            .get("/v1/whoami")
            .header("Authorization", format!("Bearer {token}"))
            .send()
            .await;
        response.assert_status_is_ok();
        response.assert_json(json!({"subject":"system:serviceaccount:dekopon:default", "quota":{"maxSessions":2}})).await;
    }
    drop(fixture.tasks);
}
async fn refused(field: &str, value: Value, reason: Reason) {
    let fixture = Fixture::new().await;
    let mut claims = fixture.claims();
    claims[field] = value;
    let token = fixture.token(&claims, "ec");
    let client = TestClient::new(app(fixture.config).await.unwrap().0);
    let response = client
        .get("/v1/whoami")
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await;
    response.assert_status(StatusCode::UNAUTHORIZED);
    response
        .assert_json(json!({"error":"unauthorized", "reason":reason}))
        .await;
    drop(fixture.tasks);
}
#[tokio::test]
async fn wrong_audience_is_refused() {
    refused("aud", json!("other"), Reason::Audience).await;
}
#[tokio::test]
async fn wrong_issuer_is_refused() {
    refused("iss", json!("http://untrusted.invalid"), Reason::Issuer).await;
}
#[tokio::test]
async fn expired_is_refused() {
    refused("exp", json!(1), Reason::Expired).await;
}
#[tokio::test]
async fn unknown_subject_is_refused() {
    refused(
        "sub",
        json!("system:serviceaccount:other:sa"),
        Reason::UnknownSubject,
    )
    .await;
}
#[tokio::test]
async fn future_iat_and_nbf_are_refused() {
    for field in ["iat", "nbf"] {
        refused(
            field,
            json!(jsonwebtoken::get_current_timestamp() + 300),
            Reason::NotYetValid,
        )
        .await;
    }
}
#[tokio::test]
async fn bad_signature_is_refused() {
    let mut fixture = Fixture::new().await;
    let key = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING).unwrap();
    fixture.ec = EncodingKey::from_ec_der(key.to_pkcs8v1().unwrap().as_ref());
    let token = fixture.token(&fixture.claims(), "ec");
    let auth = Authenticator::new(fixture.config.auth).await.unwrap();
    assert!(matches!(
        auth.verify(Some(&format!("Bearer {token}"))).await,
        Err(Reason::Signature)
    ));
}
#[tokio::test]
async fn unknown_kid_refetches_exactly_once() {
    let fixture = Fixture::new().await;
    let token = fixture.token(&fixture.claims(), "missing");
    let auth = Authenticator::new(fixture.config.auth).await.unwrap();
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
    for _ in 0..3 {
        assert!(matches!(
            auth.verify(Some(&format!("Bearer {token}"))).await,
            Err(Reason::Signature)
        ));
    }
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 2);
}
#[tokio::test]
async fn cached_key_verification_proceeds_during_refresh() {
    let fixture = Fixture::new().await;
    let known = fixture.token(&fixture.claims(), "ec");
    let unknown = fixture.token(&fixture.claims(), "missing");
    let auth = Arc::new(Authenticator::new(fixture.config.auth).await.unwrap());
    let blocked = fixture.gate.acquire().await.unwrap();
    let refreshing = Arc::clone(&auth);
    let mut tasks = fixture.tasks;
    tasks.spawn(async move {
        assert!(matches!(
            refreshing.verify(Some(&format!("Bearer {unknown}"))).await,
            Err(Reason::Signature)
        ));
    });
    fixture.refresh_started.await.unwrap();
    assert_eq!(
        auth.verify(Some(&format!("Bearer {known}"))).await.unwrap(),
        "system:serviceaccount:dekopon:default"
    );
    drop(blocked);
    tasks.join_next().await.unwrap().unwrap();
    tasks.shutdown().await;
}
#[tokio::test]
async fn cancelled_request_finishes_off_runtime_before_shutdown() {
    use opentelemetry::trace::TracerProvider;
    use tracing::instrument::WithSubscriber;
    use tracing_subscriber::layer::SubscriberExt;
    let exporter = opentelemetry_sdk::trace::InMemorySpanExporter::default();
    let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
        .with_simple_exporter(exporter.clone())
        .build();
    let subscriber = tracing_subscriber::registry()
        .with(tracing_opentelemetry::layer().with_tracer(provider.tracer("cancel-test")));
    let fixture = Fixture::new().await;
    let token = fixture.token(&fixture.claims(), "missing");
    let (endpoint, requests) = app(fixture.config).await.unwrap();
    let blocked = fixture.gate.acquire().await.unwrap();
    let mut callers = tokio::task::JoinSet::new();
    callers.spawn(
        async move {
            TestClient::new(endpoint)
                .get("/v1/whoami")
                .header("Authorization", format!("Bearer {token}"))
                .send()
                .await
                .assert_status(StatusCode::UNAUTHORIZED);
        }
        .with_subscriber(subscriber),
    );
    fixture.refresh_started.await.unwrap();
    callers.shutdown().await;
    assert!(exporter.get_finished_spans().unwrap().is_empty());
    drop(blocked);
    requests.drain().await.unwrap();
    let spans = exporter.get_finished_spans().unwrap();
    assert_eq!(spans.len(), 1);
    assert_eq!(spans[0].name, "vm_runner.request");
    assert_eq!(
        span_attribute(&spans[0], "vm_runner.auth.reason"),
        Some(&"signature".into())
    );
    provider.shutdown().unwrap();
}
#[tokio::test]
async fn http_exporter_redacts_debug_but_delivers_headers() {
    use opentelemetry::trace::{Tracer, TracerProvider};
    use std::io::Write;
    let secret = "otlp-sentinel-secret";
    let mut headers = tempfile::NamedTempFile::new().unwrap();
    writeln!(headers, "authorization: {secret}").unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let config = config::Telemetry {
        otlp: config::Otlp {
            protocol: config::Protocol::Http,
            endpoint: format!("http://{}/v1/traces", listener.local_addr().unwrap()),
            ca_bundle_file: None,
            headers_file: Some(headers.path().into()),
        },
    };
    let provider = telemetry::provider(Some(&config)).await.unwrap();
    assert!(!format!("{provider:?}").contains(secret));
    let receiver = async {
        let (stream, _) = listener.accept().await.unwrap();
        let service = hyper::service::service_fn(
            move |req: hyper::Request<hyper::body::Incoming>| async move {
                assert_eq!(req.headers()["authorization"], secret);
                assert_eq!(req.uri().path(), "/v1/traces");
                Ok::<_, std::convert::Infallible>(hyper::Response::new(http_body_util::Empty::<
                    hyper::body::Bytes,
                >::new()))
            },
        );
        hyper::server::conn::http1::Builder::new()
            .keep_alive(false)
            .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
            .await
            .unwrap();
    };
    let export = tokio::task::spawn_blocking(move || {
        provider
            .tracer("header-test")
            .in_span("test.export", |_| {});
        provider.shutdown().unwrap();
    });
    let ((), exported) = tokio::join!(receiver, export);
    exported.unwrap();
}
#[tokio::test]
async fn refusal_span_has_reason_and_incoming_parent() {
    use opentelemetry::trace::TracerProvider;
    use tracing_subscriber::layer::SubscriberExt;
    let exporter = opentelemetry_sdk::trace::InMemorySpanExporter::default();
    let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
        .with_simple_exporter(exporter.clone())
        .build();
    tracing::subscriber::set_global_default(
        tracing_subscriber::registry()
            .with(tracing_opentelemetry::layer().with_tracer(provider.tracer("test"))),
    )
    .unwrap();
    let fixture = Fixture::new().await;
    let client = TestClient::new(app(fixture.config).await.unwrap().0);
    let response = client
        .get("/v1/whoami")
        .header(
            "traceparent",
            "00-11111111111111111111111111111111-2222222222222222-01",
        )
        .send()
        .await;
    response.assert_status(StatusCode::UNAUTHORIZED);
    response
        .assert_json(json!({"error":"unauthorized", "reason":"malformed"}))
        .await;
    let spans = exporter.get_finished_spans().unwrap();
    let span = spans
        .iter()
        .find(|s| s.parent_span_id.to_string() == "2222222222222222")
        .unwrap();
    assert_eq!(span.name, "vm_runner.request");
    assert_eq!(
        span.span_context.trace_id().to_string(),
        "11111111111111111111111111111111"
    );
    assert_eq!(
        span_attribute(span, "vm_runner.auth.reason"),
        Some(&"malformed".into())
    );
    provider.shutdown().unwrap();
}
