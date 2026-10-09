use super::*;
use http_body_util::BodyExt;
use serde_json::{Value, json};

type Mock = tower_test::mock::Handle<
    hyper::Request<kube::client::Body>,
    hyper::Response<kube::client::Body>,
>;
fn config() -> Arc<Config> {
    let mut config: Config =
        serde_yaml_ng::from_str(include_str!("../../examples/vm-runner.yaml")).unwrap();
    config.jails = Some(
        serde_json::from_value(json!({
            "namespace":"jails", "image":"runner@sha256:abc", "imageCacheHostPath":"/images",
            "controllerAudience":"vm-runner-jail", "controllerSubject":"system:serviceaccount:test:controller", "tokenFile":"/token"
        }))
        .unwrap(),
    );
    Arc::new(config)
}
async fn reply(mock: &mut Mock, method: &str, path: &str, value: Value) {
    let (request, send) = mock.next_request().await.unwrap();
    assert_eq!(request.method(), method);
    assert_eq!(request.uri().path(), path);
    let _body = request.into_body().collect().await.unwrap();
    send.send_response(
        hyper::Response::builder()
            .header("content-type", "application/json")
            .body(kube::client::Body::from(
                serde_json::to_vec(&value).unwrap(),
            ))
            .unwrap(),
    );
}
pub(crate) fn pod() -> Value {
    json!({"apiVersion":"v1", "kind":"Pod", "metadata":{
        "name":"jail-rebuilt", "creationTimestamp":"2026-09-25T00:00:00Z",
        "labels":{"vm-runner/session":"019591f2-439b-7000-8000-000000000001", "vm-runner/profile":"travel",
        "vm-runner/subject-hash":subject_hash("system:serviceaccount:dekopon:default")},
        "annotations":{"vm-runner/subject":"system:serviceaccount:dekopon:default", "vm-runner/name":"default", "vm-runner/created":"100", "vm-runner/active":"200"}
    }, "spec":{"containers":[{"name":"jail", "image":"runner@sha256:abc"}]},
    "status":{"phase":"Running", "podIP":"127.0.0.1"}})
}
async fn gone(mock: &mut Mock, method: &str, path: &str) {
    let (request, send) = mock.next_request().await.unwrap();
    assert_eq!(request.method(), method);
    assert_eq!(request.uri().path(), path);
    send.send_response(hyper::Response::builder().status(404).body(kube::client::Body::from(
        json!({"kind":"Status","apiVersion":"v1","status":"Failure","reason":"NotFound","message":"gone","code":404}).to_string().into_bytes()
    )).unwrap());
}
pub(crate) async fn setup(items: Vec<Value>) -> (Controller, Mock) {
    let (service, mut mock) = tower_test::mock::pair();
    let (controller, ()) = tokio::join!(
        Controller::new(config(), Client::new(service, "jails")),
        reply(
            &mut mock,
            "GET",
            "/api/v1/namespaces/jails/pods",
            json!({"apiVersion":"v1","kind":"PodList","metadata":{},"items":items})
        )
    );
    (controller.unwrap(), mock)
}
fn create(profile: &str, name: Option<&str>) -> Create {
    Create {
        profile: profile.into(),
        name: name.map(str::to_owned),
    }
}
const SUBJECT_VALUE: &str = "system:serviceaccount:dekopon:default";
const POD_PATH: &str = "/api/v1/namespaces/jails/pods/jail-rebuilt";

#[tokio::test]
async fn controller_telemetry_round_trips_into_strict_jail_config() {
    use base64::Engine;
    let mut config = config();
    let telemetry: crate::config::Telemetry = serde_yaml_ng::from_str(
        "detail:\n  default: full\n  categories:\n    egress.exchange: drip\nomit:\n  headers: [Authorization, x-token*]\n  queryKeys: [apiKey, source*]",
    ).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let token_file = directory.path().join("token");
    let token = format!(
        "{}.{}.AA",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256"}"#),
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
            json!({
                "sub":"system:serviceaccount:test:controller",
                "iss":"https://kubernetes.default.svc", "aud":["vm-runner-jail"]
            })
            .to_string()
        )
    );
    tokio::fs::write(&token_file, token).await.unwrap();
    let mutable = Arc::get_mut(&mut config).unwrap();
    mutable.telemetry = Some(telemetry);
    mutable.jails.as_mut().unwrap().token_file = token_file;
    let (service, mut mock) = tower_test::mock::pair();
    let (controller, ()) = tokio::join!(
        Controller::new(config, Client::new(service, "jails")),
        reply(
            &mut mock,
            "GET",
            "/api/v1/namespaces/jails/pods",
            json!({"apiVersion":"v1","kind":"PodList","metadata":{},"items":[]})
        )
    );
    let controller = controller.unwrap();
    let Created::New(Json(body)) = controller
        .create(SUBJECT_VALUE, create("travel", None))
        .unwrap()
    else {
        panic!("new session")
    };
    let (_, session) = controller.session(SUBJECT_VALUE, &body.session_id).unwrap();
    let (_, secret) = controller.manifests(&session, "jail-test").await.unwrap();
    let files = secret.data.unwrap();
    let jail: Config = serde_yaml_ng::from_slice(&files["config.json"].0).unwrap();
    let encoded = serde_json::to_value(jail.telemetry.as_ref().unwrap()).unwrap();
    assert_eq!(
        jail.telemetry
            .as_ref()
            .unwrap()
            .detail
            .level(crate::config::Category::EgressExchange),
        crate::config::Detail::Drip
    );
    assert_eq!(
        jail.telemetry
            .as_ref()
            .unwrap()
            .detail
            .level(crate::config::Category::VmExec),
        crate::config::Detail::Full
    );
    assert!(jail.telemetry.as_ref().unwrap().otlp.is_none());
    assert_eq!(
        encoded["omit"]["headers"],
        json!(["authorization", "x-token*"])
    );
    assert_eq!(encoded["omit"]["queryKeys"], json!(["apikey", "source*"]));
}
#[tokio::test]
async fn stuck_delete_ends_the_session_only_when_the_pod_is_gone() {
    use tracing::instrument::WithSubscriber;
    use tracing_subscriber::layer::SubscriberExt;
    let (controller, mut mock) = setup(vec![pod()]).await;
    let exporter = opentelemetry_sdk::logs::InMemoryLogExporter::default();
    let provider = opentelemetry_sdk::logs::SdkLoggerProvider::builder()
        .with_simple_exporter(exporter.clone())
        .build();
    let dispatch =
        tracing::Dispatch::new(tracing_subscriber::registry().with(
            opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge::new(&provider),
        ));
    let mut observed = pod();
    observed["metadata"]["uid"] = json!("pod-uid-1");
    observed["status"]["phase"] = json!("Failed");
    observed["status"]["containerStatuses"] = json!([{
        "name":"jail", "ready":false, "restartCount":0,
        "state":{"terminated":{"exitCode":42, "reason":"OOMKilled"}}
    }]);
    tokio::join!(
        controller.reap(1901).with_subscriber(dispatch.clone()),
        async {
            reply(&mut mock, "GET", POD_PATH, observed).await;
            reply(&mut mock, "DELETE", POD_PATH, pod()).await;
        }
    );
    let mut terminating = pod();
    terminating["metadata"]["deletionTimestamp"] = json!("2026-09-26T00:00:00Z");
    tokio::join!(
        controller.reap(1902).with_subscriber(dispatch.clone()),
        reply(&mut mock, "GET", POD_PATH, terminating)
    );
    assert!(
        mock.poll_request().is_pending(),
        "retry must not delete an already terminating pod"
    );
    assert!(
        exporter
            .get_emitted_logs()
            .unwrap()
            .iter()
            .all(|log| log.record.event_name() != Some("vm_runner.session.ended"))
    );
    tokio::join!(
        controller.reap(1903).with_subscriber(dispatch),
        gone(&mut mock, "GET", POD_PATH)
    );
    let logs = exporter.get_emitted_logs().unwrap();
    let ended: Vec<_> = logs
        .iter()
        .filter(|log| log.record.event_name() == Some("vm_runner.session.ended"))
        .collect();
    assert_eq!(ended.len(), 1);
    for (key, value) in [
        (
            "k8s.pod.name",
            opentelemetry::logs::AnyValue::from("jail-rebuilt"),
        ),
        (
            "k8s.pod.uid",
            opentelemetry::logs::AnyValue::from("pod-uid-1"),
        ),
        (
            "k8s.pod.phase",
            opentelemetry::logs::AnyValue::from("Failed"),
        ),
        (
            "vm_runner.jail.terminated_reason",
            opentelemetry::logs::AnyValue::from("OOMKilled"),
        ),
        (
            "vm_runner.jail.exit_code",
            opentelemetry::logs::AnyValue::Int(42),
        ),
    ] {
        assert!(
            ended[0]
                .record
                .attributes_iter()
                .any(|(k, v)| k.as_str() == key && v == &value),
            "missing {key}"
        );
    }
    provider.shutdown().unwrap();
}
#[tokio::test]
async fn failed_first_read_never_uses_post_delete_retry_status() {
    use tracing::instrument::WithSubscriber;
    use tracing_subscriber::layer::SubscriberExt;
    let (controller, mut mock) = setup(vec![pod()]).await;
    let exporter = opentelemetry_sdk::logs::InMemoryLogExporter::default();
    let provider = opentelemetry_sdk::logs::SdkLoggerProvider::builder()
        .with_simple_exporter(exporter.clone())
        .build();
    let dispatch =
        tracing::Dispatch::new(tracing_subscriber::registry().with(
            opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge::new(&provider),
        ));
    tokio::join!(
        controller.reap(1901).with_subscriber(dispatch.clone()),
        async {
            let (request, send) = mock.next_request().await.unwrap();
            assert_eq!(request.method(), "GET");
            assert_eq!(request.uri().path(), POD_PATH);
            send.send_response(hyper::Response::builder().status(503)
            .body(kube::client::Body::from(json!({"kind":"Status","apiVersion":"v1","status":"Failure","reason":"ServiceUnavailable","message":"read failed","code":503}).to_string().into_bytes())).unwrap());
            reply(&mut mock, "DELETE", POD_PATH, pod()).await;
        }
    );
    let mut terminating = pod();
    terminating["metadata"]["uid"] = json!("too-late-uid");
    terminating["metadata"]["deletionTimestamp"] = json!("2026-09-26T00:00:00Z");
    terminating["status"]["phase"] = json!("Failed");
    terminating["status"]["containerStatuses"] = json!([{
        "name":"jail", "ready":false, "restartCount":0,
        "state":{"terminated":{"exitCode":42,"reason":"OOMKilled"}}
    }]);
    tokio::join!(
        controller.reap(1902).with_subscriber(dispatch.clone()),
        reply(&mut mock, "GET", POD_PATH, terminating)
    );
    assert!(
        mock.poll_request().is_pending(),
        "retry must not delete a terminating pod"
    );
    assert!(
        exporter
            .get_emitted_logs()
            .unwrap()
            .iter()
            .all(|log| log.record.event_name() != Some("vm_runner.session.ended"))
    );
    tokio::join!(
        controller.reap(1903).with_subscriber(dispatch),
        gone(&mut mock, "GET", POD_PATH)
    );
    let ended: Vec<_> = exporter
        .get_emitted_logs()
        .unwrap()
        .into_iter()
        .filter(|log| log.record.event_name() == Some("vm_runner.session.ended"))
        .collect();
    assert_eq!(ended.len(), 1);
    assert!(
        ended[0]
            .record
            .attributes_iter()
            .any(|(key, value)| key.as_str() == "k8s.pod.name"
                && value == &opentelemetry::logs::AnyValue::from("jail-rebuilt"))
    );
    for absent in [
        "k8s.pod.uid",
        "k8s.pod.phase",
        "vm_runner.jail.terminated_reason",
        "vm_runner.jail.exit_code",
    ] {
        assert!(
            !ended[0]
                .record
                .attributes_iter()
                .any(|(key, _)| key.as_str() == absent),
            "unexpected {absent}"
        );
    }
    provider.shutdown().unwrap();
}

async fn cold_setup() -> (Controller, Mock, tempfile::TempDir) {
    use base64::Engine;
    let directory = tempfile::tempdir().unwrap();
    let token_file = directory.path().join("token");
    let token = format!("{}.{}.AA",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256"}"#),
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json!({
            "sub":"system:serviceaccount:test:controller", "iss":"https://kubernetes.default.svc",
            "aud":["vm-runner-jail"]
        }).to_string()));
    tokio::fs::write(&token_file, token).await.unwrap();
    let mut config = config();
    Arc::get_mut(&mut config)
        .unwrap()
        .jails
        .as_mut()
        .unwrap()
        .token_file = token_file;
    let (service, mut mock) = tower_test::mock::pair();
    let (controller, ()) = tokio::join!(
        Controller::new(config, Client::new(service, "jails")),
        reply(
            &mut mock,
            "GET",
            "/api/v1/namespaces/jails/pods",
            json!({"apiVersion":"v1","kind":"PodList","metadata":{},"items":[]})
        )
    );
    (controller.unwrap(), mock, directory)
}

#[tokio::test]
async fn cold_boot_records_created_uid_even_if_secret_fails_and_on_success() {
    use opentelemetry::trace::TracerProvider;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tracing::instrument::WithSubscriber;
    use tracing_subscriber::layer::SubscriberExt;
    for secret_fails in [true, false] {
        let (mut controller, mut mock, _files) = cold_setup().await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        controller.jail_port = listener.local_addr().unwrap().port();
        let Created::New(Json(body)) = controller
            .create(SUBJECT_VALUE, create("travel", None))
            .unwrap()
        else {
            panic!("new session")
        };
        let (key, session) = controller.session(SUBJECT_VALUE, &body.session_id).unwrap();
        let exporter = opentelemetry_sdk::trace::InMemorySpanExporter::default();
        let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let dispatch = tracing::Dispatch::new(
            tracing_subscriber::registry()
                .with(tracing_opentelemetry::layer().with_tracer(provider.tracer("cold-test"))),
        );
        let name = format!("vm-runner-{}", body.session_id);
        let path = "/api/v1/namespaces/jails/pods";
        let (result, (), ()) = tokio::join!(
            controller.boot(&key, &session).with_subscriber(dispatch),
            async {
                let (request, send) = mock.next_request().await.unwrap();
                assert_eq!(request.method(), "POST");
                assert_eq!(request.uri().path(), path);
                let mut pod: Value = serde_json::from_slice(
                    &request.into_body().collect().await.unwrap().to_bytes(),
                )
                .unwrap();
                assert_eq!(pod["metadata"]["name"], name);
                pod["metadata"]["uid"] = json!("cold-uid");
                pod["metadata"]["resourceVersion"] = json!("10");
                pod["status"] = json!({"phase":"Running","podIP":"127.0.0.1",
                    "conditions":[{"type":"Ready","status":"True"}]});
                send.send_response(hyper::Response::new(kube::client::Body::from(
                    pod.to_string().into_bytes(),
                )));
                let (request, send) = mock.next_request().await.unwrap();
                assert_eq!(request.method(), "POST");
                assert_eq!(request.uri().path(), "/api/v1/namespaces/jails/secrets");
                let secret: Value = serde_json::from_slice(
                    &request.into_body().collect().await.unwrap().to_bytes(),
                )
                .unwrap();
                assert_eq!(secret["metadata"]["ownerReferences"][0]["uid"], "cold-uid");
                if secret_fails {
                    send.send_response(hyper::Response::builder().status(500)
                        .body(kube::client::Body::from(json!({"kind":"Status","apiVersion":"v1","status":"Failure","reason":"InternalError","message":"secret failure","code":500}).to_string().into_bytes())).unwrap());
                } else {
                    send.send_response(hyper::Response::new(kube::client::Body::from(
                        secret.to_string().into_bytes(),
                    )));
                }
            },
            async {
                if !secret_fails {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    let mut bytes = [0; 1024];
                    let count = stream.read(&mut bytes).await.unwrap();
                    assert!(
                        std::str::from_utf8(&bytes[..count])
                            .unwrap()
                            .starts_with("GET /healthz ")
                    );
                    stream
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                        .await
                        .unwrap();
                }
            }
        );
        if secret_fails {
            assert!(matches!(result, Err(super::proxy::Error::Kubernetes(500))));
        } else {
            assert!(result.is_ok());
        }
        let spans = exporter.get_finished_spans().unwrap();
        let boot = spans
            .iter()
            .find(|span| span.name == "vm_runner.boot")
            .unwrap();
        for (key, value) in [("vm_runner.boot.kind", "cold"), ("k8s.pod.uid", "cold-uid")] {
            assert!(
                boot.attributes
                    .iter()
                    .any(|kv| kv.key.as_str() == key && kv.value.as_str() == value),
                "missing {key} when secret_fails={secret_fails}"
            );
        }
        provider.shutdown().unwrap();
    }
}

#[tokio::test]
async fn warm_boot_failure_carries_cause_and_pod_status_to_once_only_end() {
    use opentelemetry::trace::TracerProvider;
    use tracing::instrument::WithSubscriber;
    use tracing_subscriber::layer::SubscriberExt;
    let (controller, mut mock) = setup(vec![pod()]).await;
    let logs = opentelemetry_sdk::logs::InMemoryLogExporter::default();
    let log_provider = opentelemetry_sdk::logs::SdkLoggerProvider::builder()
        .with_simple_exporter(logs.clone())
        .build();
    let spans = opentelemetry_sdk::trace::InMemorySpanExporter::default();
    let span_provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
        .with_simple_exporter(spans.clone())
        .build();
    let dispatch = tracing::Dispatch::new(
        tracing_subscriber::registry()
            .with(tracing_opentelemetry::layer().with_tracer(span_provider.tracer("boot-test")))
            .with(
                opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge::new(
                    &log_provider,
                ),
            ),
    );
    let session = controller.sessions.lock().unwrap()["jail-rebuilt"].clone();
    let mut failed = pod();
    failed["metadata"]["uid"] = json!("failed-uid");
    failed["status"]["phase"] = json!("Failed");
    failed["status"]["initContainerStatuses"] = json!([{
        "name":"fetch", "image":"guest", "imageID":"guest", "ready":false, "restartCount":0,
        "state":{"terminated":{"exitCode":7, "reason":"Error"}}
    }]);
    failed["status"]["containerStatuses"] = json!([{
        "name":"jail", "ready":false, "restartCount":0,
        "state":{"terminated":{"exitCode":42, "reason":"OOMKilled"}}
    }]);
    let result = tokio::join!(
        controller
            .boot("jail-rebuilt", &session)
            .with_subscriber(dispatch.clone()),
        async {
            reply(&mut mock, "GET", POD_PATH, failed.clone()).await;
            reply(&mut mock, "GET", POD_PATH, failed).await;
            gone(&mut mock, "DELETE", POD_PATH).await;
        }
    )
    .0;
    assert!(matches!(
        result,
        Err(super::proxy::Error::Boot("fetch failed"))
    ));
    controller.reap(1901).with_subscriber(dispatch).await;
    let ended: Vec<_> = logs
        .get_emitted_logs()
        .unwrap()
        .into_iter()
        .filter(|log| log.record.event_name() == Some("vm_runner.session.ended"))
        .collect();
    assert_eq!(ended.len(), 1);
    for (key, value) in [
        ("error", opentelemetry::logs::AnyValue::from("fetch failed")),
        (
            "k8s.pod.uid",
            opentelemetry::logs::AnyValue::from("failed-uid"),
        ),
        (
            "k8s.pod.phase",
            opentelemetry::logs::AnyValue::from("Failed"),
        ),
        (
            "vm_runner.jail.exit_code",
            opentelemetry::logs::AnyValue::Int(42),
        ),
    ] {
        assert!(
            ended[0]
                .record
                .attributes_iter()
                .any(|(k, v)| k.as_str() == key && v == &value),
            "missing {key}"
        );
    }
    let boot = spans.get_finished_spans().unwrap();
    let boot = boot
        .iter()
        .find(|span| span.name == "vm_runner.boot")
        .unwrap();
    for (key, value) in [
        ("vm_runner.boot.kind", "warm"),
        ("k8s.pod.uid", "failed-uid"),
    ] {
        assert!(
            boot.attributes
                .iter()
                .any(|kv| kv.key.as_str() == key && kv.value.as_str() == value),
            "missing {key}"
        );
    }
    log_provider.shutdown().unwrap();
    span_provider.shutdown().unwrap();
}

#[tokio::test]
async fn session_lifecycle_and_health_are_typed_logs_with_detail() {
    use tracing::instrument::WithSubscriber;
    use tracing_subscriber::layer::SubscriberExt;
    let (controller, _mock) = setup(vec![]).await;
    let exporter = opentelemetry_sdk::logs::InMemoryLogExporter::default();
    let provider = opentelemetry_sdk::logs::SdkLoggerProvider::builder()
        .with_simple_exporter(exporter.clone())
        .build();
    let dispatch =
        tracing::Dispatch::new(tracing_subscriber::registry().with(
            opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge::new(&provider),
        ));
    let id = tracing::dispatcher::with_default(&dispatch, || {
        let Created::New(Json(session)) = controller
            .create(SUBJECT_VALUE, create("travel", None))
            .unwrap()
        else {
            panic!("new session")
        };
        controller.health();
        session.session_id
    });
    let created = controller.sessions.lock().unwrap()[&id].created;
    controller
        .reap(created + 1801)
        .with_subscriber(dispatch)
        .await;
    let logs = exporter.get_emitted_logs().unwrap();
    provider.shutdown().unwrap();
    assert!(!logs.is_empty(), "no logs emitted");
    for event in [
        "vm_runner.session.started",
        "vm_runner.session.ended",
        "telemetry.health",
    ] {
        assert_eq!(
            logs.iter()
                .filter(|log| log.record.event_name() == Some(event))
                .count(),
            1,
            "{event}"
        );
    }
    assert!(logs.iter().all(|log| {
        log.record.attributes_iter().any(|(key, value)| {
            key.as_str() == "telemetry.detail"
                && value == &opentelemetry::logs::AnyValue::from("full")
        })
    }));
    let ended = logs
        .iter()
        .find(|log| log.record.event_name() == Some("vm_runner.session.ended"))
        .unwrap();
    assert!(
        ended
            .record
            .attributes_iter()
            .any(
                |(key, value)| key.as_str() == "vm_runner.session.end_reason"
                    && value == &opentelemetry::logs::AnyValue::from("max_seconds")
            )
    );
    let health = logs
        .iter()
        .find(|log| log.record.event_name() == Some("telemetry.health"))
        .unwrap();
    assert!(
        health
            .record
            .attributes_iter()
            .any(|(key, value)| key.as_str() == "rollup.interval_ms"
                && value == &opentelemetry::logs::AnyValue::Int(60_000))
    );
    assert!(
        health
            .record
            .attributes_iter()
            .any(
                |(key, value)| key.as_str() == "vm_runner.session.live.count"
                    && value == &opentelemetry::logs::AnyValue::Int(1)
            )
    );
}

#[tokio::test]
async fn named_sessions_are_lazy_subject_scoped_and_profile_consistent() {
    let (controller, _mock) = setup(vec![]).await;
    let Created::New(Json(first)) = controller
        .create(SUBJECT_VALUE, create("travel", None))
        .unwrap()
    else {
        panic!("new session")
    };
    assert_eq!(first.name, "default");
    assert_eq!(
        uuid::Uuid::parse_str(&first.session_id)
            .unwrap()
            .get_version_num(),
        7
    );
    let Created::Existing(Json(same)) = controller
        .create(SUBJECT_VALUE, create("travel", Some("default")))
        .unwrap()
    else {
        panic!("existing session")
    };
    assert_eq!(same.session_id, first.session_id);
    controller
        .sessions
        .lock()
        .unwrap()
        .get_mut(&first.session_id)
        .unwrap()
        .active = 1;
    assert!(matches!(
        controller
            .create(SUBJECT_VALUE, create("travel", None))
            .unwrap(),
        Created::Existing(_)
    ));
    assert!(controller.sessions.lock().unwrap()[&first.session_id].active > 1);
    assert!(matches!(
        controller
            .create(SUBJECT_VALUE, create("other", None))
            .unwrap(),
        Created::Conflict(_)
    ));
    assert!(matches!(
        controller
            .create(
                "system:serviceaccount:other:default",
                create("travel", None)
            )
            .unwrap(),
        Created::New(_)
    ));
    assert!(
        controller
            .sessions
            .lock()
            .unwrap()
            .values()
            .all(|s| s.pod.is_none())
    );
    for name in ["", "UPPER", "-prefix", "has space"] {
        assert!(matches!(
            controller
                .create(SUBJECT_VALUE, create("travel", Some(name)))
                .unwrap(),
            Created::Refused(Json(NotExecuted {
                reason: Failure::BadName,
                ..
            }))
        ));
    }
}
#[tokio::test]
async fn quota_and_bad_profile_refusals_preserve_the_registry() {
    let (controller, _mock) = setup(vec![]).await;
    let subject = "system:serviceaccount:other:default";
    assert!(matches!(
        controller.create(subject, create("missing", None)).unwrap(),
        Created::Refused(Json(NotExecuted {
            reason: Failure::BadProfile,
            ..
        }))
    ));
    assert!(matches!(
        controller.create(subject, create("travel", None)).unwrap(),
        Created::New(_)
    ));
    assert!(matches!(
        controller
            .create(subject, create("travel", Some("second")))
            .unwrap(),
        Created::Refused(Json(NotExecuted {
            reason: Failure::Quota,
            ..
        }))
    ));
    assert_eq!(controller.sessions.lock().unwrap().len(), 1);
}
#[tokio::test]
async fn rebuild_recovers_named_sessions_and_reaper_deletes_expired_pods() {
    let (controller, mut mock) = setup(vec![pod()]).await;
    let body = controller.sessions.lock().unwrap()["jail-rebuilt"]
        .body
        .clone();
    assert_eq!(body.session_id, "019591f2-439b-7000-8000-000000000001");
    controller.reap(499).await;
    assert_eq!(controller.sessions.lock().unwrap().len(), 1);
    tokio::join!(controller.reap(500), async {
        reply(&mut mock, "GET", POD_PATH, pod()).await;
        reply(&mut mock, "DELETE", POD_PATH, pod()).await;
    });
    assert!(
        controller
            .sessions
            .lock()
            .unwrap()
            .values()
            .all(|s| s.is_retiring())
    );
    tokio::join!(controller.reap(501), gone(&mut mock, "GET", POD_PATH));
    assert!(controller.sessions.lock().unwrap().is_empty());
}
#[tokio::test]
async fn rebuild_deletes_terminal_pods_instead_of_leaking_them() {
    let (service, mut mock) = tower_test::mock::pair();
    let mut terminal = pod();
    terminal["status"]["phase"] = json!("Failed");
    let (controller, ()) = tokio::join!(
        Controller::new(config(), Client::new(service, "jails")),
        async {
            reply(
                &mut mock,
                "GET",
                "/api/v1/namespaces/jails/pods",
                json!({"apiVersion":"v1","kind":"PodList","metadata":{},"items":[terminal]}),
            )
            .await;
            reply(&mut mock, "DELETE", POD_PATH, pod()).await;
        }
    );
    let controller = controller.unwrap();
    assert_eq!(controller.sessions.lock().unwrap().len(), 1);
    assert!(
        controller
            .sessions
            .lock()
            .unwrap()
            .values()
            .all(|s| s.is_retiring())
    );
}
#[tokio::test]
async fn rebuilt_already_deleting_pod_keeps_listed_status_until_once_only_end() {
    use tracing::instrument::WithSubscriber;
    use tracing_subscriber::layer::SubscriberExt;
    let mut deleting = pod();
    deleting["metadata"]["deletionTimestamp"] = json!("2026-09-26T00:00:00Z");
    deleting["metadata"]["uid"] = json!("listed-uid");
    deleting["status"]["phase"] = json!("Failed");
    let (controller, mut mock) = setup(vec![deleting.clone()]).await;
    let exporter = opentelemetry_sdk::logs::InMemoryLogExporter::default();
    let provider = opentelemetry_sdk::logs::SdkLoggerProvider::builder()
        .with_simple_exporter(exporter.clone())
        .build();
    let dispatch =
        tracing::Dispatch::new(tracing_subscriber::registry().with(
            opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge::new(&provider),
        ));
    let mut later = deleting;
    later["metadata"]["uid"] = json!("wrong-later-uid");
    later["status"]["phase"] = json!("Running");
    tokio::join!(
        controller.reap(499).with_subscriber(dispatch.clone()),
        reply(&mut mock, "GET", POD_PATH, later)
    );
    assert!(mock.poll_request().is_pending());
    tokio::join!(
        controller.reap(500).with_subscriber(dispatch.clone()),
        gone(&mut mock, "GET", POD_PATH)
    );
    controller.reap(501).with_subscriber(dispatch).await;
    let ended: Vec<_> = exporter
        .get_emitted_logs()
        .unwrap()
        .into_iter()
        .filter(|log| log.record.event_name() == Some("vm_runner.session.ended"))
        .collect();
    assert_eq!(ended.len(), 1);
    for (key, value) in [
        ("k8s.pod.uid", "listed-uid"),
        ("k8s.pod.phase", "Failed"),
        ("vm_runner.session.end_reason", "terminal"),
    ] {
        assert!(ended[0].record.attributes_iter().any(|(k, v)| k.as_str() == key
            && v == &opentelemetry::logs::AnyValue::from(value)), "missing {key}");
    }
    provider.shutdown().unwrap();
}

#[tokio::test]
async fn rebuild_tolerates_terminal_pods_deleted_since_listing() {
    let (service, mut mock) = tower_test::mock::pair();
    let mut terminal = pod();
    terminal["status"]["phase"] = json!("Succeeded");
    let (controller, ()) = tokio::join!(
        Controller::new(config(), Client::new(service, "jails")),
        async {
            reply(
                &mut mock,
                "GET",
                "/api/v1/namespaces/jails/pods",
                json!({"apiVersion":"v1","kind":"PodList","metadata":{},"items":[terminal]}),
            )
            .await;
            gone(&mut mock, "DELETE", POD_PATH).await;
        }
    );
    assert!(controller.unwrap().sessions.lock().unwrap().is_empty());
}
#[tokio::test]
async fn rebuild_keeps_the_oldest_named_session_and_deletes_duplicates_in_any_list_order() {
    for reversed in [false, true] {
        let (service, mut mock) = tower_test::mock::pair();
        let first = pod();
        let mut duplicate = pod();
        duplicate["metadata"]["name"] = json!("jail-duplicate");
        // Newer pod deliberately has the earlier-sorting UUID and pod name.
        duplicate["metadata"]["creationTimestamp"] = json!("2026-09-26T00:00:00Z");
        duplicate["metadata"]["labels"]["vm-runner/session"] =
            json!("019591f2-439b-7000-8000-000000000000");
        let items = if reversed {
            vec![duplicate.clone(), first]
        } else {
            vec![first, duplicate.clone()]
        };
        let (controller, ()) = tokio::join!(
            Controller::new(config(), Client::new(service, "jails")),
            async {
                reply(
                    &mut mock,
                    "GET",
                    "/api/v1/namespaces/jails/pods",
                    json!({"apiVersion":"v1","kind":"PodList","metadata":{},"items":items}),
                )
                .await;
                reply(
                    &mut mock,
                    "DELETE",
                    "/api/v1/namespaces/jails/pods/jail-duplicate",
                    duplicate,
                )
                .await;
            }
        );
        let controller = controller.unwrap();
        let Created::Existing(Json(session)) = controller
            .create(SUBJECT_VALUE, create("travel", None))
            .unwrap()
        else {
            panic!("recovered session")
        };
        assert_eq!(session.session_id, "019591f2-439b-7000-8000-000000000001");
        assert_eq!(controller.sessions.lock().unwrap().len(), 2);
        tokio::join!(
            controller.reap(499),
            gone(
                &mut mock,
                "GET",
                "/api/v1/namespaces/jails/pods/jail-duplicate"
            )
        );
        assert_eq!(controller.sessions.lock().unwrap().len(), 1);
    }
}
#[tokio::test]
async fn rebuild_ignores_inconsistent_metadata_or_foreign_images() {
    for (pointer, value) in [
        ("/metadata/annotations", Value::Null),
        (
            "/metadata/labels/vm-runner~1profile",
            json!("removed-profile"),
        ),
        (
            "/metadata/labels/vm-runner~1subject-hash",
            json!("0000000000000000"),
        ),
        (
            "/metadata/annotations/vm-runner~1subject",
            json!("system:serviceaccount:other:default"),
        ),
        ("/spec/containers/0/image", json!("foreign@sha256:abc")),
        (
            "/spec/containers",
            json!([
                {"name":"jail", "image":"foreign@sha256:abc"},
                {"name":"sidecar", "image":"runner@sha256:abc"}
            ]),
        ),
    ] {
        let mut foreign = pod();
        *foreign.pointer_mut(pointer).unwrap() = value;
        let (controller, mut mock) = setup(vec![foreign]).await;
        assert!(controller.sessions.lock().unwrap().is_empty(), "{pointer}");
        assert!(
            mock.poll_request().is_pending(),
            "foreign pod must not be deleted"
        );
    }
}
#[test]
fn jails_configuration_reports_all_invalid_fields() {
    let mut config = config();
    let jails = Arc::get_mut(&mut config).unwrap().jails.as_mut().unwrap();
    jails.namespace.clear();
    jails.image.clear();
    jails.controller_audience = "vm-runner".into();
    jails.controller_subject = "not-a-service-account".into();
    jails.token_file = "relative".into();
    jails.image_cache_host_path = "relative".into();
    assert_eq!(
        config.conflicts(),
        [
            "namespace",
            "image",
            "imageCacheHostPath",
            "tokenFile",
            "controllerAudience",
            "controllerSubject"
        ]
        .map(crate::config::Conflict::Jails)
    );
}
#[test]
fn jail_cpu_request_must_be_nonzero_and_fit_every_used_shape() {
    let mut config = config();
    let config = Arc::get_mut(&mut config).unwrap();
    let jails = config.jails.as_mut().unwrap();
    jails.image = format!("runner@sha256:{}", "a".repeat(64));
    let mut serialized = serde_json::to_value(&*jails).unwrap();
    serialized["cpuRequestMilli"] = json!(0);
    assert!(serde_json::from_value::<crate::config::Jails>(serialized).is_err());
    jails.cpu_request_milli = Some(std::num::NonZeroU32::new(1001).unwrap());
    assert_eq!(
        config.conflicts(),
        [crate::config::Conflict::Jails("cpuRequestMilli")]
    );
    config.jails.as_mut().unwrap().cpu_request_milli =
        Some(std::num::NonZeroU32::new(1000).unwrap());
    assert!(config.conflicts().is_empty());
    config.jails.as_mut().unwrap().cpu_request_milli =
        Some(std::num::NonZeroU32::new(250).unwrap());
    assert!(config.conflicts().is_empty());
}

#[tokio::test]
async fn maximum_lifetime_reaps_even_an_active_session() {
    let mut active = pod();
    active["metadata"]["annotations"]["vm-runner/active"] = json!("1899");
    let (controller, mut mock) = setup(vec![active]).await;
    tokio::join!(controller.reap(1900), async {
        reply(&mut mock, "GET", POD_PATH, pod()).await;
        reply(&mut mock, "DELETE", POD_PATH, pod()).await;
    });
    assert!(
        controller
            .sessions
            .lock()
            .unwrap()
            .values()
            .all(|s| s.is_retiring())
    );
    tokio::join!(controller.reap(1901), gone(&mut mock, "GET", POD_PATH));
    assert!(controller.sessions.lock().unwrap().is_empty());
}
#[tokio::test]
async fn terminating_pods_count_toward_quota_but_never_satisfy_create_or_get_until_gone() {
    let mut terminating = pod();
    terminating["metadata"]["deletionTimestamp"] = json!("2026-09-26T00:00:00Z");
    let (controller, mut mock) = setup(vec![terminating.clone()]).await;
    let Created::New(Json(new)) = controller
        .create(SUBJECT_VALUE, create("travel", None))
        .unwrap()
    else {
        panic!("terminating is not live")
    };
    assert_ne!(new.session_id, "019591f2-439b-7000-8000-000000000001");
    assert!(matches!(
        controller
            .create(SUBJECT_VALUE, create("travel", Some("second")))
            .unwrap(),
        Created::Refused(Json(NotExecuted {
            reason: Failure::Quota,
            ..
        }))
    ));
    tokio::join!(
        controller.reap(499),
        reply(&mut mock, "GET", POD_PATH, terminating)
    );
    assert_eq!(controller.sessions.lock().unwrap().len(), 2);
    tokio::join!(controller.reap(499), gone(&mut mock, "GET", POD_PATH));
    assert!(matches!(
        controller
            .create(SUBJECT_VALUE, create("travel", Some("second")))
            .unwrap(),
        Created::New(_)
    ));
}
#[test]
fn models_route_reports_every_invalid_field_and_rejects_unknown_keys() {
    let mut config = config();
    let config = Arc::get_mut(&mut config).unwrap();
    let jails = config.jails.as_mut().unwrap();
    jails.image = format!("runner@sha256:{}", "a".repeat(64));
    jails.models = Some(
        serde_json::from_value(
            json!({"upstream":"http://dekopon:9090/v1","clientCertSecret":"","subject":"system:serviceaccount:dekopon:x"}),
        )
        .unwrap(),
    );
    assert_eq!(
        config.conflicts(),
        [
            "models.upstream",
            "models.clientCertSecret",
            "models.subject"
        ]
        .map(crate::config::Conflict::Jails)
    );
    assert!(
        serde_json::from_value::<crate::config::Models>(
            json!({"upstream":"https://dekopon:9090","clientCertSecret":"s","caFile":"/x"})
        )
        .is_err()
    );
}
