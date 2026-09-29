use super::*;

#[tokio::test]
async fn reaper_kube_error_or_timeout_leaves_api_serving_and_retries_next_tick() {
    use opentelemetry::trace::TracerProvider;
    use tracing::instrument::WithSubscriber;
    use tracing_subscriber::layer::SubscriberExt;
    let exporter = opentelemetry_sdk::trace::InMemorySpanExporter::default();
    let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
        .with_simple_exporter(exporter.clone())
        .build();
    let log_exporter = opentelemetry_sdk::logs::InMemoryLogExporter::default();
    let logger = opentelemetry_sdk::logs::SdkLoggerProvider::builder()
        .with_simple_exporter(log_exporter.clone())
        .build();
    let subscriber = tracing_subscriber::registry()
        .with(tracing_opentelemetry::layer().with_tracer(provider.tracer("reaper-test")))
        .with(opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge::new(&logger));
    let timeouts = kube_timeouts(kube::Config::new("http://127.0.0.1:1".parse().unwrap()));
    assert_eq!(
        timeouts.connect_timeout,
        Some(std::time::Duration::from_secs(5))
    );
    assert_eq!(
        timeouts.read_timeout,
        Some(std::time::Duration::from_secs(15))
    );
    let mut fixture = Fixture::new().await;
    let token = fixture.token(&fixture.claims(), "ec");
    fixture.config.jails = Some(
        serde_json::from_value(json!({
            "namespace":"jails", "image":"runner@sha256:abc", "imageCacheHostPath":"/images",
            "controllerAudience":"vm-runner-jail", "controllerSubject":"system:serviceaccount:test:controller", "tokenFile":"/token"
        }))
        .unwrap(),
    );
    let config = Arc::new(fixture.config);
    let (service, mut mock) = tower_test::mock::pair();
    let (controller, ()) = tokio::join!(
        controller::Controller::new(Arc::clone(&config), kube::Client::new(service, "jails")),
        async {
            let (_, send) = mock.next_request().await.unwrap();
            send.send_response(hyper::Response::new(kube::client::Body::from(
            json!({"apiVersion":"v1","kind":"PodList","metadata":{},"items":[controller::tests::pod()]}).to_string().into_bytes())));
        }
    );
    let controller = Arc::new(controller.unwrap());
    let admission = Arc::new(tokio::sync::Semaphore::new(1));
    let requests = Arc::new(Requests {
        admission: Arc::clone(&admission),
        reaper_drain: Arc::new(tokio::sync::Semaphore::new(1)),
        controller: Some(Arc::clone(&controller)),
    });
    let client = TestClient::new(endpoint(
        Arc::new(State {
            auth: Authenticator::new(config.auth.clone()).await.unwrap(),
            config,
            controller: Some(controller),
        }),
        admission,
    ));
    tokio::time::pause();
    let mut tasks = tokio::task::JoinSet::new();
    let reaping = Arc::clone(&requests);
    tasks.spawn(async move { reaping.reap().await.unwrap() }.with_subscriber(subscriber));
    for (index, method) in ["DELETE", "GET", "GET"].into_iter().enumerate() {
        let (request, send) = tokio::select! {
            request = mock.next_request() => request.unwrap(),
            result = tasks.join_next() => panic!("reaper stopped: {result:?}"),
        };
        assert_eq!(request.method(), method);
        assert_eq!(requests.admission.available_permits(), 1);
        client.get("/healthz").send().await.assert_text("ok").await;
        client
            .post("/v1/sessions")
            .header("Authorization", format!("Bearer {token}"))
            .body_json(&json!({"profile":"travel","name":"second"}))
            .send()
            .await
            .assert_status(if index == 0 {
                StatusCode::CREATED
            } else {
                StatusCode::OK
            });
        match index {
            0 => send.send_response(hyper::Response::builder().status(503).body(kube::client::Body::from(
                json!({"kind":"Status","apiVersion":"v1","status":"Failure","reason":"ServiceUnavailable","message":"retry-test","code":503}).to_string().into_bytes())).unwrap()),
            1 => send.send_error(std::io::Error::new(std::io::ErrorKind::TimedOut, "read timeout test")),
            _ => send.send_response(hyper::Response::builder().status(404).body(kube::client::Body::from(
                json!({"kind":"Status","apiVersion":"v1","status":"Failure","reason":"NotFound","message":"gone","code":404}).to_string().into_bytes())).unwrap()),
        }
    }
    let spans = exporter.get_finished_spans().unwrap();
    assert!(spans.iter().all(|span| span.name != "vm_runner.reap"));
    let logs = log_exporter.get_emitted_logs().unwrap();
    for cause in ["retry-test", "read timeout test"] {
        assert!(
            logs.iter().any(
                |log| log.record.event_name() == Some("vm_runner.reap.failed")
                    && format!("{:?}", log.record).contains(cause)
            ),
            "missing reap failure {cause}"
        );
    }
    tasks.shutdown().await;
    Arc::try_unwrap(requests)
        .ok()
        .unwrap()
        .drain()
        .await
        .unwrap();
    assert!(exporter.get_finished_spans().unwrap().is_empty());
    fixture.tasks.shutdown().await;
    logger.shutdown().unwrap();
    provider.shutdown().unwrap();
}

#[tokio::test]
async fn session_400_and_503_bodies_match_the_openapi_declarations() {
    let mut fixture = Fixture::new().await;
    let token = fixture.token(&fixture.claims(), "ec");
    let (endpoint, requests) = app(fixture.config).await.unwrap();
    let response = TestClient::new(endpoint)
        .post("/v1/sessions")
        .header("Authorization", format!("Bearer {token}"))
        .body_json(&json!({"profile":"travel"}))
        .send()
        .await;
    response.assert_status(StatusCode::SERVICE_UNAVAILABLE);
    response.assert_text("jails are not configured").await;
    let spec: Value = serde_yaml_ng::from_str(&openapi()).unwrap();
    let responses = &spec["paths"]["/v1/sessions"]["post"]["responses"];
    assert_eq!(
        responses["503"]["content"]["text/plain; charset=utf-8"]["schema"]["type"],
        "string"
    );
    assert_eq!(
        responses["400"]["content"]["application/json; charset=utf-8"]["schema"]["$ref"],
        "#/components/schemas/NotExecuted"
    );
    assert!(
        spec["components"]["schemas"]["Failure"]["enum"]
            .as_array()
            .unwrap()
            .contains(&json!("bad_name"))
    );
    requests.drain().await.unwrap();
    fixture.tasks.shutdown().await;
}

#[test]
fn idle_and_max_below_sixty_are_reported_with_other_conflicts() {
    for (idle, max, invalid) in [
        (0, 1800, true),
        (59, 1800, true),
        (60, 60, false),
        (0, 0, true),
        (60, 59, true),
    ] {
        let mut config: Config =
            serde_yaml_ng::from_str(include_str!("../../examples/vm-runner.yaml")).unwrap();
        let profile = &mut config.profiles.0[0].1;
        profile.idle_seconds = idle;
        profile.max_seconds = max;
        profile.shape = "missing".into();
        profile.egress.allow.clear();
        let conflicts = config.conflicts();
        assert_eq!(
            conflicts.contains(&config::Conflict::Lifetime("travel".into())),
            invalid
        );
        assert!(conflicts.contains(&config::Conflict::Shape("travel".into())));
        assert!(conflicts.contains(&config::Conflict::EmptyAllow("travel".into())));
    }
}
