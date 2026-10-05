use super::*;
use serde_json::json;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

const CONTROLLER: &str = "system:serviceaccount:test:controller";

#[test]
fn guest_exec_fields_are_recorded_but_not_returned_to_controller() {
    use opentelemetry::trace::TracerProvider as _;
    use tracing_subscriber::prelude::*;
    for (frame, expected) in [
        (
            json!({"outcome":"executed","exitCode":0,"stdout":"ok","stderr":"","truncated":false}),
            None,
        ),
        (
            json!({"outcome":"executed","exitCode":0,"stdout":"ok","stderr":"","truncated":false,
            "durationMs":17,"timedOut":true,"cpuUs":43,"memoryPeakBytes":8192}),
            Some((43, 8192)),
        ),
    ] {
        let exporter = opentelemetry_sdk::trace::InMemorySpanExporter::default();
        let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let dispatch = tracing::Dispatch::new(
            tracing_subscriber::registry()
                .with(tracing_opentelemetry::layer().with_tracer(provider.tracer("guest-test"))),
        );
        tracing::dispatcher::with_default(&dispatch, || {
            let span = tracing::info_span!(
                "vm_runner.exec",
                vm_runner.exec.outcome = tracing::field::Empty,
                vm_runner.exec.truncated = tracing::field::Empty,
                vm_runner.guest.exit_code = tracing::field::Empty,
                vm_runner.guest.duration_ms = tracing::field::Empty,
                vm_runner.guest.timed_out = tracing::field::Empty,
                vm_runner.guest.cpu_us = tracing::field::Empty,
                vm_runner.guest.memory.peak.bytes = tracing::field::Empty
            );
            let _entered = span.enter();
            let GuestTerminal::Executed(value) = serde_json::from_value(frame).unwrap() else {
                panic!("executed")
            };
            let Terminal::Executed(response) = value.into_response() else {
                panic!("executed")
            };
            assert_eq!(
                (
                    response.exit_code,
                    response.stdout.as_str(),
                    response.stderr.as_str(),
                    response.truncated
                ),
                (0, "ok", "", false)
            );
        });
        provider.force_flush().unwrap();
        let spans = exporter.get_finished_spans().unwrap();
        let attrs = &spans[0].attributes;
        let field = |key: &str| {
            attrs
                .iter()
                .find(|a| a.key.as_str() == key)
                .map(|a| a.value.to_string())
        };
        assert_eq!(
            field("vm_runner.exec.outcome").as_deref(),
            Some("completed")
        );
        assert_eq!(
            field("vm_runner.guest.cpu_us"),
            expected.map(|(cpu, _)| cpu.to_string())
        );
        assert_eq!(
            field("vm_runner.guest.memory.peak.bytes"),
            expected.map(|(_, peak)| peak.to_string())
        );
        assert_eq!(
            field("vm_runner.guest.duration_ms").is_some(),
            expected.is_some()
        );
        assert_eq!(
            field("vm_runner.guest.timed_out").is_some(),
            expected.is_some()
        );
    }
}

#[tokio::test]
async fn jail_refuses_a_c4_valid_non_controller_token_as_unknown_subject() {
    let fixture = crate::tests::Fixture::new().await;
    let mut claims = fixture.claims();
    claims["aud"] = json!(["vm-runner", "vm-runner-jail"]);
    let token = format!("Bearer {}", fixture.token(&claims, "ec"));
    let c4 = Authenticator::new(fixture.config.auth.clone())
        .await
        .unwrap();
    assert_eq!(
        c4.verify(Some(&token)).await.unwrap(),
        claims["sub"].as_str().unwrap()
    );
    let dir = tempfile::tempdir().unwrap();
    let (endpoint, requests, state) = endpoint(
        fixture.config.auth,
        CONTROLLER.into(),
        Arc::new(Guest::new(dir.path().join("absent.sock"))),
    )
    .await
    .unwrap();
    let response = poem::test::TestClient::new(endpoint)
        .post("/exec")
        .header("Authorization", token)
        .body_json(&json!({"argv":["true"],"deadlineMs":25000}))
        .send()
        .await;
    response.assert_status(StatusCode::UNAUTHORIZED);
    response
        .assert_json(json!({"error":"unauthorized","reason":"unknown_subject"}))
        .await;
    assert!(state.jobs.lock().unwrap().entries.is_empty());
    requests.drain().await.unwrap();
}

async fn request(
    stream: tokio::net::UnixStream,
) -> (BufReader<tokio::net::UnixStream>, serde_json::Value) {
    let mut stream = BufReader::new(stream);
    let mut hello = String::new();
    stream.read_line(&mut hello).await.unwrap();
    assert_eq!(hello, "CONNECT 1024\n");
    stream.write_all(b"OK 1234\n").await.unwrap();
    let value = serde_json::from_slice(&guest::read_frame(&mut stream).await.unwrap()).unwrap();
    (stream, value)
}

#[tokio::test]
async fn healthz_returns_503_until_the_guest_answers_ping() {
    let fixture = crate::tests::Fixture::new().await;
    let mut claims = fixture.claims();
    claims["sub"] = json!(CONTROLLER);
    claims["aud"] = json!(["vm-runner-jail"]);
    let token = format!("Bearer {}", fixture.token(&claims, "ec"));
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("guest.sock");
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let guest = Arc::new(Guest::new(path));
    let (endpoint, requests, state) =
        endpoint(fixture.config.auth, CONTROLLER.into(), Arc::clone(&guest))
            .await
            .unwrap();
    let client = poem::test::TestClient::new(endpoint);
    let starting = client
        .get("/healthz")
        .header("Authorization", &token)
        .send()
        .await;
    starting.assert_status(StatusCode::SERVICE_UNAVAILABLE);
    starting.assert_text("starting").await;
    let peer = tokio::spawn(async move {
        let (mut stream, value) = request(listener.accept().await.unwrap().0).await;
        assert_eq!(value, json!({"op":"ping"}));
        guest::write_frame(&mut stream, &json!({"ok":true}))
            .await
            .unwrap();
    });
    guest.ready().await.unwrap();
    state.mark_ready();
    peer.await.unwrap();
    let ready = client
        .get("/healthz")
        .header("Authorization", &token)
        .send()
        .await;
    ready.assert_status_is_ok();
    ready.assert_text("ok").await;
    requests.drain().await.unwrap();
}

#[tokio::test]
async fn guest_streams_and_reason_are_capped_at_64_kib_with_truncated_in_exec_and_jobs() {
    let fixture = crate::tests::Fixture::new().await;
    let mut claims = fixture.claims();
    claims["sub"] = json!(CONTROLLER);
    claims["aud"] = json!(["vm-runner-jail"]);
    let token = format!("Bearer {}", fixture.token(&claims, "ec"));
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("guest.sock");
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let (endpoint, requests, state) = endpoint(
        fixture.config.auth,
        CONTROLLER.into(),
        Arc::new(Guest::new(path)),
    )
    .await
    .unwrap();
    let client = poem::test::TestClient::new(endpoint);
    let multibyte = format!("{}🦀", "x".repeat(65535));
    let cases = [
        (
            json!({"outcome":"executed","exitCode":0,"stdout":multibyte,"stderr":"s".repeat(65537),"truncated":false}),
            json!({"outcome":"executed","exitCode":0,"stdout":"x".repeat(65535),"stderr":"s".repeat(65536),"truncated":true}),
        ),
        (
            json!({"outcome":"not_executed","reason":multibyte}),
            json!({"outcome":"not_executed","reason":"x".repeat(65535),"truncated":true}),
        ),
    ];
    for (input, expected) in cases {
        let call = client
            .post("/exec")
            .header("Authorization", &token)
            .body_json(&json!({"argv":["true"],"deadlineMs":25000}))
            .send();
        let peer = async {
            let (mut stream, value) = request(listener.accept().await.unwrap().0).await;
            assert_eq!(value["op"], "exec");
            guest::write_frame(&mut stream, &input).await.unwrap();
        };
        let (response, ()) = tokio::join!(call, peer);
        response.assert_status_is_ok();
        response.assert_json(expected.clone()).await;
        state.drain().await.unwrap();
        let id = state.jobs.lock().unwrap().entries.back().unwrap().id;
        client
            .get(format!("/jobs/{id}"))
            .header("Authorization", &token)
            .send()
            .await
            .assert_json(expected)
            .await;
    }
    requests.drain().await.unwrap();
}

#[tokio::test]
async fn get_answers_while_all_exec_admission_capacity_is_saturated() {
    let fixture = crate::tests::Fixture::new().await;
    let mut claims = fixture.claims();
    claims["sub"] = json!(CONTROLLER);
    claims["aud"] = json!(["vm-runner-jail"]);
    let token = format!("Bearer {}", fixture.token(&claims, "ec"));
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("guest.sock");
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let (endpoint, requests, state) = endpoint(
        fixture.config.auth,
        CONTROLLER.into(),
        Arc::new(Guest::new(path)),
    )
    .await
    .unwrap();
    state.mark_ready();
    let client = Arc::new(poem::test::TestClient::new(endpoint));
    let mut posts = JoinSet::new();
    for _ in 0..16 {
        let client = Arc::clone(&client);
        let token = token.clone();
        posts.spawn(async move {
            client
                .post("/exec")
                .header("Authorization", token)
                .body_json(&json!({"argv":["true"],"deadlineMs":25000}))
                .send()
                .await
        });
    }
    let mut streams = Vec::new();
    for _ in 0..16 {
        let (stream, value) = request(listener.accept().await.unwrap().0).await;
        assert_eq!(value["op"], "exec");
        streams.push(stream);
    }
    let id = state.jobs.lock().unwrap().entries[0].id;
    tokio::select! {
        () = async {
            client.get("/healthz").header("Authorization", &token).send().await.assert_status_is_ok();
            client.get(format!("/jobs/{id}")).header("Authorization", &token).send().await.assert_json(json!({"state":"running"})).await;
        } => (),
        result = posts.join_next() => panic!("GET queued behind exec: {:?}", result.unwrap().unwrap().0.status()),
    }
    for mut stream in streams {
        guest::write_frame(
            &mut stream,
            &json!({"outcome":"executed","exitCode":0,"stdout":"","stderr":"","truncated":false}),
        )
        .await
        .unwrap();
    }
    while let Some(result) = posts.join_next().await {
        result.unwrap().assert_status_is_ok();
    }
    state.drain().await.unwrap();
    requests.drain().await.unwrap();
}

#[tokio::test]
async fn jail_auth_deadline_job_and_later_result_use_one_guest_execution() {
    let fixture = crate::tests::Fixture::new().await;
    let wrong_audience = fixture.token(&fixture.claims(), "ec");
    let mut claims = fixture.claims();
    claims["aud"] = json!(["vm-runner-jail"]);
    claims["sub"] = json!(CONTROLLER);
    let token = fixture.token(&claims, "ec");
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("guest.sock");
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let (started, receive_started) = tokio::sync::oneshot::channel();
    let (release, released) = tokio::sync::oneshot::channel();
    let peer = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut stream = BufReader::new(stream);
        let mut hello = String::new();
        stream.read_line(&mut hello).await.unwrap();
        assert_eq!(hello, "CONNECT 1024\n");
        stream.write_all(b"OK 1234\n").await.unwrap();
        let request: serde_json::Value =
            serde_json::from_slice(&guest::read_frame(&mut stream).await.unwrap()).unwrap();
        assert_eq!(request["argv"], json!(["echo", "ok"]));
        assert_eq!(request["deadlineMs"], 600_000);
        started.send(()).unwrap();
        released.await.unwrap();
        guest::write_frame(&mut stream, &json!({"outcome":"executed","exitCode":0,"stdout":"ok","stderr":"","truncated":false,"durationMs":1})).await.unwrap();
    });
    let (endpoint, requests, state) = endpoint(
        fixture.config.auth,
        CONTROLLER.into(),
        Arc::new(Guest::new(path)),
    )
    .await
    .unwrap();
    state.mark_ready();
    let client = Arc::new(poem::test::TestClient::new(endpoint));
    tokio::time::pause();
    client
        .get("/healthz")
        .send()
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
    client
        .post("/exec")
        .header("Authorization", format!("Bearer {wrong_audience}"))
        .body_json(&json!({"argv":["echo"],"deadlineMs":1}))
        .send()
        .await
        .assert_json(json!({"error":"unauthorized","reason":"audience"}))
        .await;
    client
        .get("/healthz")
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .assert_status_is_ok();
    let request_client = Arc::clone(&client);
    let auth = format!("Bearer {token}");
    let post_auth = auth.clone();
    let request = tokio::spawn(async move {
        request_client
            .post("/exec")
            .header("Authorization", post_auth)
            .body_json(&json!({"argv":["echo","ok"],"deadlineMs":25}))
            .send()
            .await
    });
    receive_started.await.unwrap();
    tokio::time::advance(Duration::from_secs(1)).await;
    let response = request.await.unwrap();
    response.assert_status(StatusCode::ACCEPTED);
    let pending: serde_json::Value = response.0.into_body().into_json().await.unwrap();
    assert_eq!(pending["outcome"], "unknown");
    let path = format!("/jobs/{}", pending["jobId"].as_str().unwrap());
    client
        .get(&path)
        .header("Authorization", &auth)
        .send()
        .await
        .assert_json(json!({"state":"running"}))
        .await;
    release.send(()).unwrap();
    peer.await.unwrap();
    state.drain().await.unwrap();
    client
        .get(&path)
        .header("Authorization", &auth)
        .send()
        .await
        .assert_json(
            json!({"outcome":"executed","exitCode":0,"stdout":"ok","stderr":"","truncated":false}),
        )
        .await;
    requests.drain().await.unwrap();
}

#[tokio::test]
async fn job_capacity_refuses_active_work_and_evicts_only_non_running_records() {
    let dir = tempfile::tempdir().unwrap();
    let mut jobs = Jobs::default();
    let mut senders = Vec::new();
    for _ in 0..JOB_CAP {
        let (sender, progress) = watch::channel(Progress::Running);
        senders.push(sender);
        jobs.entries.push_back(Job {
            id: uuid::Uuid::now_v7(),
            progress,
        });
    }
    let evicted = jobs.entries[0].id;
    let retained = jobs.entries[1].id;
    let state = State {
        guest: Arc::new(Guest::new(dir.path().join("absent.sock"))),
        ready: Arc::new(AtomicBool::new(false)),
        jobs: Mutex::new(jobs),
        transfers: Arc::new(tokio::sync::Semaphore::new(4)),
    };
    let input = || ExecInput {
        argv: vec!["true".into()],
        stdin: None,
        deadline_ms: 0,
    };
    assert!(state.submit(input()).unwrap().is_none());
    senders[0].send_replace(Progress::Unknown);
    let Job { id, progress } = state.submit(input()).unwrap().unwrap();
    state.drain().await.unwrap();
    assert!(matches!(*progress.borrow(), Progress::Unknown));
    let jobs = state.jobs.lock().unwrap();
    assert_eq!(jobs.entries.len(), JOB_CAP);
    assert!(!jobs.entries.iter().any(|job| job.id == evicted));
    assert!(jobs.entries.iter().any(|job| job.id == retained));
    assert!(jobs.entries.iter().any(|job| job.id == id));
}
