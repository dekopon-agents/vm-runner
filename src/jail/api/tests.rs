use super::*;
use futures_util::FutureExt as _;
mod wait;
use crate::jail::client::Error as GuestError;
use serde_json::json;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

const CONTROLLER: &str = "system:serviceaccount:test:controller";

pub(super) struct ProgressReadHook {
    pub(super) waiting: tokio::sync::oneshot::Sender<()>,
    pub(super) observed: tokio::sync::oneshot::Sender<()>,
    pub(super) resume: tokio::sync::oneshot::Receiver<()>,
}

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

async fn ready_guest(
    guest: &Guest,
    listener: &tokio::net::UnixListener,
    probe_reply: serde_json::Value,
) -> Result<(), GuestError> {
    let peer = async {
        let exchanges = [
            (json!({"op":"ping"}), json!({"ok":true})),
            (
                json!({"op":"exec","argv":["/bin/true"],"deadlineMs":1_200_000,"stdin":null,"env":null,"cwd":null}),
                probe_reply,
            ),
        ];
        for (expected, reply) in exchanges {
            let (mut stream, value) = request(listener.accept().await.unwrap().0).await;
            assert_eq!(value, expected);
            guest::write_frame(&mut stream, &reply).await.unwrap();
        }
    };
    let (ready, ()) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(guest.ready(), peer)
    })
    .await
    .expect("guest must complete ping and the exec deadline probe");
    ready
}

#[tokio::test]
async fn boot_ready_logs_the_guest_exec_ceiling_selected_by_the_probe() {
    use opentelemetry::logs::AnyValue;
    use opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge;
    use opentelemetry_sdk::logs::{InMemoryLogExporter, SdkLoggerProvider};
    use tracing_subscriber::layer::SubscriberExt;

    let exporter = InMemoryLogExporter::default();
    let provider = SdkLoggerProvider::builder()
        .with_simple_exporter(exporter.clone())
        .build();
    let dispatch = tracing::Dispatch::new(
        tracing_subscriber::registry().with(OpenTelemetryTracingBridge::new(&provider)),
    );

    for reply in [
        json!({"outcome":"executed","exitCode":0}),
        json!({"outcome":"not_executed","reason":"invalid_exec"}),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("guest.sock");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let guest = Guest::new(path);
        ready_guest(&guest, &listener, reply).await.unwrap();
        tracing::dispatcher::with_default(&dispatch, || super::super::log_jail_ready(&guest, None));
    }
    let logs = exporter.get_emitted_logs().unwrap();
    let deadlines: Vec<_> = logs
        .iter()
        .filter(|log| log.record.event_name() == Some("vm_runner.boot.ready"))
        .map(|log| {
            log.record
                .attributes_iter()
                .find(|(key, _)| key.as_str() == "vm_runner.guest.exec_deadline_ms")
                .map(|(_, value)| value)
        })
        .collect();
    assert_eq!(
        deadlines,
        [
            Some(&AnyValue::Int(1_200_000)),
            Some(&AnyValue::Int(600_000))
        ]
    );
    provider.shutdown().unwrap();
}

#[tokio::test]
async fn unexpected_exec_deadline_probe_replies_fail_readiness_and_keep_the_legacy_ceiling() {
    for reply in [
        json!({"outcome":"not_executed","reason":"spawn_failed"}),
        json!({"outcome":"executed","exitCode":1}),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("guest.sock");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let guest = Guest::new(path);
        let result = ready_guest(&guest, &listener, reply.clone()).await;
        assert!(
            matches!(result, Err(GuestError::ExecDeadlineProbe)),
            "{reply}: {result:?}"
        );
        assert_eq!(guest.exec_deadline_ms(), 600_000, "{reply}");
    }
}

#[tokio::test]
async fn healthz_returns_503_until_the_guest_is_ready() {
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
    ready_guest(
        &guest,
        &listener,
        json!({"outcome":"executed","exitCode":0}),
    )
    .await
    .unwrap();
    state.mark_ready();
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
    assert_exec_delivered_once(1_200_000, json!({"outcome":"executed","exitCode":0})).await;
}

#[tokio::test]
async fn the_jail_sends_the_first_job_to_an_older_guest_once_at_its_supported_deadline() {
    assert_exec_delivered_once(
        600_000,
        json!({"outcome":"not_executed","reason":"invalid_exec"}),
    )
    .await;
}

async fn assert_exec_delivered_once(deadline_ms: u32, probe_reply: serde_json::Value) {
    let fixture = crate::tests::Fixture::new().await;
    let wrong_audience = fixture.token(&fixture.claims(), "ec");
    let mut claims = fixture.claims();
    claims["aud"] = json!(["vm-runner-jail"]);
    claims["sub"] = json!(CONTROLLER);
    let token = fixture.token(&claims, "ec");
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("guest.sock");
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let guest = Arc::new(Guest::new(path));
    ready_guest(&guest, &listener, probe_reply).await.unwrap();
    let (started, receive_started) = tokio::sync::oneshot::channel();
    let (release, released) = tokio::sync::oneshot::channel();
    let peer = tokio::spawn(async move {
        let (mut stream, frame) = request(listener.accept().await.unwrap().0).await;
        assert_eq!(frame["argv"], json!(["echo", "ok"]));
        assert_eq!(frame["deadlineMs"], deadline_ms);
        started.send(()).unwrap();
        released.await.unwrap();
        guest::write_frame(&mut stream, &json!({"outcome":"executed","exitCode":0,"stdout":"ok","stderr":"","truncated":false,"durationMs":1})).await.unwrap();
        listener
    });
    let (endpoint, requests, state) = endpoint(fixture.config.auth, CONTROLLER.into(), guest)
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
    tokio::time::advance(Duration::from_millis(u64::from(deadline_ms) - 1000)).await;
    let path = format!("/jobs/{}", pending["jobId"].as_str().unwrap());
    client
        .get(&path)
        .header("Authorization", &auth)
        .send()
        .await
        .assert_json(json!({"state":"running"}))
        .await;
    release.send(()).unwrap();
    let listener = peer.await.unwrap();
    state.drain().await.unwrap();
    assert!(listener.accept().now_or_never().is_none());
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
async fn shutdown_reports_submitted_exec_as_unknown_and_refuses_new_exec() {
    let mut fixture = crate::tests::Fixture::new().await;
    let mut claims = fixture.claims();
    claims["aud"] = json!(["vm-runner-jail"]);
    claims["sub"] = json!(CONTROLLER);
    let token = fixture.token(&claims, "ec");
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("guest.sock");
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let guest = Arc::new(Guest::new(path));
    let (endpoint, requests, state) =
        endpoint(fixture.config.auth.clone(), CONTROLLER.into(), guest)
            .await
            .unwrap();
    let client = poem::test::TestClient::new(endpoint)
        .default_header("Authorization", format!("Bearer {token}"));
    let input = json!({"argv":["echo","ok"],"deadlineMs":25_000});
    let post = client.post("/exec").body_json(&input).send();
    let shutdown = async {
        let (mut stream, frame) = request(listener.accept().await.unwrap().0).await;
        assert_eq!(frame["op"], "exec");
        assert_eq!(frame["argv"], input["argv"]);
        state.stop().unwrap();
        assert_eq!(stream.read(&mut [0]).await.unwrap(), 0);
    };
    let (response, ()) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(post, shutdown)
    })
    .await
    .expect("shutdown must end the wait before the response deadline");
    response.assert_status(StatusCode::ACCEPTED);
    let pending: serde_json::Value = response.0.into_body().into_json().await.unwrap();
    assert_eq!(pending["outcome"], "unknown");
    assert!(uuid::Uuid::parse_str(pending["jobId"].as_str().unwrap()).is_ok());

    client
        .post("/exec")
        .body_json(&input)
        .send()
        .await
        .assert_status(StatusCode::SERVICE_UNAVAILABLE);
    state.drain().await.unwrap();
    assert!(listener.accept().now_or_never().is_none());
    requests.drain().await.unwrap();
    fixture.tasks.shutdown().await;
}

#[tokio::test]
async fn session_shutdown_drops_the_job_and_reaps_its_guest_process_without_resending() {
    use nix::{errno::Errno, sys::signal::kill, unistd::Pid};

    let mut auth = crate::tests::Fixture::new().await;
    let mut claims = auth.claims();
    claims["aud"] = json!(["vm-runner-jail"]);
    claims["sub"] = json!(CONTROLLER);
    let token = auth.token(&claims, "ec");
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("guest.sock");
    let marker = dir.path().join("pid");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let guest = Arc::new(Guest::new(socket));
    ready_guest(
        &guest,
        &listener,
        json!({"outcome":"executed","exitCode":0}),
    )
    .await
    .unwrap();
    let (endpoint, requests, state) = endpoint(auth.config.auth.clone(), CONTROLLER.into(), guest)
        .await
        .unwrap();
    let client = poem::test::TestClient::new(endpoint)
        .default_header("Authorization", format!("Bearer {token}"));
    let argv = json!([
        "/bin/sh",
        "-c",
        r#"printf '%s' "$$" > "$1"; exec sleep 20"#,
        "job",
        marker
    ]);
    let peer = async {
        let (mut relay, frame) = request(listener.accept().await.unwrap().0).await;
        assert_eq!(
            frame,
            json!({"op":"exec","argv":argv,"deadlineMs":1_200_000,"stdin":null,"env":null,"cwd":null})
        );
        let (mut forward, stream) = tokio::io::duplex(4096);
        guest::write_frame(&mut forward, &frame).await.unwrap();
        let (handled, transferred) = tokio::join!(
            guest::tests::serve_one(stream),
            tokio::io::copy_bidirectional(&mut relay, &mut forward)
        );
        handled.unwrap();
        assert_eq!(transferred.unwrap(), (0, 0));
    };
    let shutdown = async {
        let response = client
            .post("/exec")
            .body_json(&json!({"argv":argv,"deadlineMs":0}))
            .send()
            .await;
        response.assert_status(StatusCode::ACCEPTED);
        let pending: serde_json::Value = response.0.into_body().into_json().await.unwrap();
        let path = format!("/jobs/{}", pending["jobId"].as_str().unwrap());
        let pid = loop {
            if let Ok(text) = tokio::fs::read_to_string(&marker).await
                && let Ok(pid) = text.parse()
            {
                break Pid::from_raw(pid);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        };
        assert_eq!(kill(pid, None), Ok(()));
        client
            .get(&path)
            .send()
            .await
            .assert_json(json!({"state":"running"}))
            .await;

        state.stop().unwrap();
        state.drain().await.unwrap();
        assert!(state.jobs.lock().unwrap().entries.is_empty());
        client
            .get(path)
            .send()
            .await
            .assert_status(StatusCode::NOT_FOUND);
        pid
    };
    let ((), pid) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(peer, shutdown)
    })
    .await
    .expect("retirement should close the exchange and reap the child promptly");
    assert_eq!(kill(pid, None), Err(Errno::ESRCH));
    assert!(listener.accept().now_or_never().is_none());
    requests.drain().await.unwrap();
    auth.tasks.shutdown().await;
}

#[tokio::test]
#[ignore = "requires Chromium and a browse executable named by VM_RUNNER_BROWSE_SMOKE"]
async fn the_jail_api_keeps_named_browser_pages_independent_until_session_delete() {
    let mut auth = crate::tests::Fixture::new().await;
    let subject = "system:serviceaccount:runner:controller";
    let mut claims = auth.claims();
    claims["aud"] = json!(["vm-runner-jail"]);
    claims["sub"] = json!(subject);
    let token = auth.token(&claims, "ec");
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("guest.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let (jail, requests, state) = endpoint(
        auth.config.auth.clone(),
        subject.into(),
        Arc::new(Guest::new(socket)),
    )
    .await
    .unwrap();
    state.mark_ready();
    let upstream = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let seen = Arc::clone(&upstream);
    let jail = jail.before(move |req| {
        if req.method() == poem::http::Method::POST {
            assert_eq!(req.uri().to_string(), "/exec");
            assert!(req.header("x-dekopon-vm-subject").is_none());
            assert!(req.header("x-dekopon-vm-session").is_none());
            seen.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        async { Ok(req) }
    });
    let mut fixture = crate::controller::proxy::tests::Fixture::with_jail(
        jail.boxed(),
        token,
        auth.config.auth.clone(),
    )
    .await;
    let client = poem::test::TestClient::new(fixture.api_endpoint(&auth).await).default_header(
        "Authorization",
        format!("Bearer {}", auth.token(&auth.claims(), "ec")),
    );
    let session = format!("/v1/sessions/{}", fixture.session());
    let browse = std::env::var("VM_RUNNER_BROWSE_SMOKE").unwrap();
    let profile = format!("BROWSE_PROFILE={}/profile", dir.path().display());
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = format!("BROWSE_PORT={}", port.local_addr().unwrap().port());
    drop(port);
    let pages = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", pages.local_addr().unwrap());
    fixture.tasks.spawn(async move {
        poem::Server::new_with_acceptor(poem::listener::TcpAcceptor::from_tokio(pages).unwrap())
            .run(poem::endpoint::make_sync(|req| {
                let heading = match req.uri().path() {
                    "/research-1" => "Research one",
                    "/research-2" => "Research two",
                    "/booking-1" => "Booking one",
                    "/booking-2" => "Booking two",
                    _ => "",
                };
                poem::web::Html(format!("<h1>{heading}</h1>"))
            }))
            .await
            .unwrap();
    });
    let [research_one, research_two, booking_one, booking_two] =
        ["research-1", "research-2", "booking-1", "booking-2"].map(|page| format!("{base}/{page}"));
    let commands: &[(&[&str], Option<&str>)] = &[
        (&["--tab", "research", "open", &research_one], None),
        (&["--tab", "booking", "open", &booking_one], None),
        (&["--tab", "research", "open", &research_two], None),
        (&["--tab", "booking", "text", "h1"], Some("Booking one\n")),
        (&["--tab", "booking", "open", &booking_two], None),
        (&["--tab", "research", "text", "h1"], Some("Research two\n")),
        (&["reset"], Some("browser stopped and profile deleted\n")),
    ];
    let mut results = Vec::new();
    for (args, _) in commands {
        let argv: Vec<_> = ["/usr/bin/env", &profile, &address, &browse]
            .into_iter()
            .chain(args.iter().copied())
            .collect();
        let body = json!({"argv":argv,"deadlineMs":25000});
        let call = client
            .post(format!("{session}/exec"))
            .header("x-dekopon-vm-subject", "guest:forged")
            .body_json(&body)
            .send();
        let peer = async {
            let (mut relay, frame) = request(listener.accept().await.unwrap().0).await;
            assert_eq!(
                frame,
                json!({
                    "op":"exec","argv":argv,"deadlineMs":600_000,"stdin":null,"env":null,"cwd":null
                })
            );
            let (mut forward, stream) = tokio::io::duplex(4096);
            guest::write_frame(&mut forward, &frame).await.unwrap();
            let (handled, transferred) = tokio::join!(
                guest::tests::serve_one(stream),
                tokio::io::copy_bidirectional(&mut relay, &mut forward)
            );
            handled.unwrap();
            transferred.unwrap();
        };
        let (response, ()) =
            tokio::time::timeout(Duration::from_secs(30), async { tokio::join!(call, peer) })
                .await
                .unwrap();
        response.assert_status_is_ok();
        results.push(
            response
                .0
                .into_body()
                .into_json::<serde_json::Value>()
                .await
                .unwrap(),
        );
    }

    for (result, (_, expected)) in results.iter().zip(commands) {
        assert_eq!(result["exitCode"], 0, "{result}");
        if let Some(expected) = expected {
            assert_eq!(result["stdout"], *expected);
        }
    }
    assert_eq!(
        upstream.load(std::sync::atomic::Ordering::Relaxed),
        commands.len()
    );
    assert!(listener.accept().now_or_never().is_none());
    client
        .delete(session)
        .send()
        .await
        .assert_status(StatusCode::NO_CONTENT);
    client
        .get("/v1/sessions")
        .send()
        .await
        .assert_json(json!([]))
        .await;
    requests.drain().await.unwrap();
    state.drain().await.unwrap();
    fixture.tasks.shutdown().await;
    auth.tasks.shutdown().await;
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
        stopping: watch::channel(false).0,
        transfers: Arc::new(tokio::sync::Semaphore::new(4)),
        progress_read_hook: Mutex::new(None),
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
