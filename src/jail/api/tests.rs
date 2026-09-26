use super::*;
use serde_json::json;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

#[tokio::test]
async fn jail_auth_deadline_job_and_later_result_use_one_guest_execution() {
    let fixture = crate::tests::Fixture::new().await;
    let wrong_audience = fixture.token(&fixture.claims(), "ec");
    let mut claims = fixture.claims();
    claims["aud"] = json!(["vm-runner-jail"]);
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
    let (endpoint, requests, state) = endpoint(fixture.config.auth, Arc::new(Guest::new(path)))
        .await
        .unwrap();
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
        jobs: Mutex::new(jobs),
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
