use super::*;
use poem::{
    EndpointExt,
    test::{TestClient, TestResponse},
};

type Client = TestClient<poem::endpoint::BoxEndpoint<'static, poem::Response>>;
struct Fixture {
    client: Arc<Client>,
    auth: crate::tests::Fixture,
    requests: crate::TracedRequests,
    state: Arc<State>,
    id: uuid::Uuid,
    sender: watch::Sender<Progress>,
}
impl Fixture {
    async fn new() -> Self {
        let auth = crate::tests::Fixture::new().await;
        let mut claims = auth.claims();
        claims["sub"] = json!(CONTROLLER);
        claims["aud"] = json!(["vm-runner-jail"]);
        let token = auth.token(&claims, "ec");
        let (endpoint, requests, state) = endpoint(
            auth.config.auth.clone(),
            CONTROLLER.into(),
            Arc::new(Guest::new("/absent.sock".into())),
        )
        .await
        .unwrap();
        let id = uuid::Uuid::now_v7();
        let (sender, progress) = watch::channel(Progress::Running);
        state
            .jobs
            .lock()
            .unwrap()
            .entries
            .push_back(Job { id, progress });
        Self {
            client: Arc::new(
                TestClient::new(endpoint.boxed())
                    .default_header("Authorization", format!("Bearer {token}")),
            ),
            auth,
            requests,
            state,
            id,
            sender,
        }
    }
    fn read(&self, wait_ms: u32) -> tokio::task::JoinHandle<TestResponse> {
        let client = Arc::clone(&self.client);
        let id = self.id;
        tokio::spawn(async move {
            client
                .get(format!("/jobs/{id}?waitMs={wait_ms}"))
                .send()
                .await
        })
    }
    async fn waiting(&self) {
        let started = std::time::Instant::now();
        while self.sender.receiver_count() < 2 {
            assert!(
                started.elapsed() < Duration::from_secs(5),
                "read did not reach watch progress"
            );
            tokio::task::yield_now().await;
        }
    }
    async fn close(mut self) {
        self.requests.drain().await.unwrap();
        self.state.drain().await.unwrap();
        self.auth.tasks.shutdown().await;
    }
}
fn completed() -> Progress {
    Progress::Done(Arc::new(Terminal::Executed(Executed {
        exit_code: 7,
        stdout: "result".into(),
        stderr: "err".into(),
        truncated: false,
    })))
}

#[tokio::test]
async fn a_waiting_read_returns_the_terminal_result_well_before_the_bound() {
    let f = Fixture::new().await;
    let started = std::time::Instant::now();
    let read = f.read(25000);
    f.waiting().await;
    f.sender.send_replace(completed());
    let response = tokio::time::timeout(Duration::from_secs(1), read)
        .await
        .unwrap()
        .unwrap();
    response.assert_status_is_ok();
    response.assert_json(json!({"outcome":"executed","exitCode":7,"stdout":"result","stderr":"err","truncated":false})).await;
    assert!(started.elapsed() < Duration::from_secs(1));
    f.close().await;
}

#[tokio::test]
async fn a_still_running_read_returns_running_at_the_bound() {
    let f = Fixture::new().await;
    tokio::time::pause();
    let read = f.read(1000);
    f.waiting().await;
    tokio::time::advance(Duration::from_millis(899)).await;
    assert!(!read.is_finished());
    tokio::time::advance(Duration::from_millis(1)).await;
    tokio::time::resume();
    let response = read.await.unwrap();
    response.assert_status_is_ok();
    response.assert_json(json!({"state":"running"})).await;
    f.close().await;
}

#[tokio::test]
async fn a_read_without_a_wait_is_unchanged() {
    let f = Fixture::new().await;
    for path in [
        format!("/jobs/{}", f.id),
        format!("/jobs/{}?waitMs=0", f.id),
    ] {
        tokio::time::timeout(Duration::from_secs(1), f.client.get(path).send())
            .await
            .unwrap()
            .assert_json(json!({"state":"running"}))
            .await;
    }
    f.close().await;
}

#[tokio::test]
async fn terminal_unknown_and_missing_jobs_do_not_wait() {
    let f = Fixture::new().await;
    f.sender.send_replace(completed());
    tokio::time::timeout(Duration::from_secs(1), f.read(25000))
        .await
        .unwrap()
        .unwrap()
        .assert_status_is_ok();
    f.sender.send_replace(Progress::Unknown);
    let response = tokio::time::timeout(Duration::from_secs(1), f.read(25000))
        .await
        .unwrap()
        .unwrap();
    response.assert_status(StatusCode::ACCEPTED);
    response
        .assert_json(json!({"outcome":"unknown","jobId":f.id.to_string()}))
        .await;
    tokio::time::timeout(
        Duration::from_secs(1),
        f.client
            .get(format!("/jobs/{}?waitMs=25000", uuid::Uuid::now_v7()))
            .send(),
    )
    .await
    .unwrap()
    .assert_status(StatusCode::NOT_FOUND);
    f.close().await;
}

#[tokio::test]
async fn a_closed_progress_channel_returns_unknown_without_waiting() {
    let mut f = Fixture::new().await;
    let sender = std::mem::replace(&mut f.sender, watch::channel(Progress::Running).0);
    drop(sender);
    tokio::time::timeout(Duration::from_secs(1), f.read(25000))
        .await
        .unwrap()
        .unwrap()
        .assert_status(StatusCode::ACCEPTED);
    f.close().await;
}

#[tokio::test]
async fn jail_waits_fail_fast_at_capacity_and_reject_invalid_bounds() {
    let f = Fixture::new().await;
    let busy = f.requests.admission[1].acquire_many(16).await.unwrap();
    for value in ["25001", "-1", "4294967296", "no", ""] {
        tokio::time::timeout(
            Duration::from_secs(1),
            f.client
                .get(format!("/jobs/{}?waitMs={value}", f.id))
                .send(),
        )
        .await
        .unwrap()
        .assert_status(StatusCode::BAD_REQUEST);
    }
    tokio::time::timeout(Duration::from_secs(1), f.read(25000))
        .await
        .unwrap()
        .unwrap()
        .assert_status(StatusCode::SERVICE_UNAVAILABLE);
    drop(busy);
    f.close().await;
}

#[tokio::test]
async fn cancelled_waits_remain_owned_until_the_request_drain_finishes() {
    let mut f = Fixture::new().await;
    tokio::time::pause();
    let read = f.read(1000);
    f.waiting().await;
    read.abort();
    assert!(matches!(read.await, Err(error) if error.is_cancelled()));
    let drain = tokio::spawn(f.requests.drain());
    tokio::task::yield_now().await;
    assert!(!drain.is_finished());
    tokio::time::advance(Duration::from_secs(1)).await;
    tokio::time::resume();
    tokio::time::timeout(Duration::from_secs(1), drain)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    f.auth.tasks.shutdown().await;
}

#[tokio::test]
async fn jail_authentication_and_setup_consume_the_forwarded_wait_budget() {
    let mut f = Fixture::new().await;
    let blocked = Arc::clone(&f.auth.gate).acquire_owned().await.unwrap();
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(601)).await;
    let started = tokio::time::Instant::now();
    let read = f.read(25000);
    (&mut f.auth.refresh_started).await.unwrap();
    tokio::time::advance(Duration::from_secs(6)).await;
    drop(blocked);
    f.waiting().await;
    tokio::time::advance(Duration::from_millis(18900)).await;
    tokio::time::resume();
    read.await
        .unwrap()
        .assert_json(json!({"state":"running"}))
        .await;
    assert!(started.elapsed() >= Duration::from_millis(24900));
    assert!(started.elapsed() < Duration::from_secs(25));
    f.close().await;
}

#[tokio::test]
async fn a_controller_and_jail_wait_read_returns_the_fake_guests_terminal_result() {
    let mut auth = crate::tests::Fixture::new().await;
    let mut claims = auth.claims();
    let controller_subject = "system:serviceaccount:runner:controller";
    claims["sub"] = json!(controller_subject);
    claims["aud"] = json!(["vm-runner-jail"]);
    let token = auth.token(&claims, "ec");
    let dir = tempfile::tempdir().unwrap();
    let listener = tokio::net::UnixListener::bind(dir.path().join("guest.sock")).unwrap();
    let (endpoint, requests, state) = endpoint(
        auth.config.auth.clone(),
        controller_subject.into(),
        Arc::new(Guest::new(dir.path().join("guest.sock"))),
    )
    .await
    .unwrap();
    state.mark_ready();
    let mut f = crate::controller::proxy::tests::Fixture::with_jail(
        endpoint.boxed(),
        token,
        auth.config.auth.clone(),
    )
    .await;
    let controller = f.api_endpoint(&auth).await;
    let listener_controller = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener_controller.local_addr().unwrap());
    f.tasks.spawn(async move {
        poem::Server::new_with_acceptor(
            poem::listener::TcpAcceptor::from_tokio(listener_controller).unwrap(),
        )
        .run(controller)
        .await
        .unwrap();
    });
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap();
    let token = auth.token(&auth.claims(), "ec");
    let peer = tokio::spawn(async move {
        let (mut stream, frame) = request(listener.accept().await.unwrap().0).await;
        assert_eq!(frame["argv"], json!(["echo", "ok"]));
        assert_eq!(frame["deadlineMs"], 600000);
        tokio::time::sleep(Duration::from_secs(2)).await;
        guest::write_frame(&mut stream, &json!({"outcome":"executed","exitCode":7,"stdout":"smoke result","stderr":"","truncated":false})).await.unwrap();
    });
    let id = f.session();
    let pending = client
        .post(format!("{base}/v1/sessions/{id}/exec"))
        .bearer_auth(&token)
        .json(&json!({"argv":["echo","ok"],"deadlineMs":1000}))
        .send()
        .await
        .unwrap();
    assert_eq!(pending.status(), StatusCode::ACCEPTED);
    let pending: serde_json::Value = pending.json().await.unwrap();
    let started = std::time::Instant::now();
    let response = client
        .get(format!(
            "{base}/v1/jobs/{}?waitMs=20000",
            pending["jobId"].as_str().unwrap()
        ))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    let elapsed = started.elapsed();
    assert_eq!(response.status(), StatusCode::OK);
    let terminal: serde_json::Value = response.json().await.unwrap();
    assert_eq!(
        terminal,
        json!({"outcome":"executed","exitCode":7,"stdout":"smoke result","stderr":"","truncated":false})
    );
    assert!(elapsed < Duration::from_secs(20));
    println!(
        "job-wait smoke: exec=202 waitMs=20000 elapsedMs={} result={terminal}",
        elapsed.as_millis()
    );
    peer.await.unwrap();
    requests.drain().await.unwrap();
    state.drain().await.unwrap();
    f.tasks.shutdown().await;
    auth.tasks.shutdown().await;
}
