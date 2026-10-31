use super::*;
use poem::{http::StatusCode, test::TestClient};

#[tokio::test]
async fn another_subjects_job_is_not_found_with_or_without_a_wait() {
    let mut f = Fixture::new().await;
    let id = f.session();
    let ExecResponse::Pending(Json(pending)) =
        f.controller.exec(SUBJECT, &id, &exec()).await.unwrap()
    else {
        panic!("pending")
    };
    let mut auth = crate::tests::Fixture::new().await;
    let other = "system:serviceaccount:dekopon:other";
    auth.config.auth.subjects.push(other.into());
    let mut claims = auth.claims();
    claims["sub"] = json!(other);
    let client = TestClient::new(f.api_endpoint(&auth).await).default_header(
        "Authorization",
        format!("Bearer {}", auth.token(&claims, "ec")),
    );
    for query in ["", "?waitMs=25000"] {
        tokio::time::timeout(
            Duration::from_secs(1),
            client
                .get(format!("/v1/jobs/{}{query}", pending.job_id))
                .send(),
        )
        .await
        .unwrap()
        .assert_status(StatusCode::NOT_FOUND);
    }
    assert!(f.job_waits.lock().unwrap().is_empty());
    f.tasks.shutdown().await;
    auth.tasks.shutdown().await;
}

#[tokio::test]
async fn an_out_of_range_wait_is_refused_without_waiting() {
    let mut f = Fixture::new().await;
    let mut auth = crate::tests::Fixture::new().await;
    let token = auth.token(&auth.claims(), "ec");
    let client = TestClient::new(f.api_endpoint(&auth).await)
        .default_header("Authorization", format!("Bearer {token}"));
    let busy = f.controller.reads.acquire().await.unwrap();
    for value in ["25001", "-1", "4294967296", "no", ""] {
        tokio::time::timeout(
            Duration::from_secs(1),
            client.get(format!("/v1/jobs/absent?waitMs={value}")).send(),
        )
        .await
        .unwrap()
        .assert_status(StatusCode::BAD_REQUEST);
    }
    assert!(f.job_waits.lock().unwrap().is_empty());
    drop(busy);
    f.tasks.shutdown().await;
    auth.tasks.shutdown().await;
}

#[tokio::test]
async fn positive_waits_are_refused_when_read_admission_is_full() {
    let mut f = Fixture::new().await;
    let mut auth = crate::tests::Fixture::new().await;
    let client = TestClient::new(f.api_endpoint(&auth).await);
    let busy = f.controller.reads.acquire().await.unwrap();
    tokio::time::timeout(
        Duration::from_secs(1),
        client.get("/v1/jobs/absent?waitMs=25000").send(),
    )
    .await
    .unwrap()
    .assert_status(StatusCode::SERVICE_UNAVAILABLE);
    drop(busy);
    f.tasks.shutdown().await;
    auth.tasks.shutdown().await;
}

#[tokio::test]
async fn an_older_jail_can_return_running_without_honoring_the_wait() {
    let mut f = Fixture::new().await;
    let id = f.session();
    let ExecResponse::Pending(Json(pending)) =
        f.controller.exec(SUBJECT, &id, &exec()).await.unwrap()
    else {
        panic!("pending")
    };
    let mut auth = crate::tests::Fixture::new().await;
    let client = TestClient::new(f.api_endpoint(&auth).await).default_header(
        "Authorization",
        format!("Bearer {}", auth.token(&auth.claims(), "ec")),
    );
    let started = std::time::Instant::now();
    client
        .get(format!("/v1/jobs/{}?waitMs=25000", pending.job_id))
        .send()
        .await
        .assert_json(json!({"state":"running"}))
        .await;
    assert!(started.elapsed() < Duration::from_secs(1));
    assert_eq!(*f.job_waits.lock().unwrap(), vec![Some(25000)]);
    f.tasks.shutdown().await;
    auth.tasks.shutdown().await;
}

#[tokio::test]
async fn a_delayed_pod_lookup_consumes_the_job_read_deadline() {
    let mut f = Fixture::new().await;
    let id = f.session();
    let ExecResponse::Pending(Json(pending)) =
        f.controller.exec(SUBJECT, &id, &exec()).await.unwrap()
    else {
        panic!("pending")
    };
    let mut auth = crate::tests::Fixture::new().await;
    let client = TestClient::new(f.api_endpoint(&auth).await).default_header(
        "Authorization",
        format!("Bearer {}", auth.token(&auth.claims(), "ec")),
    );
    f.pod_read_delay.store(6000, Ordering::SeqCst);
    f.wait_for_jobs.store(true, Ordering::SeqCst);
    let started = tokio::time::Instant::now();
    let request = tokio::spawn(async move {
        client
            .get(format!("/v1/jobs/{}?waitMs=25000", pending.job_id))
            .send()
            .await
    });
    f.pod_read_started.notified().await;
    tokio::time::pause();
    tokio::time::advance(Duration::from_millis(6001)).await;
    let probe = std::time::Instant::now();
    loop {
        assert!(
            probe.elapsed() < Duration::from_secs(5),
            "jail not reached after advancing lookup"
        );
        let recorded = !f.job_waits.lock().unwrap().is_empty();
        if recorded {
            break;
        }
        assert!(
            !request.is_finished(),
            "job read ended before reaching jail"
        );
        tokio::task::yield_now().await;
    }
    tokio::time::advance(Duration::from_secs(22)).await;
    tokio::time::resume();
    let response = request.await.unwrap();
    response.assert_status_is_ok();
    response.assert_json(json!({"state":"running"})).await;
    assert!(started.elapsed() < Duration::from_secs(29));
    let waits = f.job_waits.lock().unwrap().clone();
    assert_eq!(waits.len(), 1);
    assert!(waits[0].unwrap() <= 22000);
    assert!(waits[0].unwrap() > 21000);
    f.tasks.shutdown().await;
    auth.tasks.shutdown().await;
}

#[tokio::test]
async fn a_job_read_deadline_also_bounds_response_consumption() {
    let mut f = Fixture::new().await;
    let id = f.session();
    let ExecResponse::Pending(Json(pending)) =
        f.controller.exec(SUBJECT, &id, &exec()).await.unwrap()
    else {
        panic!("pending")
    };
    let mut auth = crate::tests::Fixture::new().await;
    let client = TestClient::new(f.api_endpoint(&auth).await).default_header(
        "Authorization",
        format!("Bearer {}", auth.token(&auth.claims(), "ec")),
    );
    f.stall_job_body.store(true, Ordering::SeqCst);
    tokio::time::pause();
    let started = tokio::time::Instant::now();
    let request = tokio::spawn(async move {
        client
            .get(format!("/v1/jobs/{}?waitMs=25000", pending.job_id))
            .send()
            .await
    });
    loop {
        let recorded = !f.job_waits.lock().unwrap().is_empty();
        if recorded {
            break;
        }
        assert!(
            !request.is_finished(),
            "job read ended before reaching jail"
        );
        tokio::task::yield_now().await;
    }
    tokio::time::advance(Duration::from_secs(29)).await;
    tokio::time::resume();
    let response = request.await.unwrap();
    assert!(matches!(
        response.0.status(),
        StatusCode::REQUEST_TIMEOUT | StatusCode::BAD_GATEWAY
    ));
    assert!(started.elapsed() < Duration::from_secs(30));
    assert!(f.controller.reads.try_acquire().is_ok());
    f.tasks.shutdown().await;
    auth.tasks.shutdown().await;
}
