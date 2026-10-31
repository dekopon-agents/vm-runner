use super::*;
use poem::{http::StatusCode, test::TestClient};

#[tokio::test]
async fn another_subjects_job_is_not_found_with_or_without_a_wait_preference() {
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
    for preference in ["", "wait=25"] {
        tokio::time::timeout(
            Duration::from_secs(1),
            client
                .get(format!("/v1/jobs/{}", pending.job_id))
                .header("Prefer", preference)
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
async fn an_invalid_wait_preference_is_refused_without_waiting() {
    let mut f = Fixture::new().await;
    let mut auth = crate::tests::Fixture::new().await;
    let token = auth.token(&auth.claims(), "ec");
    let client = TestClient::new(f.api_endpoint(&auth).await)
        .default_header("Authorization", format!("Bearer {token}"));
    let busy = f.controller.waits.acquire().await.unwrap();
    for value in [
        "wait=26",
        "wait=0",
        "wait=-1",
        "wait=4294967296",
        "wait=no",
        "wait=",
        "wait",
        "wait=1.5",
        "wait=\"2\"",
    ] {
        tokio::time::timeout(
            Duration::from_secs(1),
            client.get("/v1/jobs/absent").header("Prefer", value).send(),
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
async fn wait_preferences_are_refused_when_wait_admission_is_full() {
    let mut f = Fixture::new().await;
    let mut auth = crate::tests::Fixture::new().await;
    let client = TestClient::new(f.api_endpoint(&auth).await);
    let busy = f.controller.waits.acquire().await.unwrap();
    tokio::time::timeout(
        Duration::from_secs(1),
        client
            .get("/v1/jobs/absent")
            .header("Prefer", "wait=25")
            .send(),
    )
    .await
    .unwrap()
    .assert_status(StatusCode::SERVICE_UNAVAILABLE);
    drop(busy);
    f.tasks.shutdown().await;
    auth.tasks.shutdown().await;
}

#[tokio::test]
async fn an_older_jail_does_not_claim_to_apply_a_wait_preference() {
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
    let response = client
        .get(format!("/v1/jobs/{}", pending.job_id))
        .header("Prefer", "wait=25")
        .send()
        .await;
    assert!(!response.0.headers().contains_key("Preference-Applied"));
    response.assert_json(json!({"state":"running"})).await;
    assert!(started.elapsed() < Duration::from_secs(1));
    assert_eq!(*f.job_waits.lock().unwrap(), vec![Some(25)]);
    f.tasks.shutdown().await;
    auth.tasks.shutdown().await;
}

#[tokio::test]
async fn a_delayed_pod_lookup_consumes_the_header_wait_deadline() {
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
            .get(format!("/v1/jobs/{}", pending.job_id))
            .header("Prefer", "wait=25")
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
    response.assert_header("Preference-Applied", "wait=25");
    response.assert_json(json!({"state":"running"})).await;
    assert!(started.elapsed() < Duration::from_secs(29));
    let waits = f.job_waits.lock().unwrap().clone();
    assert_eq!(waits.len(), 1);
    assert!(waits[0].unwrap() <= 22);
    assert!(waits[0].unwrap() >= 21);
    f.tasks.shutdown().await;
    auth.tasks.shutdown().await;
}

#[tokio::test]
async fn a_header_wait_deadline_also_bounds_response_consumption() {
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
            .get(format!("/v1/jobs/{}", pending.job_id))
            .header("Prefer", "wait=25")
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
    assert!(f.controller.waits.try_acquire().is_ok());
    f.tasks.shutdown().await;
    auth.tasks.shutdown().await;
}

#[tokio::test]
async fn unrelated_preferences_and_wait_ms_queries_leave_controller_reads_unchanged() {
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
    f.wait_for_jobs.store(true, Ordering::SeqCst);
    let mut baseline = None;
    for (query, preference) in [
        ("", None),
        ("", Some("return=minimal")),
        ("", Some("custom=\"café\"")),
        ("", Some("custom=\"x,wait=99\", respond-async")),
        ("?waitMs=25000", None),
        ("?waitMs=bad", None),
    ] {
        let mut request = client.get(format!("/v1/jobs/{}{query}", pending.job_id));
        if let Some(preference) = preference {
            request = request.header("Prefer", preference);
        }
        let response = tokio::time::timeout(Duration::from_secs(1), request.send())
            .await
            .unwrap();
        response.assert_status_is_ok();
        assert!(!response.0.headers().contains_key("Preference-Applied"));
        let bytes = response.0.into_body().into_vec().await.unwrap();
        if let Some(baseline) = &baseline {
            assert_eq!(&bytes, baseline);
        } else {
            baseline = Some(bytes);
        }
    }
    assert!(f.job_waits.lock().unwrap().iter().all(Option::is_none));
    f.tasks.shutdown().await;
    auth.tasks.shutdown().await;
}

#[tokio::test]
async fn quoted_opaque_preferences_do_not_reject_a_controller_wait() {
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
    f.wait_for_jobs.store(true, Ordering::SeqCst);
    for value in [
        "custom=\"café\", wait=1".as_bytes(),
        "wait=1; note=\"café\"".as_bytes(),
        b"custom=\"\xff\\\",wait=99\", wait=1, wait=26".as_slice(),
    ] {
        let response = client
            .get(format!("/v1/jobs/{}", pending.job_id))
            .header(
                "Prefer",
                poem::http::HeaderValue::from_bytes(value).unwrap(),
            )
            .send()
            .await;
        response.assert_status_is_ok();
        response.assert_header("Preference-Applied", "wait=1");
    }
    assert_eq!(
        *f.job_waits.lock().unwrap(),
        vec![Some(1), Some(1), Some(1)]
    );
    f.tasks.shutdown().await;
    auth.tasks.shutdown().await;
}

#[tokio::test]
async fn a_held_wait_leaves_polling_and_another_subjects_artifact_listing_available() {
    let mut f = Fixture::new().await;
    let session = f.session();
    let ExecResponse::Pending(Json(pending)) =
        f.controller.exec(SUBJECT, &session, &exec()).await.unwrap()
    else {
        panic!("pending")
    };
    let other = "system:serviceaccount:dekopon:other";
    let Created::New(Json(other_session)) = f
        .controller
        .create(
            other,
            Create {
                profile: "travel".into(),
                name: None,
            },
        )
        .unwrap()
    else {
        panic!("other session")
    };
    f.controller
        .exec(other, &other_session.session_id, &exec())
        .await
        .unwrap();
    let mut auth = crate::tests::Fixture::new().await;
    auth.config.auth.subjects.push(other.into());
    let owner_token = format!("Bearer {}", auth.token(&auth.claims(), "ec"));
    let mut other_claims = auth.claims();
    other_claims["sub"] = json!(other);
    let other_token = format!("Bearer {}", auth.token(&other_claims, "ec"));
    let client = Arc::new(TestClient::new(f.api_endpoint(&auth).await));
    f.wait_for_jobs.store(true, Ordering::SeqCst);
    let (release, held) = tokio::sync::oneshot::channel();
    *f.job_read_hold.lock().unwrap() = Some(held);
    let reader = Arc::clone(&client);
    let wait_token = owner_token.clone();
    let job_path = format!("/v1/jobs/{}", pending.job_id);
    let wait_path = job_path.clone();
    let waiting = tokio::spawn(async move {
        reader
            .get(wait_path)
            .header("Authorization", wait_token)
            .header("Prefer", "wait=8")
            .send()
            .await
    });
    let started = std::time::Instant::now();
    while f.job_waits.lock().unwrap().is_empty() {
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "wait did not reach jail"
        );
        tokio::task::yield_now().await;
    }
    let expected: Value = serde_json::from_str(&f.artifact_list.lock().unwrap()).unwrap();
    let immediate = tokio::time::timeout(Duration::from_secs(1), async {
        let (job, listing) = tokio::join!(
            client
                .get(&job_path)
                .header("Authorization", owner_token)
                .send(),
            client
                .get(format!(
                    "/v1/sessions/{}/artifacts",
                    other_session.session_id
                ))
                .header("Authorization", other_token)
                .send()
        );
        job.assert_status_is_ok();
        job.assert_json(json!({"state":"running"})).await;
        listing.assert_status_is_ok();
        listing.assert_json(expected).await;
    })
    .await;
    let still_waiting = !waiting.is_finished();
    release.send(()).unwrap();
    waiting.await.unwrap().assert_status_is_ok();
    immediate.expect("a held wait blocked polling or another subject's listing");
    assert!(
        still_waiting,
        "the held wait finished before the independent reads"
    );
    f.tasks.shutdown().await;
    auth.tasks.shutdown().await;
}
