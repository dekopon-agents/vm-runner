use super::*;
use poem::IntoResponse;

#[tokio::test]
async fn transient_kube_and_healthz_errors_keep_session_and_return_502_not_executed() {
    let mut f = Fixture::new().await;
    let id = f.session();
    assert!(matches!(
        f.controller.exec(SUBJECT, &id, &exec()).await.unwrap(),
        ExecResponse::Pending(_)
    ));
    for (kube, health) in [
        (0, 200),
        (503, 200),
        (200, 401),
        (200, 408),
        (200, 500),
        (200, 503),
    ] {
        f.kube_status.store(kube, Ordering::SeqCst);
        f.health_status.store(health, Ordering::SeqCst);
        let error = match f.controller.exec(SUBJECT, &id, &exec()).await {
            Err(error) => error,
            _ => panic!("transient error must propagate"),
        };
        match &error {
            Error::Kubernetes(code) => assert_eq!(usize::from(*code), kube),
            Error::Status(code) => assert_eq!(usize::from(*code), health),
            other => panic!("wrong cause: {other}"),
        }
        let response = ResponseError::from(error).into_response();
        assert_eq!(response.status(), poem::http::StatusCode::BAD_GATEWAY);
        let body: Value = response.into_body().into_json().await.unwrap();
        assert_eq!(body["outcome"], "not_executed");
        assert!(!f.controller.sessions.lock().unwrap()[&id].retiring);
        assert_eq!(f.calls.load(Ordering::SeqCst), 1);
    }
    f.kube_status.store(200, Ordering::SeqCst);
    f.health_status.store(200, Ordering::SeqCst);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    Arc::get_mut(&mut f.controller).unwrap().jail_port = listener.local_addr().unwrap().port();
    drop(listener);
    let error = match f.controller.exec(SUBJECT, &id, &exec()).await {
        Err(error @ Error::Http { .. }) => error,
        _ => panic!("health transport cause"),
    };
    let response = ResponseError::from(error).into_response();
    assert_eq!(response.status(), poem::http::StatusCode::BAD_GATEWAY);
    let body: Value = response.into_body().into_json().await.unwrap();
    assert_eq!(body["outcome"], "not_executed");
    assert!(!f.controller.sessions.lock().unwrap()[&id].retiring);
    f.tasks.shutdown().await;
}

#[tokio::test]
async fn terminal_unknown_is_terminal_and_polling_does_not_count_as_activity() {
    let mut f = Fixture::new().await;
    let id = f.session();
    let ExecResponse::Pending(Json(pending)) =
        f.controller.exec(SUBJECT, &id, &exec()).await.unwrap()
    else {
        panic!("pending")
    };
    let active = now() - 301;
    f.controller
        .sessions
        .lock()
        .unwrap()
        .get_mut(&id)
        .unwrap()
        .active = active;
    let patches = f.patches.load(Ordering::SeqCst);
    assert!(matches!(
        f.controller.job(SUBJECT, &pending.job_id).await.unwrap(),
        JobResponse::Ok(Json(JobStatus::Running(_)))
    ));
    let JobResponse::Ok(Json(JobStatus::Complete(ExecResult::NotExecuted(unknown)))) =
        f.controller.job(SUBJECT, &pending.job_id).await.unwrap()
    else {
        panic!("terminal unknown")
    };
    assert_eq!(unknown.reason, "unknown");
    assert!(
        !f.controller
            .jobs
            .lock()
            .unwrap()
            .contains_key(&pending.job_id)
    );
    assert!(matches!(
        f.controller.job(SUBJECT, &pending.job_id).await,
        Err(Error::NotFound)
    ));
    assert_eq!(f.controller.sessions.lock().unwrap()[&id].active, active);
    assert_eq!(f.patches.load(Ordering::SeqCst), patches);
    f.controller.reap(now()).await;
    assert!(f.controller.sessions.lock().unwrap()[&id].retiring);
    f.tasks.shutdown().await;
}

#[tokio::test]
async fn terminal_pod_evidence_retires_session_without_dispatch() {
    let mut f = Fixture::new().await;
    let id = f.session();
    assert!(matches!(
        f.controller.exec(SUBJECT, &id, &exec()).await.unwrap(),
        ExecResponse::Pending(_)
    ));
    *f.pod_status.lock().unwrap() = Some(json!({"phase":"Failed"}));
    let ExecResponse::Complete(Json(ExecResult::NotExecuted(result))) =
        f.controller.exec(SUBJECT, &id, &exec()).await.unwrap()
    else {
        panic!("boot failure")
    };
    assert_eq!(result.reason, "boot_failure");
    assert!(f.controller.sessions.lock().unwrap()[&id].retiring);
    assert_eq!(f.calls.load(Ordering::SeqCst), 1);
    f.controller.reap(now()).await;
    assert!(f.controller.sessions.lock().unwrap().is_empty());
    f.tasks.shutdown().await;
}

#[tokio::test]
async fn global_job_cap_refuses_before_any_guest_effect() {
    let mut f = Fixture::new().await;
    let id = f.session();
    f.controller.jobs.lock().unwrap().extend((0..1024).map(|n| {
        (
            n.to_string(),
            Job {
                session: format!("other-{}", n / 64),
                jail_id: n.to_string(),
            },
        )
    }));
    let ExecResponse::Complete(Json(ExecResult::NotExecuted(result))) =
        f.controller.exec(SUBJECT, &id, &exec()).await.unwrap()
    else {
        panic!("job capacity")
    };
    assert_eq!(result.reason, "job_capacity");
    assert_eq!(f.calls.load(Ordering::SeqCst), 0);
    assert!(f.captured.lock().unwrap().is_empty());
    f.tasks.shutdown().await;
}
