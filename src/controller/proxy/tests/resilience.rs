use super::*;
use poem::IntoResponse;

#[tokio::test]
async fn kube_and_nonretryable_health_errors_keep_session_and_return_502_not_executed() {
    let mut f = Fixture::new().await;
    let id = f.session();
    assert!(matches!(
        f.controller.exec(SUBJECT, &id, &exec()).await.unwrap(),
        ExecResponse::Pending(_)
    ));
    for (kube, health) in [(0, 200), (503, 200), (200, 401), (200, 408), (200, 500)] {
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
    f.tasks.shutdown().await;
}

#[tokio::test]
async fn connection_refused_during_boot_waits_for_pod_failure_without_exec() {
    let mut f = Fixture::new().await;
    let id = f.session();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    Arc::get_mut(&mut f.controller).unwrap().jail_port = listener.local_addr().unwrap().port();
    drop(listener);
    let controller = Arc::clone(&f.controller);
    let id_for_exec = id.clone();
    let execution =
        tokio::spawn(async move { controller.exec(SUBJECT, &id_for_exec, &exec()).await });
    tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
    assert!(!execution.is_finished());
    *f.pod_status.lock().unwrap() = Some(json!({"phase":"Failed"}));
    let ExecResponse::Complete(Json(ExecResult::NotExecuted(result))) =
        tokio::time::timeout(std::time::Duration::from_secs(4), execution)
            .await
            .unwrap()
            .unwrap()
            .unwrap()
    else {
        panic!("terminal pod must refuse");
    };
    assert_eq!(result.reason, "boot_failure");
    assert_eq!(f.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn cold_jail_503_is_polled_before_a_single_exec() {
    let f = Fixture::new().await;
    let id = f.session();
    f.health_status.store(503, Ordering::SeqCst);
    let controller = Arc::clone(&f.controller);
    let id_for_exec = id.clone();
    let execution =
        tokio::spawn(async move { controller.exec(SUBJECT, &id_for_exec, &exec()).await });
    tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
    assert!(!execution.is_finished());
    assert_eq!(f.calls.load(Ordering::SeqCst), 0);
    f.health_status.store(200, Ordering::SeqCst);
    assert!(matches!(
        tokio::time::timeout(std::time::Duration::from_secs(4), execution)
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
        ExecResponse::Pending(_)
    ));
    assert_eq!(f.calls.load(Ordering::SeqCst), 1);
    assert!(matches!(
        f.controller.sessions.lock().unwrap()[&id].body.state,
        SessionState::Ready
    ));
}

#[tokio::test]
async fn cold_jail_503_stops_at_boot_timeout_without_exec() {
    let f = Fixture::new().await;
    let id = f.session();
    f.health_status.store(503, Ordering::SeqCst);
    let finished =
        k8s_openapi::jiff::Timestamp::from_second(i64::try_from(now() - 61).unwrap()).unwrap();
    *f.pod_status.lock().unwrap() = Some(json!({
        "podIP":"127.0.0.1","phase":"Running",
        "conditions":[{"type":"Ready","status":"True"}],
        "initContainerStatuses":[{"name":"fetch","image":"guest","imageID":"guest","ready":false,"restartCount":0,
            "state":{"terminated":{"exitCode":0,"finishedAt":finished}}}]
    }));
    let ExecResponse::Complete(Json(ExecResult::NotExecuted(result))) = tokio::time::timeout(
        std::time::Duration::from_secs(4),
        f.controller.exec(SUBJECT, &id, &exec()),
    )
    .await
    .unwrap()
    .unwrap() else {
        panic!("boot timeout must refuse");
    };
    assert_eq!(result.reason, "boot_failure");
    assert_eq!(f.calls.load(Ordering::SeqCst), 0);
    assert!(
        f.controller
            .sessions
            .lock()
            .unwrap()
            .get(&id)
            .is_none_or(|s| s.retiring)
    );
}

#[tokio::test]
async fn terminal_pod_while_waiting_for_health_stops_without_exec() {
    let f = Fixture::new().await;
    let id = f.session();
    f.health_status.store(503, Ordering::SeqCst);
    let controller = Arc::clone(&f.controller);
    let id_for_exec = id.clone();
    let execution =
        tokio::spawn(async move { controller.exec(SUBJECT, &id_for_exec, &exec()).await });
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    *f.pod_status.lock().unwrap() = Some(json!({"phase":"Failed"}));
    let ExecResponse::Complete(Json(ExecResult::NotExecuted(result))) =
        tokio::time::timeout(std::time::Duration::from_secs(4), execution)
            .await
            .unwrap()
            .unwrap()
            .unwrap()
    else {
        panic!("terminal pod must refuse");
    };
    assert_eq!(result.reason, "boot_failure");
    assert_eq!(f.calls.load(Ordering::SeqCst), 0);
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
