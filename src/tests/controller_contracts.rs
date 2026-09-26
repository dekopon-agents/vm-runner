use super::*;

#[tokio::test]
async fn empty_argv_is_400_oversize_is_413_and_deadlines_require_1000ms() {
    let mut f = Fixture::new().await;
    let token = f.token(&f.claims(), "ec");
    let client = TestClient::new(app(f.config).await.unwrap().0);
    for body in [
        json!({"argv":[],"deadlineMs":1000}),
        json!({"argv":[""],"deadlineMs":1000}),
        json!({"argv":["true"],"deadlineMs":999}),
        json!({"argv":["true"],"deadlineMs":25001}),
    ] {
        let response = client
            .post("/v1/sessions/absent/exec")
            .header("Authorization", format!("Bearer {token}"))
            .body_json(&body)
            .send()
            .await;
        response.assert_status(StatusCode::BAD_REQUEST);
        response
            .assert_json(
                json!({"outcome":"not_executed","reason":"invalid exec request","truncated":false}),
            )
            .await;
    }
    let response = client.post("/v1/sessions/absent/exec")
        .header("Authorization", format!("Bearer {token}"))
        .body_json(&json!({"argv":["true"],"deadlineMs":1000,"stdin":"x".repeat(controller::proxy::BODY_LIMIT)}))
        .send().await;
    response.assert_status(StatusCode::PAYLOAD_TOO_LARGE);
    response
        .assert_json(
            json!({"outcome":"not_executed","reason":"request body too large","truncated":false}),
        )
        .await;
    let spec: Value = serde_yaml_ng::from_str(&openapi()).unwrap();
    let responses = &spec["paths"]["/v1/sessions/{id}/exec"]["post"]["responses"];
    for status in ["400", "413", "502"] {
        assert!(responses[status]["content"]["application/json; charset=utf-8"].is_object());
    }
    f.tasks.shutdown().await;
}

#[tokio::test]
async fn get_admission_remains_available_during_exec_boot() {
    let mut f = Fixture::new().await;
    let token = f.token(&f.claims(), "ec");
    let (controller, _mock) = controller::tests::setup(vec![]).await;
    let controller = Arc::new(controller);
    let busy = controller.execution.acquire().await.unwrap();
    let state = State {
        auth: Authenticator::new(f.config.auth.clone()).await.unwrap(),
        config: Arc::new(f.config),
        controller: Some(Arc::clone(&controller)),
    };
    let client = TestClient::new(endpoint(
        Arc::new(state),
        Arc::new(tokio::sync::Semaphore::new(1)),
    ));
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        client
            .get("/v1/jobs/absent")
            .header("Authorization", format!("Bearer {token}"))
            .send()
            .await
            .assert_status(StatusCode::NOT_FOUND);
    })
    .await
    .expect("GET must not wait for exec admission");
    drop(busy);
    f.tasks.shutdown().await;
}

#[test]
fn non_digest_images_are_config_conflicts_together_with_other_errors() {
    let mut config: Config =
        serde_yaml_ng::from_str(include_str!("../../examples/vm-runner.yaml")).unwrap();
    config.jails = Some(serde_json::from_value(json!({
        "namespace":"jails", "image":"runner:latest", "imageCacheHostPath":"/images",
        "controllerAudience":"vm-runner-jail", "controllerSubject":"system:serviceaccount:test:controller", "tokenFile":"/token"
    })).unwrap());
    assert_eq!(config.jails.as_ref().unwrap().fetch_timeout_seconds, 900);
    for image in [
        "guest:latest".to_string(),
        "guest@sha256:abc".into(),
        format!("guest@sha256:{}", "g".repeat(64)),
    ] {
        config.profiles.0[0].1.image = image;
        config.profiles.0[0].1.shape = "missing".into();
        let conflicts = config.conflicts();
        assert!(conflicts.contains(&config::Conflict::Jails("image")));
        assert!(conflicts.contains(&config::Conflict::Image("travel".into())));
        assert!(conflicts.contains(&config::Conflict::Shape("travel".into())));
    }
    config.jails.as_mut().unwrap().fetch_timeout_seconds = 0;
    assert!(
        config
            .conflicts()
            .contains(&config::Conflict::Jails("fetchTimeoutSeconds"))
    );
    assert!(config::digest_pinned(&format!(
        "ghcr.io/test/image@sha256:{}",
        "a".repeat(64)
    )));
}
