use super::*;
use http_body_util::BodyExt;
use serde_json::{Value, json};

type Mock = tower_test::mock::Handle<
    hyper::Request<kube::client::Body>,
    hyper::Response<kube::client::Body>,
>;
fn config() -> Arc<Config> {
    let mut config: Config =
        serde_yaml_ng::from_str(include_str!("../../examples/vm-runner.yaml")).unwrap();
    config.jails = Some(
        serde_json::from_value(json!({
            "namespace":"jails", "image":"runner@sha256:abc", "imageCacheHostPath":"/images",
            "controllerAudience":"vm-runner-jail", "tokenFile":"/token"
        }))
        .unwrap(),
    );
    Arc::new(config)
}
async fn reply(mock: &mut Mock, method: &str, path: &str, value: Value) -> Value {
    let (request, send) = mock.next_request().await.unwrap();
    assert_eq!(request.method(), method);
    assert_eq!(request.uri().path(), path);
    let bytes = request.into_body().collect().await.unwrap().to_bytes();
    send.send_response(
        hyper::Response::builder()
            .header("content-type", "application/json")
            .body(kube::client::Body::from(
                serde_json::to_vec(&value).unwrap(),
            ))
            .unwrap(),
    );
    if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    }
}
fn pod() -> Value {
    json!({"apiVersion":"v1", "kind":"Pod", "metadata":{
        "name":"jail-rebuilt", "labels": {"vm-runner/session":"019591f2-439b-7000-8000-000000000001", "vm-runner/profile":"travel"},
        "annotations":{"vm-runner/subject":"system:serviceaccount:dekopon:default", "vm-runner/name":"default", "vm-runner/created":"100", "vm-runner/active":"200"}
    }, "status":{"phase":"Running", "podIP":"127.0.0.1"}})
}
async fn setup(items: Vec<Value>) -> (Controller, Mock) {
    let (service, mut mock) = tower_test::mock::pair();
    let client = Client::new(service, "jails");
    let (controller, _) = tokio::join!(
        Controller::new(config(), client),
        reply(
            &mut mock,
            "GET",
            "/api/v1/namespaces/jails/pods",
            json!({"apiVersion":"v1","kind":"PodList","metadata":{},"items":items})
        )
    );
    (controller.unwrap(), mock)
}
fn create(profile: &str, name: Option<&str>) -> Create {
    Create {
        profile: profile.into(),
        name: name.map(str::to_owned),
    }
}
#[tokio::test]
async fn named_sessions_are_lazy_subject_scoped_and_profile_consistent() {
    let (controller, _mock) = setup(vec![]).await;
    let Created::New(Json(first)) = controller
        .create(
            "system:serviceaccount:dekopon:default",
            create("travel", None),
        )
        .unwrap()
    else {
        panic!("new session")
    };
    assert_eq!(first.name, "default");
    assert_eq!(
        uuid::Uuid::parse_str(&first.session_id)
            .unwrap()
            .get_version_num(),
        7
    );
    let Created::Existing(Json(same)) = controller
        .create(
            "system:serviceaccount:dekopon:default",
            create("travel", Some("default")),
        )
        .unwrap()
    else {
        panic!("existing session")
    };
    assert_eq!(same.session_id, first.session_id);
    assert!(matches!(
        controller
            .create(
                "system:serviceaccount:dekopon:default",
                create("other", None)
            )
            .unwrap(),
        Created::Conflict(_)
    ));
    assert!(matches!(
        controller
            .create(
                "system:serviceaccount:other:default",
                create("travel", None)
            )
            .unwrap(),
        Created::New(_)
    ));
    assert!(
        controller
            .sessions
            .lock()
            .unwrap()
            .values()
            .all(|s| s.pod.is_none())
    );
    for name in ["", "UPPER", "-prefix", "has space"] {
        assert_eq!(
            controller
                .create(
                    "system:serviceaccount:other:default",
                    create("travel", Some(name))
                )
                .err()
                .unwrap()
                .status(),
            poem::http::StatusCode::BAD_REQUEST
        );
    }
}
#[tokio::test]
async fn quota_and_bad_profile_refusals_preserve_the_registry() {
    let (controller, _mock) = setup(vec![]).await;
    let subject = "system:serviceaccount:other:default";
    assert!(matches!(
        controller.create(subject, create("missing", None)).unwrap(),
        Created::Refused(Json(NotExecuted {
            reason: Failure::BadProfile,
            ..
        }))
    ));
    assert!(matches!(
        controller.create(subject, create("travel", None)).unwrap(),
        Created::New(_)
    ));
    assert!(matches!(
        controller
            .create(subject, create("travel", Some("second")))
            .unwrap(),
        Created::Refused(Json(NotExecuted {
            reason: Failure::Quota,
            ..
        }))
    ));
    assert_eq!(controller.sessions.lock().unwrap().len(), 1);
}
#[tokio::test]
async fn rebuild_recovers_named_sessions_and_reaper_deletes_expired_pods() {
    let (controller, mut mock) = setup(vec![pod()]).await;
    let Created::Existing(Json(body)) = controller
        .create(
            "system:serviceaccount:dekopon:default",
            create("travel", None),
        )
        .unwrap()
    else {
        panic!("rebuilt session")
    };
    assert_eq!(body.session_id, "019591f2-439b-7000-8000-000000000001");
    controller.reap(499).await.unwrap();
    assert_eq!(controller.sessions.lock().unwrap().len(), 1);
    let (result, _) = tokio::join!(
        controller.reap(500),
        reply(
            &mut mock,
            "DELETE",
            "/api/v1/namespaces/jails/pods/jail-rebuilt",
            pod()
        )
    );
    result.unwrap();
    assert!(controller.sessions.lock().unwrap().is_empty());
}
#[tokio::test]
async fn rebuild_deletes_terminal_pods_instead_of_leaking_them() {
    let (service, mut mock) = tower_test::mock::pair();
    let mut terminal = pod();
    terminal["status"]["phase"] = json!("Failed");
    let (controller, ()) = tokio::join!(
        Controller::new(config(), Client::new(service, "jails")),
        async {
            reply(
                &mut mock,
                "GET",
                "/api/v1/namespaces/jails/pods",
                json!({"apiVersion":"v1","kind":"PodList","metadata":{},"items":[terminal]}),
            )
            .await;
            reply(
                &mut mock,
                "DELETE",
                "/api/v1/namespaces/jails/pods/jail-rebuilt",
                pod(),
            )
            .await;
        }
    );
    assert!(controller.unwrap().sessions.lock().unwrap().is_empty());
}
#[tokio::test]
async fn rebuild_tolerates_terminal_pods_deleted_since_listing() {
    let (service, mut mock) = tower_test::mock::pair();
    let mut terminal = pod();
    terminal["status"]["phase"] = json!("Succeeded");
    let (controller, ()) = tokio::join!(
        Controller::new(config(), Client::new(service, "jails")),
        async {
            reply(
                &mut mock,
                "GET",
                "/api/v1/namespaces/jails/pods",
                json!({"apiVersion":"v1","kind":"PodList","metadata":{},"items":[terminal]}),
            )
            .await;
            let (request, send) = mock.next_request().await.unwrap();
            assert_eq!(request.method(), "DELETE");
            send.send_response(hyper::Response::builder().status(404).body(kube::client::Body::from(
            json!({"kind":"Status","apiVersion":"v1","status":"Failure","reason":"NotFound","message":"gone","code":404}).to_string().into_bytes()
        )).unwrap());
        }
    );
    assert!(controller.unwrap().sessions.lock().unwrap().is_empty());
}
#[tokio::test]
async fn rebuild_keeps_the_oldest_named_session_and_deletes_duplicates_in_any_list_order() {
    for reversed in [false, true] {
        let (service, mut mock) = tower_test::mock::pair();
        let first = pod();
        let mut duplicate = pod();
        duplicate["metadata"]["name"] = json!("jail-duplicate");
        duplicate["metadata"]["labels"]["vm-runner/session"] =
            json!("019591f2-439b-7000-8000-000000000002");
        let items = if reversed {
            vec![duplicate.clone(), first]
        } else {
            vec![first, duplicate.clone()]
        };
        let (controller, ()) = tokio::join!(
            Controller::new(config(), Client::new(service, "jails")),
            async {
                reply(
                    &mut mock,
                    "GET",
                    "/api/v1/namespaces/jails/pods",
                    json!({"apiVersion":"v1","kind":"PodList","metadata":{},"items":items}),
                )
                .await;
                reply(
                    &mut mock,
                    "DELETE",
                    "/api/v1/namespaces/jails/pods/jail-duplicate",
                    duplicate,
                )
                .await;
            }
        );
        let controller = controller.unwrap();
        let Created::Existing(Json(session)) = controller
            .create(
                "system:serviceaccount:dekopon:default",
                create("travel", None),
            )
            .unwrap()
        else {
            panic!("recovered session")
        };
        assert_eq!(session.session_id, "019591f2-439b-7000-8000-000000000001");
        assert_eq!(controller.sessions.lock().unwrap().len(), 1);
    }
}
#[tokio::test]
async fn rebuild_reaps_pods_that_cannot_be_restored() {
    for missing_annotations in [true, false] {
        let (service, mut mock) = tower_test::mock::pair();
        let mut orphan = pod();
        if missing_annotations {
            orphan["metadata"]
                .as_object_mut()
                .unwrap()
                .remove("annotations");
        } else {
            orphan["metadata"]["labels"]["vm-runner/profile"] = json!("removed-profile");
        }
        let (controller, ()) = tokio::join!(
            Controller::new(config(), Client::new(service, "jails")),
            async {
                reply(
                    &mut mock,
                    "GET",
                    "/api/v1/namespaces/jails/pods",
                    json!({"apiVersion":"v1","kind":"PodList","metadata":{},"items":[orphan]}),
                )
                .await;
                reply(
                    &mut mock,
                    "DELETE",
                    "/api/v1/namespaces/jails/pods/jail-rebuilt",
                    pod(),
                )
                .await;
            }
        );
        assert!(controller.unwrap().sessions.lock().unwrap().is_empty());
    }
}
#[test]
fn jails_configuration_reports_all_invalid_fields() {
    let mut config = config();
    let jails = Arc::get_mut(&mut config).unwrap().jails.as_mut().unwrap();
    jails.namespace.clear();
    jails.image.clear();
    jails.controller_audience = "vm-runner".into();
    jails.token_file = "relative".into();
    jails.image_cache_host_path = "relative".into();
    assert_eq!(
        config.conflicts(),
        [
            "namespace",
            "image",
            "imageCacheHostPath",
            "tokenFile",
            "controllerAudience"
        ]
        .map(crate::config::Conflict::Jails)
    );
}
#[tokio::test]
async fn maximum_lifetime_reaps_even_an_active_session() {
    let mut pod = pod();
    pod["metadata"]["annotations"]["vm-runner/active"] = json!("1899");
    let (controller, mut mock) = setup(vec![pod]).await;
    let (result, _) = tokio::join!(
        controller.reap(1900),
        reply(
            &mut mock,
            "DELETE",
            "/api/v1/namespaces/jails/pods/jail-rebuilt",
            super::tests::pod()
        )
    );
    result.unwrap();
    assert!(controller.sessions.lock().unwrap().is_empty());
}
