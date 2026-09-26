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
            "controllerAudience":"vm-runner-jail", "controllerSubject":"system:serviceaccount:test:controller", "tokenFile":"/token"
        }))
        .unwrap(),
    );
    Arc::new(config)
}
async fn reply(mock: &mut Mock, method: &str, path: &str, value: Value) {
    let (request, send) = mock.next_request().await.unwrap();
    assert_eq!(request.method(), method);
    assert_eq!(request.uri().path(), path);
    let _body = request.into_body().collect().await.unwrap();
    send.send_response(
        hyper::Response::builder()
            .header("content-type", "application/json")
            .body(kube::client::Body::from(
                serde_json::to_vec(&value).unwrap(),
            ))
            .unwrap(),
    );
}
pub(crate) fn pod() -> Value {
    json!({"apiVersion":"v1", "kind":"Pod", "metadata":{
        "name":"jail-rebuilt", "creationTimestamp":"2026-09-25T00:00:00Z",
        "labels":{"vm-runner/session":"019591f2-439b-7000-8000-000000000001", "vm-runner/profile":"travel",
        "vm-runner/subject-hash":subject_hash("system:serviceaccount:dekopon:default")},
        "annotations":{"vm-runner/subject":"system:serviceaccount:dekopon:default", "vm-runner/name":"default", "vm-runner/created":"100", "vm-runner/active":"200"}
    }, "spec":{"containers":[{"name":"jail", "image":"runner@sha256:abc"}]},
    "status":{"phase":"Running", "podIP":"127.0.0.1"}})
}
async fn gone(mock: &mut Mock, method: &str, path: &str) {
    let (request, send) = mock.next_request().await.unwrap();
    assert_eq!(request.method(), method);
    assert_eq!(request.uri().path(), path);
    send.send_response(hyper::Response::builder().status(404).body(kube::client::Body::from(
        json!({"kind":"Status","apiVersion":"v1","status":"Failure","reason":"NotFound","message":"gone","code":404}).to_string().into_bytes()
    )).unwrap());
}
pub(crate) async fn setup(items: Vec<Value>) -> (Controller, Mock) {
    let (service, mut mock) = tower_test::mock::pair();
    let (controller, ()) = tokio::join!(
        Controller::new(config(), Client::new(service, "jails")),
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
const SUBJECT_VALUE: &str = "system:serviceaccount:dekopon:default";
const POD_PATH: &str = "/api/v1/namespaces/jails/pods/jail-rebuilt";

#[tokio::test]
async fn named_sessions_are_lazy_subject_scoped_and_profile_consistent() {
    let (controller, _mock) = setup(vec![]).await;
    let Created::New(Json(first)) = controller
        .create(SUBJECT_VALUE, create("travel", None))
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
        .create(SUBJECT_VALUE, create("travel", Some("default")))
        .unwrap()
    else {
        panic!("existing session")
    };
    assert_eq!(same.session_id, first.session_id);
    assert!(matches!(
        controller
            .create(SUBJECT_VALUE, create("other", None))
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
        assert!(matches!(
            controller
                .create(SUBJECT_VALUE, create("travel", Some(name)))
                .unwrap(),
            Created::Refused(Json(NotExecuted {
                reason: Failure::BadName,
                ..
            }))
        ));
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
        .create(SUBJECT_VALUE, create("travel", None))
        .unwrap()
    else {
        panic!("rebuilt session")
    };
    assert_eq!(body.session_id, "019591f2-439b-7000-8000-000000000001");
    controller.reap(499).await;
    assert_eq!(controller.sessions.lock().unwrap().len(), 1);
    tokio::join!(
        controller.reap(500),
        reply(&mut mock, "DELETE", POD_PATH, pod())
    );
    assert!(
        controller
            .sessions
            .lock()
            .unwrap()
            .values()
            .all(|s| s.retiring)
    );
    tokio::join!(controller.reap(501), gone(&mut mock, "GET", POD_PATH));
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
            reply(&mut mock, "DELETE", POD_PATH, pod()).await;
        }
    );
    let controller = controller.unwrap();
    assert_eq!(controller.sessions.lock().unwrap().len(), 1);
    assert!(
        controller
            .sessions
            .lock()
            .unwrap()
            .values()
            .all(|s| s.retiring)
    );
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
            gone(&mut mock, "DELETE", POD_PATH).await;
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
        // Newer pod deliberately has the earlier-sorting UUID and pod name.
        duplicate["metadata"]["creationTimestamp"] = json!("2026-09-26T00:00:00Z");
        duplicate["metadata"]["labels"]["vm-runner/session"] =
            json!("019591f2-439b-7000-8000-000000000000");
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
            .create(SUBJECT_VALUE, create("travel", None))
            .unwrap()
        else {
            panic!("recovered session")
        };
        assert_eq!(session.session_id, "019591f2-439b-7000-8000-000000000001");
        assert_eq!(controller.sessions.lock().unwrap().len(), 2);
        tokio::join!(
            controller.reap(499),
            gone(
                &mut mock,
                "GET",
                "/api/v1/namespaces/jails/pods/jail-duplicate"
            )
        );
        assert_eq!(controller.sessions.lock().unwrap().len(), 1);
    }
}
#[tokio::test]
async fn rebuild_ignores_inconsistent_metadata_or_foreign_images() {
    for (pointer, value) in [
        ("/metadata/annotations", Value::Null),
        (
            "/metadata/labels/vm-runner~1profile",
            json!("removed-profile"),
        ),
        (
            "/metadata/labels/vm-runner~1subject-hash",
            json!("0000000000000000"),
        ),
        (
            "/metadata/annotations/vm-runner~1subject",
            json!("system:serviceaccount:other:default"),
        ),
        ("/spec/containers/0/image", json!("foreign@sha256:abc")),
        (
            "/spec/containers",
            json!([
                {"name":"jail", "image":"foreign@sha256:abc"},
                {"name":"sidecar", "image":"runner@sha256:abc"}
            ]),
        ),
    ] {
        let mut foreign = pod();
        *foreign.pointer_mut(pointer).unwrap() = value;
        let (controller, mut mock) = setup(vec![foreign]).await;
        assert!(controller.sessions.lock().unwrap().is_empty(), "{pointer}");
        assert!(
            mock.poll_request().is_pending(),
            "foreign pod must not be deleted"
        );
    }
}
#[test]
fn jails_configuration_reports_all_invalid_fields() {
    let mut config = config();
    let jails = Arc::get_mut(&mut config).unwrap().jails.as_mut().unwrap();
    jails.namespace.clear();
    jails.image.clear();
    jails.controller_audience = "vm-runner".into();
    jails.controller_subject = "not-a-service-account".into();
    jails.token_file = "relative".into();
    jails.image_cache_host_path = "relative".into();
    assert_eq!(
        config.conflicts(),
        [
            "namespace",
            "image",
            "imageCacheHostPath",
            "tokenFile",
            "controllerAudience",
            "controllerSubject"
        ]
        .map(crate::config::Conflict::Jails)
    );
}
#[tokio::test]
async fn maximum_lifetime_reaps_even_an_active_session() {
    let mut active = pod();
    active["metadata"]["annotations"]["vm-runner/active"] = json!("1899");
    let (controller, mut mock) = setup(vec![active]).await;
    tokio::join!(
        controller.reap(1900),
        reply(&mut mock, "DELETE", POD_PATH, pod())
    );
    assert!(
        controller
            .sessions
            .lock()
            .unwrap()
            .values()
            .all(|s| s.retiring)
    );
    tokio::join!(controller.reap(1901), gone(&mut mock, "GET", POD_PATH));
    assert!(controller.sessions.lock().unwrap().is_empty());
}
#[tokio::test]
async fn terminating_pods_count_toward_quota_but_never_satisfy_create_or_get_until_gone() {
    let mut terminating = pod();
    terminating["metadata"]["deletionTimestamp"] = json!("2026-09-26T00:00:00Z");
    let (controller, mut mock) = setup(vec![terminating.clone()]).await;
    let Created::New(Json(new)) = controller
        .create(SUBJECT_VALUE, create("travel", None))
        .unwrap()
    else {
        panic!("terminating is not live")
    };
    assert_ne!(new.session_id, "019591f2-439b-7000-8000-000000000001");
    assert!(matches!(
        controller
            .create(SUBJECT_VALUE, create("travel", Some("second")))
            .unwrap(),
        Created::Refused(Json(NotExecuted {
            reason: Failure::Quota,
            ..
        }))
    ));
    tokio::join!(
        controller.reap(499),
        reply(&mut mock, "GET", POD_PATH, terminating)
    );
    assert_eq!(controller.sessions.lock().unwrap().len(), 2);
    tokio::join!(controller.reap(499), gone(&mut mock, "GET", POD_PATH));
    assert!(matches!(
        controller
            .create(SUBJECT_VALUE, create("travel", Some("second")))
            .unwrap(),
        Created::New(_)
    ));
}
