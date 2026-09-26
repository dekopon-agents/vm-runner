#![cfg(unix)]
use super::*;
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use http_body_util::{BodyExt, Full};
use serde_json::{Value, json};
use std::sync::atomic::{AtomicUsize, Ordering};
const SUBJECT: &str = "system:serviceaccount:dekopon:default";
type Captures = Arc<Mutex<Vec<Value>>>;
struct Fixture {
    controller: Arc<Controller>,
    tasks: tokio::task::JoinSet<()>,
    _files: tempfile::TempDir,
    captured: Captures,
    calls: Arc<AtomicUsize>,
    create_pause: Arc<tokio::sync::Semaphore>,
    create_started: Arc<tokio::sync::Notify>,
}
impl Fixture {
    async fn new() -> Self {
        let files = tempfile::tempdir().unwrap();
        let token = format!("{}.{}.AA", URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256"}"#), URL_SAFE_NO_PAD.encode(json!({"sub":"system:serviceaccount:runner:controller","iss":"https://kubernetes.default.svc","aud":["vm-runner-jail"]}).to_string()));
        let token_file = files.path().join("token");
        tokio::fs::write(&token_file, &token).await.unwrap();
        let mut config: Config =
            serde_yaml_ng::from_str(include_str!("../../../examples/vm-runner.yaml")).unwrap();
        config.jails = Some(serde_json::from_value(json!({"namespace":"jails","image":"runner@sha256:abc","imageCacheHostPath":"/var/cache/images","controllerAudience":"vm-runner-jail","controllerSubject":"system:serviceaccount:runner:controller","tokenFile":token_file})).unwrap());
        let captured = Arc::new(Mutex::new(Vec::new()));
        let captures = Arc::clone(&captured);
        let (service, mut mock) = tower_test::mock::pair::<
            hyper::Request<kube::client::Body>,
            hyper::Response<kube::client::Body>,
        >();
        let mut tasks = tokio::task::JoinSet::new();
        let create_pause = Arc::new(tokio::sync::Semaphore::new(1));
        let pause = Arc::clone(&create_pause);
        let create_started = Arc::new(tokio::sync::Notify::new());
        let started = Arc::clone(&create_started);
        tasks.spawn(async move {
            let mut pod = Value::Null;
            let mut deleted = false;
            while let Some((request, send)) = mock.next_request().await {
                let method = request.method().clone();
                let uri = request.uri().clone();
                let body = request.into_body().collect().await.unwrap().to_bytes();
                let mut status = 200;
                let response = match method.as_str() {
                    "POST" if uri.path().ends_with("/pods") => {
                        started.notify_one();
                        let _permit = pause.acquire().await.unwrap();
                        pod = serde_json::from_slice(&body).unwrap();
                        captures.lock().unwrap().push(pod.clone());
                        pod["metadata"]["uid"] = json!("pod-uid");
                        pod["metadata"]["resourceVersion"] = json!("10");
                        pod.clone()
                    }
                    "POST" if uri.path().ends_with("/secrets") => {
                        let secret: Value = serde_json::from_slice(&body).unwrap();
                        assert_eq!(secret["metadata"]["ownerReferences"][0]["uid"], "pod-uid");
                        captures.lock().unwrap().push(secret.clone());
                        pod["status"] = json!({"podIP":"127.0.0.1","phase":"Running","conditions":[{"type":"Ready","status":"True"}]});
                        secret
                    }
                    "GET" if uri.path().ends_with("/pods") => json!({"apiVersion":"v1","kind":"PodList","metadata":{},"items":[]}),
                    "PATCH" => {
                        let patch: Value = serde_json::from_slice(&body).unwrap();
                        pod["metadata"]["annotations"][super::super::ACTIVE] = patch["metadata"]["annotations"][super::super::ACTIVE].clone();
                        pod.clone()
                    }
                    "GET" if deleted => { status = 404; json!({"kind":"Status","apiVersion":"v1","code":404,"status":"Failure","reason":"NotFound","message":"gone"}) }
                    "GET" => pod.clone(),
                    "DELETE" => { deleted = true; pod.clone() },
                    _ => panic!("unexpected Kubernetes method"),
                };
                send.send_response(hyper::Response::builder().status(status).body(kube::client::Body::from(response.to_string().into_bytes())).unwrap());
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&calls);
        tasks.spawn(async move {
            let jobs = Arc::new(AtomicUsize::new(0));
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let token_file = token_file.clone();
                let counter = Arc::clone(&counter);
                let jobs = Arc::clone(&jobs);
                let service = hyper::service::service_fn(move |request: hyper::Request<hyper::body::Incoming>| {
                    let token_file = token_file.clone();
                    let counter = Arc::clone(&counter);
                    let jobs = Arc::clone(&jobs);
                    async move {
                        let token = tokio::fs::read_to_string(token_file).await.unwrap();
                        assert_eq!(request.headers()["authorization"], format!("Bearer {}", token.trim()));
                        let mut response = hyper::Response::builder();
                        let body = match request.uri().path() {
                            "/healthz" => "ok".into(),
                            "/exec" => {
                                let bytes = request.into_body().collect().await.unwrap().to_bytes();
                                let body: Value = serde_json::from_slice(&bytes).unwrap();
                                assert_eq!(body["argv"], json!(["echo","ok"]));
                                assert_eq!(body["stdin"], "input");
                                assert_eq!(body["deadlineMs"], 25);
                                if counter.fetch_add(1, Ordering::SeqCst) == 0 {
                                    response = response.status(202);
                                    json!({"outcome":"unknown","jobId":"remote-id"}).to_string()
                                } else { json!({"outcome":"executed","exitCode":7,"stdout":"x".repeat(65537),"stderr":"err","truncated":false}).to_string() }
                            }
                            "/jobs/remote-id" if jobs.fetch_add(1, Ordering::SeqCst) == 0 => json!({"state":"running"}).to_string(),
                            "/jobs/remote-id" if jobs.load(Ordering::SeqCst) == 2 => { response = response.status(202); json!({"outcome":"unknown","jobId":"remote-id"}).to_string() },
                            "/jobs/remote-id" => json!({"outcome":"executed","exitCode":0,"stdout":"ok","stderr":"","truncated":false}).to_string(),
                            _ => panic!("unexpected jail route: {}", request.uri()),
                        };
                        Ok::<_, std::convert::Infallible>(response.body(Full::new(hyper::body::Bytes::from(body))).unwrap())
                    }
                });
                hyper::server::conn::http1::Builder::new().keep_alive(false).serve_connection(hyper_util::rt::TokioIo::new(stream), service).await.unwrap();
            }
        });
        let mut controller = Controller::new(Arc::new(config), Client::new(service, "jails"))
            .await
            .unwrap();
        controller.jail_port = port;
        Self {
            controller: Arc::new(controller),
            tasks,
            _files: files,
            captured,
            calls,
            create_pause,
            create_started,
        }
    }
    fn session(&self) -> String {
        let Created::New(Json(session)) = self
            .controller
            .create(
                SUBJECT,
                Create {
                    profile: "travel".into(),
                    name: None,
                },
            )
            .unwrap()
        else {
            panic!("new session")
        };
        session.session_id
    }
}
fn exec() -> Exec {
    Exec {
        argv: vec!["echo".into(), "ok".into()],
        stdin: Some("input".into()),
        deadline_ms: 25,
    }
}
#[tokio::test]
async fn lazy_pods_proxy_exec_and_jobs_only_for_the_owner() {
    let mut f = Fixture::new().await;
    let id = f.session();
    assert!(f.captured.lock().unwrap().is_empty());
    assert!(matches!(
        f.controller.exec("other", &id, &exec()).await,
        Err(Error::NotFound)
    ));
    let ExecResponse::Pending(Json(pending)) =
        f.controller.exec(SUBJECT, &id, &exec()).await.unwrap()
    else {
        panic!("unknown execution")
    };
    assert_ne!(pending.job_id, "remote-id");
    assert!(matches!(
        f.controller.job("other", &pending.job_id).await,
        Err(Error::NotFound)
    ));
    assert!(matches!(
        f.controller.job(SUBJECT, &pending.job_id).await.unwrap(),
        JobResponse::Ok(Json(JobStatus::Running(_)))
    ));
    let JobResponse::Pending(Json(unknown)) =
        f.controller.job(SUBJECT, &pending.job_id).await.unwrap()
    else {
        panic!("unknown job")
    };
    assert_eq!(unknown.job_id, pending.job_id);
    assert!(matches!(
        f.controller.job(SUBJECT, &pending.job_id).await.unwrap(),
        JobResponse::Ok(Json(JobStatus::Complete(ExecResult::Executed(Executed {
            exit_code: 0,
            ..
        }))))
    ));
    let token_file = &f.controller.config.jails.as_ref().unwrap().token_file;
    let old = tokio::fs::read_to_string(token_file).await.unwrap();
    let rotated = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256","kid":"rotated"}"#),
        old.split_once('.').unwrap().1
    );
    tokio::fs::write(token_file, rotated).await.unwrap();
    let ExecResponse::Complete(Json(ExecResult::Executed(done))) =
        f.controller.exec(SUBJECT, &id, &exec()).await.unwrap()
    else {
        panic!("terminal execution")
    };
    assert_eq!(
        (
            done.exit_code,
            done.stdout.len(),
            done.stderr.as_str(),
            done.truncated
        ),
        (7, 65536, "err", true)
    );
    {
        let captured = f.captured.lock().unwrap();
        assert_eq!(captured.len(), 2);
        let pod = &captured[0];
        let c = &pod["spec"]["containers"][0];
        assert_eq!(c["resources"]["requests"], c["resources"]["limits"]);
        assert_eq!(
            c["resources"]["limits"],
            json!({"cpu":"1","memory":"1152Mi","smarter-devices/kvm":"1","smarter-devices/net-tun":"1"})
        );
        assert_eq!(
            c["securityContext"]["capabilities"],
            json!({"drop":["ALL"],"add":["NET_ADMIN","SETUID","SETGID"]})
        );
        assert_eq!(pod["spec"]["securityContext"]["fsGroup"], 1000);
        assert_eq!(c["securityContext"]["allowPrivilegeEscalation"], false);
        assert_eq!(
            pod["spec"]["securityContext"]["seccompProfile"]["type"],
            "RuntimeDefault"
        );
        assert_eq!(pod["spec"]["automountServiceAccountToken"], false);
        assert_eq!(pod["spec"]["serviceAccountName"], "vm-runner-jail");
        assert_eq!(pod["spec"]["volumes"][1]["emptyDir"]["sizeLimit"], "4160Mi");
        assert_eq!(c["volumeMounts"][0]["readOnly"], true);
        assert_eq!(c["readinessProbe"]["tcpSocket"]["port"], 8080);
        assert_eq!(
            pod["spec"]["initContainers"][0]["resources"]["requests"],
            pod["spec"]["initContainers"][0]["resources"]["limits"]
        );
        assert_eq!(
            pod["metadata"]["annotations"][super::super::SUBJECT],
            SUBJECT
        );
        let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, SUBJECT.as_bytes());
        let expected: String = digest.as_ref()[..8]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(
            pod["metadata"]["labels"]["vm-runner/subject-hash"],
            expected
        );
        let bytes = STANDARD
            .decode(captured[1]["data"]["config.json"].as_str().unwrap())
            .unwrap();
        let config: Config = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            config.auth.subjects,
            ["system:serviceaccount:runner:controller"]
        );
        assert_eq!(config.auth.audience, "vm-runner-jail");
        assert_eq!(
            config.jails.as_ref().unwrap().controller_subject,
            "system:serviceaccount:runner:controller"
        );
        assert!(config.conflicts().is_empty());
    }
    f.controller.jobs.lock().unwrap().extend((0..1023).map(|n| {
        (
            n.to_string(),
            Job {
                session: id.clone(),
                jail_id: n.to_string(),
            },
        )
    }));
    let ExecResponse::Complete(Json(ExecResult::NotExecuted(refused))) =
        f.controller.exec(SUBJECT, &id, &exec()).await.unwrap()
    else {
        panic!("capacity")
    };
    assert_eq!(refused.reason, "job_capacity");
    assert_eq!(f.calls.load(Ordering::SeqCst), 2);
    f.controller.reap(u64::MAX).await;
    assert!(!f.controller.sessions.lock().unwrap().is_empty());
    f.controller.reap(u64::MAX).await;
    assert!(f.controller.jobs.lock().unwrap().is_empty());
    f.tasks.shutdown().await;
}
#[tokio::test]
async fn boot_failure_never_dispatches_exec_and_releases_the_reservation() {
    let mut f = Fixture::new().await;
    let id = f.session();
    let file = &f.controller.config.jails.as_ref().unwrap().token_file;
    let token = format!(
        "{}.{}.AA",
        URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256"}"#),
        URL_SAFE_NO_PAD.encode(
            json!({"sub":SUBJECT,"iss":"https://kubernetes.default.svc","aud":["vm-runner-jail"]})
                .to_string()
        )
    );
    tokio::fs::write(file, token).await.unwrap();
    let ExecResponse::Complete(Json(ExecResult::NotExecuted(refused))) =
        f.controller.exec(SUBJECT, &id, &exec()).await.unwrap()
    else {
        panic!("boot refusal")
    };
    assert_eq!(refused.reason, "boot_failure");
    assert_eq!(f.calls.load(Ordering::SeqCst), 0);
    assert!(f.controller.sessions.lock().unwrap().is_empty());
    f.tasks.shutdown().await;
}
#[tokio::test]
async fn reap_cannot_free_quota_or_orphan_a_pod_while_create_is_in_flight() {
    use futures_util::FutureExt;
    let mut f = Fixture::new().await;
    let id = f.session();
    let hold = f.create_pause.acquire().await.unwrap();
    let command = exec();
    let (result, ()) = tokio::join!(f.controller.exec(SUBJECT, &id, &command), async {
        f.create_started.notified().await;
        assert!(f.controller.reap(u64::MAX).now_or_never().is_some());
        let sessions = f.controller.sessions.lock().unwrap();
        assert_eq!(sessions.len(), 1);
        assert!(sessions[&id].starting && sessions[&id].retiring);
        drop(hold);
    });
    assert!(matches!(
        result.unwrap(),
        ExecResponse::Complete(Json(ExecResult::NotExecuted(_)))
    ));
    assert_eq!(f.calls.load(Ordering::SeqCst), 0);
    assert!(!f.controller.sessions.lock().unwrap()[&id].starting);
    f.controller.reap(u64::MAX).await;
    assert!(f.controller.sessions.lock().unwrap().is_empty());
    f.tasks.shutdown().await;
}
