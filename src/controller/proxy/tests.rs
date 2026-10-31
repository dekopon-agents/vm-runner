#![cfg(unix)]
use super::*;
mod resilience;
mod wait;
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use http_body_util::{BodyExt, Full};
use serde_json::{Value, json};
use std::sync::atomic::{AtomicUsize, Ordering};
pub(super) const SUBJECT: &str = "system:serviceaccount:dekopon:default";
type Captures = Arc<Mutex<Vec<Value>>>;
pub(crate) struct Fixture {
    pub(super) controller: Arc<Controller>,
    pub(crate) tasks: tokio::task::JoinSet<()>,
    pub(super) artifact_list: Arc<Mutex<String>>,
    _files: tempfile::TempDir,
    captured: Captures,
    calls: Arc<AtomicUsize>,
    create_pause: Arc<tokio::sync::Semaphore>,
    create_started: Arc<tokio::sync::Notify>,
    kube_status: Arc<AtomicUsize>,
    health_status: Arc<AtomicUsize>,
    patches: Arc<AtomicUsize>,
    pod_status: Arc<Mutex<Option<Value>>>,
    pod_read_delay: Arc<AtomicUsize>,
    pod_read_started: Arc<tokio::sync::Notify>,
    job_waits: Arc<Mutex<Vec<Option<u32>>>>,
    wait_for_jobs: Arc<std::sync::atomic::AtomicBool>,
    stall_job_body: Arc<std::sync::atomic::AtomicBool>,
}
impl Fixture {
    pub(super) async fn new() -> Self {
        Self::setup(None).await
    }
    pub(crate) async fn with_jail(
        endpoint: poem::endpoint::BoxEndpoint<'static, poem::Response>,
        token: String,
        auth: crate::config::Auth,
    ) -> Self {
        Self::setup(Some((endpoint, token, auth))).await
    }
    async fn setup(
        jail: Option<(
            poem::endpoint::BoxEndpoint<'static, poem::Response>,
            String,
            crate::config::Auth,
        )>,
    ) -> Self {
        let files = tempfile::tempdir().unwrap();
        let token = format!("{}.{}.AA", URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256"}"#), URL_SAFE_NO_PAD.encode(json!({"sub":"system:serviceaccount:runner:controller","iss":"https://kubernetes.default.svc","aud":["vm-runner-jail"]}).to_string()));
        let token = jail.as_ref().map_or(token, |(_, token, _)| token.clone());
        let token_file = files.path().join("token");
        tokio::fs::write(&token_file, &token).await.unwrap();
        let mut config: Config =
            serde_yaml_ng::from_str(include_str!("../../../examples/vm-runner.yaml")).unwrap();
        config.jails = Some(serde_json::from_value(json!({"namespace":"jails","image":format!("runner@sha256:{}", "a".repeat(64)),"imageCacheHostPath":"/var/cache/images","controllerAudience":"vm-runner-jail","controllerSubject":"system:serviceaccount:runner:controller","tokenFile":token_file})).unwrap());
        if let Some((_, _, auth)) = &jail {
            config.auth = auth.clone();
        }
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
        let kube_status = Arc::new(AtomicUsize::new(200));
        let kube_code = Arc::clone(&kube_status);
        let patches = Arc::new(AtomicUsize::new(0));
        let patch_count = Arc::clone(&patches);
        let pod_status = Arc::new(Mutex::new(None::<Value>));
        let current_status = Arc::clone(&pod_status);
        let pod_read_delay = Arc::new(AtomicUsize::new(0));
        let read_delay = Arc::clone(&pod_read_delay);
        let pod_read_started = Arc::new(tokio::sync::Notify::new());
        let read_started = Arc::clone(&pod_read_started);
        tasks.spawn(async move {
            let mut pod = Value::Null;
            let mut deleted = false;
            while let Some((request, send)) = mock.next_request().await {
                let method = request.method().clone();
                let uri = request.uri().clone();
                let body = request.into_body().collect().await.unwrap().to_bytes();
                let mut status = 200;
                if method == "GET" && kube_code.load(Ordering::SeqCst) == 0 {
                    send.send_error(std::io::Error::from(std::io::ErrorKind::TimedOut));
                    continue;
                }
                let response = match method.as_str() {
                    "GET" if kube_code.load(Ordering::SeqCst) != 200 => {
                        status = u16::try_from(kube_code.load(Ordering::SeqCst)).unwrap();
                        json!({"kind":"Status","apiVersion":"v1","code":status,"status":"Failure","reason":"ServiceUnavailable","message":"transient"})
                    }
                    "POST" if uri.path().ends_with("/pods") => {
                        started.notify_one();
                        let _permit = pause.acquire().await.unwrap();
                        pod = serde_json::from_slice(&body).unwrap();
                        captures.lock().unwrap().push(pod.clone());
                        pod["metadata"]["uid"] = json!("pod-uid");
                        pod["metadata"]["resourceVersion"] = json!("10");
                        pod["metadata"]["creationTimestamp"] = serde_json::to_value(k8s_openapi::jiff::Timestamp::now()).unwrap();
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
                        patch_count.fetch_add(1, Ordering::SeqCst);
                        let patch: Value = serde_json::from_slice(&body).unwrap();
                        pod["metadata"]["annotations"][super::super::ACTIVE] = patch["metadata"]["annotations"][super::super::ACTIVE].clone();
                        pod.clone()
                    }
                    "GET" if deleted => { status = 404; json!({"kind":"Status","apiVersion":"v1","code":404,"status":"Failure","reason":"NotFound","message":"gone"}) }
                    "GET" => {
                        let delay = read_delay.load(Ordering::SeqCst);
                        if delay > 0 {
                            read_started.notify_one();
                            tokio::time::sleep(Duration::from_millis(delay as u64)).await;
                        }
                        if let Some(status) = &*current_status.lock().unwrap() {
                            pod["status"] = status.clone();
                        }
                        pod.clone()
                    },
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
        let health_status = Arc::new(AtomicUsize::new(200));
        let health = Arc::clone(&health_status);
        let artifact_list = Arc::new(Mutex::new(
            json!([{"path":"nested/a file%.bin","bytes":6,"sha256":"a".repeat(64)}]).to_string(),
        ));
        let listing = Arc::clone(&artifact_list);
        let job_waits = Arc::new(Mutex::new(Vec::new()));
        let waits = Arc::clone(&job_waits);
        let wait_for_jobs = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let waiting = Arc::clone(&wait_for_jobs);
        let stall_job_body = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stalling = Arc::clone(&stall_job_body);
        if let Some((endpoint, _, _)) = jail {
            tasks.spawn(async move {
                poem::Server::new_with_acceptor(
                    poem::listener::TcpAcceptor::from_tokio(listener).unwrap(),
                )
                .run(endpoint)
                .await
                .unwrap();
            });
        } else {
            tasks.spawn(async move {
            let jobs = Arc::new(AtomicUsize::new(0));
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let token_file = token_file.clone();
                let counter = Arc::clone(&counter);
                let jobs = Arc::clone(&jobs);
                let health = Arc::clone(&health);
                let listing = Arc::clone(&listing);
                let waits = Arc::clone(&waits);
                let waiting = Arc::clone(&waiting);
                let stalling = Arc::clone(&stalling);
                let service = hyper::service::service_fn(move |request: hyper::Request<hyper::body::Incoming>| {
                    let token_file = token_file.clone();
                    let counter = Arc::clone(&counter);
                    let jobs = Arc::clone(&jobs);
                    let health = Arc::clone(&health);
                    let listing = Arc::clone(&listing);
                    let waits = Arc::clone(&waits);
                    let waiting = Arc::clone(&waiting);
                    let stalling = Arc::clone(&stalling);
                    async move {
                        let token = tokio::fs::read_to_string(token_file).await.unwrap();
                        assert_eq!(request.headers()["authorization"], format!("Bearer {}", token.trim()));
                        let mut response = hyper::Response::builder();
                        if request.uri().path().starts_with("/jobs/") {
                            let wait = url::form_urlencoded::parse(request.uri().query().unwrap_or_default().as_bytes())
                                .find(|(key, _)| key == "waitMs").map(|(_, value)| value.parse::<u32>().unwrap());
                            waits.lock().unwrap().push(wait);
                            if stalling.load(Ordering::SeqCst) {
                                let stream = futures_util::stream::pending::<Result<hyper::body::Frame<hyper::body::Bytes>, std::convert::Infallible>>();
                                return Ok(response.body(http_body_util::StreamBody::new(stream).boxed()).unwrap());
                            }
                            if waiting.load(Ordering::SeqCst) {
                                tokio::time::sleep(Duration::from_millis(wait.unwrap_or(0).into())).await;
                                return Ok(response.body(Full::new(hyper::body::Bytes::from_static(b"{\"state\":\"running\"}")).boxed()).unwrap());
                            }
                        }
                        if request.uri().path() == "/artifacts/stall" {
                            let stream = futures_util::stream::pending::<Result<hyper::body::Frame<hyper::body::Bytes>, std::convert::Infallible>>();
                            return Ok(response.header("sha256", "a".repeat(64)).header("Content-Length", 6).body(http_body_util::StreamBody::new(stream).boxed()).unwrap());
                        }
                        let body = match request.uri().path() {
                            "/healthz" => { response = response.status(u16::try_from(health.load(Ordering::SeqCst)).unwrap()); "ok".into() },
                            "/exec" => {
                                let bytes = request.into_body().collect().await.unwrap().to_bytes();
                                let body: Value = serde_json::from_slice(&bytes).unwrap();
                                assert_eq!(body["argv"], json!(["echo","ok"]));
                                assert_eq!(body["stdin"], "input");
                                assert_eq!(body["deadlineMs"], 1000);
                                if counter.fetch_add(1, Ordering::SeqCst) == 0 {
                                    response = response.status(202);
                                    json!({"outcome":"unknown","jobId":"remote-id"}).to_string()
                                } else { json!({"outcome":"executed","exitCode":7,"stdout":"x".repeat(65537),"stderr":"err","truncated":false}).to_string() }
                            }
                            "/jobs/remote-id" if jobs.fetch_add(1, Ordering::SeqCst) == 0 => json!({"state":"running"}).to_string(),
                            "/jobs/remote-id" if jobs.load(Ordering::SeqCst) == 2 => { response = response.status(202); json!({"outcome":"unknown","jobId":"remote-id"}).to_string() },
                            "/jobs/remote-id" => json!({"outcome":"executed","exitCode":0,"stdout":"ok","stderr":"","truncated":false}).to_string(),
                            "/artifacts" => listing.lock().unwrap().clone(),
                            "/artifacts/nested%2Fa%20file%25.bin" => {
                                response = response.header("sha256", "a".repeat(64));
                                match request.headers().get("range").map(|v| v.to_str().unwrap()) {
                                    None => "abcdef".into(),
                                    Some("bytes=1-3") => { response = response.status(206).header("Content-Range", "bytes 1-3/6"); "bcd".into() }
                                    Some("bytes=99-") => { response = response.status(416).header("Content-Range", "bytes */6"); String::new() }
                                    _ => panic!("unexpected range"),
                                }
                            }
                            "/artifacts/missing" => { response = response.status(404); String::new() }
                            "/artifacts/forbidden" => { response = response.status(403); String::new() }
                            "/artifacts/unavailable" => { response = response.status(503); String::new() }
                            "/artifacts/malformed" => { response = response.header("sha256", "invalid"); "bad".into() }
                            _ => panic!("unexpected jail route: {}", request.uri()),
                        };
                        Ok::<_, std::convert::Infallible>(response.body(Full::new(hyper::body::Bytes::from(body)).boxed()).unwrap())
                    }
                });
                let _disconnected = hyper::server::conn::http1::Builder::new().keep_alive(false).serve_connection(hyper_util::rt::TokioIo::new(stream), service).await;
            }
        });
        }
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
            kube_status,
            health_status,
            patches,
            pod_status,
            artifact_list,
            pod_read_delay,
            pod_read_started,
            job_waits,
            wait_for_jobs,
            stall_job_body,
        }
    }
    pub(crate) async fn api_endpoint(
        &self,
        fixture: &crate::tests::Fixture,
    ) -> poem::endpoint::BoxEndpoint<'static, poem::Response> {
        use poem::EndpointExt;
        crate::endpoint(
            Arc::new(crate::State {
                auth: crate::Authenticator::new(fixture.config.auth.clone())
                    .await
                    .unwrap(),
                config: Arc::clone(&self.controller.config),
                controller: Some(Arc::clone(&self.controller)),
            }),
            Arc::new(tokio::sync::Semaphore::new(1)),
            Arc::new(Mutex::new(crate::RequestRollups::new(
                crate::Origin::Controller,
            ))),
        )
        .map_to_response()
        .boxed()
    }
    pub(crate) fn session(&self) -> String {
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
        deadline_ms: 1000,
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
        f.controller.job("other", &pending.job_id, None).await,
        Err(Error::NotFound)
    ));
    assert!(matches!(
        f.controller
            .job(SUBJECT, &pending.job_id, None)
            .await
            .unwrap(),
        JobResponse::Ok(Json(JobStatus::Running(_)))
    ));
    assert!(matches!(
        f.controller
            .job(SUBJECT, &pending.job_id, None)
            .await
            .unwrap(),
        JobResponse::Ok(Json(JobStatus::Complete(ExecResult::NotExecuted(_))))
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
    f.tasks.shutdown().await;
}
#[tokio::test]
async fn pod_spec_golden_has_0400_credentials_readonly_root_60s_grace_console_limit_and_net_tun() {
    let mut f = Fixture::new().await;
    let id = f.session();
    assert!(matches!(
        f.controller.exec(SUBJECT, &id, &exec()).await.unwrap(),
        ExecResponse::Pending(_)
    ));
    {
        let captured = f.captured.lock().unwrap();
        assert_eq!(captured.len(), 2);
        let pod = &captured[0];
        let c = &pod["spec"]["containers"][0];
        assert_eq!(c["resources"]["requests"], c["resources"]["limits"]);
        assert_eq!(
            c["resources"]["limits"],
            json!({"cpu":"1","memory":"1152Mi","smarter-devices/kvm":"1","smarter-devices/net_tun":"1"})
        );
        assert_eq!(
            c["securityContext"]["capabilities"],
            json!({"drop":["ALL"],"add":["NET_ADMIN","SETUID","SETGID"]})
        );
        assert_eq!(pod["spec"]["securityContext"]["fsGroup"], 1000);
        assert_eq!(c["securityContext"]["allowPrivilegeEscalation"], false);
        assert_eq!(c["securityContext"]["readOnlyRootFilesystem"], true);
        assert_eq!(pod["spec"]["terminationGracePeriodSeconds"], 60);
        for volume in pod["spec"]["volumes"].as_array().unwrap() {
            for kind in ["secret", "projected", "configMap"] {
                if let Some(source) = volume.get(kind) {
                    assert_eq!(source["defaultMode"], 0o400);
                }
            }
        }
        assert_eq!(
            pod["spec"]["volumes"][2],
            json!({"name":"console","emptyDir":{"sizeLimit":"16Mi"}})
        );
        assert!(
            c["volumeMounts"]
                .as_array()
                .unwrap()
                .contains(&json!({"name":"console","mountPath":"/run/vm-runner/console"}))
        );
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
    f.tasks.shutdown().await;
}
#[tokio::test]
async fn jail_cpu_reservation_applies_to_fetch_and_jail_without_lowering_limits() {
    let mut f = Fixture::new().await;
    let config = Arc::get_mut(&mut Arc::get_mut(&mut f.controller).unwrap().config).unwrap();
    config.jails.as_mut().unwrap().cpu_request_milli =
        Some(std::num::NonZeroU32::new(250).unwrap());
    config.shapes.0[0].1.memory = std::num::NonZeroU32::new(512).unwrap();
    assert!(config.conflicts().is_empty());
    let id = f.session();
    assert!(matches!(
        f.controller.exec(SUBJECT, &id, &exec()).await.unwrap(),
        ExecResponse::Pending(_)
    ));
    let captured = f.captured.lock().unwrap();
    assert_eq!(captured.len(), 2);
    let pod = &captured[0];
    let fetch = &pod["spec"]["initContainers"][0]["resources"];
    let jail = &pod["spec"]["containers"][0]["resources"];
    assert_eq!(fetch["requests"], json!({"cpu":"250m","memory":"640Mi"}));
    assert_eq!(fetch["limits"], json!({"cpu":"1","memory":"640Mi"}));
    assert_eq!(
        jail["requests"],
        json!({"cpu":"250m","memory":"640Mi","smarter-devices/kvm":"1","smarter-devices/net_tun":"1"})
    );
    assert_eq!(
        jail["limits"],
        json!({"cpu":"1","memory":"640Mi","smarter-devices/kvm":"1","smarter-devices/net_tun":"1"})
    );
    let config_json = STANDARD
        .decode(captured[1]["data"]["config.json"].as_str().unwrap())
        .unwrap();
    let guest_config: Value = serde_json::from_slice(&config_json).unwrap();
    assert!(guest_config["jails"].get("cpuRequestMilli").is_none());
    let parsed_guest: Config = serde_json::from_slice(&config_json).unwrap();
    assert!(parsed_guest.conflicts().is_empty());
}

#[tokio::test]
async fn per_session_job_cap_still_admits_another_session() {
    let mut f = Fixture::new().await;
    let id = f.session();
    f.controller.jobs.lock().unwrap().extend((0..64).map(|n| {
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
    assert_eq!(f.calls.load(Ordering::SeqCst), 0);
    let Created::New(Json(other)) = f
        .controller
        .create(
            SUBJECT,
            Create {
                profile: "travel".into(),
                name: Some("other".into()),
            },
        )
        .unwrap()
    else {
        panic!("other session admitted")
    };
    assert!(matches!(
        f.controller
            .exec(SUBJECT, &other.session_id, &exec())
            .await
            .unwrap(),
        ExecResponse::Pending(_)
    ));
    assert_eq!(f.calls.load(Ordering::SeqCst), 1);
    f.controller.reap(u64::MAX).await;
    assert!(!f.controller.sessions.lock().unwrap().is_empty());
    f.controller.reap(u64::MAX).await;
    assert!(f.controller.jobs.lock().unwrap().is_empty());
    f.tasks.shutdown().await;
}
#[tokio::test]
async fn invalid_token_never_dispatches_exec_but_keeps_the_reservation() {
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
    assert!(matches!(
        f.controller.exec(SUBJECT, &id, &exec()).await,
        Err(Error::Token)
    ));
    assert_eq!(f.calls.load(Ordering::SeqCst), 0);
    assert!(!f.controller.sessions.lock().unwrap()[&id].is_retiring());
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
        assert!(sessions[&id].starting && sessions[&id].is_retiring());
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
#[tokio::test]
async fn models_route_mounts_the_client_cert_secret_0400_and_writes_the_caller_subject() {
    let mut f = Fixture::new().await;
    let config = Arc::get_mut(&mut Arc::get_mut(&mut f.controller).unwrap().config).unwrap();
    config.jails.as_mut().unwrap().models = Some(
        serde_json::from_value(json!({"upstream":"https://dekopon.dekopon.svc.cluster.local:9090","clientCertSecret":"vm-runner-jail-models-tls"}))
            .unwrap(),
    );
    assert!(config.conflicts().is_empty());
    let id = f.session();
    assert!(matches!(
        f.controller.exec(SUBJECT, &id, &exec()).await.unwrap(),
        ExecResponse::Pending(_)
    ));
    let captured = f.captured.lock().unwrap();
    let pod = &captured[0];
    assert!(pod["spec"]["volumes"].as_array().unwrap().contains(&json!(
        {"name":"models-tls","secret":{"secretName":"vm-runner-jail-models-tls","defaultMode":0o400}}
    )));
    assert!(
        pod["spec"]["containers"][0]["volumeMounts"]
            .as_array()
            .unwrap()
            .contains(&json!({"name":"models-tls","mountPath":"/models-tls","readOnly":true}))
    );
    let bytes = STANDARD
        .decode(captured[1]["data"]["config.json"].as_str().unwrap())
        .unwrap();
    let guest: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        guest["jails"]["models"],
        json!({"upstream":"https://dekopon.dekopon.svc.cluster.local:9090","clientCertSecret":"vm-runner-jail-models-tls","subject":"dekopon:default"})
    );
    let parsed: Config = serde_json::from_slice(&bytes).unwrap();
    assert!(parsed.conflicts().is_empty());
}
#[tokio::test]
async fn without_models_the_pod_and_jail_config_are_unchanged() {
    let f = Fixture::new().await;
    let id = f.session();
    assert!(matches!(
        f.controller.exec(SUBJECT, &id, &exec()).await.unwrap(),
        ExecResponse::Pending(_)
    ));
    let captured = f.captured.lock().unwrap();
    assert!(!captured[0].to_string().contains("models"));
    let bytes = STANDARD
        .decode(captured[1]["data"]["config.json"].as_str().unwrap())
        .unwrap();
    let guest: Value = serde_json::from_slice(&bytes).unwrap();
    assert!(guest["jails"].get("models").is_none());
}
