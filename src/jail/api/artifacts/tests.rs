use super::*;
use crate::{guest, jail::api};
use poem::{EndpointExt, test::TestClient};
use serde_json::json;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    task::JoinSet,
};

struct Fixture {
    client: TestClient<poem::endpoint::BoxEndpoint<'static, poem::Response>>,
    state: Arc<State>,
    tasks: JoinSet<()>,
    _dir: tempfile::TempDir,
}
impl Fixture {
    async fn new(data: Vec<u8>, short: bool) -> Self {
        let auth = crate::tests::Fixture::new().await;
        let mut claims = auth.claims();
        claims["aud"] = json!(["vm-runner-jail"]);
        claims["sub"] = json!("system:serviceaccount:test:controller");
        let token = auth.token(&claims, "ec");
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("guest.sock");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let mut tasks = JoinSet::new();
        tasks.spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let mut stream = BufReader::new(stream);
                let mut hello = String::new();
                if stream.read_line(&mut hello).await.unwrap() == 0 { continue; }
                assert_eq!(hello, "CONNECT 1024\n");
                if stream.write_all(b"OK 1234\n").await.is_err() { continue; }
                let frame = match guest::read_frame(&mut stream).await {
                    Ok(frame) => frame,
                    Err(guest::Error::Io(error)) if matches!(error.kind(), io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset) => continue,
                    Err(error) => panic!("{error}"),
                };
                let request: Request = serde_json::from_slice(&frame).unwrap();
                let response = match request {
                    Request::List => json!([{"path":"nested/artifact.bin","bytes":data.len(),"sha256":"a".repeat(64)}, {"path":"empty","bytes":0,"sha256":"b".repeat(64)}]),
                    Request::Read { path, offset, len } => {
                        assert_eq!(path, PathBuf::from("nested/artifact.bin"));
                        assert!(len <= CHUNK);
                        let end = (offset as usize + len as usize).min(data.len());
                        json!({"data":STANDARD.encode(if short { &[] } else { &data[offset as usize..end] }),"eof":end==data.len()})
                    }
                    _ => panic!("unexpected guest operation"),
                };
                if let Err(error) = guest::write_frame(&mut stream, &response).await {
                    assert!(matches!(error, guest::Error::Io(error) if matches!(error.kind(), io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset)));
                }
            }
        });
        let (endpoint, _, state) = api::endpoint(
            auth.config.auth,
            claims["sub"].as_str().unwrap().into(),
            Arc::new(Guest::new(path)),
        )
        .await
        .unwrap();
        state.mark_ready();
        Self {
            client: TestClient::new(endpoint.boxed())
                .default_header("Authorization", format!("Bearer {token}")),
            state,
            tasks,
            _dir: dir,
        }
    }
    async fn close(mut self) {
        self.tasks.abort_all();
        while let Some(result) = self.tasks.join_next().await {
            assert!(result.unwrap_err().is_cancelled());
        }
        self.state.drain().await.unwrap();
    }
}
#[tokio::test]
async fn artifact_bytes_ranges_nested_paths_and_sha_headers_match_metadata() {
    let data: Vec<u8> = (0..CHUNK as usize * 2 + 9)
        .map(|n| (n % 251) as u8)
        .collect();
    let fixture = Fixture::new(data.clone(), false).await;
    fixture
        .client
        .get("/artifacts")
        .send()
        .await
        .assert_status_is_ok();
    let response = fixture
        .client
        .get("/artifacts/nested%2Fartifact.bin")
        .send()
        .await;
    response.assert_status_is_ok();
    response.assert_header("sha256", "a".repeat(64));
    response.assert_header("content-length", data.len().to_string());
    response.assert_header("accept-ranges", "bytes");
    assert_eq!(response.0.into_body().into_vec().await.unwrap(), data);
    for (path, expected, sha) in [
        ("nested%2Fartifact.bin", &data[..], "a"),
        ("empty", &[], "b"),
    ] {
        let response = fixture
            .client
            .get(format!("/artifacts/{path}"))
            .header("Range", "items=0-1")
            .send()
            .await;
        response.assert_status_is_ok();
        response.assert_header("content-length", expected.len().to_string());
        response.assert_header("sha256", sha.repeat(64));
        assert_eq!(response.0.into_body().into_vec().await.unwrap(), expected);
    }
    for (range, start, end) in [
        ("ByTeS=1-3", 1, 4),
        ("bytes=-3", data.len() - 3, data.len()),
        ("bytes=65536-", 65536, data.len()),
        ("bytes=-999999", 0, data.len()),
    ] {
        let response = fixture
            .client
            .get("/artifacts/nested%2Fartifact.bin")
            .header("Range", range)
            .send()
            .await;
        response.assert_status(StatusCode::PARTIAL_CONTENT);
        response.assert_header(
            "content-range",
            format!("bytes {start}-{}/{}", end - 1, data.len()),
        );
        response.assert_header("sha256", "a".repeat(64));
        assert_eq!(
            response.0.into_body().into_vec().await.unwrap(),
            data[start..end]
        );
    }
    let response = fixture
        .client
        .get("/artifacts/nested%2Fartifact.bin")
        .header("Range", "bytes=999999-")
        .send()
        .await;
    response.assert_status(StatusCode::RANGE_NOT_SATISFIABLE);
    response.assert_header("content-range", format!("bytes */{}", data.len()));
    fixture
        .client
        .get("/artifacts/empty")
        .header("Range", "bytes=-1")
        .send()
        .await
        .assert_status(StatusCode::RANGE_NOT_SATISFIABLE);
    fixture
        .client
        .get("/artifacts/..%2Fsecret")
        .send()
        .await
        .assert_status(StatusCode::FORBIDDEN);
    fixture.close().await;
}
#[tokio::test]
async fn response_bodies_hold_bounded_admission_until_cancelled() {
    let fixture = Fixture::new(vec![42; CHUNK as usize + 1], false).await;
    let mut bodies = Vec::new();
    for _ in 0..4 {
        bodies.push(
            fixture
                .client
                .get("/artifacts/nested%2Fartifact.bin")
                .send()
                .await,
        );
    }
    assert_eq!(fixture.state.transfers.available_permits(), 0);
    fixture
        .client
        .get("/artifacts/nested%2Fartifact.bin")
        .send()
        .await
        .assert_status(StatusCode::SERVICE_UNAVAILABLE);
    drop(bodies);
    assert_eq!(fixture.state.transfers.available_permits(), 4);
    fixture.close().await;
}
#[tokio::test]
async fn a_short_guest_chunk_fails_the_body_instead_of_succeeding_with_truncation() {
    let exporter = crate::tests::trace_exporter();
    let fixture = Fixture::new(vec![42; 10], true).await;
    let response = fixture
        .client
        .get("/artifacts/nested%2Fartifact.bin")
        .header(
            "traceparent",
            "00-55555555555555555555555555555555-6666666666666666-01",
        )
        .send()
        .await;
    response.assert_status_is_ok();
    assert!(matches!(
        response.0.into_body().into_bytes().await,
        Err(poem::error::ReadBodyError::Io(_))
    ));
    assert_eq!(fixture.state.transfers.available_permits(), 4);
    fixture.close().await;
    let spans = exporter.get_finished_spans().unwrap();
    let reads: Vec<_> = spans
        .iter()
        .filter(|span| {
            span.name == "vm_runner.artifact.read"
                && span.span_context.trace_id().to_string() == "55555555555555555555555555555555"
        })
        .collect();
    assert_eq!(reads.len(), 1);
    assert!(crate::tests::span_attribute(reads[0], "error.message").is_some());
}
