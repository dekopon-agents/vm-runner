#![cfg(unix)]
use super::super::tests::{Fixture, SUBJECT};
use super::*;
use poem::{IntoResponse, http::StatusCode, test::TestClient};
use serde_json::json;

async fn ready(f: &Fixture) -> String {
    let id = f.session();
    let (key, session) = f.controller.session(SUBJECT, &id).unwrap();
    f.controller.boot(&key, &session).await.unwrap();
    id
}
#[tokio::test]
async fn artifacts_require_auth_and_ownership_and_proxy_encoded_paths_ranges_and_hashes() {
    let mut f = Fixture::new().await;
    let id = f.session();
    assert!(matches!(
        f.controller.artifacts(SUBJECT, &id).await,
        Err(Error::NotFound)
    ));
    assert!(matches!(
        f.controller.artifact(SUBJECT, &id, "file", None).await,
        Err(Error::NotFound)
    ));
    let (key, session) = f.controller.session(SUBJECT, &id).unwrap();
    f.controller.boot(&key, &session).await.unwrap();
    let mut auth = crate::tests::Fixture::new().await;
    let token = auth.token(&auth.claims(), "ec");
    let state = crate::State {
        auth: crate::auth::Authenticator::new(auth.config.auth.clone())
            .await
            .unwrap(),
        config: Arc::new(auth.config),
        controller: Some(Arc::clone(&f.controller)),
    };
    let client = TestClient::new(crate::endpoint(
        Arc::new(state),
        Arc::new(tokio::sync::Semaphore::new(1)),
    ));
    let base = format!("/v1/sessions/{id}/artifacts");
    client
        .get(&base)
        .send()
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
    client
        .get(format!("{base}/..%2Fsecret"))
        .send()
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
    assert!(matches!(
        f.controller
            .artifacts("system:serviceaccount:other:caller", &id)
            .await,
        Err(Error::NotFound)
    ));
    assert!(matches!(
        f.controller
            .artifact(
                "system:serviceaccount:other:caller",
                &id,
                "nested/a file%.bin",
                None
            )
            .await,
        Err(Error::NotFound)
    ));
    client
        .get(&base)
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .assert_json(json!([{"path":"nested/a file%.bin","bytes":6,"sha256":"a".repeat(64)}]))
        .await;
    for (range, status, content, content_range) in [
        (None, 200, "abcdef", None),
        (Some("bytes=1-3"), 206, "bcd", Some("bytes 1-3/6")),
        (Some("bytes=99-"), 416, "", Some("bytes */6")),
    ] {
        let mut request = client
            .get(format!("{base}/nested%2Fa%20file%25.bin"))
            .header("Authorization", format!("Bearer {token}"));
        if let Some(range) = range {
            request = request.header("Range", range);
        }
        let response = request.send().await;
        response.assert_status(StatusCode::from_u16(status).unwrap());
        if status != 416 {
            response.assert_header("sha256", "a".repeat(64));
            response.assert_header("Content-Length", content.len().to_string());
            response.assert_header("Accept-Ranges", "bytes");
        }
        if let Some(range) = content_range {
            response.assert_header("Content-Range", range);
        }
        response.assert_text(content).await;
    }
    client
        .get(format!("{base}/..%2Fsecret"))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .assert_status(StatusCode::FORBIDDEN);
    auth.tasks.shutdown().await;
    f.tasks.shutdown().await;
}
#[tokio::test]
async fn transfer_slot_lasts_until_body_completion_or_drop_and_rejects_excess() {
    let mut f = Fixture::new().await;
    let id = ready(&f).await;
    let download = f
        .controller
        .artifact(SUBJECT, &id, "nested/a file%.bin", None)
        .await
        .unwrap();
    assert!(matches!(
        f.controller
            .artifact(SUBJECT, &id, "nested/a file%.bin", None)
            .await,
        Err(Error::Unavailable)
    ));
    assert_eq!(f.controller.artifacts(SUBJECT, &id).await.unwrap().len(), 1);
    drop(download);
    assert_eq!(f.controller.downloads.available_permits(), 1);
    let download = f
        .controller
        .artifact(SUBJECT, &id, "nested/a file%.bin", None)
        .await
        .unwrap();
    let (key, _) = f.controller.session(SUBJECT, &id).unwrap();
    f.controller
        .sessions
        .lock()
        .unwrap()
        .get_mut(&key)
        .unwrap()
        .active = 0;
    assert_eq!(
        download
            .into_response()
            .into_body()
            .into_vec()
            .await
            .unwrap(),
        b"abcdef"
    );
    assert_ne!(
        f.controller
            .sessions
            .lock()
            .unwrap()
            .get(&key)
            .unwrap()
            .active,
        0
    );
    assert_eq!(f.controller.downloads.available_permits(), 1);
    f.tasks.shutdown().await;
}
#[tokio::test]
async fn metadata_bounds_and_upstream_refusals_fail_closed_without_holding_transfer_slot() {
    let mut f = Fixture::new().await;
    let id = ready(&f).await;
    for (path, expected) in [
        ("missing", 404),
        ("forbidden", 403),
        ("unavailable", 503),
        ("malformed", 502),
        ("../secret", 403),
        ("/absolute", 403),
    ] {
        let error = f
            .controller
            .artifact(SUBJECT, &id, path, None)
            .await
            .err()
            .unwrap();
        assert!(matches!(
            (&error, expected),
            (Error::NotFound, 404)
                | (Error::Forbidden, 403)
                | (Error::Unavailable, 503)
                | (Error::Protocol, 502)
        ));
        assert_eq!(
            ResponseError::from(error).into_response().status().as_u16(),
            expected
        );
        assert_eq!(f.controller.downloads.available_permits(), 1);
    }
    *f.artifact_list.lock().unwrap() =
        json!([{"path":"../secret","bytes":0,"sha256":"a".repeat(64)}]).to_string();
    assert!(matches!(
        f.controller.artifacts(SUBJECT, &id).await,
        Err(Error::Protocol)
    ));
    *f.artifact_list.lock().unwrap() = " ".repeat(1_048_577);
    assert!(matches!(
        f.controller.artifacts(SUBJECT, &id).await,
        Err(Error::Protocol)
    ));
    f.tasks.shutdown().await;
}
#[tokio::test]
async fn stalled_transfer_times_out_and_releases_its_slot() {
    let mut f = Fixture::new().await;
    let id = ready(&f).await;
    let download = f
        .controller
        .artifact(SUBJECT, &id, "stall", None)
        .await
        .unwrap();
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(31)).await;
    let error = download
        .into_response()
        .into_body()
        .into_vec()
        .await
        .unwrap_err();
    let poem::error::ReadBodyError::Io(error) = error else {
        panic!("expected transport error")
    };
    assert!(matches!(
        error
            .get_ref()
            .and_then(|e| e.downcast_ref::<std::io::Error>())
            .and_then(std::io::Error::get_ref)
            .and_then(|e| e.downcast_ref::<Error>()),
        Some(Error::Http { timeout: true, .. })
    ));
    assert_eq!(f.controller.downloads.available_permits(), 1);
    f.tasks.shutdown().await;
}
