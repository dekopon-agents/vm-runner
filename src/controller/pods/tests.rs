use super::*;

fn pod(finished: Option<u64>) -> Pod {
    let mut value =
        json!({"metadata":{"creationTimestamp":"1970-01-01T00:00:00Z"},"spec":{"containers":[]}});
    if let Some(finished) = finished {
        value["status"] = json!({"initContainerStatuses":[{"name":"fetch","image":"guest","imageID":"guest","ready":false,"restartCount":0,
            "state":{"terminated":{"exitCode":0,"finishedAt":k8s_openapi::jiff::Timestamp::from_second(i64::try_from(finished).unwrap()).unwrap()}}}]});
    }
    serde_json::from_value(value).unwrap()
}

#[test]
fn boot_window_starts_after_init_completes_not_at_pod_creation() {
    assert!(boot_window(&pod(None), 900, 600).is_ok());
    assert!(boot_window(&pod(Some(600)), 900, 659).is_ok());
    assert!(matches!(
        boot_window(&pod(Some(600)), 900, 660),
        Err(Error::Boot("startup timed out"))
    ));
    assert!(matches!(
        boot_window(&pod(Some(600)), 900, 700),
        Err(Error::Boot("startup timed out"))
    ));
}

#[test]
fn image_fetch_has_its_own_configurable_timeout_and_failed_init_is_terminal() {
    assert!(boot_window(&pod(None), 900, 899).is_ok());
    assert!(matches!(
        boot_window(&pod(None), 900, 900),
        Err(Error::Boot("fetch timed out"))
    ));
    assert!(boot_window(&pod(None), 1200, 1000).is_ok());
    let mut failed = pod(Some(600));
    failed
        .status
        .as_mut()
        .unwrap()
        .init_container_statuses
        .as_mut()
        .unwrap()[0]
        .state
        .as_mut()
        .unwrap()
        .terminated
        .as_mut()
        .unwrap()
        .exit_code = 1;
    assert!(matches!(
        boot_window(&failed, 900, 600),
        Err(Error::Boot("fetch failed"))
    ));
}
