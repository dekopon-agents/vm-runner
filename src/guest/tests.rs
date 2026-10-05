use super::*;
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::{
    fs,
    io::{DuplexStream, duplex},
};

fn guest() -> (TempDir, Guest) {
    let dir = tempfile::tempdir().unwrap();
    let guest = Guest {
        artifacts: dir.path().join("artifacts"),
        home: dir.path().to_owned(),
        identity: None,
    };
    std::fs::create_dir(&guest.artifacts).unwrap();
    (dir, guest)
}

async fn send(stream: &mut DuplexStream, request: Value) {
    let bytes = serde_json::to_vec(&request).unwrap();
    stream.write_u32(bytes.len() as u32).await.unwrap();
    stream.write_all(&bytes).await.unwrap();
}

async fn receive(stream: &mut DuplexStream) -> Value {
    let size = stream.read_u32().await.unwrap() as usize;
    assert!(size <= FRAME_CAP);
    let mut bytes = vec![0; size];
    stream.read_exact(&mut bytes).await.unwrap();
    assert_eq!(
        stream.read_u8().await.unwrap_err().kind(),
        io::ErrorKind::UnexpectedEof
    );
    serde_json::from_slice(&bytes).unwrap()
}

async fn call(guest: &Guest, request: Value) -> Value {
    let (mut client, server) = duplex(4096);
    let (result, response) = tokio::join!(guest.serve(server), async {
        send(&mut client, request).await;
        receive(&mut client).await
    });
    result.unwrap();
    response
}

fn exec(script: &str) -> Value {
    json!({"op":"exec", "argv":["/bin/sh", "-c", script], "deadlineMs":600000})
}

#[tokio::test]
async fn exec_delivers_stdin_environment_and_default_home() {
    let (_dir, guest) = guest();
    let mut request =
        exec("read line; printf '%s:%s:%s' \"$line\" \"$MARK\" \"$HOME\"; printf error >&2");
    request["stdin"] = json!("input\n");
    request["env"] = json!({"MARK":"value"});
    let response = call(&guest, request).await;
    assert_eq!(response["outcome"], "executed");
    assert_eq!(response["exitCode"], 0);
    assert_eq!(
        response["stdout"],
        format!("input:value:{}", guest.home.display())
    );
    assert_eq!(response["stderr"], "error");
    assert_eq!(response["truncated"], false);
    assert!(response["durationMs"].is_u64());
    assert!(response.get("timedOut").is_none());
    let mut request = exec("pwd");
    request["cwd"] = json!(guest.artifacts);
    assert_eq!(
        call(&guest, request).await["stdout"],
        format!("{}\n", guest.artifacts.canonicalize().unwrap().display())
    );
}

#[test]
fn per_command_cgroup_measurements_are_optional_on_failure() {
    let root = tempfile::tempdir().unwrap();
    assert!(ExecCgroup::attach(&root.path().join("missing"), 123).is_none());
    let group = ExecCgroup::attach(root.path(), 123).unwrap();
    assert_eq!(
        std::fs::read_to_string(group.0.join("cgroup.procs")).unwrap(),
        "123"
    );
    assert_eq!(group.measurements(), None);
    std::fs::write(group.0.join("cpu.stat"), "usage_usec 42\nuser_usec 40\n").unwrap();
    std::fs::write(group.0.join("memory.peak"), "8192\n").unwrap();
    assert_eq!(group.measurements(), Some((42, 8192)));
    let path = group.0.clone();
    std::fs::remove_file(path.join("cgroup.procs")).unwrap();
    std::fs::remove_file(path.join("cpu.stat")).unwrap();
    std::fs::remove_file(path.join("memory.peak")).unwrap();
    drop(group);
    assert!(!path.exists());
}

#[tokio::test]
async fn exec_reports_nonzero_exit_and_spawn_refusals() {
    let (_dir, guest) = guest();
    assert_eq!(call(&guest, exec("exit 7")).await["exitCode"], 7);
    for request in [
        json!({"op":"exec", "argv":[], "deadlineMs":1}),
        json!({"op":"exec", "argv":["/bin/true"], "deadlineMs":600001}),
    ] {
        assert_eq!(
            call(&guest, request).await,
            json!({"outcome":"not_executed", "reason":"invalid_exec"})
        );
    }
    assert_eq!(
        call(
            &guest,
            json!({"op":"exec", "argv":["/no/such/executable"], "deadlineMs":1})
        )
        .await,
        json!({"outcome":"not_executed", "reason":"io"})
    );
}

#[tokio::test]
async fn deadline_kills_the_child_and_its_grandchild() {
    let (_dir, guest) = guest();
    let ready = guest.home.join("ready");
    let (mut client, server) = duplex(4096);
    let task = tokio::spawn(async move { guest.serve(server).await });
    send(
        &mut client,
        exec("sleep 600 & printf '%s %s' \"$$\" \"$!\" > ready; wait"),
    )
    .await;
    let pids = timeout(Duration::from_secs(10), async {
        loop {
            if let Ok(text) = fs::read_to_string(&ready).await {
                let pids: Vec<u32> = text
                    .split_whitespace()
                    .filter_map(|v| v.parse().ok())
                    .collect();
                if pids.len() == 2 {
                    break pids;
                }
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(600)).await;
    let response = receive(&mut client).await;
    task.await.unwrap().unwrap();
    tokio::time::resume();
    assert_eq!(response["exitCode"], -9);
    assert_eq!(response["timedOut"], true);
    assert_eq!(response["outcome"], "executed");
    for pid in pids {
        timeout(Duration::from_secs(10), async {
            loop {
                let output = Command::new("ps")
                    .args(["-o", "stat=", "-p", &pid.to_string()])
                    .output()
                    .await
                    .unwrap();
                let state = String::from_utf8(output.stdout).unwrap();
                if state.trim().is_empty() || state.trim().starts_with('Z') {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn output_is_drained_but_each_stream_is_capped() {
    let (_dir, guest) = guest();
    let response = call(
        &guest,
        exec("head -c 70000 /dev/zero; head -c 70000 /dev/zero >&2"),
    )
    .await;
    assert_eq!(response["exitCode"], 0);
    assert_eq!(response["stdout"].as_str().unwrap().len(), OUTPUT_CAP);
    assert_eq!(response["stderr"].as_str().unwrap().len(), OUTPUT_CAP);
    assert_eq!(response["truncated"], true);
}

#[tokio::test]
async fn artifacts_list_hashes_nested_files_and_read_supports_offsets() {
    let (_dir, guest) = guest();
    fs::create_dir(guest.artifacts.join("nested"))
        .await
        .unwrap();
    fs::write(guest.artifacts.join("nested/file"), b"abc")
        .await
        .unwrap();
    assert_eq!(
        call(&guest, json!({"op":"artifacts.list"})).await,
        json!([{
            "path":"nested/file", "bytes":3,
            "sha256":"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        }])
    );
    assert_eq!(
        call(
            &guest,
            json!({"op":"artifacts.read", "path":"nested/file", "offset":1, "len":1})
        )
        .await,
        json!({"data":"Yg==", "eof":false})
    );
    assert_eq!(
        call(
            &guest,
            json!({"op":"artifacts.read", "path":"nested/file", "offset":2, "len":10})
        )
        .await,
        json!({"data":"Yw==", "eof":true})
    );
    fs::write(guest.artifacts.join("large"), vec![42; FRAME_CAP])
        .await
        .unwrap();
    let response = call(
        &guest,
        json!({"op":"artifacts.read", "path":"large", "offset":0, "len":FRAME_CAP}),
    )
    .await;
    assert_eq!(
        STANDARD
            .decode(response["data"].as_str().unwrap())
            .unwrap()
            .len(),
        READ_CAP as usize
    );
    assert_eq!(response["eof"], false);
}

#[tokio::test]
async fn artifacts_refuse_parent_and_symlink_escapes() {
    let (_dir, guest) = guest();
    fs::write(guest.home.join("secret"), b"secret")
        .await
        .unwrap();
    std::os::unix::fs::symlink(guest.home.join("secret"), guest.artifacts.join("link")).unwrap();
    for path in ["../secret", "link", "/etc/passwd"] {
        assert_eq!(
            call(
                &guest,
                json!({"op":"artifacts.read", "path":path, "offset":0, "len":100})
            )
            .await,
            json!({"outcome":"not_executed", "reason":"path_escape"})
        );
    }
    assert_eq!(
        call(&guest, json!({"op":"artifacts.list"})).await,
        json!([])
    );
}

#[tokio::test]
async fn replacement_after_canonicalization_cannot_escape_the_open_root() {
    for replace_parent in [false, true] {
        let (_dir, guest) = guest();
        fs::create_dir(guest.artifacts.join("nested"))
            .await
            .unwrap();
        fs::write(guest.artifacts.join("nested/file"), b"inside")
            .await
            .unwrap();
        let outside = guest.home.join("outside");
        fs::create_dir(&outside).await.unwrap();
        fs::write(outside.join("file"), b"outside secret")
            .await
            .unwrap();
        let root = Dir::open_ambient_dir(&guest.artifacts, cap_std::ambient_authority()).unwrap();
        let (checked, ready) = tokio::sync::oneshot::channel();
        let (replaced, changed) = tokio::sync::oneshot::channel();
        let worker = tokio::task::spawn_blocking(move || {
            let path = root.canonicalize("nested/file").unwrap();
            checked.send(()).unwrap();
            changed.blocking_recv().unwrap();
            open_artifact(&root, &path).map(|_| ())
        });
        ready.await.unwrap();
        if replace_parent {
            fs::rename(guest.artifacts.join("nested"), guest.home.join("moved"))
                .await
                .unwrap();
            std::os::unix::fs::symlink(&outside, guest.artifacts.join("nested")).unwrap();
        } else {
            fs::remove_file(guest.artifacts.join("nested/file"))
                .await
                .unwrap();
            std::os::unix::fs::symlink(outside.join("file"), guest.artifacts.join("nested/file"))
                .unwrap();
        }
        replaced.send(()).unwrap();
        assert!(matches!(worker.await.unwrap(), Err(Error::PathEscape)));
        assert_eq!(
            call(
                &guest,
                json!({"op":"artifacts.read", "path":"nested/file", "offset":0, "len":100})
            )
            .await,
            json!({"outcome":"not_executed", "reason":"path_escape"})
        );
        assert_eq!(
            call(&guest, json!({"op":"artifacts.list"})).await,
            json!([])
        );
    }
}

#[tokio::test]
async fn non_regular_artifacts_are_refused_without_blocking_on_open() {
    let (_dir, guest) = guest();
    assert!(
        Command::new("mkfifo")
            .arg(guest.artifacts.join("pipe"))
            .status()
            .await
            .unwrap()
            .success()
    );
    assert_eq!(
        call(
            &guest,
            json!({"op":"artifacts.read", "path":"pipe", "offset":0, "len":1})
        )
        .await,
        json!({"outcome":"not_executed", "reason":"not_file"})
    );
}

#[tokio::test]
async fn oversized_frame_is_refused_before_reading_its_body() {
    let (_dir, guest) = guest();
    let (mut client, server) = duplex(64);
    client.write_u32((FRAME_CAP + 1) as u32).await.unwrap();
    assert!(matches!(
        guest.serve(server).await,
        Err(Error::FrameTooLarge)
    ));
    assert_eq!(
        client.read_u8().await.unwrap_err().kind(),
        io::ErrorKind::UnexpectedEof
    );
}

#[tokio::test]
async fn ping_closes_after_one_response_and_malformed_json_is_refused() {
    let (_dir, guest) = guest();
    assert_eq!(call(&guest, json!({"op":"ping"})).await, json!({"ok":true}));
    assert_eq!(
        call(&guest, json!({"op":"no-such-op"})).await,
        json!({"outcome":"not_executed", "reason":"invalid_request"})
    );
}

// Run by CI in a privileged, private-cgroupns container. Never silently skip this witness:
// the job explicitly invokes the ignored test, and missing cgroup support fails it.
#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "requires writable cgroup v2; CI runs this in an isolated privileged container"]
async fn detached_descendants_survive_and_exec_cgroups_are_reaped() {
    struct Survivor(u32);
    impl Drop for Survivor {
        fn drop(&mut self) {
            drop(kill(Pid::from_raw(self.0 as i32), Signal::SIGKILL));
        }
    }
    let root = Path::new("/sys/fs/cgroup");
    assert!(
        root.join("cgroup.controllers").exists(),
        "cgroup v2 required"
    );
    for controller in ["cpu", "memory"] {
        assert!(
            std::fs::read_to_string(root.join("cgroup.subtree_control"))
                .unwrap()
                .split_whitespace()
                .any(|name| name == controller),
            "{controller} controller must be enabled"
        );
    }
    let (_dir, guest) = guest();
    let mut survivors = Vec::new();
    for _ in 0..4 {
        let start = Instant::now();
        let response = timeout(
            Duration::from_secs(5),
            call(
                &guest,
                exec(
                    "setsid sh -c 'exec sleep 30' </dev/null >/dev/null 2>&1 & daemon=$!; \
             until [ \"$(cut -d ' ' -f6 /proc/$daemon/stat)\" = \"$daemon\" ]; do :; done; \
             printf '%s %s' \"$$\" \"$daemon\"",
                ),
            ),
        )
        .await
        .expect("exec must not wait for the detached descendant");
        assert_eq!(response["exitCode"], 0, "{response}");
        let pids: Vec<u32> = response["stdout"]
            .as_str()
            .unwrap()
            .split_whitespace()
            .map(|pid| pid.parse().unwrap())
            .collect();
        assert_eq!(pids.len(), 2, "{response}");
        let (shell, daemon) = (pids[0], pids[1]);
        survivors.push(Survivor(daemon));
        assert!(
            start.elapsed() < Duration::from_secs(3),
            "exec waited on cleanup"
        );
        assert!(
            !root.join(format!("exec-{shell}")).exists(),
            "per-exec cgroup leaked"
        );
        let stat = fs::read_to_string(format!("/proc/{daemon}/stat"))
            .await
            .unwrap();
        assert!(
            !stat
                .rsplit_once(')')
                .unwrap()
                .1
                .trim_start()
                .starts_with('Z'),
            "daemon died"
        );
        assert!(
            std::fs::read_to_string(root.join("cgroup.procs"))
                .unwrap()
                .split_whitespace()
                .any(|pid| pid == daemon.to_string()),
            "daemon not moved to parent"
        );
        assert!(
            response["cpuUs"].is_u64(),
            "CPU measurement absent: {response}"
        );
        assert!(
            response["memoryPeakBytes"].is_u64(),
            "peak measurement absent: {response}"
        );
        assert_eq!(
            std::fs::read_dir(root)
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| entry.file_name().to_string_lossy().starts_with("exec-"))
                .count(),
            0,
            "repeated exec leaked a cgroup"
        );
    }
    drop(survivors); // Kill only test-owned daemons; production preserves them.
}

// The guest's PID 1 is tini with the agent as its only child; `tini -s` stands in for PID 1 here.
#[cfg(target_os = "linux")]
#[test]
fn orphaned_grandchildren_are_reaped_by_init_while_exec_exit_codes_stay_exact() {
    let status = std::process::Command::new("tini")
        .args(["-s", "--"])
        .arg(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "guest::tests::agent_under_init",
            "--ignored",
            "--nocapture",
        ])
        .status()
        .expect("tini, the guest's init, must be installed");
    assert!(status.success(), "agent under tini failed: {status}");
}

#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "runs as tini's child from orphaned_grandchildren_are_reaped_by_init_..."]
async fn agent_under_init() {
    let init = std::os::unix::process::parent_id();
    let (_dir, guest) = guest();
    // Like `browse`, each exec leaves a setsid orphan that outlives it and exits later.
    let responses = futures_util::future::join_all((0..8).map(|code| {
        call(
            &guest,
            exec(&format!(
                "setsid sleep 1 & until [ \"$(cut -d' ' -f6 /proc/$!/stat)\" = $! ]; do :; done; echo $!; exit {code}"
            )),
        )
    }))
    .await;
    for (code, response) in responses.iter().enumerate() {
        assert_eq!(response["exitCode"], code, "{response}");
        let orphan: u32 = response["stdout"].as_str().unwrap().trim().parse().unwrap();
        let stat = format!("/proc/{orphan}/stat");
        timeout(Duration::from_secs(10), async {
            while let Ok(text) = fs::read_to_string(&stat).await {
                let fields: Vec<&str> = text
                    .rsplit_once(')')
                    .unwrap()
                    .1
                    .split_whitespace()
                    .collect();
                assert_eq!(
                    fields[1].parse::<u32>().unwrap(),
                    init,
                    "orphan {orphan} not adopted by init"
                );
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("orphan {orphan} was never reaped"));
    }
}
