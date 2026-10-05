use std::{
    collections::BTreeMap,
    io::{self, Read, Seek},
    path::{Component, Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use aws_lc_rs::digest::{Context, SHA256};
use base64::{Engine, engine::general_purpose::STANDARD};
use cap_std::fs::{Dir, File, OpenOptions, OpenOptionsExt};
use nix::{
    sys::signal::{Signal, kill},
    unistd::Pid,
};
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    process::Command,
    time::{Instant, timeout},
};

pub(crate) const FRAME_CAP: usize = 1024 * 1024;
const OUTPUT_CAP: usize = 64 * 1024;
// Base64 plus the JSON envelope must fit in one response frame.
const READ_CAP: u32 = ((FRAME_CAP - 64) / 4 * 3) as u32;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("frame exceeds 1 MiB")]
    FrameTooLarge,
    #[error("invalid request: {0}")]
    Json(#[from] serde_json::Error),
    #[error("guest I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("invalid exec arguments")]
    InvalidExec,
    #[error("artifact path escapes root")]
    PathEscape,
    #[error("artifact is not a regular file")]
    NotFile,
    #[error("invalid artifact read length")]
    InvalidLength,
}

impl Error {
    fn reason(&self) -> &'static str {
        match self {
            Self::FrameTooLarge => "frame_too_large",
            Self::Json(_) => "invalid_request",
            Self::Io(_) => "io",
            Self::InvalidExec => "invalid_exec",
            Self::PathEscape => "path_escape",
            Self::NotFile => "not_file",
            Self::InvalidLength => "invalid_length",
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "op")]
pub(crate) enum Request {
    #[serde(rename = "exec", rename_all = "camelCase")]
    Exec {
        argv: Vec<String>,
        stdin: Option<String>,
        deadline_ms: u32,
        env: Option<BTreeMap<String, String>>,
        cwd: Option<PathBuf>,
    },
    #[serde(rename = "artifacts.list")]
    List,
    #[serde(rename = "artifacts.read")]
    Read {
        path: PathBuf,
        offset: u64,
        len: u32,
    },
    #[serde(rename = "ping")]
    Ping,
}

#[derive(Serialize)]
#[serde(untagged)]
enum Response {
    Exec(Executed),
    Refused {
        outcome: &'static str,
        reason: &'static str,
    },
    List(Vec<Artifact>),
    Read {
        data: String,
        eof: bool,
    },
    Pong {
        ok: bool,
    },
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Executed {
    outcome: &'static str,
    exit_code: i32,
    stdout: String,
    stderr: String,
    truncated: bool,
    duration_ms: u64,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    timed_out: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    cpu_us: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    memory_peak_bytes: Option<u64>,
}

#[derive(Serialize)]
struct Artifact {
    path: String,
    bytes: u64,
    sha256: String,
}

struct Guest {
    artifacts: PathBuf,
    home: PathBuf,
    identity: Option<(u32, u32)>,
}

pub async fn serve(stream: impl AsyncRead + AsyncWrite + Unpin) -> Result<(), Error> {
    Guest {
        artifacts: "/artifacts".into(),
        home: "/home/jail".into(),
        identity: Some((1000, 1000)),
    }
    .serve(stream)
    .await
}

impl Guest {
    async fn serve(&self, mut stream: impl AsyncRead + AsyncWrite + Unpin) -> Result<(), Error> {
        let bytes = read_frame(&mut stream).await?;
        let result = match serde_json::from_slice(&bytes) {
            Ok(request) => self.dispatch(request).await,
            Err(error) => Err(error.into()),
        };
        let response = match result {
            Ok(response) => response,
            Err(error) => Response::Refused {
                outcome: "not_executed",
                reason: error.reason(),
            },
        };
        write_frame(&mut stream, &response).await?;
        stream.shutdown().await?;
        Ok(())
    }

    async fn dispatch(&self, request: Request) -> Result<Response, Error> {
        match request {
            Request::Exec {
                argv,
                stdin,
                deadline_ms,
                env,
                cwd,
            } => {
                if argv.first().is_none_or(String::is_empty) || deadline_ms > 600_000 {
                    return Err(Error::InvalidExec);
                }
                let mut command = Command::new(&argv[0]);
                command
                    .args(&argv[1..])
                    .env_clear()
                    .env("PATH", "/usr/local/bin:/usr/bin:/bin")
                    .envs(
                        std::env::var_os("NODE_EXTRA_CA_CERTS")
                            .map(|value| ("NODE_EXTRA_CA_CERTS", value)),
                    )
                    .envs(env.unwrap_or_default())
                    .env("HOME", &self.home)
                    .current_dir(cwd.as_deref().unwrap_or(&self.home))
                    .process_group(0)
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .kill_on_drop(true);
                if let Some((uid, gid)) = self.identity {
                    command.uid(uid).gid(gid);
                }
                Ok(Response::Exec(execute(command, stdin, deadline_ms).await?))
            }
            Request::List => self.artifacts(list).await,
            Request::Read { path, offset, len } => {
                self.artifacts(move |root| read(root, &path, offset, len))
                    .await
            }
            Request::Ping => Ok(Response::Pong { ok: true }),
        }
    }

    async fn artifacts(
        &self,
        operation: impl FnOnce(&Dir) -> Result<Response, Error> + Send + 'static,
    ) -> Result<Response, Error> {
        let path = self.artifacts.clone();
        // The sequential listener awaits this single worker before admitting another request.
        tokio::task::spawn_blocking(move || {
            let root = Dir::open_ambient_dir(path, cap_std::ambient_authority())?;
            operation(&root)
        })
        .await
        .map_err(io::Error::other)?
    }
}

fn confined_error(error: io::Error) -> Error {
    if error.kind() == io::ErrorKind::PermissionDenied {
        Error::PathEscape
    } else {
        Error::Io(error)
    }
}

fn open_artifact(root: &Dir, path: &Path) -> Result<File, Error> {
    if path
        .components()
        .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err(Error::PathEscape);
    }
    // Resolve beneath the open root atomically; a separate canonicalize/check races with renames.
    let file = root
        .open_with(
            path,
            OpenOptions::new()
                .read(true)
                .custom_flags(rustix::fs::OFlags::NONBLOCK.bits() as i32),
        )
        .map_err(confined_error)?;
    if !file.metadata()?.is_file() {
        return Err(Error::NotFile);
    }
    Ok(file)
}

fn read(root: &Dir, path: &Path, offset: u64, len: u32) -> Result<Response, Error> {
    if len > FRAME_CAP as u32 {
        return Err(Error::InvalidLength);
    }
    let mut file = open_artifact(root, path)?;
    let size = file.metadata()?.len();
    file.seek(io::SeekFrom::Start(offset))?;
    let mut data = Vec::new();
    file.take(u64::from(len.min(READ_CAP)))
        .read_to_end(&mut data)?;
    Ok(Response::Read {
        eof: offset.saturating_add(data.len() as u64) >= size,
        data: STANDARD.encode(data),
    })
}

fn list(root: &Dir) -> Result<Response, Error> {
    let mut directories = vec![(PathBuf::new(), root.entries()?)];
    let mut artifacts = Vec::new();
    let mut encoded_size = 2;
    while let Some((parent, directory)) = directories.last_mut() {
        let Some(entry) = directory.next() else {
            directories.pop();
            continue;
        };
        let entry = entry?;
        let kind = entry.file_type()?;
        let relative = parent.join(entry.file_name());
        if kind.is_dir() {
            let directory = root.read_dir(&relative).map_err(confined_error)?;
            directories.push((relative, directory));
        } else if kind.is_file() {
            let mut file = open_artifact(root, &relative)?;
            let mut hash = Context::new(&SHA256);
            let mut bytes = 0;
            let mut buffer = [0; 8192];
            loop {
                let n = file.read(&mut buffer)?;
                if n == 0 {
                    break;
                }
                hash.update(&buffer[..n]);
                bytes += n as u64;
            }
            let artifact = Artifact {
                path: relative.to_string_lossy().into_owned(),
                bytes,
                sha256: hash
                    .finish()
                    .as_ref()
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect(),
            };
            encoded_size += serde_json::to_vec(&artifact)?.len() + 1;
            if encoded_size > FRAME_CAP {
                return Err(Error::FrameTooLarge);
            }
            artifacts.push(artifact);
        }
    }
    artifacts.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(Response::List(artifacts))
}

pub(crate) async fn read_frame(stream: &mut (impl AsyncRead + Unpin)) -> Result<Vec<u8>, Error> {
    let size = stream.read_u32().await? as usize;
    if size > FRAME_CAP {
        return Err(Error::FrameTooLarge);
    }
    let mut bytes = vec![0; size];
    stream.read_exact(&mut bytes).await?;
    Ok(bytes)
}
pub(crate) async fn write_frame(
    stream: &mut (impl AsyncWrite + Unpin),
    value: &impl Serialize,
) -> Result<(), Error> {
    let bytes = serde_json::to_vec(value)?;
    if bytes.len() > FRAME_CAP {
        return Err(Error::FrameTooLarge);
    }
    stream.write_u32(bytes.len() as u32).await?;
    stream.write_all(&bytes).await?;
    Ok(())
}

struct ProcessGroup(Option<Pid>);
impl ProcessGroup {
    fn kill(&mut self) -> io::Result<()> {
        if let Some(pid) = self.0.take() {
            match kill(pid, Signal::SIGKILL) {
                Ok(()) | Err(nix::errno::Errno::ESRCH) => {}
                Err(error) => return Err(io::Error::from_raw_os_error(error as i32)),
            }
        }
        Ok(())
    }
}
impl Drop for ProcessGroup {
    fn drop(&mut self) {
        if let Err(error) = self.kill() {
            tracing::error!(name: "vm_runner.exec.cleanup_failed", target: crate::config::Category::VmExec.target(), {
                telemetry.detail = crate::telemetry::detail!(crate::config::Category::VmExec), %error,
            }, "guest process-group cleanup failed");
        }
    }
}

#[derive(Default)]
struct Output {
    bytes: Vec<u8>,
    truncated: bool,
}
impl Output {
    async fn drain(&mut self, mut stream: impl AsyncRead + Unpin) -> io::Result<()> {
        let mut buffer = [0; 8192];
        loop {
            let n = stream.read(&mut buffer).await?;
            if n == 0 {
                return Ok(());
            }
            let keep = n.min(OUTPUT_CAP - self.bytes.len());
            self.bytes.extend_from_slice(&buffer[..keep]);
            self.truncated |= keep < n;
        }
    }

    fn text(self) -> (String, bool) {
        let mut text = String::from_utf8_lossy(&self.bytes).into_owned();
        let mut end = text.len().min(OUTPUT_CAP);
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        let truncated = self.truncated || end < text.len();
        text.truncate(end);
        (text, truncated)
    }
}

// Each spawned pid names one cgroup. Failure to measure is never an exec failure.
struct ExecCgroup(PathBuf);
impl ExecCgroup {
    fn attach(root: &Path, pid: u32) -> Option<Self> {
        let path = root.join(format!("exec-{pid}"));
        std::fs::create_dir(&path).ok()?;
        let group = Self(path);
        std::fs::write(group.0.join("cgroup.procs"), pid.to_string()).ok()?;
        Some(group)
    }

    fn measurements(&self) -> Option<(u64, u64)> {
        let stat = std::fs::read_to_string(self.0.join("cpu.stat")).ok()?;
        let cpu = stat
            .lines()
            .find_map(|line| line.strip_prefix("usage_usec "))?
            .parse()
            .ok()?;
        let peak = std::fs::read_to_string(self.0.join("memory.peak"))
            .ok()?
            .trim()
            .parse()
            .ok()?;
        Some((cpu, peak))
    }

    async fn finish(self) -> Option<(u64, u64)> {
        let values = self.measurements();
        let _ = self.release().await;
        values
    }

    // Detached daemons (browse's Chromium, agent-browser) outlive their exec by design, so
    // survivors move to the parent group instead of pinning this one.
    async fn release(&self) -> Option<()> {
        let parent = self.0.parent()?.join("cgroup.procs");
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let events = std::fs::read_to_string(self.0.join("cgroup.events")).ok()?;
            if events.lines().any(|line| line == "populated 0") {
                return std::fs::remove_dir(&self.0).ok();
            }
            if Instant::now() >= deadline {
                return None;
            }
            for pid in std::fs::read_to_string(self.0.join("cgroup.procs"))
                .ok()?
                .split_whitespace()
            {
                drop(std::fs::write(&parent, pid));
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}
impl Drop for ExecCgroup {
    fn drop(&mut self) {
        drop(std::fs::remove_dir(&self.0));
    }
}

async fn execute(
    mut command: Command,
    input: Option<String>,
    deadline_ms: u32,
) -> Result<Executed, Error> {
    let start = Instant::now();
    let mut child = command.spawn()?;
    let pid = child
        .id()
        .ok_or_else(|| io::Error::other("child has no pid"))?;
    let mut group = ProcessGroup(Some(Pid::from_raw(-(pid as i32))));
    let cgroup = ExecCgroup::attach(Path::new("/sys/fs/cgroup"), pid);
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| io::Error::other("missing stdin"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("missing stdout"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("missing stderr"))?;
    let mut out = Output::default();
    let mut err = Output::default();
    let work = async {
        tokio::try_join!(child.wait(), out.drain(stdout), err.drain(stderr), async {
            if let Some(input) = input
                && let Err(error) = stdin.write_all(input.as_bytes()).await
                && error.kind() != io::ErrorKind::BrokenPipe
            {
                return Err(error);
            }
            drop(stdin);
            Ok(())
        })
    };
    let result = timeout(Duration::from_millis(u64::from(deadline_ms)), work).await;
    let ended = match result {
        Ok(Ok((status, (), (), ()))) => {
            use std::os::unix::process::ExitStatusExt;
            Ok((
                status
                    .code()
                    .unwrap_or_else(|| -status.signal().unwrap_or(1)),
                false,
            ))
        }
        failure => {
            async {
                group.kill()?;
                child.start_kill()?;
                child.wait().await?;
                if let Ok(Err(error)) = failure {
                    return Err(error);
                }
                Ok::<_, io::Error>((-9, true))
            }
            .await
        }
    };
    let duration = start.elapsed();
    let killed = group.kill();
    let measurements = match cgroup {
        Some(cgroup) => cgroup.finish().await,
        None => None,
    };
    let (exit_code, timed_out) = ended?;
    killed?;
    let (stdout, out_truncated) = out.text();
    let (stderr, err_truncated) = err.text();
    Ok(Executed {
        outcome: "executed",
        exit_code,
        stdout,
        stderr,
        truncated: out_truncated || err_truncated,
        duration_ms: duration.as_millis().try_into().unwrap_or(u64::MAX),
        timed_out,
        cpu_us: measurements.map(|(cpu, _)| cpu),
        memory_peak_bytes: measurements.map(|(_, peak)| peak),
    })
}

#[cfg(test)]
mod tests;
