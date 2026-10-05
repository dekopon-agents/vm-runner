use crate::config::Config;
use k8s_openapi::api::core::v1::{Pod, Secret};
mod pods;
pub(crate) mod proxy;
use kube::{
    Api, Client,
    api::{DeleteParams, ListParams},
};
use poem_openapi::{
    ApiResponse, Object,
    payload::{Json, PlainText},
};
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use tracing::Instrument;

const SESSION: &str = "vm-runner/session";
const PROFILE: &str = "vm-runner/profile";
const SUBJECT: &str = "vm-runner/subject";
const SUBJECT_HASH: &str = "vm-runner/subject-hash";
const NAME: &str = "vm-runner/name";
const CREATED: &str = "vm-runner/created";
const ACTIVE: &str = "vm-runner/active";
#[derive(Object)]
#[oai(deny_unknown_fields)]
pub(crate) struct Create {
    profile: String,
    name: Option<String>,
}
#[derive(Clone, Object)]
#[oai(rename_all = "camelCase")]
pub(crate) struct SessionBody {
    session_id: String,
    name: String,
    profile: String,
    shape: String,
    state: SessionState,
}
#[derive(Clone, Copy, poem_openapi::Enum)]
#[oai(rename_all = "snake_case")]
enum SessionState {
    Pending,
    Ready,
}
#[derive(Object)]
pub(crate) struct NotExecuted {
    outcome: NotExecutedOutcome,
    reason: Failure,
}
#[derive(poem_openapi::Enum)]
#[oai(rename_all = "snake_case")]
enum NotExecutedOutcome {
    NotExecuted,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, poem_openapi::Enum)]
#[oai(rename_all = "snake_case")]
enum Failure {
    Quota,
    BadProfile,
    BadName,
}
#[derive(Object)]
pub(crate) struct Conflict {
    error: ConflictCode,
}
#[derive(poem_openapi::Enum)]
#[oai(rename_all = "snake_case")]
enum ConflictCode {
    SessionProfileConflict,
}
#[derive(ApiResponse)]
pub(crate) enum Created {
    #[oai(status = 201)]
    New(Json<SessionBody>),
    #[oai(status = 200)]
    Existing(Json<SessionBody>),
    #[oai(status = 409)]
    Conflict(Json<Conflict>),
    #[oai(status = 400)]
    Refused(Json<NotExecuted>),
    #[oai(status = 401)]
    Unauthorized(Json<crate::Refusal>),
    #[oai(status = 503)]
    Unavailable(PlainText<&'static str>),
}
impl Created {
    fn refused(reason: Failure) -> Self {
        Self::Refused(Json(NotExecuted {
            outcome: NotExecutedOutcome::NotExecuted,
            reason,
        }))
    }
}
#[derive(Clone)]
struct Session {
    body: SessionBody,
    subject: String,
    created: u64,
    active: u64,
    pod: Option<String>,
    retiring: Option<EndReason>,
    boot_cause: Option<&'static str>,
    pod_end: PodEnd,
    pod_read: bool,
    starting: bool,
}
#[derive(Clone, Copy)]
enum EndReason {
    Idle,
    MaxSeconds,
    BootFailure,
    Duplicate,
    Terminal,
}
#[derive(Clone, Default)]
struct PodEnd {
    uid: Option<String>,
    phase: Option<String>,
    terminated_reason: Option<String>,
    exit_code: Option<i32>,
}
impl PodEnd {
    fn from_pod(pod: &Pod) -> Self {
        let terminated = pod
            .status
            .as_ref()
            .and_then(|s| s.container_statuses.as_ref())
            .and_then(|statuses| statuses.iter().find(|s| s.name == "jail"))
            .and_then(|s| s.state.as_ref())
            .and_then(|s| s.terminated.as_ref());
        Self {
            uid: pod.metadata.uid.clone(),
            phase: pod.status.as_ref().and_then(|s| s.phase.clone()),
            terminated_reason: terminated.and_then(|s| s.reason.clone()),
            exit_code: terminated.map(|s| s.exit_code),
        }
    }
}
enum ReapAttempt {
    First,
    Retry,
}
struct Expired {
    key: String,
    session_id: String,
    pod: Option<String>,
    attempt: ReapAttempt,
}
#[must_use]
fn remove_retired(
    sessions: &mut HashMap<String, Session>,
    key: &str,
    at: u64,
) -> Option<EndRecord> {
    let reason = sessions.get(key)?.retiring?;
    let session = sessions.remove(key)?;
    Some(EndRecord {
        session,
        reason,
        at,
    })
}
impl EndReason {
    const fn label(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::MaxSeconds => "max_seconds",
            Self::BootFailure => "boot_failure",
            Self::Duplicate => "duplicate",
            Self::Terminal => "terminal",
        }
    }
}
struct EndRecord {
    session: Session,
    reason: EndReason,
    at: u64,
}
impl EndRecord {
    fn emit(self) {
        let session = &self.session;
        let duration = i64::try_from(self.at.saturating_sub(session.created).saturating_mul(1000))
            .unwrap_or(i64::MAX);
        tracing::info!(name: "vm_runner.session.ended", target: crate::config::Category::VmLifecycle.target(), {
            telemetry.detail = crate::telemetry::detail!(crate::config::Category::VmLifecycle),
            vm_runner.session_id = %session.body.session_id,
            vm_runner.subject = %session.subject,
            vm_runner.profile = %session.body.profile,
            vm_runner.shape = %session.body.shape,
            vm_runner.session.end_reason = self.reason.label(),
            duration_ms = duration,
            k8s.pod.name = session.pod.as_deref(),
            k8s.pod.uid = session.pod_end.uid.as_deref(),
            k8s.pod.phase = session.pod_end.phase.as_deref(),
            vm_runner.jail.terminated_reason = session.pod_end.terminated_reason.as_deref(),
            vm_runner.jail.exit_code = session.pod_end.exit_code.map(i64::from),
            error = session.boot_cause,
        }, "session ended");
    }
}
impl Session {
    fn is_retiring(&self) -> bool {
        self.retiring.is_some()
    }
}
pub(crate) struct Controller {
    config: Arc<Config>,
    pods: Api<Pod>,
    // Rebuilt entries use pod names as keys, so even duplicate session IDs count toward quota.
    sessions: Mutex<HashMap<String, Session>>,
    secrets: Api<Secret>,
    jail_port: u16,
    jobs: Mutex<HashMap<String, proxy::Job>>,
    pub(super) execution: Arc<tokio::sync::Semaphore>,
    pub(super) reads: Arc<tokio::sync::Semaphore>,
    downloads: Arc<tokio::sync::Semaphore>,
}
pub(super) fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 63
        && name.as_bytes()[0].is_ascii_alphanumeric()
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}
fn subject_hash(subject: &str) -> String {
    aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, subject.as_bytes()).as_ref()[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

impl Controller {
    pub(crate) async fn new(config: Arc<Config>, client: Client) -> Result<Self, kube::Error> {
        let namespace = &config
            .jails
            .as_ref()
            .expect("controller requires jails config")
            .namespace;
        let secrets = Api::namespaced(client.clone(), namespace);
        let pods: Api<Pod> = Api::namespaced(client, namespace);
        let mut listed = pods
            .list(&ListParams::default().labels(SESSION))
            .await?
            .items;
        listed.sort_by(|a, b| {
            a.metadata
                .creation_timestamp
                .cmp(&b.metadata.creation_timestamp)
                .then_with(|| a.metadata.name.cmp(&b.metadata.name))
        });
        let mut sessions = HashMap::new();
        let mut names = HashSet::new();
        let mut ids = HashSet::new();
        for pod in listed {
            let labels = pod.metadata.labels.as_ref();
            let annotations = pod.metadata.annotations.as_ref();
            let fields = labels.zip(annotations).and_then(|(l, a)| {
                Some((
                    l.get(SESSION)?,
                    l.get(PROFILE)?,
                    a.get(SUBJECT)?,
                    a.get(NAME)?,
                    a.get(CREATED)?.parse::<u64>().ok()?,
                    a.get(ACTIVE)?.parse::<u64>().ok()?,
                ))
            });
            let recovered = fields.and_then(|(id, profile, subject, name, created, active)| {
                let (_, selected) = config.profiles.0.iter().find(|(n, _)| n == profile)?;
                if !valid_name(name)
                    || !config.auth.subjects.contains(subject)
                    || labels?.get(SUBJECT_HASH)? != &subject_hash(subject)
                    || !matches!(pod.spec.as_ref()?.containers.as_slice(), [container]
                        if container.image.as_deref() == config.jails.as_ref().map(|j| j.image.as_str()))
                    || pod.metadata.creation_timestamp.is_none()
                    || !uuid::Uuid::parse_str(id).is_ok_and(|id| id.get_version_num() == 7)
                {
                    return None;
                }
                Some(Session {
                    body: SessionBody {
                        session_id: id.clone(),
                        name: name.clone(),
                        profile: profile.clone(),
                        shape: selected.shape.clone(),
                        state: SessionState::Pending,
                    },
                    subject: subject.clone(),
                    created: created.min(now()),
                    active: active.min(now()),
                    pod: Some(pod.metadata.name.clone()?),
                    starting: false,
                    boot_cause: None,
                    pod_end: PodEnd::default(),
                    pod_read: false,
                    retiring: (pod.metadata.deletion_timestamp.is_some()
                        || matches!(pod.status.as_ref().and_then(|s| s.phase.as_deref()),
                            Some("Failed" | "Succeeded"))).then_some(EndReason::Terminal),
                })
            });
            // Foreign/inconsistent pods are not ours to adopt or delete.
            let Some(mut session) = recovered else {
                continue;
            };
            if !session.is_retiring()
                && (!ids.insert(session.body.session_id.clone())
                    || !names.insert((session.subject.clone(), session.body.name.clone())))
            {
                session.retiring = Some(EndReason::Duplicate);
            }
            let name = session.pod.as_ref().expect("recovered pod has a name");
            // The list is the pre-cleanup observation even for pods already deleting.
            if session.is_retiring() {
                session.pod_end = PodEnd::from_pod(&pod);
                session.pod_read = true;
            }
            if let Some(reason) = session
                .retiring
                .filter(|_| pod.metadata.deletion_timestamp.is_none())
            {
                // The listed pod is already a read of its status; no extra GET is needed.
                match delete_pod(&pods, name).await {
                    Ok(true) => {
                        EndRecord {
                            session,
                            reason,
                            at: now(),
                        }
                        .emit();
                        continue;
                    }
                    Ok(false) => {}
                    Err(error) => {
                        tracing::warn!(name: "vm_runner.reap.failed", target: crate::config::Category::VmLifecycle.target(), {
                        telemetry.detail = crate::telemetry::detail!(crate::config::Category::VmLifecycle),
                        vm_runner.session_id = %session.body.session_id,
                        k8s.pod.name = %name,
                        %error,
                    }, "pod cleanup failed; retrying next tick")
                    }
                }
            }
            sessions.insert(name.clone(), session);
        }
        Ok(Self {
            config,
            pods,
            sessions: Mutex::new(sessions),
            secrets,
            jail_port: 8080,
            jobs: Mutex::new(HashMap::new()),
            execution: Arc::new(tokio::sync::Semaphore::new(1)),
            reads: Arc::new(tokio::sync::Semaphore::new(1)),
            downloads: Arc::new(tokio::sync::Semaphore::new(1)),
        })
    }
    pub(crate) fn create(&self, subject: &str, request: Create) -> poem::Result<Created> {
        let name = request.name.as_deref().unwrap_or("default");
        if !valid_name(name) {
            return Ok(Created::refused(Failure::BadName));
        }
        let mut sessions = self.sessions.lock().expect("session registry poisoned");
        if let Some(existing) = sessions
            .values_mut()
            .find(|s| !s.is_retiring() && s.subject == subject && s.body.name == name)
        {
            return Ok(if existing.body.profile == request.profile {
                existing.active = now();
                Created::Existing(Json(existing.body.clone()))
            } else {
                Created::Conflict(Json(Conflict {
                    error: ConflictCode::SessionProfileConflict,
                }))
            });
        }
        let Some((_, profile)) = self
            .config
            .profiles
            .0
            .iter()
            .find(|(n, _)| n == &request.profile)
        else {
            return Ok(Created::refused(Failure::BadProfile));
        };
        let quota = self
            .config
            .quotas
            .subjects
            .0
            .iter()
            .find(|(s, _)| s == subject)
            .map_or(self.config.quotas.default, |(_, q)| *q);
        if sessions.values().filter(|s| s.subject == subject).count() >= quota.max_sessions as usize
        {
            return Ok(Created::refused(Failure::Quota));
        }
        let body = SessionBody {
            session_id: uuid::Uuid::now_v7().to_string(),
            name: name.into(),
            profile: request.profile,
            shape: profile.shape.clone(),
            state: SessionState::Pending,
        };
        let Some((_, shape)) = self
            .config
            .shapes
            .0
            .iter()
            .find(|(name, _)| name == &body.shape)
        else {
            return Ok(Created::refused(Failure::BadProfile));
        };
        sessions.insert(
            body.session_id.clone(),
            Session {
                body: body.clone(),
                subject: subject.into(),
                created: now(),
                active: now(),
                pod: None,
                retiring: None,
                boot_cause: None,
                pod_end: PodEnd::default(),
                pod_read: false,
                starting: false,
            },
        );
        tracing::info!(name: "vm_runner.session.started", target: crate::config::Category::VmLifecycle.target(), {
            telemetry.detail = crate::telemetry::detail!(crate::config::Category::VmLifecycle),
            vm_runner.session_id = %body.session_id,
            vm_runner.subject = %subject,
            vm_runner.profile = %body.profile,
            vm_runner.shape = %body.shape,
            vm_runner.shape.vcpu.count = i64::from(shape.vcpus.get()),
            vm_runner.shape.memory.bytes = i64::from(shape.memory.get()) * 1_048_576,
        }, "session started");
        Ok(Created::New(Json(body)))
    }
    pub(crate) fn health(&self) {
        let count = self
            .sessions
            .lock()
            .expect("session registry poisoned")
            .len();
        tracing::info!(name: "telemetry.health", target: crate::config::Category::Telemetry.target(), {
            telemetry.detail = crate::telemetry::detail!(crate::config::Category::Telemetry),
            rollup.interval_ms = i64::try_from(crate::ROLLUP_INTERVAL.as_millis()).unwrap_or(i64::MAX),
            vm_runner.session.live.count = i64::try_from(count).unwrap_or(i64::MAX),
        }, "telemetry healthy");
    }
    pub(crate) async fn reap(&self, now: u64) {
        // Mark under the same mutex used by create. Network I/O never owns admission
        // or the registry lock; retiring entries reserve quota, but cannot be returned.
        let expired: Vec<_> = self
            .sessions
            .lock()
            .expect("session registry poisoned")
            .iter_mut()
            .filter_map(|(key, s)| {
                let was_retiring = s.is_retiring();
                if !was_retiring {
                    s.retiring = self
                        .config
                        .profiles
                        .0
                        .iter()
                        .find(|(n, _)| n == &s.body.profile)
                        .and_then(|(_, p)| {
                            if now.saturating_sub(s.created) >= p.max_seconds {
                                Some(EndReason::MaxSeconds)
                            } else if now.saturating_sub(s.active) >= p.idle_seconds {
                                Some(EndReason::Idle)
                            } else {
                                None
                            }
                        });
                }
                s.retiring?;
                if s.starting {
                    return None;
                }
                Some(Expired {
                    key: key.clone(),
                    session_id: s.body.session_id.clone(),
                    pod: s.pod.clone(),
                    attempt: if was_retiring {
                        ReapAttempt::Retry
                    } else {
                        ReapAttempt::First
                    },
                })
            })
            .collect();
        for Expired {
            key,
            session_id,
            pod,
            attempt,
        } in expired
        {
            let result = async {
                let Some(pod) = pod else { return Ok(true) };
                // A failed status read must not prevent cleanup. Retry retains its
                // existing error/recheck semantics for an already-issued delete.
                let current = match self.pods.get_opt(&pod).await {
                    Ok(current) => current,
                    Err(_) if matches!(attempt, ReapAttempt::First) => None,
                    Err(error) => return Err(error),
                };
                if matches!(attempt, ReapAttempt::First)
                    && let Some(stored) = self
                        .sessions
                        .lock()
                        .expect("session registry poisoned")
                        .get_mut(&key)
                        .filter(|s| !s.pod_read)
                {
                    if let Some(current) = &current {
                        stored.pod_end = PodEnd::from_pod(current);
                    }
                    stored.pod_read = true;
                }
                if let Some(current) = current {
                    if matches!(attempt, ReapAttempt::Retry)
                        && current.metadata.deletion_timestamp.is_some()
                    {
                        return Ok(false);
                    }
                } else if matches!(attempt, ReapAttempt::Retry) {
                    return Ok(true);
                }
                delete_pod(&self.pods, &pod).await
            }
            .await;
            match result {
                Ok(true) => {
                    let (ended, live) = {
                        let mut sessions = self.sessions.lock().expect("session registry poisoned");
                        let ended = remove_retired(&mut sessions, &key, now);
                        let live = sessions
                            .values()
                            .any(|s| !s.is_retiring() && s.body.session_id == session_id);
                        (ended, live)
                    };
                    if let Some(ended) = ended {
                        ended.emit();
                    }
                    if !live {
                        self.jobs
                            .lock()
                            .expect("job registry poisoned")
                            .retain(|_, job| job.session != session_id);
                    }
                }
                Ok(false) => {}
                Err(error) => {
                    tracing::warn!(name: "vm_runner.reap.failed", target: crate::config::Category::VmLifecycle.target(), {
                        telemetry.detail = crate::telemetry::detail!(crate::config::Category::VmLifecycle),
                        vm_runner.session_id = %session_id,
                        %error,
                    }, "pod cleanup failed; retrying next tick")
                }
            }
        }
    }
}
async fn delete_pod(pods: &Api<Pod>, name: &str) -> Result<bool, kube::Error> {
    match pods.delete(name, &DeleteParams::default()).await {
        // A successful DELETE only starts termination; quota is held until GET returns 404.
        Ok(_) => Ok(false),
        Err(kube::Error::Api(error)) if error.code == 404 => Ok(true),
        Err(error) => Err(error),
    }
}
#[cfg(test)]
pub(crate) mod tests;
