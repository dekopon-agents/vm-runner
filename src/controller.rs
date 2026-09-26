use crate::config::Config;
use k8s_openapi::api::core::v1::Pod;
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
struct Session {
    body: SessionBody,
    subject: String,
    created: u64,
    active: u64,
    pod: Option<String>,
    retiring: bool,
}
pub(crate) struct Controller {
    config: Arc<Config>,
    pods: Api<Pod>,
    // Rebuilt entries use pod names as keys, so even duplicate session IDs count toward quota.
    sessions: Mutex<HashMap<String, Session>>,
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
                    retiring: pod.metadata.deletion_timestamp.is_some()
                        || matches!(
                            pod.status.as_ref().and_then(|s| s.phase.as_deref()),
                            Some("Failed" | "Succeeded")
                        ),
                })
            });
            // Foreign/inconsistent pods are not ours to adopt or delete.
            let Some(mut session) = recovered else {
                continue;
            };
            if !session.retiring {
                session.retiring = !ids.insert(session.body.session_id.clone())
                    || !names.insert((session.subject.clone(), session.body.name.clone()));
            }
            let name = session.pod.as_ref().expect("recovered pod has a name");
            if session.retiring && pod.metadata.deletion_timestamp.is_none() {
                let gone = async {
                    match delete_pod(&pods, name).await {
                        Ok(gone) => gone,
                        Err(error) => {
                            tracing::warn!(%error, "pod cleanup failed; retrying next tick");
                            false
                        }
                    }
                }
                .instrument(tracing::info_span!(
                    "vm_runner.reap",
                    k8s.pod.name = name,
                    cause = "terminal_or_duplicate"
                ))
                .await;
                if gone {
                    continue;
                }
            }
            sessions.insert(name.clone(), session);
        }
        Ok(Self {
            config,
            pods,
            sessions: Mutex::new(sessions),
        })
    }
    pub(crate) fn create(&self, subject: &str, request: Create) -> poem::Result<Created> {
        let name = request.name.as_deref().unwrap_or("default");
        if !valid_name(name) {
            return Ok(Created::refused(Failure::BadName));
        }
        let mut sessions = self.sessions.lock().expect("session registry poisoned");
        if let Some(existing) = sessions
            .values()
            .find(|s| !s.retiring && s.subject == subject && s.body.name == name)
        {
            return Ok(if existing.body.profile == request.profile {
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
        sessions.insert(
            body.session_id.clone(),
            Session {
                body: body.clone(),
                subject: subject.into(),
                created: now(),
                active: now(),
                pod: None,
                retiring: false,
            },
        );
        Ok(Created::New(Json(body)))
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
                let expired = self
                    .config
                    .profiles
                    .0
                    .iter()
                    .find(|(n, _)| n == &s.body.profile)
                    .is_some_and(|(_, p)| {
                        now.saturating_sub(s.created) >= p.max_seconds
                            || now.saturating_sub(s.active) >= p.idle_seconds
                    });
                if !s.retiring && !expired {
                    return None;
                }
                let was_retiring = s.retiring;
                s.retiring = true;
                Some((
                    key.clone(),
                    s.body.session_id.clone(),
                    s.pod.clone(),
                    was_retiring,
                ))
            })
            .collect();
        for (key, id, pod, was_retiring) in expired {
            async {
                let result = async {
                    let Some(pod) = pod else { return Ok(true) };
                    if was_retiring {
                        let Some(current) = self.pods.get_opt(&pod).await? else {
                            return Ok(true);
                        };
                        if current.metadata.deletion_timestamp.is_some() {
                            return Ok(false);
                        }
                    }
                    delete_pod(&self.pods, &pod).await
                }
                .await;
                match result {
                    Ok(true) => {
                        self.sessions
                            .lock()
                            .expect("session registry poisoned")
                            .remove(&key);
                    }
                    Ok(false) => {}
                    Err(error) => tracing::warn!(%error, "pod cleanup failed; retrying next tick"),
                }
            }
            .instrument(tracing::info_span!(
                "vm_runner.reap",
                vm_runner.session_id = id
            ))
            .await;
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
