use crate::config::Config;
use k8s_openapi::api::core::v1::Pod;
use kube::{
    Api, Client,
    api::{DeleteParams, ListParams},
};
use poem_openapi::{ApiResponse, Object, payload::Json};
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use tracing::Instrument;

const SESSION: &str = "vm-runner/session";
const PROFILE: &str = "vm-runner/profile";
const SUBJECT: &str = "vm-runner/subject";
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
}
pub(crate) struct Controller {
    config: Arc<Config>,
    pods: Api<Pod>,
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
        fn key(pod: &Pod) -> (Option<&str>, Option<&str>) {
            (
                pod.metadata
                    .labels
                    .as_ref()
                    .and_then(|l| l.get(SESSION))
                    .map(String::as_str),
                pod.metadata.name.as_deref(),
            )
        }
        listed.sort_by(|a, b| key(a).cmp(&key(b)));
        let mut sessions = HashMap::new();
        let mut names = HashSet::new();
        for pod in listed {
            if pod.metadata.deletion_timestamp.is_some() {
                continue;
            }
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
                    || !crate::config::service_account(subject)
                    || !uuid::Uuid::parse_str(id).is_ok_and(|id| id.get_version_num() == 7)
                    || matches!(
                        pod.status.as_ref().and_then(|s| s.phase.as_deref()),
                        Some("Failed" | "Succeeded")
                    )
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
                    created,
                    active,
                    pod: pod.metadata.name.clone(),
                })
            });
            if let Some(session) = recovered
                && !sessions.contains_key(&session.body.session_id)
                && names.insert((session.subject.clone(), session.body.name.clone()))
            {
                sessions.insert(session.body.session_id.clone(), session);
            } else if let Some(name) = &pod.metadata.name {
                delete_pod(&pods, name)
                    .instrument(tracing::info_span!(
                        "vm_runner.reap",
                        k8s.pod.name = name,
                        cause = "unrecoverable_or_duplicate"
                    ))
                    .await?;
            }
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
            return Err(poem::Error::from_string(
                "invalid session name",
                poem::http::StatusCode::BAD_REQUEST,
            ));
        }
        let mut sessions = self.sessions.lock().expect("session registry poisoned");
        if let Some(existing) = sessions
            .values()
            .find(|s| s.subject == subject && s.body.name == name)
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
            },
        );
        Ok(Created::New(Json(body)))
    }
    pub(crate) async fn reap(&self, now: u64) -> Result<(), kube::Error> {
        let expired: Vec<_> = self
            .sessions
            .lock()
            .expect("session registry poisoned")
            .iter()
            .filter(|(_, s)| {
                self.config
                    .profiles
                    .0
                    .iter()
                    .find(|(n, _)| n == &s.body.profile)
                    .is_some_and(|(_, p)| {
                        now.saturating_sub(s.created) >= p.max_seconds
                            || now.saturating_sub(s.active) >= p.idle_seconds
                    })
            })
            .map(|(id, s)| (id.clone(), s.pod.clone()))
            .collect();
        for (id, pod) in expired {
            async {
                if let Some(pod) = pod {
                    delete_pod(&self.pods, &pod).await?;
                }
                self.sessions
                    .lock()
                    .expect("session registry poisoned")
                    .remove(&id);
                Ok::<_, kube::Error>(())
            }
            .instrument(tracing::info_span!(
                "vm_runner.reap",
                vm_runner.session_id = id
            ))
            .await?;
        }
        Ok(())
    }
}
async fn delete_pod(pods: &Api<Pod>, name: &str) -> Result<(), kube::Error> {
    match pods.delete(name, &DeleteParams::default()).await {
        Ok(_) => Ok(()),
        Err(kube::Error::Api(error)) if error.code == 404 => Ok(()),
        Err(error) => Err(error),
    }
}
#[cfg(test)]
mod tests;
