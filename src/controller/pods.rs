use super::proxy::Error;
use super::*;
use kube::{
    Resource,
    api::{Patch, PatchParams, PostParams},
};
use serde::Deserialize;
use serde_json::json;
use std::{collections::BTreeMap, path::Path, time::Duration};
use tokio::io::AsyncReadExt;
#[cfg(test)]
mod tests;

pub(super) async fn read(path: &Path) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    tokio::fs::File::open(path)
        .await?
        .take(1_048_577)
        .read_to_end(&mut bytes)
        .await?;
    if bytes.len() > 1_048_576 {
        return Err(Error::Protocol);
    }
    Ok(bytes)
}
// Kubernetes timestamps survive controller restarts and repeated exec attempts: neither
// retries nor a long image fetch reset or consume the guest's separate boot window.
fn boot_window(pod: &Pod, fetch_seconds: u64, now: u64) -> Result<(), Error> {
    let finished = pod
        .status
        .as_ref()
        .and_then(|s| s.init_container_statuses.as_ref())
        .and_then(|statuses| statuses.iter().find(|s| s.name == "fetch"))
        .and_then(|s| s.state.as_ref())
        .and_then(|s| s.terminated.as_ref());
    let (start, limit) = if let Some(finished) = finished {
        if finished.exit_code != 0 {
            return Err(Error::Boot);
        }
        (finished.finished_at.as_ref(), 60)
    } else {
        (pod.metadata.creation_timestamp.as_ref(), fetch_seconds)
    };
    let start = start.ok_or(Error::Protocol)?.0.as_second();
    if now.saturating_sub(u64::try_from(start)?) >= limit {
        return Err(Error::Boot);
    }
    Ok(())
}
struct Starting<'a>(&'a Controller, &'a str);
impl Drop for Starting<'_> {
    fn drop(&mut self) {
        if let Some(session) = self
            .0
            .sessions
            .lock()
            .expect("session registry poisoned")
            .get_mut(self.1)
        {
            session.starting = false;
        }
    }
}
impl Controller {
    pub(super) fn session(&self, subject: &str, id: &str) -> Result<(String, Session), Error> {
        self.sessions
            .lock()
            .expect("session registry poisoned")
            .iter()
            .find(|(_, s)| !s.retiring && s.subject == subject && s.body.session_id == id)
            .map(|(key, session)| (key.clone(), session.clone()))
            .ok_or(Error::NotFound)
    }
    pub(super) fn address(&self, pod: &Pod) -> Result<Option<url::Url>, Error> {
        if pod.metadata.deletion_timestamp.is_some()
            || matches!(
                pod.status.as_ref().and_then(|s| s.phase.as_deref()),
                Some("Failed" | "Succeeded")
            )
        {
            return Err(Error::Boot);
        }
        let Some(status) = &pod.status else {
            return Ok(None);
        };
        if !status.conditions.as_ref().is_some_and(|conditions| {
            conditions
                .iter()
                .any(|c| c.type_ == "Ready" && c.status == "True")
        }) {
            return Ok(None);
        }
        let ip: std::net::IpAddr = status
            .pod_ip
            .as_ref()
            .ok_or(Error::Protocol)?
            .parse()
            .map_err(Error::Address)?;
        Ok(Some(url::Url::parse(&format!(
            "http://{}/",
            std::net::SocketAddr::new(ip, self.jail_port)
        ))?))
    }
    pub(super) async fn target(&self, key: &str, session: &Session) -> Result<url::Url, Error> {
        let name = session.pod.as_ref().ok_or(Error::NotFound)?;
        let active = now();
        let pod = self
            .pods
            .patch(
                name,
                &PatchParams::default(),
                &Patch::Merge(json!({"metadata":{"annotations":{ACTIVE:active.to_string()}}})),
            )
            .await?;
        if let Some(stored) = self
            .sessions
            .lock()
            .expect("session registry poisoned")
            .get_mut(key)
            .filter(|s| !s.retiring)
        {
            stored.active = active;
        } else {
            return Err(Error::NotFound);
        }
        self.address(&pod)?.ok_or(Error::Boot)
    }
    pub(super) async fn boot(&self, key: &str, session: &Session) -> Result<url::Url, Error> {
        self.sessions
            .lock()
            .expect("session registry poisoned")
            .get_mut(key)
            .filter(|s| !s.retiring)
            .ok_or(Error::NotFound)?
            .starting = true;
        // A reap may retire this entry, but cannot free it while pod creation is in flight.
        let _starting = Starting(self, key);
        let name = session
            .pod
            .clone()
            .unwrap_or_else(|| format!("vm-runner-{}", session.body.session_id));
        let result = async {
            let mut pod = if session.pod.is_some() {
                self.pods.get(&name).await?
            } else {
                let (pod, mut secret) = self.manifests(session, &name).await?;
                // Record before create so a lost create response still leaves a reapable pod name.
                if let Some(stored) = self
                    .sessions
                    .lock()
                    .expect("session registry poisoned")
                    .get_mut(key)
                    .filter(|s| !s.retiring)
                {
                    stored.pod = Some(name.clone());
                } else {
                    return Err(Error::Boot);
                }
                let pod = self.pods.create(&PostParams::default(), &pod).await?;
                secret.metadata.owner_references =
                    Some(vec![pod.controller_owner_ref(&()).ok_or(Error::Protocol)?]);
                self.secrets.create(&PostParams::default(), &secret).await?;
                pod
            };
            let mut tick = tokio::time::interval(Duration::from_secs(1));
            let address = loop {
                if self
                    .sessions
                    .lock()
                    .expect("session registry poisoned")
                    .get(key)
                    .is_none_or(|s| s.retiring)
                {
                    return Err(Error::Boot);
                }
                let fetch_seconds = self
                    .config
                    .jails
                    .as_ref()
                    .ok_or(Error::Boot)?
                    .fetch_timeout_seconds;
                boot_window(&pod, fetch_seconds, now())?;
                if let Some(address) = self.address(&pod)? {
                    // A Ready pod can precede the jail listener or the guest's ping. Only
                    // these startup states are retried; auth and other failures propagate.
                    match self
                        .send(reqwest::Method::GET, address.join("healthz")?, None)
                        .await
                    {
                        Ok(response) if response.status().as_u16() == 200 => {
                            boot_window(&pod, fetch_seconds, now())?;
                            break address;
                        }
                        Ok(response) if response.status().as_u16() == 503 => {}
                        Ok(response) => return Err(Error::Status(response.status().as_u16())),
                        Err(Error::Http {
                            connect: true,
                            timeout: false,
                        }) => {}
                        Err(error) => return Err(error),
                    }
                }
                tick.tick().await;
                pod = self.pods.get(&name).await?;
            };
            if let Some(stored) = self
                .sessions
                .lock()
                .expect("session registry poisoned")
                .get_mut(key)
                .filter(|s| !s.retiring)
            {
                stored.body.state = SessionState::Ready;
            } else {
                return Err(Error::Boot);
            }
            Ok(address)
        }
        .instrument(tracing::info_span!(
            "vm_runner.boot",
            vm_runner.session_id = session.body.session_id
        ))
        .await;
        match result {
            Err(Error::Boot) => {
                let registered = {
                    let mut sessions = self.sessions.lock().expect("session registry poisoned");
                    let stored = sessions.get_mut(key).ok_or(Error::NotFound)?;
                    stored.retiring = true;
                    stored.pod.is_some()
                };
                if !registered || delete_pod(&self.pods, &name).await? {
                    self.sessions
                        .lock()
                        .expect("session registry poisoned")
                        .remove(key);
                    self.jobs
                        .lock()
                        .expect("job registry poisoned")
                        .retain(|_, job| job.session != session.body.session_id);
                }
                Err(Error::Boot)
            }
            other => other,
        }
    }
    async fn manifests(&self, session: &Session, name: &str) -> Result<(Pod, Secret), Error> {
        let jails = self.config.jails.as_ref().ok_or(Error::Boot)?;
        let profile = &self
            .config
            .profiles
            .0
            .iter()
            .find(|(n, _)| n == &session.body.profile)
            .ok_or(Error::Boot)?
            .1;
        let shape = &self
            .config
            .shapes
            .0
            .iter()
            .find(|(n, _)| n == &profile.shape)
            .ok_or(Error::Boot)?
            .1;
        #[derive(Deserialize)]
        struct Claims {
            sub: String,
            iss: String,
            aud: Vec<String>,
        }
        let token = read(&jails.token_file).await?;
        let token = std::str::from_utf8(&token)?;
        let claims = jsonwebtoken::dangerous::insecure_decode::<Claims>(token.trim())?.claims;
        if claims.sub != jails.controller_subject
            || !claims.aud.contains(&jails.controller_audience)
            || !self
                .config
                .auth
                .issuers
                .iter()
                .any(|i| i.issuer == claims.iss)
        {
            return Err(Error::Token);
        }
        let mut files = BTreeMap::new();
        let mut telemetry = serde_json::to_value(&self.config.telemetry)?;
        if let Some(t) = &self.config.telemetry {
            for (key, filename, path) in [
                ("caBundleFile", "otlp-ca", &t.otlp.ca_bundle_file),
                ("headersFile", "otlp-headers", &t.otlp.headers_file),
            ] {
                if let Some(path) = path {
                    files.insert(
                        filename.to_string(),
                        k8s_openapi::ByteString(read(path).await?),
                    );
                    telemetry["otlp"][key] = json!(format!("/config/{filename}"));
                }
            }
        }
        let mut jail_config = serde_json::to_value(jails)?;
        jail_config["tokenFile"] = json!("/kube/token");
        let config = json!({"listen":"0.0.0.0:8080", "jails":jail_config, "auth":{"audience":jails.controller_audience, "subjects":[jails.controller_subject],
            "issuers":[{"issuer":claims.iss,"caFile":"/kube/ca.crt","tokenFile":"/kube/token"}]},
            "profiles":{&session.body.profile:profile}, "shapes":{&profile.shape:shape},
            "quotas":{"default":{"maxSessions":1},"subjects":{}}, "telemetry":telemetry});
        files.insert(
            "config.json".into(),
            k8s_openapi::ByteString(serde_json::to_vec(&config)?),
        );
        let hash = subject_hash(&session.subject);
        let compute = json!({"cpu":shape.vcpus.to_string(), "memory":format!("{}Mi", u64::from(shape.memory.get())+128)});
        let mut resources = compute.clone();
        resources["smarter-devices/kvm"] = json!("1");
        resources["smarter-devices/net_tun"] = json!("1");
        let pod = serde_json::from_value(
            json!({"apiVersion":"v1", "kind":"Pod", "metadata":{"name":name,
            "labels":{SESSION:session.body.session_id, PROFILE:session.body.profile,SUBJECT_HASH:hash},
            "annotations":{SUBJECT:session.subject, NAME:session.body.name, CREATED:session.created.to_string(), ACTIVE:now().to_string()}},
            "spec":{"restartPolicy":"Never", "terminationGracePeriodSeconds":60, "serviceAccountName":"vm-runner-jail", "automountServiceAccountToken":false,
                "securityContext":{"fsGroup":1000, "seccompProfile":{"type":"RuntimeDefault"}, "sysctls":[
                    {"name":"net.ipv4.ip_forward","value":"0"}, {"name":"net.ipv4.ip_unprivileged_port_start","value":"0"}, {"name":"net.ipv4.conf.all.rp_filter","value":"1"}, {"name":"net.ipv4.conf.default.rp_filter","value":"1"}]},
                "initContainers":[{"name":"fetch", "image":jails.image, "args":["fetch-image","--digest",profile.image,"--cache","/images"], "resources":{"requests":compute,"limits":compute},
                    "securityContext":{"runAsUser":0,"runAsGroup":1000,"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]}},
                    "volumeMounts":[{"name":"images","mountPath":"/images"}]}],
                "containers":[{"name":"jail","image":jails.image,"args":["jail","--config","/config/config.json","--profile",session.body.profile,"--session",session.body.session_id],
                    "env":[{"name":"OTEL_RESOURCE_ATTRIBUTES","value":format!("vm_runner.subject={}",session.subject)}],
                    "securityContext":{"runAsUser":0,"runAsGroup":1000,"privileged":false,"allowPrivilegeEscalation":false,"readOnlyRootFilesystem":true,"capabilities":{"drop":["ALL"],"add":["NET_ADMIN","SETUID","SETGID"]}},
                    "resources":{"requests":resources,"limits":resources}, "readinessProbe":{"tcpSocket":{"port":8080},"periodSeconds":1},
                    "volumeMounts":[{"name":"images","mountPath":"/images","readOnly":true},{"name":"runtime","mountPath":"/run/vm-runner"},{"name":"console","mountPath":"/run/vm-runner/console"},{"name":"config","mountPath":"/config","readOnly":true},{"name":"api","mountPath":"/kube","readOnly":true}]}],
                "volumes":[{"name":"images","hostPath":{"path":jails.image_cache_host_path,"type":"DirectoryOrCreate"}},
                    {"name":"runtime","emptyDir":{"sizeLimit":format!("{}Mi",u64::from(shape.disk.get())+64)}},
                    {"name":"console","emptyDir":{"sizeLimit":"16Mi"}},
                    {"name":"config","secret":{"secretName":name,"defaultMode":256}},
                    {"name":"api","projected":{"defaultMode":256,"sources":[{"serviceAccountToken":{"path":"token","expirationSeconds":3600}},{"configMap":{"name":"kube-root-ca.crt","items":[{"key":"ca.crt","path":"ca.crt"}]}}]}}]}}),
        )?;
        Ok((
            pod,
            Secret {
                metadata: kube::api::ObjectMeta {
                    name: Some(name.into()),
                    ..Default::default()
                },
                data: Some(files),
                ..Default::default()
            },
        ))
    }
}
