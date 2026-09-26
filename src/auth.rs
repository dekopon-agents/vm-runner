use crate::config::{Auth, Issuer, service_account};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, errors::ErrorKind, jwk::JwkSet};
use serde::Deserialize;
use std::{sync::Mutex, time::Duration};
use tokio::time::Instant;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, poem_openapi::Enum)]
#[serde(rename_all = "snake_case")]
#[oai(rename_all = "snake_case")]
pub(crate) enum Reason {
    Audience,
    Issuer,
    Expired,
    NotYetValid,
    Signature,
    UnknownSubject,
    Malformed,
}
impl Reason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Audience => "audience",
            Self::Issuer => "issuer",
            Self::Expired => "expired",
            Self::NotYetValid => "not_yet_valid",
            Self::Signature => "signature",
            Self::UnknownSubject => "unknown_subject",
            Self::Malformed => "malformed",
        }
    }
}
fn jwt_error(error: jsonwebtoken::errors::Error) -> Reason {
    match error.kind() {
        ErrorKind::InvalidAudience => Reason::Audience,
        ErrorKind::InvalidIssuer => Reason::Issuer,
        ErrorKind::ExpiredSignature => Reason::Expired,
        ErrorKind::ImmatureSignature => Reason::NotYetValid,
        ErrorKind::InvalidSignature | ErrorKind::InvalidAlgorithm => Reason::Signature,
        _ => Reason::Malformed,
    }
}
#[derive(Deserialize)]
struct Claims {
    iss: String,
    sub: String,
    exp: u64,
    iat: u64,
    nbf: Option<u64>,
}
struct Cache {
    keys: JwkSet,
    fetched: Instant,
    unknown: Option<Instant>,
}
struct Source {
    client: reqwest::Client,
    url: String,
    token_file: Option<std::path::PathBuf>,
    cache: Mutex<Cache>,
    refresh: tokio::sync::Mutex<()>,
}
pub(crate) struct Authenticator {
    config: Auth,
    sources: Vec<Source>,
}
#[derive(Debug, thiserror::Error)]
#[error("could not initialize issuer trust or JWKS")]
pub(crate) struct SetupError;
impl Source {
    #[expect(
        clippy::map_err_ignore,
        reason = "issuer transport errors must not expose bearer headers or response bodies"
    )]
    async fn fetch(&self) -> Result<JwkSet, Reason> {
        let mut request = self.client.get(&self.url);
        // Projected tokens rotate; a token read once at startup expires under a long-lived runner.
        if let Some(path) = &self.token_file {
            let token = tokio::fs::read_to_string(path)
                .await
                .map_err(|_| Reason::Signature)?;
            let mut value =
                reqwest::header::HeaderValue::from_str(&format!("Bearer {}", token.trim()))
                    .map_err(|_| Reason::Signature)?;
            value.set_sensitive(true);
            request = request.header(reqwest::header::AUTHORIZATION, value);
        }
        let mut response = request
            .send()
            .await
            .map_err(|_| Reason::Signature)?
            .error_for_status()
            .map_err(|_| Reason::Signature)?;
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| Reason::Signature)? {
            if bytes.len() + chunk.len() > 1024 * 1024 {
                return Err(Reason::Signature);
            }
            bytes.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&bytes).map_err(|_| Reason::Signature)
    }
    #[expect(
        clippy::map_err_ignore,
        reason = "startup errors must not expose CA-file contents"
    )]
    async fn new(issuer: &Issuer) -> Result<Self, SetupError> {
        let mut builder = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none());
        if let Some(path) = &issuer.ca_file {
            let pem = tokio::fs::read(path).await.map_err(|_| SetupError)?;
            builder = builder.add_root_certificate(
                reqwest::Certificate::from_pem(&pem).map_err(|_| SetupError)?,
            );
        }
        let mut source = Self {
            refresh: tokio::sync::Mutex::new(()),
            client: builder.build().map_err(|_| SetupError)?,
            token_file: issuer.token_file.clone(),
            url: format!("{}/openid/v1/jwks", issuer.issuer.trim_end_matches('/')),
            cache: Mutex::new(Cache {
                keys: JwkSet { keys: vec![] },
                fetched: Instant::now(),
                unknown: None,
            }),
        };
        let keys = source.fetch().await.map_err(|_| SetupError)?;
        source.cache.get_mut().map_err(|_| SetupError)?.keys = keys;
        Ok(source)
    }
    #[expect(
        clippy::map_err_ignore,
        reason = "poisoned trust state refuses authentication without exposing keys"
    )]
    async fn key(&self, kid: &str) -> Result<DecodingKey, Reason> {
        {
            let cache = self.cache.lock().map_err(|_| Reason::Signature)?;
            if cache.fetched.elapsed() < Duration::from_secs(600)
                && let Some(key) = cache.keys.find(kid)
            {
                return DecodingKey::from_jwk(key).map_err(jwt_error);
            }
        }
        // Only refreshers serialize over network I/O; cached-key readers never take this gate.
        let _refresh = self.refresh.lock().await;
        {
            let mut cache = self.cache.lock().map_err(|_| Reason::Signature)?;
            let stale = cache.fetched.elapsed() >= Duration::from_secs(600);
            let unknown = cache.keys.find(kid).is_none()
                && cache
                    .unknown
                    .is_none_or(|t| t.elapsed() >= Duration::from_secs(60));
            if !stale && !unknown {
                return DecodingKey::from_jwk(cache.keys.find(kid).ok_or(Reason::Signature)?)
                    .map_err(jwt_error);
            }
            if unknown {
                cache.unknown = Some(Instant::now());
            }
            cache.fetched = Instant::now();
        }
        let fetched = self.fetch().await;
        let mut cache = self.cache.lock().map_err(|_| Reason::Signature)?;
        match fetched {
            Ok(keys) => cache.keys = keys,
            // A failed refresh keeps serving keys already trusted; only unknown kids fail.
            Err(reason) if cache.keys.find(kid).is_none() => return Err(reason),
            Err(_) => {}
        }
        DecodingKey::from_jwk(cache.keys.find(kid).ok_or(Reason::Signature)?).map_err(jwt_error)
    }
}
impl Authenticator {
    pub async fn new(config: Auth) -> Result<Self, SetupError> {
        let mut sources = Vec::new();
        for issuer in &config.issuers {
            sources.push(Source::new(issuer).await?);
        }
        Ok(Self { config, sources })
    }
    pub async fn verify(&self, bearer: Option<&str>) -> Result<String, Reason> {
        let token = bearer
            .and_then(|s| s.strip_prefix("Bearer "))
            .ok_or(Reason::Malformed)?;
        let unsigned =
            jsonwebtoken::dangerous::insecure_decode::<Claims>(token).map_err(jwt_error)?;
        let index = self
            .config
            .issuers
            .iter()
            .position(|i| i.issuer == unsigned.claims.iss)
            .ok_or(Reason::Issuer)?;
        if !matches!(unsigned.header.alg, Algorithm::RS256 | Algorithm::ES256) {
            return Err(Reason::Signature);
        }
        let kid = unsigned.header.kid.as_deref().ok_or(Reason::Malformed)?;
        let key = self.sources[index].key(kid).await?;
        let mut validation = Validation::new(unsigned.header.alg);
        validation.leeway = 30;
        validation.validate_nbf = true;
        validation.set_audience(&[&self.config.audience]);
        validation.set_issuer(&[&self.config.issuers[index].issuer]);
        validation.set_required_spec_claims(&["exp", "iat", "iss", "sub", "aud"]);
        let claims = jsonwebtoken::decode::<Claims>(token, &key, &validation)
            .map_err(jwt_error)?
            .claims;
        let now = jsonwebtoken::get_current_timestamp();
        if claims.exp <= now.saturating_sub(30) {
            return Err(Reason::Expired);
        }
        if claims.iat > now.saturating_add(30)
            || claims.nbf.is_some_and(|n| n > now.saturating_add(30))
        {
            return Err(Reason::NotYetValid);
        }
        if !service_account(&claims.sub) || !self.config.subjects.contains(&claims.sub) {
            return Err(Reason::UnknownSubject);
        }
        Ok(claims.sub)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    async fn issuer(
        status: Arc<std::sync::atomic::AtomicU16>,
        seen: Arc<Mutex<Vec<String>>>,
    ) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let (status, seen) = (Arc::clone(&status), Arc::clone(&seen));
                let service = hyper::service::service_fn(move |req: hyper::Request<_>| {
                    let auth = req.headers()[hyper::header::AUTHORIZATION]
                        .to_str()
                        .unwrap();
                    seen.lock().unwrap().push(auth.to_owned());
                    let mut response = hyper::Response::new(http_body_util::Full::new(
                        hyper::body::Bytes::from_static(br#"{"keys":[{"kty":"EC","crv":"P-256","kid":"k","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}]}"#),
                    ));
                    *response.status_mut() = hyper::StatusCode::from_u16(
                        status.load(std::sync::atomic::Ordering::SeqCst),
                    )
                    .unwrap();
                    async move { Ok::<_, std::convert::Infallible>(response) }
                });
                hyper::server::conn::http1::Builder::new()
                    .keep_alive(false)
                    .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                    .await
                    .unwrap();
            }
        });
        url
    }

    #[tokio::test]
    async fn jwks_refresh_sends_the_rotated_token_and_keeps_cached_keys_on_failure() {
        let status = Arc::new(std::sync::atomic::AtomicU16::new(200));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let dir = tempfile::tempdir().unwrap();
        let token_file = dir.path().join("token");
        std::fs::write(&token_file, "first\n").unwrap();
        let source = Source::new(&Issuer {
            issuer: issuer(Arc::clone(&status), Arc::clone(&seen)).await,
            ca_file: None,
            token_file: Some(token_file.clone()),
        })
        .await
        .unwrap();
        std::fs::write(&token_file, "second").unwrap();
        status.store(401, std::sync::atomic::Ordering::SeqCst);
        source.cache.lock().unwrap().fetched = Instant::now()
            .checked_sub(Duration::from_secs(601))
            .unwrap();

        assert!(source.key("k").await.is_ok());
        assert!(matches!(source.key("other").await, Err(Reason::Signature)));
        assert_eq!(
            *seen.lock().unwrap(),
            ["Bearer first", "Bearer second", "Bearer second"]
        );
    }
}
