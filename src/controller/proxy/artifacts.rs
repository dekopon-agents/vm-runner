use super::*;
use poem_openapi::{param::Header, payload::Binary};

#[derive(Object, Deserialize)]
#[oai(rename = "ControllerArtifact")]
struct Artifact {
    path: String,
    bytes: u64,
    sha256: String,
}
#[derive(ApiResponse)]
enum ListResponse {
    #[oai(status = 200)]
    Files(Json<Vec<Artifact>>),
    #[oai(status = 401)]
    Unauthorized(Json<crate::Refusal>),
}
#[derive(ApiResponse)]
enum Download {
    #[oai(status = 200)]
    Whole(
        Binary<poem::Body>,
        #[oai(header = "sha256")] String,
        #[oai(header = "Content-Length")] u64,
        #[oai(header = "Accept-Ranges")] String,
    ),
    #[oai(status = 206)]
    Partial(
        Binary<poem::Body>,
        #[oai(header = "sha256")] String,
        #[oai(header = "Content-Length")] u64,
        #[oai(header = "Content-Range")] String,
        #[oai(header = "Accept-Ranges")] String,
    ),
    #[oai(status = 416)]
    Range(#[oai(header = "Content-Range")] String),
    #[oai(status = 401)]
    Unauthorized(Json<crate::Refusal>),
}
fn path_valid(path: &str) -> bool {
    !path.contains('\0')
        && path
            .split('/')
            .all(|p| !p.is_empty() && !matches!(p, "." | ".."))
}
fn hash_valid(hash: &str) -> bool {
    hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit())
}
fn status(response: reqwest::Response) -> Result<reqwest::Response, Error> {
    match response.status().as_u16() {
        200 | 206 | 416 => Ok(response),
        403 => Err(Error::Forbidden),
        404 => Err(Error::NotFound),
        503 => Err(Error::Unavailable),
        code => Err(Error::Status(code)),
    }
}
impl Controller {
    async fn artifacts(&self, subject: &str, id: &str) -> Result<Vec<Artifact>, Error> {
        let (key, session) = self.session(subject, id)?;
        let address = self.target(&key, &session).await?;
        let response = self
            .send(reqwest::Method::GET, address.join("artifacts")?, None)
            .await?;
        let files: Vec<Artifact> = json(checked(status(response)?, 200)?).await?;
        if files
            .iter()
            .any(|f| !path_valid(&f.path) || !hash_valid(&f.sha256))
        {
            return Err(Error::Protocol);
        }
        Ok(files)
    }
    async fn artifact(
        self: &Arc<Self>,
        subject: &str,
        id: &str,
        path: &str,
        range: Option<&str>,
    ) -> Result<Download, Error> {
        let (key, session) = self.session(subject, id)?;
        if !path_valid(path) {
            return Err(Error::Forbidden);
        }
        // HTTP admission ends at headers; the body owns this separate transfer bound until drop.
        let permit = Arc::clone(&self.downloads)
            .try_acquire_owned()
            .map_err(|_full| Error::Unavailable)?;
        let mut url = self.target(&key, &session).await?;
        url.path_segments_mut()
            .map_err(|()| Error::Protocol)?
            .extend(["artifacts", path]);
        let mut request = self.request(reqwest::Method::GET, url).await?;
        if let Some(range) = range {
            request = request.header("Range", range);
        }
        let response = status(request.send().await?)?;
        let header = |name: &str| {
            response
                .headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned)
                .ok_or(Error::Protocol)
        };
        if response.status().as_u16() == 416 {
            return Ok(Download::Range(header("Content-Range")?));
        }
        let hash = header("sha256")?;
        if !hash_valid(&hash) {
            return Err(Error::Protocol);
        }
        let length = header("Content-Length")?
            .parse::<u64>()
            .map_err(|_invalid_length| Error::Protocol)?;
        let content_range = if response.status().as_u16() == 206 {
            Some(header("Content-Range")?)
        } else {
            None
        };
        let owner = Arc::clone(self);
        // Body polling does no tracing: synchronous span export stays on the admitted request worker.
        let body = poem::Body::from_bytes_stream(futures_util::stream::try_unfold(
            (response, permit, owner, key),
            |(mut response, permit, owner, key)| async move {
                let chunk = response
                    .chunk()
                    .await
                    .map_err(|e| std::io::Error::other(Error::from(e)))?;
                if chunk.is_some()
                    && let Some(session) = owner
                        .sessions
                        .lock()
                        .expect("session registry poisoned")
                        .get_mut(&key)
                        .filter(|s| !s.retiring)
                {
                    session.active = now();
                }
                Ok::<_, std::io::Error>(chunk.map(|chunk| (chunk, (response, permit, owner, key))))
            },
        ));
        Ok(match content_range {
            Some(range) => Download::Partial(Binary(body), hash, length, range, "bytes".into()),
            None => Download::Whole(Binary(body), hash, length, "bytes".into()),
        })
    }
}
pub(crate) struct Api;
#[OpenApi]
impl Api {
    #[oai(path = "/v1/sessions/:id/artifacts", method = "get")]
    async fn list(
        &self,
        request: &poem::Request,
        state: poem::web::Data<&Arc<crate::State>>,
        id: Path<String>,
    ) -> Result<ListResponse, ResponseError> {
        let subject = match state.authenticate(request).await {
            Ok(s) => s,
            Err(r) => return Ok(ListResponse::Unauthorized(Json(r))),
        };
        Ok(ListResponse::Files(Json(
            controller(&state)?.artifacts(&subject, &id).await?,
        )))
    }
    #[oai(path = "/v1/sessions/:id/artifacts/:path", method = "get")]
    async fn read(
        &self,
        request: &poem::Request,
        state: poem::web::Data<&Arc<crate::State>>,
        id: Path<String>,
        path: Path<String>,
        #[oai(name = "Range")] range: Header<Option<String>>,
    ) -> Result<Download, ResponseError> {
        let subject = match state.authenticate(request).await {
            Ok(s) => s,
            Err(r) => return Ok(Download::Unauthorized(Json(r))),
        };
        Ok(controller(&state)?
            .artifact(&subject, &id, &path, range.0.as_deref())
            .instrument(tracing::info_span!(
                "vm_runner.artifact.read",
                vm_runner.session_id = crate::egress::cut(&id.0)
            ))
            .await?)
    }
}
#[cfg(test)]
mod tests;
