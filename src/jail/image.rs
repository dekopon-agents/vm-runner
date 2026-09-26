use super::{Error, Result};
use oci_client::{Client, Reference, manifest::OciImageManifest, secrets::RegistryAuth};
use std::{
    io,
    path::{Path, PathBuf},
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::io::{AsyncWrite, AsyncWriteExt};

const ROOTFS: &str = "org.dekopon.vm-runner.guest.rootfs";
const KERNEL: &str = "org.dekopon.vm-runner.guest.kernel";
const MAX_LAYER: u64 = 16 * 1024 * 1024 * 1024;
const MAX_ROOTFS: u64 = 16 * 1024 * 1024 * 1024;

#[expect(
    clippy::map_err_ignore,
    reason = "invalid references can contain credentials; do not echo their input"
)]
fn reference(digest: &str) -> Result<Reference> {
    let reference: Reference = digest.parse().map_err(|_| Error::ImageReference)?;
    if !reference.registry().eq_ignore_ascii_case("ghcr.io") {
        return Err(Error::RegistryHost.into());
    }
    if !crate::config::digest_pinned(digest) {
        return Err(Error::ImageReference.into());
    }
    Ok(reference)
}
pub(super) fn directory(cache: &Path, digest: &str) -> Result<PathBuf> {
    let reference = reference(digest)?;
    let hash = reference
        .digest()
        .ok_or(Error::ImageReference)?
        .replace(':', "-");
    Ok(cache.join(format!("{hash}-{}", std::env::consts::ARCH)))
}
fn layers(manifest: &OciImageManifest) -> Result<[&oci_client::manifest::OciDescriptor; 2]> {
    let find = |key, value| {
        manifest.layers.iter().find(|layer| {
            layer
                .annotations
                .as_ref()
                .and_then(|a| a.get(key))
                .is_some_and(|v| v == value)
        })
    };
    let rootfs = find(ROOTFS, "rootfs.ext4").ok_or(Error::ImageLayers)?;
    let kernel = find(KERNEL, "vmlinux").ok_or(Error::ImageLayers)?;
    if manifest.layers.len() != 2
        || std::ptr::eq(rootfs, kernel)
        || [rootfs, kernel].iter().any(|l| {
            l.size <= 0
                || l.size as u64 > MAX_LAYER
                || l.urls.as_ref().is_some_and(|urls| !urls.is_empty())
        })
    {
        return Err(Error::ImageLayers.into());
    }
    Ok([rootfs, kernel])
}

struct SizedFile {
    file: tokio::fs::File,
    remaining: u64,
}
impl AsyncWrite for SizedFile {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if bytes.len() as u64 > self.remaining {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "layer exceeds descriptor size",
            )));
        }
        let result = Pin::new(&mut self.file).poll_write(cx, bytes);
        if let Poll::Ready(Ok(n)) = result {
            self.remaining -= n as u64;
        }
        result
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.file).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.file).poll_shutdown(cx)
    }
}

async fn pull_layer(
    client: &Client,
    reference: &Reference,
    layer: &oci_client::manifest::OciDescriptor,
    path: &Path,
) -> Result<()> {
    let mut file = SizedFile {
        file: tokio::fs::File::create(path).await?,
        remaining: layer.size as u64,
    };
    client.pull_blob(reference, layer, &mut file).await?;
    if file.remaining != 0 {
        return Err(Error::ImageLayers.into());
    }
    file.file.flush().await?;
    file.file.sync_all().await?;
    Ok(())
}

fn registry_error(error: oci_client::errors::OciDistributionError) -> Error {
    use oci_client::errors::OciDistributionError as E;
    let (kind, status) = match error {
        E::DigestError(_) => ("digest mismatch", None),
        E::UnauthorizedError { .. } | E::AuthenticationFailure(_) => ("authentication", None),
        E::ServerError { code, .. } => ("server response", Some(code)),
        E::RequestError(error) => (
            if error.is_timeout() {
                "timeout"
            } else if error.is_connect() {
                "connection"
            } else {
                "HTTP transfer"
            },
            error.status().map(|s| s.as_u16()),
        ),
        E::IoError(error) => return Error::RegistryIo(error.kind()),
        _ => ("protocol", None),
    };
    Error::Registry { kind, status }
}
fn unpack(reader: impl io::Read, writer: &mut impl io::Write, limit: u64) -> Result<()> {
    use io::Read;
    let mut decoder = zstd::stream::read::Decoder::new(reader)?.take(limit + 1);
    if io::copy(&mut decoder, writer)? > limit {
        return Err(Error::ImageLayers.into());
    }
    Ok(())
}
fn publish(staging: &Path, destination: &Path, cache: &std::fs::File) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    for name in ["rootfs.ext4", "vmlinux"] {
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(staging.join(name))?;
        file.set_permissions(std::fs::Permissions::from_mode(0o444))?;
        file.sync_all()?;
    }
    std::fs::set_permissions(staging, std::fs::Permissions::from_mode(0o755))?;
    std::fs::File::open(staging)?.sync_all()?;
    std::fs::rename(staging, destination)?;
    cache.sync_all()?;
    Ok(())
}

pub async fn fetch(digest: &str, cache: &Path) -> Result<()> {
    let digest = digest.to_owned();
    let cache = cache.to_owned();
    let runtime = tokio::runtime::Handle::current();
    let dispatch = tracing::dispatcher::get_default(Clone::clone);
    // The init process owns one fetch; keep flock and staging cleanup with it even if its caller cancels.
    tokio::task::spawn_blocking(move || {
        tracing::dispatcher::with_default(&dispatch, || {
            let span = tracing::info_span!(
                "vm_runner.boot",
                boot.phase = "fetch",
                error.message = tracing::field::Empty
            );
            span.in_scope(|| {
                let result = fetch_locked(&digest, &cache, &runtime);
                super::record_failure(&result);
                result
            })
        })
    })
    .await?
}
fn fetch_locked(digest: &str, cache: &Path, runtime: &tokio::runtime::Handle) -> Result<()> {
    let reference = reference(digest)?;
    let destination = directory(cache, digest)?;
    std::fs::create_dir_all(cache)?;
    let lock = std::fs::File::open(cache)?;
    lock.lock()?;
    if destination.is_dir() {
        return Ok(());
    }
    let staging = tempfile::tempdir_in(cache)?;
    runtime.block_on(async {
        let client = Client::new(oci_client::client::ClientConfig {
            read_timeout: Some(Duration::from_secs(60)),
            connect_timeout: Some(Duration::from_secs(30)),
            platform_resolver: Some(Box::new(|entries| {
                let arch = match std::env::consts::ARCH {
                    "x86_64" => "amd64",
                    "aarch64" => "arm64",
                    _ => return None,
                };
                entries
                    .iter()
                    .find(|entry| {
                        entry.platform.as_ref().is_some_and(|p| {
                            p.os == "linux".into() && p.architecture == arch.into()
                        })
                    })
                    .map(|entry| entry.digest.clone())
            })),
            ..Default::default()
        });
        let (manifest, _) = client
            .pull_image_manifest(&reference, &RegistryAuth::Anonymous)
            .await
            .map_err(registry_error)?;
        for (layer, filename) in layers(&manifest)?
            .into_iter()
            .zip(["rootfs.zst", "vmlinux"])
        {
            pull_layer(&client, &reference, layer, &staging.path().join(filename))
                .await
                .map_err(|error| {
                    match error.downcast::<oci_client::errors::OciDistributionError>() {
                        Ok(error) => Box::new(registry_error(*error))
                            as Box<dyn std::error::Error + Send + Sync>,
                        Err(error) => error,
                    }
                })?;
        }
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    })?;
    let compressed = std::fs::File::open(staging.path().join("rootfs.zst"))?;
    let mut rootfs = std::fs::File::create(staging.path().join("rootfs.ext4"))?;
    unpack(compressed, &mut rootfs, MAX_ROOTFS)?;
    drop(rootfs);
    std::fs::remove_file(staging.path().join("rootfs.zst"))?;
    publish(staging.path(), &destination, &lock)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn a_corrupt_registry_layer_is_refused_by_its_digest() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let reference: Reference = format!("{}/guest:fixture", listener.local_addr().unwrap())
            .parse()
            .unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            hyper::server::conn::http1::Builder::new()
                .serve_connection(
                    hyper_util::rt::TokioIo::new(stream),
                    hyper::service::service_fn(|_request| async {
                        Ok::<_, std::convert::Infallible>(
                            hyper::Response::builder()
                                .header("connection", "close")
                                .body(http_body_util::Full::new(hyper::body::Bytes::from_static(
                                    b"corrupt",
                                )))
                                .unwrap(),
                        )
                    }),
                )
                .await
                .unwrap();
        });
        let client = Client::new(oci_client::client::ClientConfig {
            protocol: oci_client::client::ClientProtocol::Http,
            ..Default::default()
        });
        let directory = tempfile::tempdir().unwrap();
        let descriptor = oci_client::manifest::OciDescriptor {
            size: 7,
            digest: format!("sha256:{}", "0".repeat(64)),
            ..Default::default()
        };
        let error = pull_layer(
            &client,
            &reference,
            &descriptor,
            &directory.path().join("layer"),
        )
        .await
        .unwrap_err();
        assert!(matches!(
            error.downcast_ref::<oci_client::errors::OciDistributionError>(),
            Some(oci_client::errors::OciDistributionError::DigestError(_))
        ));
        server.await.unwrap();
    }
    #[test]
    fn expanded_rootfs_cannot_escape_its_limit_and_only_complete_files_are_published() {
        let compressed = zstd::stream::encode_all(&b"123456789"[..], 0).unwrap();
        let error = unpack(&compressed[..], &mut Vec::new(), 8).unwrap_err();
        assert!(matches!(
            error.downcast_ref::<Error>(),
            Some(Error::ImageLayers)
        ));
        assert_eq!(MAX_ROOTFS, 16 * 1024 * 1024 * 1024);
        let cache = tempfile::tempdir().unwrap();
        let staging = tempfile::tempdir_in(cache.path()).unwrap();
        std::fs::write(staging.path().join("rootfs.ext4"), b"root").unwrap();
        std::fs::write(staging.path().join("vmlinux"), b"kernel").unwrap();
        let destination = cache.path().join("complete");
        publish(
            staging.path(),
            &destination,
            &std::fs::File::open(cache.path()).unwrap(),
        )
        .unwrap();
        assert!(!staging.path().exists());
        assert_eq!(
            std::fs::read(destination.join("rootfs.ext4")).unwrap(),
            b"root"
        );
        assert_eq!(
            std::fs::read(destination.join("vmlinux")).unwrap(),
            b"kernel"
        );
        assert!(
            std::fs::metadata(destination.join("rootfs.ext4"))
                .unwrap()
                .permissions()
                .readonly()
        );
    }
    #[test]
    fn cache_names_require_a_sha256_pin() {
        assert!(matches!(
            reference(&format!("evil.example/test@sha256:{}", "a".repeat(64)))
                .unwrap_err()
                .downcast_ref::<Error>(),
            Some(Error::RegistryHost)
        ));
        assert!(matches!(
            reference("ghcr.io/test/image:latest")
                .unwrap_err()
                .downcast_ref::<Error>(),
            Some(Error::ImageReference)
        ));
        let digest = format!("ghcr.io/test/image@sha256:{}", "a".repeat(64));
        assert_eq!(
            directory(Path::new("/cache"), &digest).unwrap(),
            Path::new("/cache").join(format!(
                "sha256-{}-{}",
                "a".repeat(64),
                std::env::consts::ARCH
            ))
        );
    }
    #[test]
    fn only_the_two_distinct_guest_layers_are_accepted() {
        let mut manifest = OciImageManifest::default();
        assert!(matches!(
            layers(&manifest).unwrap_err().downcast_ref::<Error>(),
            Some(Error::ImageLayers)
        ));
        for (key, name) in [(ROOTFS, "rootfs.ext4"), (KERNEL, "vmlinux")] {
            manifest.layers.push(oci_client::manifest::OciDescriptor {
                size: 1,
                annotations: Some([(key.to_owned(), name.to_owned())].into()),
                ..Default::default()
            });
        }
        assert!(layers(&manifest).is_ok());
        manifest.layers[0].urls = Some(vec!["http://127.0.0.1/foreign".into()]);
        assert!(matches!(
            layers(&manifest).unwrap_err().downcast_ref::<Error>(),
            Some(Error::ImageLayers)
        ));
        manifest.layers[0].urls = None;
        manifest.layers[0].size = MAX_LAYER as i64 + 1;
        assert!(matches!(
            layers(&manifest).unwrap_err().downcast_ref::<Error>(),
            Some(Error::ImageLayers)
        ));
    }
}
