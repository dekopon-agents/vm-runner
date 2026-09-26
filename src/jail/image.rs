use super::{Error, Result};
use oci_client::{Client, Reference, manifest::OciImageManifest, secrets::RegistryAuth};
use std::{
    io,
    path::{Path, PathBuf},
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::io::AsyncWrite;

const ROOTFS: &str = "org.dekopon.vm-runner.guest.rootfs";
const KERNEL: &str = "org.dekopon.vm-runner.guest.kernel";
const MAX_LAYER: u64 = 16 * 1024 * 1024 * 1024;
const MAX_ROOTFS: u64 = 64 * 1024 * 1024 * 1024;

fn reference(digest: &str) -> Result<Reference> {
    let reference: Reference = digest.parse()?;
    let hash = reference.digest().and_then(|s| s.strip_prefix("sha256:"));
    if !hash.is_some_and(|s| s.len() == 64 && s.bytes().all(|c| c.is_ascii_hexdigit())) {
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
        || [rootfs, kernel]
            .iter()
            .any(|l| l.size <= 0 || l.size as u64 > MAX_LAYER)
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
    Ok(())
}

pub async fn fetch(digest: &str, cache: &Path) -> Result<()> {
    let reference = reference(digest)?;
    let destination = directory(cache, digest)?;
    let cache = cache.to_owned();
    let runtime = tokio::runtime::Handle::current();
    // The init process owns one fetch; keep flock and staging cleanup with it even if its caller cancels.
    tokio::task::spawn_blocking(move || {
        std::fs::create_dir_all(&cache)?;
        let lock = std::fs::File::open(&cache)?;
        lock.lock()?;
        if destination.is_dir() {
            return Ok(());
        }
        let staging = tempfile::tempdir_in(&cache)?;
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
                .await?;
            for (layer, filename) in layers(&manifest)?
                .into_iter()
                .zip(["rootfs.zst", "vmlinux"])
            {
                pull_layer(&client, &reference, layer, &staging.path().join(filename)).await?;
            }
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        })?;
        use io::Read;
        let compressed = std::fs::File::open(staging.path().join("rootfs.zst"))?;
        let mut decoder = zstd::stream::read::Decoder::new(compressed)?.take(MAX_ROOTFS + 1);
        let mut rootfs = std::fs::File::create(staging.path().join("rootfs.ext4"))?;
        if io::copy(&mut decoder, &mut rootfs)? > MAX_ROOTFS {
            return Err(Error::ImageLayers.into());
        }
        std::fs::remove_file(staging.path().join("rootfs.zst"))?;
        // Jail root has no DAC_OVERRIDE and may differ from the init container's cache owner.
        use std::os::unix::fs::PermissionsExt;
        for file in ["rootfs.ext4", "vmlinux"] {
            std::fs::set_permissions(
                staging.path().join(file),
                std::fs::Permissions::from_mode(0o444),
            )?;
        }
        std::fs::set_permissions(staging.path(), std::fs::Permissions::from_mode(0o755))?;
        std::fs::rename(staging.path(), destination)?;
        Ok(())
    })
    .await?
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
    fn cache_names_require_a_sha256_pin() {
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
        manifest.layers[0].size = MAX_LAYER as i64 + 1;
        assert!(matches!(
            layers(&manifest).unwrap_err().downcast_ref::<Error>(),
            Some(Error::ImageLayers)
        ));
    }
}
