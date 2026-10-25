#![cfg_attr(test, allow(clippy::unwrap_used, clippy::disallowed_methods))]
#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let listener =
        tokio_vsock::VsockListener::bind(vsock::VsockAddr::new(vsock::VMADDR_CID_ANY, 1024))?;
    serve_connections(|| async { listener.accept().await.map(|(stream, _)| stream) }).await?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("linux only");
    std::process::exit(2);
}

#[cfg(target_os = "linux")]
async fn serve_connections<S, F, A>(mut accept: A) -> std::io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    F: std::future::Future<Output = std::io::Result<S>>,
    A: FnMut() -> F,
{
    const CONNECTION_CAP: usize = 128;
    let mut connections = tokio::task::JoinSet::new();
    let error = loop {
        tokio::select! {
            result = connections.join_next(), if !connections.is_empty() => {
                if let Some(Err(error)) = result {
                    eprintln!("guest connection task failed: {error}");
                }
            }
            accepted = accept(), if connections.len() < CONNECTION_CAP => {
                match accepted {
                    Ok(stream) => {
                        connections.spawn(async move {
                            if let Err(error) = vm_runner::guest::serve(stream).await {
                                eprintln!("guest connection failed: {error}");
                            }
                        });
                    }
                    Err(error) => break error,
                }
            }
        }
    };
    connections.abort_all();
    while let Some(result) = connections.join_next().await {
        if let Err(error) = result {
            eprintln!("guest connection task failed: {error}");
        }
    }
    Err(error)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn stalled_frames_and_responses_do_not_block_other_connections_and_accept_errors_drain_tasks()
     {
        let (mut slow, slow_server) = tokio::io::duplex(64);
        let (mut blocked, blocked_server) = tokio::io::duplex(1);
        let (mut ping, ping_server) = tokio::io::duplex(64);
        let streams = std::sync::Mutex::new([slow_server, blocked_server, ping_server].into_iter());
        let finished = tokio::sync::Notify::new();
        let owner = serve_connections(|| async {
            let stream = streams.lock().unwrap().next();
            if let Some(stream) = stream {
                return Ok(stream);
            }
            finished.notified().await;
            Err(std::io::Error::from(std::io::ErrorKind::ConnectionAborted))
        });
        let client = async {
            slow.write_all(&[0, 0]).await.unwrap();
            let request = br#"{"op":"ping"}"#;
            blocked.write_u32(request.len() as u32).await.unwrap();
            blocked.write_all(request).await.unwrap();
            ping.write_u32(request.len() as u32).await.unwrap();
            ping.write_all(request).await.unwrap();
            let size = ping.read_u32().await.unwrap();
            let mut bytes = vec![0; size as usize];
            ping.read_exact(&mut bytes).await.unwrap();
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
                serde_json::json!({"ok":true})
            );
            assert_eq!(
                ping.read_u8().await.unwrap_err().kind(),
                std::io::ErrorKind::UnexpectedEof
            );
            drop(slow);
            drop(blocked);
            finished.notify_one();
        };
        let (result, ()) = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            tokio::join!(owner, client)
        })
        .await
        .unwrap();
        assert_eq!(
            result.unwrap_err().kind(),
            std::io::ErrorKind::ConnectionAborted
        );
    }

    #[tokio::test]
    async fn an_accept_error_returns_even_when_a_peer_keeps_a_partial_frame_open() {
        let (mut peer, server) = tokio::io::duplex(64);
        peer.write_all(&[0, 0]).await.unwrap();
        let stream = std::sync::Mutex::new(Some(server));
        let injected = nix::errno::Errno::EMFILE as i32;
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            serve_connections(|| {
                std::future::ready(
                    stream
                        .lock()
                        .unwrap()
                        .take()
                        .ok_or_else(|| std::io::Error::from_raw_os_error(injected)),
                )
            }),
        )
        .await
        .unwrap();
        assert_eq!(result.unwrap_err().raw_os_error(), Some(injected));
        assert_eq!(
            peer.read_u8().await.unwrap_err().kind(),
            std::io::ErrorKind::UnexpectedEof
        );
    }
}
