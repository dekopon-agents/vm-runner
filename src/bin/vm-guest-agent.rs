#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let listener =
        tokio_vsock::VsockListener::bind(vsock::VsockAddr::new(vsock::VMADDR_CID_ANY, 1024))?;
    loop {
        let (stream, _) = listener.accept().await?;
        if let Err(error) = vm_runner::guest::serve(stream).await {
            eprintln!("guest connection failed: {error}");
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("linux only");
    std::process::exit(2);
}
