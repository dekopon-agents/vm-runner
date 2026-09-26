use clap::{Parser, Subcommand};
use std::path::PathBuf;
use vm_runner::{app, config::Config, openapi, telemetry};
#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    #[cfg(unix)]
    FetchImage {
        #[arg(long)]
        digest: String,
        #[arg(long)]
        cache: PathBuf,
    },
    #[cfg(unix)]
    Jail {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        profile: String,
        #[arg(long)]
        session: String,
    },
    Serve {
        #[arg(long)]
        config: PathBuf,
    },
    Egress {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        profile: String,
        #[arg(long, required_unless_present = "gateway")]
        listen: Option<std::net::SocketAddr>,
        #[arg(long)]
        gateway: Option<std::net::Ipv4Addr>,
        #[arg(long)]
        ca_out: PathBuf,
    },
    Check {
        #[arg(long)]
        config: PathBuf,
    },
    Openapi,
}
fn conflicts(config: &Config, command: &Command) -> Vec<String> {
    let mut conflicts: Vec<_> = config.conflicts().iter().map(ToString::to_string).collect();
    if let Command::Egress {
        gateway: Some(address),
        ..
    } = command
        && let Err(error) = vm_runner::egress::validate_gateway(*address)
    {
        conflicts.push(error.to_string());
    }
    conflicts
}

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let command = Cli::parse().command;
    #[cfg(unix)]
    if matches!(command, Command::Jail { .. }) {
        // Set before starting threads: VMM-created sockets must admit the launcher's fsGroup.
        rustix::process::umask(rustix::fs::Mode::from_raw_mode(0o007));
    }
    // Reserve room beyond egress's 255 connection/lookup pairs for bounded API and job workers.
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .max_blocking_threads(1024)
        .build()?
        .block_on(run(command))
}
async fn run(command: Command) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let path = match &command {
        #[cfg(unix)]
        Command::FetchImage { digest, cache } => {
            return vm_runner::jail::image::fetch(digest, cache).await;
        }
        #[cfg(unix)]
        Command::Jail { config, .. } => config,
        Command::Openapi => {
            print!("{}", openapi());
            return Ok(());
        }
        Command::Serve { config } | Command::Check { config } | Command::Egress { config, .. } => {
            config
        }
    };
    let config = Config::load(path).await?;
    let conflicts = conflicts(&config, &command);
    for conflict in &conflicts {
        eprintln!("{conflict}");
    }
    if !conflicts.is_empty() {
        return Err("configuration conflicts".into());
    }
    if matches!(command, Command::Check { .. }) {
        return Ok(());
    }
    #[cfg(unix)]
    if let Command::Jail {
        profile, session, ..
    } = command
    {
        return vm_runner::jail::run(config, &profile, &session).await;
    }
    if let Command::Egress {
        profile,
        listen,
        gateway,
        ca_out,
        ..
    } = command
    {
        return vm_runner::egress::run(config, &profile, listen, gateway, &ca_out).await;
    }
    let provider = telemetry::init(config.telemetry.as_ref()).await?;
    let listen = config.listen;
    let result = async {
        let (endpoint, requests) = app(config).await?;
        let server = poem::Server::new(poem::listener::TcpListener::bind(listen));
        let result = tokio::select! {
            result = server.run_with_graceful_shutdown(endpoint, vm_runner::shutdown_signal(), Some(std::time::Duration::from_secs(30))) => result.map_err(Into::into),
            result = requests.reap() => result,
        };
        requests.drain().await?;
        result?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    }
    .await;
    tokio::task::spawn_blocking(move || provider.shutdown()).await??;
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn egress_requires_a_listener_and_gateway_accepts_only_ipv4() {
        let base = [
            "vm-runnerd",
            "egress",
            "--config",
            "config.yaml",
            "--profile",
            "travel",
            "--ca-out",
            "/tmp/ca",
        ];
        assert_eq!(
            Cli::try_parse_from(base).err().map(|e| e.kind()),
            Some(clap::error::ErrorKind::MissingRequiredArgument)
        );
        for address in ["::1", "localhost", "127.0.0.1:53"] {
            assert_eq!(
                Cli::try_parse_from(base.into_iter().chain(["--gateway", address]))
                    .err()
                    .map(|e| e.kind()),
                Some(clap::error::ErrorKind::ValueValidation)
            );
        }
        assert!(Cli::try_parse_from(base.into_iter().chain(["--gateway", "10.0.2.1"])).is_ok());
        assert!(
            Cli::try_parse_from(base.into_iter().chain(["--listen", "127.0.0.1:8080"])).is_ok()
        );
        assert!(
            Cli::try_parse_from(base.into_iter().chain([
                "--gateway",
                "10.0.2.1",
                "--listen",
                "127.0.0.1:8080"
            ]))
            .is_ok()
        );
    }
}
