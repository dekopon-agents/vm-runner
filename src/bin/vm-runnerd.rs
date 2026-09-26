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
    Serve {
        #[arg(long)]
        config: PathBuf,
    },
    Egress {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        profile: String,
        #[arg(long)]
        listen: std::net::SocketAddr,
        #[arg(long)]
        ca_out: PathBuf,
    },
    Check {
        #[arg(long)]
        config: PathBuf,
    },
    Openapi,
}
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let command = Cli::parse().command;
    let path = match &command {
        Command::Openapi => {
            print!("{}", openapi());
            return Ok(());
        }
        Command::Serve { config } | Command::Check { config } | Command::Egress { config, .. } => {
            config
        }
    };
    let config = Config::load(path).await?;
    let conflicts = config.conflicts();
    for conflict in &conflicts {
        eprintln!("{conflict}");
    }
    if !conflicts.is_empty() {
        return Err("configuration conflicts".into());
    }
    if matches!(command, Command::Check { .. }) {
        return Ok(());
    }
    if let Command::Egress {
        profile,
        listen,
        ca_out,
        ..
    } = command
    {
        return vm_runner::egress::run(config, &profile, listen, &ca_out).await;
    }
    let provider = telemetry::init(config.telemetry.as_ref()).await?;
    let listen = config.listen;
    let result = async {
        let (endpoint, requests) = app(config).await?;
        let result = poem::Server::new(poem::listener::TcpListener::bind(listen))
            .run_with_graceful_shutdown(
                endpoint,
                async {
                    if let Err(error) = tokio::signal::ctrl_c().await {
                        tracing::error!(%error, "signal handler failed");
                    }
                },
                None,
            )
            .await;
        requests.drain().await?;
        result?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    }
    .await;
    tokio::task::spawn_blocking(move || provider.shutdown()).await??;
    result
}
