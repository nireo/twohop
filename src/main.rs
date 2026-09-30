use std::{path::PathBuf, process::ExitCode};

use clap::{Parser, Subcommand};

mod client;
pub mod config;
mod protocol;
mod relay;
mod transport;

#[derive(Parser)]
#[command(about = "Forward WireGuard packets through a QUIC entry relay")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the local forwarding client.
    Client {
        /// Path to the client TOML configuration file.
        #[arg(long, value_name = "PATH")]
        config: PathBuf,
    },
    /// Run the entry relay.
    Relay {
        /// Path to the relay TOML configuration file.
        #[arg(long, value_name = "PATH")]
        config: PathBuf,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_target(false)
        .without_time()
        .init();

    let result = match cli.command {
        Command::Client { config } => match config::load_client(&config) {
            Ok(config) => client::run(config).await,
            Err(error) => Err(anyhow::anyhow!(error)),
        },
        Command::Relay { config } => match config::load_relay(&config) {
            Ok(config) => relay::run(config).await,
            Err(error) => Err(anyhow::anyhow!(error)),
        },
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error:#}");
            ExitCode::FAILURE
        }
    }
}
