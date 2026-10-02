use std::{path::PathBuf, process::ExitCode};

use clap::{Parser, Subcommand};

mod client;
mod config;
mod credentials;
mod error;
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

    let result = run(cli.command).await;

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

async fn run(command: Command) -> Result<(), error::AppError> {
    match command {
        Command::Client { config } => client::run(config::load_client(&config)?).await?,
        Command::Relay { config } => relay::run(config::load_relay(&config)?).await?,
    }
    Ok(())
}
