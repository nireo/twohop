use std::{path::PathBuf, process::ExitCode};

use clap::{Parser, Subcommand};

pub mod config;

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

fn main() -> ExitCode {
    let cli = Cli::parse();

    match cli.command {
        Command::Client { config } => match config::load_client(&config) {
            Ok(_config) => transport_not_implemented("client"),
            Err(error) => config_error(error),
        },
        Command::Relay { config } => match config::load_relay(&config) {
            Ok(_config) => transport_not_implemented("relay"),
            Err(error) => config_error(error),
        },
    }
}

fn config_error(error: String) -> ExitCode {
    eprintln!("{error}");
    ExitCode::FAILURE
}

fn transport_not_implemented(command: &str) -> ExitCode {
    eprintln!("{command} configuration loaded; transport is not implemented yet (M2)");
    ExitCode::FAILURE
}
