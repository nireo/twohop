use std::{path::PathBuf, process::ExitCode};

use clap::{Parser, Subcommand};

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
        Command::Client { config } => run_placeholder("client", config),
        Command::Relay { config } => run_placeholder("relay", config),
    }
}

fn run_placeholder(command: &str, _config: PathBuf) -> ExitCode {
    eprintln!("{command} configuration loading is not implemented yet (M1 step 2)");
    ExitCode::FAILURE
}
