use clap::Command;
use docker_credential_icr::credential::handle_get;
use std::fs::OpenOptions;
use std::process;
use std::sync::Mutex;
use tokio::signal;
use tracing::{debug, error, info};
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

fn build_cli() -> Command {
    Command::new("docker-credential-icr")
        .about("Docker credential helper for IBM Cloud Container Registry")
        .version(env!("CARGO_PKG_VERSION"))
        .long_about("A Docker credential helper that uses OAuth2 web flow to authenticate with IBM Cloud Container Registry (ICR).\n\n\
                     This helper only implements the 'get' command and performs a fresh OAuth2 authentication flow each time credentials are requested.")
        .subcommand(
            Command::new("get")
                .about("Get credentials for a registry server")
        )
}

#[tokio::main]
async fn main() {
    // Initialize logging (controlled by DOCKER_CREDENTIAL_ICR_LOG environment variable)
    init_logging();

    // Parse command line arguments
    let matches = build_cli().get_matches();

    // Check which subcommand was used
    match matches.subcommand() {
        Some(("get", _)) => {
            info!("Executing 'get' command");

            // Set up signal handler for graceful shutdown
            let ctrl_c = async {
                signal::ctrl_c()
                    .await
                    .expect("Failed to install Ctrl+C handler");
            };

            // Execute the get command with signal handling
            let result = tokio::select! {
                result = handle_get() => result,
                _ = ctrl_c => {
                    debug!("Received interrupt signal, exiting gracefully");
                    process::exit(0);
                }
            };

            // Handle errors
            if let Err(e) = result {
                error!("Error: {}", e);
                eprintln!("{}", e);
                process::exit(1);
            }
        }
        _ => {
            eprintln!("Error: No command specified");
            eprintln!();
            eprintln!(
                "This is a Docker credential helper. It should be called by Docker, not directly."
            );
            eprintln!("To use it, configure Docker to use this helper in ~/.docker/config.json:");
            eprintln!();
            eprintln!(r#"  {{"#);
            eprintln!(r#"    "credHelpers": {{"#);
            eprintln!(r#"      "icr.io": "icr","#);
            eprintln!(r#"      "us.icr.io": "icr""#);
            eprintln!(r#"    }}"#);
            eprintln!(r#"  }}"#);
            eprintln!();
            eprintln!("Available command: get");
            eprintln!();
            eprintln!("Set DOCKER_CREDENTIAL_ICR_LOG environment variable to control logging:");
            eprintln!("  off, error, warn, info, debug, or trace");
            eprintln!();
            eprintln!("Set DOCKER_CREDENTIAL_ICR_LOG_FILE to write logs to a file instead of stderr.");
            eprintln!("Set DOCKER_CREDENTIAL_ICR_ALLOW_FILE_STORE=1 to enable the file-store fallback");
            eprintln!("  when the keyring is unavailable (e.g. rootless podman).");
            process::exit(1);
        }
    }
}

/// Initialize logging based on DOCKER_CREDENTIAL_ICR_LOG environment variable.
/// Defaults to "error" if not set.
///
/// If DOCKER_CREDENTIAL_ICR_LOG_FILE is set and the file can be opened for
/// writing, log output is directed there instead of stderr.
fn init_logging() {
    let filter = EnvFilter::try_from_env("DOCKER_CREDENTIAL_ICR_LOG")
        .unwrap_or_else(|_| EnvFilter::new("docker_credential_icr=error"));

    // Attempt to open a log file when the env var is set.
    let log_file = std::env::var("DOCKER_CREDENTIAL_ICR_LOG_FILE")
        .ok()
        .and_then(|path| {
            OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&path)
                .ok()
        });

    if let Some(file) = log_file {
        tracing_subscriber::registry()
            .with(filter)
            .with(fmt::layer().with_writer(Mutex::new(file)))
            .init();
    } else {
        tracing_subscriber::registry()
            .with(filter)
            .with(fmt::layer().with_writer(std::io::stderr))
            .init();
    }
}
