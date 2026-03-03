use clap::{Parser, Subcommand, ValueEnum};
use docker_credential_icr::credential::handle_get;
use std::process;
use tokio::signal;
use tracing::{debug, error, info};
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

#[derive(Debug, Clone, ValueEnum)]
enum LogLevel {
    /// No logging output
    Off,
    /// Only errors
    Error,
    /// Warnings and errors (default)
    Warn,
    /// Info, warnings, and errors
    Info,
    /// Debug information
    Debug,
    /// All trace information
    Trace,
}

impl LogLevel {
    fn as_filter(&self) -> &str {
        match self {
            LogLevel::Off => "off",
            LogLevel::Error => "docker_credential_icr=error",
            LogLevel::Warn => "docker_credential_icr=warn",
            LogLevel::Info => "docker_credential_icr=info",
            LogLevel::Debug => "docker_credential_icr=debug",
            LogLevel::Trace => "docker_credential_icr=trace",
        }
    }
}

#[derive(Parser)]
#[command(
    name = "docker-credential-icr",
    about = "Docker credential helper for IBM Cloud Container Registry",
    version,
    long_about = "A Docker credential helper that uses OAuth2 web flow to authenticate with IBM Cloud Container Registry (ICR).\n\n\
                  This helper only implements the 'get' command and performs a fresh OAuth2 authentication flow each time credentials are requested."
)]
struct Cli {
    /// Set log verbosity level
    #[arg(short, long, value_enum, default_value = "warn", global = true)]
    log_level: LogLevel,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Get credentials for a registry server
    Get,
}

#[tokio::main]
async fn main() {
    // Parse command line arguments first to get log level
    let cli = Cli::parse();

    // Initialize tracing/logging with specified level
    init_logging(&cli.log_level);

    // If no command is provided, show help
    let command = match cli.command {
        Some(cmd) => cmd,
        None => {
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
            eprintln!(
                "Use --log-level to control verbosity (off, error, warn, info, debug, trace)"
            );
            process::exit(1);
        }
    };

    // Set up signal handler for graceful shutdown
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    // Execute the get command with signal handling
    let result = tokio::select! {
        result = async {
            match command {
                Commands::Get => {
                    info!("Executing 'get' command");
                    handle_get().await
                }
            }
        } => result,
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

/// Initialize logging with specified level
fn init_logging(log_level: &LogLevel) {
    // DOCKER_CREDENTIAL_ICR_LOG environment variable takes precedence over command-line argument
    let filter = EnvFilter::try_from_env("DOCKER_CREDENTIAL_ICR_LOG")
        .unwrap_or_else(|_| EnvFilter::new(log_level.as_filter()));

    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer().with_writer(std::io::stderr))
        .init();
}

// Made with Bob
