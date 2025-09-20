use std::{env, fs::OpenOptions, path::PathBuf, process::exit};

use anyhow::{Context, Result};
use futures::{
    future::{self, Either},
    pin_mut,
};
use rustls::crypto::ring::default_provider;
use tokio::signal::unix::{SignalKind, signal};
use tracing::{error, info, metadata::LevelFilter};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{
    EnvFilter, Layer, fmt, prelude::__tracing_subscriber_SubscriberExt, util::SubscriberInitExt,
};

#[tokio::main]
async fn main() -> Result<()> {
    let config = review::Config::load_config(parse().as_deref())?;
    let _guards = init_tracing(config.log_path())?;
    default_provider()
        .install_default()
        .expect("first install should be successful");

    match review::run(config).await {
        Ok((am_shutdown_handle, web_srv_shutdown_handle, cert_monitor_shutdown_handle)) => {
            if let Err(e) = shutdown().await {
                error!("Signal handling failed: {}", e);
            }

            // Send shutdown notifications
            am_shutdown_handle.notify_one();
            web_srv_shutdown_handle.notify_one();
            if let Some(cert_monitor_shutdown_handle) = &cert_monitor_shutdown_handle {
                cert_monitor_shutdown_handle.notify_one();
            }

            // Wait for the shutdowns to be complete
            am_shutdown_handle.notified().await;
            web_srv_shutdown_handle.notified().await;
            if let Some(cert_monitor_shutdown_handle) = &cert_monitor_shutdown_handle {
                cert_monitor_shutdown_handle.notified().await;
            }

            info!("exit");
            Ok(())
        }
        Err(e) => {
            error!("An error occurred while starting REview: {:#}", e);
            std::process::exit(1);
        }
    }
}

fn parse() -> Option<String> {
    let args = env::args().collect::<Vec<_>>();
    if args.len() <= 1 {
        return None;
    }

    if args[1] == "--help" || args[1] == "-h" {
        println!("{} {}", package(), version());
        println!();
        println!(
            "USAGE: \
            \n    {} [CONFIG] \
            \n \
            \nFLAGS: \
            \n    -h, --help       Prints help information \
            \n    -V, --version    Prints version information \
            \n \
            \nARG: \
            \n    <CONFIG>    A TOML config file",
            package()
        );
        exit(0);
    }
    if args[1] == "--version" || args[1] == "-V" {
        println!("{}", version());
        exit(0);
    }

    Some(args[1].clone())
}

fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

fn package() -> &'static str {
    env!("CARGO_PKG_NAME")
}

async fn shutdown() -> Result<()> {
    let mut terminate = signal(SignalKind::terminate())?;
    let terminate = terminate.recv();

    let mut interrupt = signal(SignalKind::interrupt())?;
    let interrupt = interrupt.recv();

    pin_mut!(terminate, interrupt);

    match future::select(terminate, interrupt).await {
        Either::Left(_) => info!("SIGTERM received"),
        Either::Right(_) => info!("SIGINT received"),
    }

    Ok(())
}

/// If `log_path` is `None`, logs will be printed to stdout.
/// If the log file cannot be opened or created, an error will be returned.
///
/// # Errors
///
/// Returns an error if the log file cannot be opened or created.
fn init_tracing(log_path: Option<&PathBuf>) -> Result<Vec<WorkerGuard>> {
    let mut guards = vec![];

    let file_layer = if let Some(log_path) = log_path {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_path)
            .with_context(|| format!("Failed to open the log file: {}", log_path.display()))?;
        let (non_blocking, file_guard) = tracing_appender::non_blocking(file);
        guards.push(file_guard);
        Some(
            fmt::Layer::default()
                .with_ansi(false)
                .with_target(false)
                .with_writer(non_blocking)
                .with_filter(
                    EnvFilter::builder()
                        .with_default_directive(LevelFilter::INFO.into())
                        .from_env_lossy(),
                ),
        )
    } else {
        None
    };

    let stdout_layer = if file_layer.is_none() {
        let (stdout_writer, stdout_guard) = tracing_appender::non_blocking(std::io::stdout());
        guards.push(stdout_guard);
        Some(
            fmt::Layer::default()
                .with_ansi(true)
                .with_line_number(true)
                .with_writer(stdout_writer)
                .with_filter(
                    EnvFilter::builder()
                        .with_default_directive(LevelFilter::INFO.into())
                        .from_env_lossy(),
                ),
        )
    } else {
        None
    };

    tracing_subscriber::Registry::default()
        .with(stdout_layer)
        .with(file_layer)
        .init();

    info!("Initialized tracing logger");
    Ok(guards)
}
