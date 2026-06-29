use std::{path::PathBuf, sync::Arc};

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use dashmap::DashMap;
use tokio::sync::mpsc;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

mod client;
mod config;
mod dbus;
mod error;
mod messages;
mod proxy;
mod store;

use client::PanClient;
use config::read_config;
use messages::{DaemonToUi, UiToDaemon};
use proxy::{
    daemon::ProxyDaemon,
    routes::{load_from_keyring, save_to_keyring},
};
use store::PanStore;

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser, Debug)]
#[command(
    name = "pantalaimon",
    version = "0.11.0",
    about = "E2E encryption-aware Matrix reverse proxy daemon"
)]
struct Cli {
    /// Path to the config file (default: $XDG_CONFIG_HOME/pantalaimon/pantalaimon.conf)
    #[arg(short = 'c', long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Override the log level from the config file
    #[arg(long, value_enum)]
    log_level: Option<LogLevelArg>,

    /// Override the data directory (default: $XDG_DATA_HOME/pantalaimon)
    #[arg(long, value_name = "DIR")]
    data_path: Option<PathBuf>,

    /// Enable verbose Olm/Megolm debug logging
    #[arg(long)]
    debug_encryption: bool,
}

#[derive(ValueEnum, Clone, Debug)]
enum LogLevelArg {
    Error,
    Warning,
    Info,
    Debug,
}

impl From<LogLevelArg> for tracing::Level {
    fn from(a: LogLevelArg) -> Self {
        match a {
            LogLevelArg::Error => tracing::Level::ERROR,
            LogLevelArg::Warning => tracing::Level::WARN,
            LogLevelArg::Info => tracing::Level::INFO,
            LogLevelArg::Debug => tracing::Level::DEBUG,
        }
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Config file
    let config_path = cli
        .config
        .or_else(default_config_path)
        .context("Cannot determine config directory; use --config")?;

    let pan_conf = read_config(&config_path)
        .with_context(|| format!("Failed to read config {}", config_path.display()))?;

    // Log level: CLI flag > config file
    let level = cli
        .log_level
        .map(tracing::Level::from)
        .unwrap_or(pan_conf.log_level);

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(level.to_string()));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    if pan_conf.servers.is_empty() {
        anyhow::bail!(
            "No homeserver sections found in {}",
            config_path.display()
        );
    }

    // Data directory
    let data_dir = cli
        .data_path
        .or_else(default_data_path)
        .context("Cannot determine data directory; use --data-path")?;

    std::fs::create_dir_all(&data_dir)
        .with_context(|| format!("Cannot create data dir {}", data_dir.display()))?;

    // Shared SQLite store
    let store = Arc::new(PanStore::new(&data_dir).await?);

    // Channels: daemon → D-Bus signals, D-Bus commands → daemon.
    let (ui_tx, ui_rx) = mpsc::channel::<DaemonToUi>(256);
    let (pan_tx, pan_rx) = mpsc::channel::<UiToDaemon>(256);

    // Build one ProxyDaemon per configured server.
    let daemons: Arc<DashMap<String, Arc<ProxyDaemon>>> = Arc::new(DashMap::new());

    for (server_name, server_conf) in &pan_conf.servers {
        let daemon =
            ProxyDaemon::new(server_conf.clone(), store.clone(), data_dir.clone(), Some(ui_tx.clone())).await?;
        daemons.insert(server_name.clone(), daemon);
    }

    // Restore PanClients for every user that was logged in during a previous run.
    for (server_name, server_conf) in &pan_conf.servers {
        let sessions = store.load_session_tokens(server_name).await?;

        if sessions.is_empty() {
            info!(server = %server_name, "No saved sessions to restore — waiting for first login");
        } else {
            info!(server = %server_name, count = sessions.len(), "Restoring saved sessions");
        }

        for (user_id, device_id, db_token) in sessions {
            let token = if server_conf.use_keyring {
                load_from_keyring(&user_id, &device_id).unwrap_or(db_token.clone())
            } else {
                db_token.clone()
            };

            if server_conf.use_keyring && token != db_token {
                if let Err(e) = store.save_access_token(&user_id, &device_id, &token).await {
                    warn!(%user_id, "Failed to refresh DB token from keyring: {e}");
                }
            }

            if server_conf.use_keyring {
                save_to_keyring(&user_id, &device_id, &token);
            }

            info!(%user_id, %device_id, server = %server_name, "Restored session");

            let daemon = daemons.get(server_name).unwrap().clone();
            let client = match PanClient::new(
                user_id,
                device_id,
                token,
                server_conf.clone(),
                store.clone(),
                &data_dir,
                daemon.http_client.clone(),
                Some(ui_tx.clone()),
            )
            .await
            {
                Ok(c) => Arc::new(c),
                Err(e) => {
                    warn!(%server_name, "Failed to create PanClient on restore: {e}");
                    continue;
                }
            };

            client.clone().start_sync().await;
            daemon.register_client(client);
        }
    }

    // Message router: dispatches D-Bus commands to the right PanClient.
    // Needs its own ui_tx handle so it can reply with an error when no client
    // is found — otherwise panctl hangs until its signal timeout.
    let daemons_for_router = daemons.clone();
    let router_ui_tx = ui_tx.clone();
    tokio::spawn(async move {
        let mut rx = pan_rx;
        while let Some(cmd) = rx.recv().await {
            let user = cmd.pan_user().to_owned();
            let mut found = false;
            for daemon in daemons_for_router.iter() {
                if let Some(client) = daemon.pan_clients.get(&user) {
                    client.handle_ui_command(cmd.clone()).await;
                    found = true;
                    break;
                }
            }
            if !found {
                warn!(user_id = %user, "message_router: no PanClient for user — not logged in through pantalaimon?");
                let _ = router_ui_tx
                    .send(DaemonToUi::Response {
                        message_id: cmd.message_id().to_owned(),
                        pan_user: user,
                        code: "M_NOT_FOUND".to_owned(),
                        message: "No session for that user — log in through pantalaimon first".to_owned(),
                    })
                    .await;
            }
        }
    });

    // D-Bus server.
    tokio::spawn(dbus::server::DbusServer::new(pan_tx, ui_rx, daemons.clone()).run());

    // Start one axum server per configured homeserver.
    let mut handles = Vec::new();

    for (server_name, server_conf) in pan_conf.servers {
        let daemon = daemons.get(&server_name).unwrap().clone();
        info!(
            server = %server_conf.name,
            listen = %format!("{}:{}", server_conf.listen_address, server_conf.listen_port),
            homeserver = %server_conf.homeserver,
            "Starting proxy"
        );
        let handle = tokio::spawn(proxy::run(daemon, server_conf));
        handles.push(handle);
    }

    println!("pantalaimon running — press Ctrl+C to stop");

    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = signal(SignalKind::terminate())?;
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = sigterm.recv() => {},
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await?;
    }

    info!("Shutting down");
    for h in handles {
        h.abort();
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn default_config_path() -> Option<PathBuf> {
    dirs::config_dir().map(|d| d.join("pantalaimon").join("pantalaimon.conf"))
}

fn default_data_path() -> Option<PathBuf> {
    dirs::data_dir().map(|d| d.join("pantalaimon"))
}
