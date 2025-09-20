mod agent;
mod config;
mod monitors;
mod syslog_format;
mod tls;

use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result, anyhow, bail};
use review_database::{Database, EventMessage, Store, migrate_data_dir};
use syslog::{Logger, LoggerBackend};
use syslog_format::OrderedFormatter5424;
use tokio::sync::{Notify, RwLock, mpsc};
use tracing::{error, info, warn};

pub use self::config::Config;

/// Initializes and runs servers and periodic tasks.
///
/// # Errors
///
/// The following errors are possible:
///
/// * `Error::DatabaseConnection`: The database connection could not be
///   established.
/// * `Error::DatabaseMigration`: The database migration could not be
///   performed.
/// * `Error::PoolInitialization`: The pool could not be initialized.
/// * `Error::ServerInitialization`: The server could not be initialized.
pub async fn run(config: Config) -> Result<(Arc<Notify>, Arc<Notify>, Option<Arc<Notify>>)> {
    migrate_data_dir(config.data_dir(), config.backup_dir()).context("migration failed")?;

    let db = Database::new(config.database_url(), &config.ca_certs(), config.data_dir())
        .await
        .context("failed to connect to the PostgreSQL database")?;
    let store = Store::new(config.data_dir(), config.backup_dir())?;

    // transfer data from PostgreSQL to RocksDB.
    review_database::migrate_backend(&db, &store, config.data_dir()).await?;

    let store = Arc::new(RwLock::new(store));

    let (syslog_tx, syslog_rx) = mpsc::channel(256);
    let logger = syslog_logger(config.pen());
    if !config.syslog_tx() || logger.is_err() {
        if config.syslog_tx() {
            warn!("syslog is not available");
        } else {
            info!("syslog is disabled");
        }
        tokio::task::spawn(run_null_sink(syslog_rx));
    } else if let Ok(logger) = logger {
        info!("syslog is enabled");
        tokio::task::spawn(run_syslog_sink(syslog_rx, logger));
    }

    let agent_manager = agent::Manager::new(
        db.clone(),
        store.clone(),
        syslog_tx,
        config.tls_cert_config().clone(),
    );

    if let Some(poll_interval) = config.tor_exit_node_list_poll_interval() {
        let store = store.clone();
        let agent_manager = agent_manager.clone();
        tokio::spawn(async move {
            monitors::tor_monitor::run(store, poll_interval, agent_manager).await;
        });
    }

    let cert_reload_handle = Arc::new(Notify::new());
    let am_shutdown_handle = agent_manager
        .clone()
        .run(cert_reload_handle.clone(), config.rpc_srv_addr());

    tokio::spawn(schedule_backup(
        store.clone(),
        *config.backup_schedule(),
        config.num_of_backups_to_keep(),
    ));

    #[cfg(feature = "web")]
    let web_srv_shutdown_handle = run_web(
        agent_manager,
        db,
        store.clone(),
        cert_reload_handle.clone(),
        &config,
    )
    .await?;
    #[cfg(not(feature = "web"))]
    let web_srv_shutdown_handle = Arc::new(Notify::new());
    let monitoring_shutdown_handle =
        monitors::cert_monitor::monitor_loop(cert_reload_handle, config.tls_cert_config().clone())?;

    Ok((
        am_shutdown_handle,
        web_srv_shutdown_handle,
        monitoring_shutdown_handle,
    ))
}

fn syslog_logger(pen: u32) -> Result<Logger<LoggerBackend, OrderedFormatter5424>> {
    let pen = pen.to_string();
    let formatter = OrderedFormatter5424::new(syslog::Facility::LOG_USER, &pen);
    syslog::unix(formatter).map_err(|e| {
        let err_msg = format!("failed to initialize syslog: {e:#}");
        error!("{}", err_msg);
        anyhow!(err_msg)
    })
}

async fn run_null_sink(mut rx: mpsc::Receiver<EventMessage>) -> Result<()> {
    while let Some(_msg) = rx.recv().await {}
    Ok(())
}

async fn run_syslog_sink(
    mut rx: mpsc::Receiver<EventMessage>,
    mut logger: Logger<LoggerBackend, OrderedFormatter5424>,
) -> Result<()> {
    while let Some(msg) = rx.recv().await {
        match msg.syslog_rfc5424() {
            Ok(message) => {
                if let Err(e) = logger.info(message) {
                    let err_msg = format!("failed to log to syslog: {e:#}");
                    error!("{}", err_msg);
                    bail!(err_msg);
                }
            }
            Err(e) => {
                error!("failed to format syslog message: {e:#}");
            }
        }
    }
    Ok(())
}

#[cfg(feature = "web")]
async fn run_web(
    agent_manager: agent::Manager,
    db: Database,
    store: Arc<RwLock<Store>>,
    cert_reload_handle: Arc<Notify>,
    config: &Config,
) -> Result<Arc<Notify>> {
    use std::path::Path;

    use review_web::{self as web, backend::CertManager};

    init_store(&store, config).await?;

    let ip_locator = if let Some(path) = config.ip2location() {
        Some(
            ip2location::DB::from_file(path)
                .map_err(|e| anyhow!("cannot read IP location database: {e:#?}"))?,
        )
    } else {
        None
    };

    let cert_manager: Arc<dyn CertManager> =
        Arc::new(tls::CertManager::new(config.tls_cert_config().clone()));

    let web_config = web::ServerConfig {
        addr: config.graphql_srv_addr(),
        document_root: config.htdocs_dir().to_owned(),
        cert_manager,
        cert_reload_handle: cert_reload_handle.clone(),
        ca_certs: config
            .ca_certs()
            .into_iter()
            .map(Path::to_path_buf)
            .collect(),
        reverse_proxies: config.reverse_proxies(),
        client_cert_path: config.client_cert().map(Path::to_path_buf), // Single client cert
        client_key_path: config.client_key().map(Path::to_path_buf),   // Single client key
    };

    Ok(web::serve(web_config, db, store, ip_locator, agent_manager))
}

#[cfg(feature = "web")]
async fn init_store(store: &Arc<RwLock<Store>>, config: &Config) -> Result<()> {
    use review_web::{
        auth,
        graphql::account::{self, set_initial_admin_password},
    };

    let store = store.read().await;

    // Ignores the error if the initial admin password is already set.
    _ = set_initial_admin_password(&store);
    if let Ok(time) = account::expiration_time(&store) {
        let time = u32::try_from(time).unwrap_or(if time <= 0 { 1 } else { u32::MAX });
        auth::update_jwt_expires_in(time)?;
    } else if let Some(jwt_expires_in) = config.jwt_expires_in() {
        let jwt_expires_in =
            u32::try_from(jwt_expires_in).unwrap_or(if jwt_expires_in <= 0 { 1 } else { u32::MAX });
        auth::update_jwt_expires_in(jwt_expires_in)?;
        account::init_expiration_time(&store, jwt_expires_in)?;
    }
    let path = config.tls_cert_config().key_path();
    let new_secret = tls::read_private_key(path)?.secret_der().to_vec();
    auth::update_jwt_secret(new_secret)?;

    Ok(())
}

async fn schedule_backup(
    store: Arc<RwLock<Store>>,
    schedule: (Duration, Duration),
    backups_to_keep: u32,
) {
    use review_database::backup::create;
    use tokio::time::{interval, sleep};

    let (init, duration) = schedule;
    // Initial delay
    sleep(init).await;

    // Then start periodic backups
    let mut interval = interval(duration);
    interval.tick().await; // Skip the first immediate tick

    loop {
        interval.tick().await;
        let _res = create(&store, false, backups_to_keep).await;
    }
}
