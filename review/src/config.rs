use std::{
    env,
    net::{SocketAddr, ToSocketAddrs},
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result, anyhow};
use chrono::NaiveTime;
use config::{Environment, File};
use serde::Deserialize;

use super::tls::{self, TlsCertConfig};

const DEFAULT_BACKUP_TIME: &str = "23:59:59"; // format: "%H:%M:%S"
const DEFAULT_BACKUP_DURATION: i16 = 1; // unit: day
pub(crate) const DEFAULT_OUTLIER_RETENTION: i64 = 14; // unit: day
const DEFAULT_NUM_OF_BACKUPS_TO_KEEP: i32 = 5;
const DEFAULT_DATA_PORT: u16 = 38390;
const DEFAULT_DATABASE_URL: &str = "postgres://review@localhost/review";
const DEFAULT_HOSTNAME: &str = "localhost";
const DEFAULT_USER_PORT: u16 = 8000;
const DEFAULT_SERVER: &str = "localhost";
const DEFAULT_PEN: u32 = 0;

#[allow(clippy::struct_field_names)]
pub struct Config {
    data_dir: PathBuf,
    backup_dir: PathBuf,
    log_path: Option<PathBuf>,
    backup_schedule: (Duration, Duration),
    num_of_backups_to_keep: u32,
    htdocs_dir: PathBuf,
    database_url: String,
    graphql_srv_addr: SocketAddr,
    rpc_srv_addr: SocketAddr,
    ip2location: Option<PathBuf>,
    jwt_expires_in: Option<i64>,
    tor_exit_node_list_poll_interval: Option<u32>,
    #[cfg(feature = "web")]
    reverse_proxies: Vec<review_web::archive::Config>,
    ca_certs: Vec<PathBuf>,
    client_cert: Option<PathBuf>,
    client_key: Option<PathBuf>,
    syslog_tx: bool,
    pen: u32,
    tls_cert_config: TlsCertConfig,
}

impl Config {
    /// Reads configuration from the file on disk and environment variables and
    /// returns Config struct.
    ///
    /// # Errors
    ///
    /// If input arguments are invalid, an error will be returned.
    #[allow(clippy::too_many_lines)]
    pub fn load_config(path: Option<&str>) -> Result<Self> {
        let builder = config::Config::builder()
            .set_default("database_url", DEFAULT_DATABASE_URL)
            .context("cannot set the default database URL")?
            .set_default("rpc_srv_addr", DEFAULT_SERVER)
            .context("cannot set the default RPC server address")?
            .set_default("graphql_srv_addr", DEFAULT_SERVER)
            .context("cannot set the default GraphQL server address")?
            .set_default("hostname", DEFAULT_HOSTNAME)
            .context("cannot set the default host name")?
            .set_default("cert", env::current_dir()?.join("cert.pem").to_str())
            .context("cannot set the default certificate file name")?
            .set_default("key", env::current_dir()?.join("key.pem").to_str())
            .context("cannot set the default private key file name")?
            .set_default(
                "client_cert_path",
                env::current_dir()?.join("client_cert.pem").to_str(),
            )
            .context("cannot set the default client certificate file name")?
            .set_default(
                "client_key_path",
                env::current_dir()?.join("client_key.pem").to_str(),
            )
            .context("cannot set the default client private key file name")?
            .set_default("data_dir", env::current_dir()?.join("data").to_str())
            .context("cannot set the default data directory")?
            .set_default("backup_dir", env::current_dir()?.join("backup").to_str())
            .context("cannot set the default backup directory")?
            .set_default("backup_time", DEFAULT_BACKUP_TIME)
            .context("cannot set the default backup schedule time")?
            .set_default("backup_duration", DEFAULT_BACKUP_DURATION)
            .context("cannot set the default backup period")?
            .set_default("num_of_backups_to_keep", DEFAULT_NUM_OF_BACKUPS_TO_KEEP)
            .context("cannot set the default number of backups to keep")?
            .set_default("htdocs_dir", env::current_dir()?.join("htdocs").to_str())
            .context("cannot set the default web directory")?
            .set_default("syslog_tx", false)
            .context("cannot set the default syslog_tx")?
            .set_default("pen", DEFAULT_PEN)
            .context("cannot set the default pen")?;
        let config: ConfigParser = if let Some(path) = path {
            builder.add_source(File::with_name(path))
        } else {
            builder
        }
        .add_source(Environment::with_prefix("REVIEW"))
        .build()
        .context("cannot build the config")?
        .try_deserialize()?;

        if !hostname_validator::is_valid(&config.hostname) {
            anyhow::bail!("Invalid hostname");
        }

        config.tls_config()?;
        let tls_cert_config = TlsCertConfig::new(config.cert.clone(), config.key.clone());

        let backup_schedule = {
            let time = config.backup_time()?;
            let duration = config.backup_duration();
            let init = backup_initial(time, duration)?;
            (init, duration)
        };

        let rpc_srv_addr = config.rpc_srv_addr()?;
        let graphql_srv_addr = config.graphql_srv_addr()?;
        if let Some(jwt_expires_in) = config.jwt_expires_in
            && jwt_expires_in <= 0
        {
            anyhow::bail!("jwt_expires_in must be a positive integer");
        }

        if let Some(poll_interval) = config.tor_exit_node_list_poll_interval
            && poll_interval == 0
        {
            anyhow::bail!("tor_exit_node_list_poll_interval must be a positive integer");
        }

        #[cfg(feature = "web")]
        let reverse_proxies = {
            let mut reverse_proxies = config.reverse_proxies.clone().unwrap_or_default();
            if let Some(archive) = config.archive {
                reverse_proxies.push(archive);
            }
            reverse_proxies
        };

        Ok(Self {
            data_dir: config.data_dir,
            backup_dir: config.backup_dir,
            log_path: config.log_path,
            backup_schedule,
            num_of_backups_to_keep: config.num_of_backups_to_keep,
            htdocs_dir: config.htdocs_dir,
            database_url: config.database_url,
            graphql_srv_addr,
            rpc_srv_addr,
            ip2location: config.ip2location,
            jwt_expires_in: config.jwt_expires_in,
            tor_exit_node_list_poll_interval: config.tor_exit_node_list_poll_interval,
            #[cfg(feature = "web")]
            reverse_proxies,
            ca_certs: config.ca_certs.unwrap_or_default(),
            syslog_tx: config.syslog_tx,
            pen: config.pen,
            tls_cert_config,
            client_cert: config.client_cert,
            client_key: config.client_key,
        })
    }

    #[must_use]
    pub fn data_dir(&self) -> &Path {
        self.data_dir.as_ref()
    }

    #[must_use]
    pub fn backup_dir(&self) -> &Path {
        self.backup_dir.as_ref()
    }

    #[must_use]
    pub fn log_path(&self) -> Option<&PathBuf> {
        self.log_path.as_ref()
    }

    #[must_use]
    pub fn backup_schedule(&self) -> &(Duration, Duration) {
        &self.backup_schedule
    }

    #[must_use]
    pub fn num_of_backups_to_keep(&self) -> u32 {
        self.num_of_backups_to_keep
    }

    #[must_use]
    pub fn htdocs_dir(&self) -> &Path {
        self.htdocs_dir.as_ref()
    }

    #[must_use]
    pub fn database_url(&self) -> &str {
        &self.database_url
    }

    #[must_use]
    pub fn graphql_srv_addr(&self) -> SocketAddr {
        self.graphql_srv_addr
    }

    #[must_use]
    pub fn rpc_srv_addr(&self) -> SocketAddr {
        self.rpc_srv_addr
    }

    #[must_use]
    pub fn ip2location(&self) -> Option<&Path> {
        self.ip2location.as_deref()
    }

    #[must_use]
    pub fn jwt_expires_in(&self) -> Option<i64> {
        self.jwt_expires_in
    }

    #[must_use]
    pub fn tor_exit_node_list_poll_interval(&self) -> Option<u32> {
        self.tor_exit_node_list_poll_interval
    }

    #[cfg(feature = "web")]
    pub(crate) fn reverse_proxies(&self) -> Vec<review_web::archive::Config> {
        self.reverse_proxies.clone()
    }

    #[must_use]
    pub(crate) fn ca_certs(&self) -> Vec<&Path> {
        self.ca_certs
            .iter()
            .map(std::convert::AsRef::as_ref)
            .collect()
    }

    #[must_use]
    pub(crate) fn syslog_tx(&self) -> bool {
        self.syslog_tx
    }

    #[must_use]
    pub(crate) fn pen(&self) -> u32 {
        self.pen
    }

    #[must_use]
    pub fn tls_cert_config(&self) -> &TlsCertConfig {
        &self.tls_cert_config
    }
    #[must_use]
    pub(crate) fn client_cert(&self) -> Option<&Path> {
        self.client_cert.as_deref()
    }

    #[must_use]
    pub(crate) fn client_key(&self) -> Option<&Path> {
        self.client_key.as_deref()
    }
}

#[derive(Debug, Deserialize)]
struct ConfigParser {
    data_dir: PathBuf,
    backup_dir: PathBuf,
    log_path: Option<PathBuf>,
    backup_time: String,
    backup_duration: u16,
    num_of_backups_to_keep: u32,
    htdocs_dir: PathBuf,
    database_url: String,
    graphql_srv_addr: String,
    rpc_srv_addr: String,
    hostname: String,
    cert: PathBuf,
    key: PathBuf,
    ip2location: Option<PathBuf>,
    jwt_expires_in: Option<i64>,
    tor_exit_node_list_poll_interval: Option<u32>,
    #[cfg(feature = "web")]
    archive: Option<review_web::archive::Config>,
    #[cfg(feature = "web")]
    reverse_proxies: Option<Vec<review_web::archive::Config>>,
    ca_certs: Option<Vec<PathBuf>>,
    client_cert: Option<PathBuf>,
    client_key: Option<PathBuf>,
    syslog_tx: bool,
    pen: u32,
}

impl ConfigParser {
    fn backup_duration(&self) -> Duration {
        Duration::from_secs(u64::from(self.backup_duration) * 24 * 60 * 60)
    }

    fn backup_time(&self) -> Result<NaiveTime> {
        Ok(NaiveTime::parse_from_str(&self.backup_time, "%H:%M:%S")?)
    }

    fn rpc_srv_addr(&self) -> Result<SocketAddr> {
        server_addr::<DEFAULT_DATA_PORT>(&self.rpc_srv_addr)
    }

    fn graphql_srv_addr(&self) -> Result<SocketAddr> {
        server_addr::<DEFAULT_USER_PORT>(&self.graphql_srv_addr)
    }

    fn tls_config(&self) -> Result<()> {
        if !self.cert.is_file() || !self.key.is_file() {
            tls::new_self_signed_certificate(&self.hostname, &self.cert, &self.key)?;
        }

        tls::validate_certificate_count(&self.cert)
    }
}

fn server_addr<const DEFAULT_PORT: u16>(dest: &str) -> Result<SocketAddr> {
    let mut iter = if let Ok(iter) = dest.to_socket_addrs() {
        iter
    } else {
        (dest, DEFAULT_PORT).to_socket_addrs()?
    };
    iter.next().ok_or_else(|| anyhow!("cannot find address"))
}

fn backup_initial(time: NaiveTime, duration: Duration) -> Result<Duration> {
    use chrono::Utc;

    let now = Utc::now();
    let schedule = now.date_naive().and_time(time) - now.date_naive().and_time(now.time());

    if schedule.num_seconds() > 0 {
        Ok(schedule.to_std()?)
    } else {
        Ok((schedule + chrono::Duration::from_std(duration)?).to_std()?)
    }
}
