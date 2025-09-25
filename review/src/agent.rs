//! A protocol between REview and agents.

mod requests;

use std::{collections::HashMap, future::Future, io, net::SocketAddr, pin::Pin, sync::Arc};

use anyhow::{Context as AnyhowContext, Error, Result, anyhow, bail};
use bincode::Options;
use futures::{
    Stream, StreamExt,
    task::{Context, Poll},
};
use quinn::{Endpoint, Incoming, RecvStream};
use review_database::{AgentStatus, Database, EventMessage, Store, UniqueKey};
use review_protocol::{server::Connection, types::Status};
use tokio::{
    sync::{Notify, RwLock, mpsc},
    task::JoinHandle,
};
use tracing::{error, info, warn};
#[cfg(feature = "web")]
use {
    review_protocol::types::TrafficFilterRule,
    review_web::{
        backend::{AgentManager, Process, ResourceUsage, SamplingPolicy},
        graphql::{
            agent_keys_by_customer_id, customer::NetworksTargetAgentKeysPair, get_customer_networks,
        },
    },
    std::time::Duration,
};

use crate::tls::{TlsCertConfig, make_server_config};

/// A controller that manages agents.
pub struct Manager {
    db: Database,
    store: Arc<RwLock<Store>>,
    agents: Arc<RwLock<HashMap<String, RwLock<Agent>>>>,
    syslog_tx: mpsc::Sender<EventMessage>,
    tls_cert_config: TlsCertConfig,
}

impl Clone for Manager {
    fn clone(&self) -> Self {
        Self {
            db: self.db.clone(),
            store: Arc::clone(&self.store),
            agents: Arc::clone(&self.agents),
            syslog_tx: self.syslog_tx.clone(),
            tls_cert_config: self.tls_cert_config.clone(),
        }
    }
}

impl Manager {
    pub fn new(
        db: Database,
        store: Arc<RwLock<Store>>,
        syslog_tx: mpsc::Sender<EventMessage>,
        tls_cert_config: TlsCertConfig,
    ) -> Self {
        Self {
            db,
            store,
            agents: Arc::new(RwLock::new(HashMap::new())),
            syslog_tx,
            tls_cert_config,
        }
    }

    pub fn run(self, cert_reload_handle: Arc<Notify>, addr: SocketAddr) -> Arc<Notify> {
        let am_shutdown_handle = Arc::new(Notify::new());
        let shutdown_handle = am_shutdown_handle.clone();
        let am: JoinHandle<Result<()>> = tokio::spawn(async move {
            let crypto = make_server_config(&self.tls_cert_config)?;
            let tls_config = quinn::ServerConfig::with_crypto(Arc::new(
                quinn::crypto::rustls::QuicServerConfig::try_from(crypto)?,
            ));
            let endpoint = Endpoint::server(tls_config, addr)?;

            loop {
                let wait_shutdown = am_shutdown_handle.notified();
                let cert_reload = cert_reload_handle.notified();

                tokio::select! {
                    () = cert_reload => {
                        info!("Reloading Agent manger certificates");
                        let crypto = make_server_config(&self.tls_cert_config)?;
                        let tls_config = quinn::ServerConfig::with_crypto(Arc::new(
                            quinn::crypto::rustls::QuicServerConfig::try_from(crypto)?,
                        ));
                        endpoint.set_server_config(Some(tls_config));
                    }
                    () = wait_shutdown => {
                        info!("Shutting down Agent manager");
                        endpoint.close(0_u32.into(), &[]);
                        am_shutdown_handle.notify_one();
                        break;
                    },
                    res = endpoint.accept() => {
                        if let Some(conn) = res {
                            let manager = self.clone();
                            tokio::spawn(async {
                                if let Err(e) = manager.handle_connection(conn).await {
                                    error!("An error occurred while handling connections from agent: {e}");
                                }
                            });
                        } else {
                            break;
                        }
                    }
                }
            }

            Ok(())
        });

        info!("Starting Agent manager");
        tokio::spawn(async {
            match am.await {
                Ok(Err(e)) => error!("Agent manager died: {:?}", e),
                Err(e) => error!(
                    "Agent manager task failed to execute to completion: {:?}",
                    e
                ),
                _ => (),
            }
        });

        shutdown_handle
    }

    async fn handle_connection(mut self, conn: Incoming) -> Result<(), Error> {
        // The protocol version is the version of REview that implements the
        // protocol.
        const PROTOCOL_VERSION_REQUIREMENT: &str = ">=0.45.0";
        const HIGHEST_PROTOCOL_VERSION: &str = "0.45.0";

        let addr = conn.remote_address();
        let connection = conn.await?;

        let agent = Agent::new(
            review_protocol::server::handshake(
                &connection,
                addr,
                PROTOCOL_VERSION_REQUIREMENT,
                HIGHEST_PROTOCOL_VERSION,
            )
            .await?,
            Connection::from_quinn(connection.clone()),
            true,
        )?;

        let key = agent.key();
        if let Err(e) = self
            .update_agent_status(&key, agent.host(), agent.status)
            .await
        {
            // Status update failures are expected when the node or agent is not yet registered.
            // However, failures due to database errors may indicate underlying issues.
            info!(
                "Failed to update agent status: key={}, host={}, status={:?}, error={}",
                key,
                agent.host(),
                agent.status,
                e
            );
        }
        self.insert_agent(key.clone(), agent).await?;

        loop {
            tokio::select! {
                res = connection.accept_bi() => {
                    if let Ok((send, recv)) = res {
                        let manager = self.clone();
                        let peer = key.clone();
                        tokio::spawn( async {
                            if let Err(e) = manager.handle_request(
                                send,
                                recv,
                                peer
                            ).await {
                                error!("Failed to handle the request: {:#}", e);
                            }
                        });
                    } else {
                        break;
                    }
                },
                res = connection.accept_uni() => {
                    if let Ok(recv) = res {
                        let manager = self.clone();
                        tokio::spawn(async {
                            if let Err(e) = manager.handle_event_stream(recv).await {
                                error!("An error occurred while handling event streams: {e}");
                            }
                        });
                    } else {
                       break;
                    }
                }
            }
        }

        self.remove_agent(key, addr).await?;
        Ok(())
    }

    async fn handle_event_stream(self, mut recv: RecvStream) -> Result<()> {
        let mut buf = vec![0_u8; 2];
        recv.read_exact(&mut buf).await.context("not enough data")?;

        let codec = bincode::DefaultOptions::new();

        info!("started receiving events");

        let mut buf = Vec::new();
        loop {
            if let Err(e) = recv_raw(&mut recv, &mut buf).await {
                if e.kind() == io::ErrorKind::UnexpectedEof {
                    break;
                }
                warn!("failed to receive event: {}", e);
                return Err(e.into());
            }

            match codec.deserialize::<EventMessage>(&buf) {
                Ok(msg) => {
                    {
                        let store = self.store.read().await;

                        let event_db = store.events();
                        event_db.put(&msg)?;
                    }
                    if let Err(e) = self.syslog_tx.send(msg).await {
                        warn!("syslog error: {}", e);
                    }
                }
                Err(e) => warn!("decoding error! {}", e),
            }
        }
        Ok(())
    }

    async fn insert_agent(&mut self, key: String, agent: Agent) -> Result<(), Error> {
        info!("insert agent {}", agent);
        let mut agents = self.agents.write().await;

        agents.insert(key.clone(), RwLock::new(agent));
        Ok(())
    }

    async fn remove_agent(&mut self, key: String, addr: SocketAddr) -> Result<(), Error> {
        {
            let agents = self.agents.read().await;
            let agent = agents.get(&key);
            if let Some(agent) = agent {
                let agent_read = agent.read().await;
                if agent_read.addr() != addr {
                    return Ok(());
                }
                info!("remove agent {}", agent_read);
            } else {
                return Ok(());
            }
        }
        self.agents.write().await.remove(&key);
        Ok(())
    }

    async fn update_agent_status(&self, key: &str, hostname: &str, status: Status) -> Result<()> {
        let status = match status {
            Status::Idle => AgentStatus::ReloadFailed,
            Status::Ready => AgentStatus::Enabled,
        };
        let store = self.store.write().await;
        store
            .node_map()
            .update_agent_status_by_hostname(hostname, key, status)?;
        Ok(())
    }

    pub async fn broadcast_tor_exit_node_list(&self) -> Result<(), Error> {
        let exit_node_list = self.tor_exit_node_list().await?;

        let mut iter = AgentIterator::new(self.agents.clone(), "hog".to_string());
        while let Some((key, connection)) = iter.next().await {
            if let Err(e) = connection.send_tor_exit_node_list(&exit_node_list).await {
                warn!("failed to send tor exit node list to {}: {}", key, e);
            }
        }
        Ok(())
    }

    #[cfg(feature = "web")]
    async fn find_agent(
        &self,
        host_id: &str,
        app_name: &str,
    ) -> Result<(String, Connection), Error> {
        let keys = self.agents.read().await.keys().cloned().collect::<Vec<_>>();
        for key in keys {
            let agents = self.agents.read().await;
            let Some(agent) = agents.get(&key) else {
                continue;
            };
            let channel = agent.read().await.channel.clone();
            if agent.read().await.host() == host_id && agent.read().await.app_name() == app_name {
                return Ok((key, channel));
            }
        }

        Err(anyhow!("agent \"{app_name} of {host_id}\" not found"))
    }

    /// Finds an agent running on the specified host, and returns the agent's
    /// key and channel if found.
    ///
    /// Returns `None` if no agent is found.
    #[cfg(feature = "web")]
    async fn find_agent_by_host(&self, host_id: &str) -> Option<(String, Connection)> {
        let agents = self.agents.read().await;
        for agent in agents.values() {
            let agent = agent.read().await;
            if agent.host() == host_id {
                return Some((agent.key(), agent.channel.clone()));
            }
        }
        None
    }

    async fn trusted_domain_list(&self) -> Result<Vec<String>, Error> {
        use review_database::{Iterable, event::Direction};

        let store = self.store.read().await;
        store
            .trusted_domain_map()
            .iter(Direction::Forward, None)
            .map(|res| res.map(|td| td.name))
            .collect::<Result<Vec<_>>>()
    }

    async fn tor_exit_node_list(&self) -> Result<Vec<String>> {
        use review_database::{Iterable, event::Direction};

        let store = self.store.read().await;
        store
            .tor_exit_node_map()
            .iter(Direction::Forward, None)
            .map(|res| res.map(|td| String::from_utf8_lossy(td.unique_key()).into_owned()))
            .collect::<Result<Vec<_>>>()
    }

    #[cfg(feature = "web")]
    async fn internal_network_list(
        &self,
        agent_key: &str,
    ) -> Result<review_database::HostNetworkGroup, String> {
        let store = self.store.read().await;
        if let Ok(customer_agent_keys) = agent_keys_by_customer_id(&store) {
            if let Some((customer_id, _)) = customer_agent_keys
                .iter()
                .find(|(_, keys)| keys.contains(&agent_key.to_string()))
            {
                get_customer_networks(&store, *customer_id).map_err(|e| format!("{e:?}"))
            } else {
                Ok(review_database::HostNetworkGroup::new(
                    vec![],
                    vec![],
                    vec![],
                ))
            }
        } else {
            Ok(review_database::HostNetworkGroup::new(
                vec![],
                vec![],
                vec![],
            ))
        }
    }
}

#[cfg(feature = "web")]
#[async_trait::async_trait]
impl AgentManager for Manager {
    /// Sends the list of trusted domains to all the agents.
    async fn broadcast_trusted_domains(&self) -> Result<(), Error> {
        let domains = self.trusted_domain_list().await?;
        let mut iter = AgentIterator::new(self.agents.clone(), "hog".to_string());

        while let Some((key, connection)) = iter.next().await {
            if let Err(e) = connection.send_trusted_domain_list(&domains).await {
                warn!("failed to send trusted domains to {}: {}", key, e);
            }
        }

        Ok(())
    }

    /// Sends the internal networks to all the Hogs.
    async fn send_agent_specific_internal_networks(
        &self,
        networks: &[NetworksTargetAgentKeysPair],
    ) -> Result<Vec<String>, Error> {
        let mut networks_by_agent = HashMap::new();
        for pair in networks {
            pair.target_agent_keys().iter().for_each(|key| {
                networks_by_agent
                    .entry(key.clone())
                    .or_insert_with(Vec::new)
                    .push(pair.networks().clone());
            });
        }

        let networks_by_agent = networks_by_agent
            .into_iter()
            .map(|(key, networks)| {
                let mut hosts = vec![];
                let mut ip_ranges = vec![];
                let mut nets = vec![];
                for network in networks {
                    hosts.extend(network.hosts());
                    ip_ranges.extend(network.ip_ranges().to_vec());
                    nets.extend(network.networks());
                }
                let hng = review_database::HostNetworkGroup::new(hosts, nets, ip_ranges);
                (key, db2proto_host_network_group(&hng))
            })
            .collect::<HashMap<_, _>>();

        let mut success = vec![];
        let mut iter = AgentIterator::new(self.agents.clone(), "hog".to_string());
        while let Some((key, connection)) = iter.next().await {
            if let Some(hng) = networks_by_agent.get(&key) {
                if let Err(e) = connection.send_internal_network_list(hng).await {
                    warn!("failed to send internal network list to {}: {}", key, e);
                } else {
                    success.push(key);
                }
            }
        }
        Ok(success)
    }

    /// Sends the allow network list to all the Hogs.
    async fn broadcast_allow_networks(
        &self,
        networks: &review_database::HostNetworkGroup,
    ) -> Result<Vec<String>, Error> {
        let networks = db2proto_host_network_group(networks);

        let mut success = vec![];
        let mut iter = AgentIterator::new(self.agents.clone(), "hog".to_string());
        while let Some((key, connection)) = iter.next().await {
            if let Err(e) = connection.send_allowlist(&networks).await {
                warn!("failed to send allowlist to {}: {}", key, e);
            } else {
                success.push(key);
            }
        }
        Ok(success)
    }

    /// Sends the block network list to all the Hogs.
    async fn broadcast_block_networks(
        &self,
        networks: &review_database::HostNetworkGroup,
    ) -> Result<Vec<String>, Error> {
        let networks = db2proto_host_network_group(networks);

        let mut success = vec![];
        let mut iter = AgentIterator::new(self.agents.clone(), "hog".to_string());
        while let Some((key, connection)) = iter.next().await {
            if let Err(e) = connection.send_blocklist(&networks).await {
                warn!("failed to send blocklist to {}: {}", key, e);
            } else {
                success.push(key);
            }
        }
        Ok(success)
    }

    /// Sends trusted user agent list to all the Hogs.
    async fn broadcast_trusted_user_agent_list(&self, list: &[String]) -> Result<(), Error> {
        let mut success_cnt = 0;
        let mut iter = AgentIterator::new(self.agents.clone(), "hog".to_string());
        while let Some((key, connection)) = iter.next().await {
            if let Err(e) = connection.send_trusted_user_agent_list(list).await {
                warn!("failed to send trusted user agents to {}: {}", key, e);
            } else {
                success_cnt += 1;
            }
        }
        if success_cnt == 0 {
            bail!("failed to send trusted user agents to any agent");
        }
        Ok(())
    }

    async fn online_apps_by_host_id(
        &self,
    ) -> Result<HashMap<String, Vec<(String, String)>>, Error> {
        use std::collections::hash_map::Entry::{Occupied, Vacant};

        let mut apps: HashMap<String, Vec<(String, String)>> = HashMap::new(); // (host_id, (agent key, app name))
        let agents = self.agents.read().await;

        for agent in agents.values() {
            let agent = agent.read().await;
            if agent.is_online {
                match apps.entry(agent.host_id.clone()) {
                    Occupied(mut entry) => {
                        entry
                            .get_mut()
                            .push((agent.key(), agent.app_name().to_lowercase()));
                    }
                    Vacant(entry) => {
                        let new_app: Vec<(String, String)> =
                            vec![(agent.key(), agent.app_name().to_lowercase())];
                        entry.insert(new_app);
                    }
                }
            }
        }

        Ok(apps)
    }

    async fn broadcast_crusher_sampling_policy(
        &self,
        sampling_policies: &[SamplingPolicy],
    ) -> Result<(), anyhow::Error> {
        let policies = sampling_policies
            .iter()
            .map(web2proto_sampling_policy)
            .collect::<Vec<_>>();

        let mut success_cnt = 0;
        let mut iter = AgentIterator::new(self.agents.clone(), "crusher".to_string());
        while let Some((key, connection)) = iter.next().await {
            if let Err(e) = connection.send_sampling_policies(&policies).await {
                warn!("failed to send sampling policy to {}: {}", key, e);
            } else {
                success_cnt += 1;
            }
        }
        if success_cnt == 0 {
            bail!("failed to send sampling policy to any agent");
        }
        Ok(())
    }

    async fn update_config(&self, agent_key: &str) -> Result<(), Error> {
        let agents = self.agents.read().await;
        let channel = {
            let Some(agent) = agents.get(agent_key) else {
                bail!("agent not found");
            };
            agent.read().await.channel.clone()
        };
        drop(agents);
        channel.send_config_update_cmd().await
    }

    async fn get_process_list(&self, hostname: &str) -> Result<Vec<Process>, anyhow::Error> {
        let agents = self.agents.read().await;
        let mut candidates = vec![None, None, None];
        for agent in agents.values() {
            let agent = agent.read().await;
            if agent.host() != hostname {
                continue;
            }

            // The priority of applications (`Hog`, followed by `Crusher` and
            // then `Piglet`) is determined based on their roles and
            // capabilities in the system.
            //
            // 1. `Hog` has the highest priority because it can act as a dummy
            //    agent to monitor servers where our software isn't installed.
            //    This is essential for comprehensive system monitoring.
            // 2. `Crusher` and `Piglet` are preferred for process list
            //    collection because they maintain a continuous connection to
            //    REview.
            // 3. `REconverge` is not suited for process list collection due to
            //    its intermittent connection.
            // 4. The order of Hog, Crusher, and Piglet also considers the load
            //    each program can handle.
            if agent.app_name() == "hog" {
                candidates[0] = Some((agent.key(), agent.channel.clone()));
            } else if agent.app_name() == "crusher" {
                candidates[1] = Some((agent.key(), agent.channel.clone()));
            } else if agent.app_name() == "piglet" {
                candidates[2] = Some((agent.key(), agent.channel.clone()));
            }
        }
        let (_key, channel) = candidates
            .into_iter()
            .flatten()
            .next()
            .ok_or_else(|| anyhow!("no capable agent found"))?;
        let processes = channel.get_process_list().await?;
        Ok(processes
            .into_iter()
            .map(|p| Process {
                user: p.user,
                cpu_usage: p.cpu_usage,
                mem_usage: p.mem_usage,
                start_time: p.start_time,
                command: p.command,
            })
            .collect())
    }

    async fn halt(&self, hostname: &str) -> Result<(), Error> {
        let Some((_key, channel)) = self.find_agent_by_host(hostname).await else {
            bail!("agent not found");
        };
        channel.send_shutdown_cmd().await
    }

    async fn get_resource_usage(&self, hostname: &str) -> Result<ResourceUsage, anyhow::Error> {
        let Some((_key, channel)) = self.find_agent_by_host(hostname).await else {
            bail!("agent not found");
        };
        let usage = channel.get_resource_usage().await?;
        Ok(ResourceUsage {
            cpu_usage: usage.cpu_usage,
            total_memory: usage.total_memory,
            used_memory: usage.used_memory,
            disk_used_bytes: usage.disk_used_bytes,
            disk_available_bytes: usage.disk_available_bytes,
        })
    }

    async fn ping(&self, hostname: &str) -> Result<std::time::Duration, Error> {
        use std::time::Instant;

        let Some((_key, channel)) = self.find_agent_by_host(hostname).await else {
            bail!("agent not found");
        };
        let start = Instant::now();
        channel.send_ping().await?;
        let end = Instant::now();
        Ok(end - start)
    }

    async fn reboot(&self, hostname: &str) -> Result<(), Error> {
        let Some((_key, channel)) = self.find_agent_by_host(hostname).await else {
            bail!("agent not found");
        };
        channel.send_reboot_cmd().await
    }

    /// Sends traffic filtering rules to the specified agents.
    async fn update_traffic_filter_rules(
        &self,
        host: &str,
        rules: &[TrafficFilterRule],
    ) -> Result<(), Error> {
        let Ok((_, channel)) = self.find_agent(host, "piglet").await else {
            bail!("failed to update traffic filter rules to {host}. Not connected.");
        };
        channel.send_filtering_rules(rules).await?;
        Ok(())
    }
}

/// An iterator that yields agents with the specified app name.
struct AgentIterator {
    agents: Arc<RwLock<HashMap<String, RwLock<Agent>>>>,
    app_name: String,
    keys: Vec<String>,
    index: usize,
}

impl AgentIterator {
    fn new(agents: Arc<RwLock<HashMap<String, RwLock<Agent>>>>, app_name: String) -> Self {
        AgentIterator {
            agents,
            app_name,
            keys: vec![],
            index: 0,
        }
    }

    async fn load_keys(&mut self) {
        let agents = self.agents.read().await;
        self.keys = agents.keys().cloned().collect();
    }
}

impl Stream for AgentIterator {
    type Item = (String, Connection);

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.keys.is_empty() {
            // Load keys if not loaded yet
            let this = self.as_mut().get_mut();
            let mut future = Box::pin(this.load_keys());
            match Future::poll(Pin::new(&mut future), cx) {
                Poll::Ready(()) => {}
                Poll::Pending => return Poll::Pending,
            }
        }

        let this = self.get_mut();
        while this.index < this.keys.len() {
            let key = &this.keys[this.index];
            this.index += 1;

            let agents = this.agents.clone();
            let app_name = this.app_name.clone();
            let key = key.clone();

            let mut future = Box::pin(async move {
                let agents = agents.read().await;
                if let Some(agent) = agents.get(&key) {
                    let agent_read = agent.read().await;
                    if agent_read.app_name == app_name {
                        let connection = agent_read.channel.clone();
                        return Some((key, connection));
                    }
                }
                None
            });

            match Future::poll(Pin::new(&mut future), cx) {
                Poll::Ready(Some(item)) => return Poll::Ready(Some(item)),
                Poll::Ready(None) => {}
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(None)
    }
}

struct Agent {
    app_name: String,
    _version: String, // will be used when GraphQL API to retrieve agent's version is implemented
    _protocol_version: String, // will be used when REview needs to support multiple protocol versions
    host_id: String,           // hostname
    id: String,
    addr: SocketAddr,
    channel: Connection,
    is_online: bool,
    status: Status,
}

impl std::fmt::Display for Agent {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}, {}@{}, {}, Direct, online={}, status={:?}",
            self.app_name, self.id, self.host_id, self.addr, self.is_online, self.status,
        )
    }
}

impl Agent {
    fn new(info: review_protocol::AgentInfo, channel: Connection, is_online: bool) -> Result<Self> {
        let certs = channel
            .peer_identity()
            .expect("already passed TLS handshake")
            .downcast::<Vec<rustls::pki_types::CertificateDer>>()
            .map_err(|_| anyhow!("unable to retrieve agent certificate"))?;
        let cert = certs.first().expect("there should be only one certificate");
        let Some((agent_id, host_id)) = crate::tls::AgentCertificate::parse(cert).agent_info()
        else {
            bail!("unable to retrieve agent info.");
        };
        Ok(Self {
            app_name: info.app_name,
            _version: info.version,
            _protocol_version: info.protocol_version,
            host_id,
            id: agent_id,
            addr: info.addr,
            channel,
            is_online,
            status: info.status,
        })
    }

    fn key(&self) -> String {
        format!("{}@{}", self.id, self.host_id)
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    #[cfg(feature = "web")]
    pub fn app_name(&self) -> &str {
        &self.app_name
    }

    pub fn host(&self) -> &str {
        &self.host_id
    }
}

async fn recv_raw(recv: &mut RecvStream, buf: &mut Vec<u8>) -> io::Result<()> {
    use std::mem;

    let mut len_buf = [0; mem::size_of::<u32>()];
    if let Err(e) = recv.read_exact(&mut len_buf).await {
        return Err(from_read_exact_error_to_io_error(e));
    }
    let len = u32::from_be_bytes(len_buf) as usize;

    buf.resize(len, 0);
    recv.read_exact(buf.as_mut_slice())
        .await
        .map_err(from_read_exact_error_to_io_error)
}

fn from_read_exact_error_to_io_error(e: quinn::ReadExactError) -> io::Error {
    match e {
        quinn::ReadExactError::FinishedEarly(_) => io::Error::from(io::ErrorKind::UnexpectedEof),
        quinn::ReadExactError::ReadError(e) => e.into(),
    }
}

#[cfg(feature = "web")]
/// Converts `review_database::HostNetworkGroup` to `review_protocol::HostNetworkGroup`.
fn db2proto_host_network_group(
    db: &review_database::HostNetworkGroup,
) -> review_protocol::types::HostNetworkGroup {
    review_protocol::types::HostNetworkGroup {
        hosts: db.hosts().to_vec(),
        networks: db.networks().to_vec(),
        ip_ranges: db.ip_ranges().to_vec(),
    }
}

pub(super) fn proto2db_outlier_info(
    proto: &review_protocol::types::OutlierInfo,
    model_id: i32,
    timestamp: i64,
    is_saved: bool,
) -> review_database::OutlierInfo {
    review_database::OutlierInfo {
        model_id,
        timestamp,
        rank: proto.rank,
        id: proto.id,
        sensor: proto.sensor.clone(),
        distance: proto.distance,
        is_saved,
    }
}

pub(super) fn proto2db_event_message(
    proto: &review_protocol::types::EventMessage,
) -> review_database::EventMessage {
    use review_database::EventKind;

    // Convert protocol EventKind to database EventKind
    let kind = match proto.kind {
        review_protocol::types::EventKind::DnsCovertChannel => EventKind::DnsCovertChannel,
        review_protocol::types::EventKind::HttpThreat => EventKind::HttpThreat,
        review_protocol::types::EventKind::RdpBruteForce => EventKind::RdpBruteForce,
        review_protocol::types::EventKind::RepeatedHttpSessions => EventKind::RepeatedHttpSessions,
        review_protocol::types::EventKind::ExtraThreat => EventKind::ExtraThreat,
        review_protocol::types::EventKind::TorConnection => EventKind::TorConnection,
        review_protocol::types::EventKind::DomainGenerationAlgorithm => {
            EventKind::DomainGenerationAlgorithm
        }
        review_protocol::types::EventKind::FtpBruteForce => EventKind::FtpBruteForce,
        review_protocol::types::EventKind::FtpPlainText => EventKind::FtpPlainText,
        review_protocol::types::EventKind::PortScan => EventKind::PortScan,
        review_protocol::types::EventKind::MultiHostPortScan => EventKind::MultiHostPortScan,
        review_protocol::types::EventKind::NonBrowser => EventKind::NonBrowser,
        review_protocol::types::EventKind::LdapBruteForce => EventKind::LdapBruteForce,
        review_protocol::types::EventKind::LdapPlainText => EventKind::LdapPlainText,
        review_protocol::types::EventKind::ExternalDdos => EventKind::ExternalDdos,
        review_protocol::types::EventKind::CryptocurrencyMiningPool => {
            EventKind::CryptocurrencyMiningPool
        }
        review_protocol::types::EventKind::BlocklistConn => EventKind::BlocklistConn,
        review_protocol::types::EventKind::BlocklistDns => EventKind::BlocklistDns,
        review_protocol::types::EventKind::BlocklistDceRpc => EventKind::BlocklistDceRpc,
        review_protocol::types::EventKind::BlocklistFtp => EventKind::BlocklistFtp,
        review_protocol::types::EventKind::BlocklistHttp => EventKind::BlocklistHttp,
        review_protocol::types::EventKind::BlocklistKerberos => EventKind::BlocklistKerberos,
        review_protocol::types::EventKind::BlocklistLdap => EventKind::BlocklistLdap,
        review_protocol::types::EventKind::BlocklistMqtt => EventKind::BlocklistMqtt,
        review_protocol::types::EventKind::BlocklistNfs => EventKind::BlocklistNfs,
        review_protocol::types::EventKind::BlocklistNtlm => EventKind::BlocklistNtlm,
        review_protocol::types::EventKind::BlocklistRdp => EventKind::BlocklistRdp,
        review_protocol::types::EventKind::BlocklistSmb => EventKind::BlocklistSmb,
        review_protocol::types::EventKind::BlocklistSmtp => EventKind::BlocklistSmtp,
        review_protocol::types::EventKind::BlocklistSsh => EventKind::BlocklistSsh,
        review_protocol::types::EventKind::BlocklistTls => EventKind::BlocklistTls,
        review_protocol::types::EventKind::WindowsThreat => EventKind::WindowsThreat,
        review_protocol::types::EventKind::NetworkThreat => EventKind::NetworkThreat,
        review_protocol::types::EventKind::LockyRansomware => EventKind::LockyRansomware,
        review_protocol::types::EventKind::SuspiciousTlsTraffic => EventKind::SuspiciousTlsTraffic,
        review_protocol::types::EventKind::BlocklistBootp => EventKind::BlocklistBootp,
        review_protocol::types::EventKind::BlocklistDhcp => EventKind::BlocklistDhcp,
        review_protocol::types::EventKind::TorConnectionConn => EventKind::TorConnectionConn,
    };

    review_database::EventMessage {
        time: proto.time,
        kind,
        fields: proto.fields.clone(),
    }
}

pub(super) fn proto2db_data_source(
    proto: &review_protocol::types::DataSource,
) -> review_database::DataSource {
    review_database::DataSource {
        id: proto.id,
        name: proto.name.clone(),
        server_name: proto.server_name.clone(),
        address: proto.address,
        data_type: match proto.data_type {
            review_protocol::types::DataType::Csv => review_database::DataType::Csv,
            review_protocol::types::DataType::Log => review_database::DataType::Log,
            review_protocol::types::DataType::TimeSeries => review_database::DataType::TimeSeries,
        },
        source: proto.source.clone(),
        kind: proto.kind.clone(),
        description: proto.description.clone(),
    }
}

pub(super) fn proto2db_update_cluster_request(
    proto: &review_protocol::types::UpdateClusterRequest,
) -> review_database::UpdateClusterRequest {
    review_database::UpdateClusterRequest {
        cluster_id: proto.cluster_id.clone(),
        detector_id: proto.detector_id,
        signature: proto.signature.clone(),
        score: proto.score,
        size: proto.size,
        event_ids: proto.event_ids.clone(),
        status_id: proto.status_id,
        labels: proto.labels.clone(),
    }
}

#[cfg(feature = "web")]
/// Converts review-web's `SamplingPolicy` to review-protocol's `SamplingPolicy`.
fn web2proto_sampling_policy(
    policy: &review_web::graphql::SamplingPolicy,
) -> review_protocol::types::SamplingPolicy {
    let kind = match policy.kind {
        review_web::graphql::SamplingKind::Conn => review_protocol::types::SamplingKind::Conn,
        review_web::graphql::SamplingKind::Dns => review_protocol::types::SamplingKind::Dns,
        review_web::graphql::SamplingKind::Http => review_protocol::types::SamplingKind::Http,
        review_web::graphql::SamplingKind::Rdp => review_protocol::types::SamplingKind::Rdp,
    };
    let interval = match policy.interval {
        review_web::graphql::SamplingInterval::FiveMinutes => Duration::from_secs(300),
        review_web::graphql::SamplingInterval::TenMinutes => Duration::from_secs(600),
        review_web::graphql::SamplingInterval::FifteenMinutes => Duration::from_secs(900),
        review_web::graphql::SamplingInterval::ThirtyMinutes => Duration::from_secs(1800),
        review_web::graphql::SamplingInterval::OneHour => Duration::from_secs(3600),
    };
    let period = match policy.period {
        review_web::graphql::SamplingPeriod::SixHours => Duration::from_secs(21600),
        review_web::graphql::SamplingPeriod::TwelveHours => Duration::from_secs(43200),
        review_web::graphql::SamplingPeriod::OneDay => Duration::from_secs(86400),
    };

    review_protocol::types::SamplingPolicy {
        id: policy.id,
        kind,
        interval,
        period,
        offset: policy.offset,
        src_ip: policy.src_ip,
        dst_ip: policy.dst_ip,
        node: policy.node.clone(),
        column: policy.column,
    }
}

/// Converts protocol `ColumnStatistics` to structured `ColumnStatistics`
pub(super) fn proto2db_column_statistics(
    proto_stats: &[review_protocol::types::ColumnStatistics],
) -> Vec<structured::ColumnStatistics> {
    proto_stats
        .iter()
        .map(|proto| {
            // Direct field mapping conversion
            structured::ColumnStatistics {
                description: proto.description.clone(),
                n_largest_count: proto.n_largest_count.clone(),
            }
        })
        .collect()
}

/// Converts protocol `TimeSeriesUpdate` to database `TimeSeriesUpdate`
pub(super) fn proto2db_time_series_updates(
    proto_updates: &[review_protocol::types::TimeSeriesUpdate],
) -> Result<Vec<review_database::TimeSeriesUpdate>, String> {
    // We assume that the types are identical. This is temporary until
    // review-database-0.41.0, where it uses a different type for time series.
    use bincode::Options;

    let codec = bincode::DefaultOptions::new();

    proto_updates
        .iter()
        .map(|proto| {
            // Use bincode for efficient conversion between compatible types
            let serialized = codec
                .serialize(proto)
                .map_err(|e| format!("Failed to serialize time series update: {e}"))?;
            codec
                .deserialize(&serialized)
                .map_err(|e| format!("Failed to deserialize time series update: {e}"))
        })
        .collect()
}
