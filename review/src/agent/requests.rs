//! Request handlers.

use std::collections::HashSet;

use anyhow::{Context, Result, anyhow};
use chrono::DateTime;
use quinn::{RecvStream, SendStream};
use review_database::{
    self as database, DataSource, EventMessage, Model, OutlierInfo, Store, Tidb,
    UpdateClusterRequest, event::Direction,
};
use review_protocol::{server::Handler, types as protocol};
use tracing::{error, warn};

use super::Manager;

const DEFAULT_SAVED: bool = false;

#[async_trait::async_trait]
impl Handler for Manager {
    #[cfg(feature = "web")]
    async fn get_allowlist(&self) -> Result<protocol::HostNetworkGroup, String> {
        use review_web::graphql::get_allow_networks;

        let store = self.store.read().await;
        get_allow_networks(&store)
            .map(|networks| super::db2proto_host_network_group(&networks))
            .map_err(|e| format!("{e:?}"))
    }

    #[cfg(feature = "web")]
    async fn get_blocklist(&self) -> Result<protocol::HostNetworkGroup, String> {
        use review_web::graphql::get_block_networks;

        let store = self.store.read().await;
        get_block_networks(&store)
            .map(|networks| super::db2proto_host_network_group(&networks))
            .map_err(|e| format!("{e:?}"))
    }

    async fn get_config(&self, peer: &str) -> Result<String, String> {
        self.get_agent_config(peer)
            .await
            .map_err(|e| format!("{e}"))
    }

    async fn get_data_source(
        &self,
        key: &protocol::DataSourceKey<'_>,
    ) -> Result<Option<protocol::DataSource>, String> {
        let database_data_source = {
            let store = self.store.read().await;
            get_data_source(&store, key).map_err(|e| format!("database error: {e}"))?
        };
        let data_source = {
            database_data_source.map(|ds| protocol::DataSource {
                id: ds.id,
                name: ds.name,
                server_name: ds.server_name,
                address: ds.address,
                data_type: match ds.data_type {
                    database::DataType::Csv => protocol::DataType::Csv,
                    database::DataType::Log => protocol::DataType::Log,
                    database::DataType::TimeSeries => protocol::DataType::TimeSeries,
                },
                source: ds.source,
                kind: ds.kind,
                description: ds.description,
            })
        };
        Ok(data_source)
    }

    async fn get_indicator(&self, name: &str) -> Result<HashSet<Vec<String>>, String> {
        let model_indicator = {
            let store = self.store.read().await;
            let map = store.model_indicator_map();
            map.get(name)
        }
        .map_err(|e| format!("database error: {e}"))?;
        Ok(model_indicator.map(|m| m.tokens).unwrap_or_default())
    }

    #[cfg(feature = "web")]
    async fn get_internal_network_list(
        &self,
        peer: &str,
    ) -> Result<protocol::HostNetworkGroup, String> {
        self.internal_network_list(peer)
            .await
            .map(|networks| super::db2proto_host_network_group(&networks))
    }

    async fn get_model_names(&self) -> Result<Vec<String>, String> {
        let models = self
            .model_names()
            .await
            .map_err(|e| format!("cannot load model names: {e}"))?;
        Ok(models)
    }

    #[cfg(feature = "web")]
    async fn get_pretrained_model(&self, name: &str) -> Result<Vec<u8>, String> {
        self.get_pretrained_model(name)
            .await
            .map_err(|e| format!("cannot load pretrained model: {e}"))
    }

    async fn get_tidb_patterns(
        &self,
        db_names: &[(&str, &str)],
    ) -> Result<Vec<(String, Option<protocol::Tidb>)>, String> {
        let result = {
            let store = self.store.read().await;
            let table = store.tidb_map();
            table.get_patterns(db_names)
        }
        .map_err(|e| format!("cannot load TiDB patterns: {e}"))?;

        Ok(result
            .into_iter()
            .map(|(key, value)| {
                let value = value.map(protocol_tidb);
                (key.to_string(), value)
            })
            .collect())
    }

    async fn get_tor_exit_node_list(&self) -> Result<Vec<String>, String> {
        self.tor_exit_node_list().await.map_err(|e| e.to_string())
    }

    async fn get_trusted_domain_list(&self) -> Result<Vec<String>, String> {
        self.trusted_domain_list().await.map_err(|e| e.to_string())
    }

    #[cfg(feature = "web")]
    async fn get_trusted_user_agent_list(&self) -> Result<Vec<String>, String> {
        use review_database::Iterable;

        let store = self.store.read().await;
        let table = store.trusted_user_agent_map();
        table
            .iter(Direction::Forward, None)
            .map(|res| res.map(|entry| entry.user_agent))
            .collect::<Result<Vec<_>, anyhow::Error>>()
            .map_err(|e| e.to_string())
    }

    async fn renew_certificate(&self, peer_key: &str) -> Result<(String, String), String> {
        self.renew_certificate(peer_key)
            .await
            .map_err(|e| e.to_string())
    }

    async fn get_model(&self, name: &str) -> Result<Vec<u8>, String> {
        let model = self
            .db
            .load_model_by_name(name)
            .await
            .map_err(|e| format!("Failed to load model: {e}"))?;
        model
            .into_serialized()
            .map_err(|e| format!("Failed to serialize model: {e}"))
    }

    async fn insert_column_statistics(
        &self,
        statistics: &[protocol::ColumnStatisticsUpdate],
        model_id: i32,
        batch_ts: i64,
    ) -> Result<(), String> {
        use std::collections::HashMap;

        let names = statistics
            .iter()
            .map(|stat| stat.cluster_id.as_str())
            .collect::<Vec<_>>();
        let cluster_id_map = self
            .db
            .cluster_name_to_ids(model_id, &names)
            .await
            .map_err(|e| format!("Failed to get cluster IDs: {e}"))?
            .into_iter()
            .map(|(id, name)| (name, id))
            .collect::<HashMap<_, _>>();
        let batch_ts = DateTime::from_timestamp_nanos(batch_ts).naive_utc();
        let store = self.store.read().await;
        let cstat = store.column_stats_map();

        let stats = statistics
            .iter()
            .filter_map(|stat| {
                cluster_id_map.get(&stat.cluster_id).and_then(|&cid| {
                    u32::try_from(cid).ok().map(|cid_u32| {
                        let column_stats =
                            super::proto2db_column_statistics(&stat.column_statistics);
                        (cid_u32, column_stats)
                    })
                })
            })
            .collect();
        cstat
            .insert_column_statistics(stats, model_id, batch_ts)
            .map_err(|e| format!("Failed to insert column statistics: {e}"))?;
        Ok(())
    }

    async fn insert_model(&self, model_bytes: &[u8]) -> Result<i32, String> {
        use review_database::{BatchInfo, Scores};

        let model = Model::from_serialized(model_bytes)
            .map_err(|e| format!("Failed to deserialize model: {e}"))?;
        let id = self
            .db
            .add_model(&model)
            .await
            .map_err(|e| format!("Failed to add model: {e}"))?;
        self.with_store(|store| {
            for batch in model.batch_info {
                let record = BatchInfo {
                    model: id,
                    inner: batch.clone(),
                };
                store.batch_info_map().insert(&record)?;
            }
            let record = Scores::new(id, model.scores.clone());
            store.scores_map().insert(&record)
        })
        .await
        .map_err(|e| format!("Failed to store model info: {e}"))?;
        Ok(id)
    }

    async fn insert_time_series(
        &self,
        time_series: &[protocol::TimeSeriesUpdate],
        model_id: i32,
        batch_ts: i64,
    ) -> Result<(), String> {
        let batch_ts = DateTime::from_timestamp_nanos(batch_ts).naive_utc();

        let db_time_series = super::proto2db_time_series_updates(time_series)
            .map_err(|e| format!("Failed to convert time series: {e}"))?;

        self.db
            .add_time_series(db_time_series, model_id, batch_ts)
            .await
            .map_err(|e| format!("Failed to add time series: {e}"))?;
        Ok(())
    }

    async fn remove_model(&self, name: &str) -> Result<(), String> {
        let id = self
            .db
            .delete_model(name)
            .await
            .map_err(|e| format!("Failed to delete model: {e}"))?;
        self.with_store(|store| {
            store.batch_info_map().delete_all_for(id)?;
            store.scores_map().delete(id)
        })
        .await
        .map_err(|e| format!("Failed to remove model info: {e}"))?;
        Ok(())
    }

    async fn update_clusters(
        &self,
        input: &[protocol::UpdateClusterRequest],
        model_id: i32,
    ) -> Result<(), String> {
        let db_input: Vec<UpdateClusterRequest> = input
            .iter()
            .map(super::proto2db_update_cluster_request)
            .collect();
        self.db
            .update_clusters(db_input, model_id)
            .await
            .map_err(|e| format!("Failed to update clusters: {e}"))?;
        Ok(())
    }

    async fn update_model(&self, model_bytes: &[u8]) -> Result<i32, String> {
        use review_database::{BatchInfo, Scores};

        let model = Model::from_serialized(model_bytes)
            .map_err(|e| format!("Failed to deserialize model: {e}"))?;
        let model_id = self
            .db
            .update_model(&model)
            .await
            .map_err(|e| format!("Failed to update model: {e}"))?;
        self.with_store(|store| {
            for batch in model.batch_info {
                let record = BatchInfo {
                    model: model_id,
                    inner: batch.clone(),
                };
                store.batch_info_map().put(&record)?;
            }
            let record = Scores::new(model_id, model.scores.clone());
            store.scores_map().put(&record)
        })
        .await
        .map_err(|e| format!("Failed to store model info: {e}"))?;
        Ok(model_id)
    }

    async fn update_outliers(
        &self,
        outliers: &[protocol::OutlierInfo],
        model_id: i32,
        timestamp: i64,
    ) -> Result<(), String> {
        let db_outliers = outliers
            .iter()
            .map(|proto| super::proto2db_outlier_info(proto, model_id, timestamp, DEFAULT_SAVED))
            .collect::<Vec<_>>();

        self.with_store(|store| {
            let retention_cutoff = jiff::Timestamp::now()
                .checked_sub(
                    jiff::Span::new()
                        .seconds(crate::config::DEFAULT_OUTLIER_RETENTION * 24 * 60 * 60),
                )
                .context("failed to calculate retention cutoff")?
                .as_nanosecond()
                .try_into()
                .context("retention cutoff timestamp out of range")?;
            clean_up_outliers(store, model_id, retention_cutoff)?;
            update_outliers(store, &db_outliers)
        })
        .await
        .map_err(|e| format!("Failed to update outliers: {e}"))
    }

    async fn insert_event_labels(
        &self,
        _model_id: i32,
        _round: u32,
        event_labels: &[protocol::EventMessage],
    ) -> Result<(), String> {
        let db_event_labels: Vec<EventMessage> = event_labels
            .iter()
            .map(super::proto2db_event_message)
            .collect();

        self.with_store(|store| {
            for event in &db_event_labels {
                if let Err(e) = store.events().put(event) {
                    error!("{e:?}");
                }
            }
            Ok(())
        })
        .await
        .map_err(|e| format!("Failed to insert event labels: {e}"))?;

        for event in db_event_labels {
            if let Err(e) = self.syslog_tx.send(event).await {
                warn!("syslog error: {e}");
            }
        }
        Ok(())
    }

    async fn insert_data_source(&self, data_source: &protocol::DataSource) -> Result<u32, String> {
        let db_data_source = super::proto2db_data_source(data_source);
        self.with_store(|store| {
            insert_data_source(store, &db_data_source).context(format!(
                "failed to insert data source {}",
                db_data_source.name
            ))
        })
        .await
        .map_err(|e| format!("{e}"))
    }

    async fn get_outliers(
        &self,
        model_id: i32,
        timestamp: i64,
    ) -> Result<Vec<(String, Vec<i64>)>, String> {
        self.with_store(|store| {
            let map = store.outlier_map();
            let mut outliers = std::collections::HashMap::new();

            for res in map.get(model_id, Some(timestamp), Direction::Forward, None) {
                let outlier = res?;
                let e = outliers.entry(outlier.sensor).or_insert(vec![]);
                e.push(outlier.id);
            }

            Ok(outliers.into_iter().collect::<Vec<_>>())
        })
        .await
        .map_err(|e| format!("Failed to get outliers: {e}"))
    }
}

impl Manager {
    pub(super) async fn handle_request(
        mut self,
        mut send: SendStream,
        mut recv: RecvStream,
        peer: String,
    ) -> Result<()> {
        review_protocol::server::handle(&mut self, &mut send, &mut recv, &peer).await?;
        Ok(())
    }

    async fn model_names(&self) -> Result<Vec<String>> {
        let limit = 100;
        let is_first = true;
        let models = self.db.load_models(&None, &None, is_first, limit).await?;
        Ok(models.into_iter().map(|m| m.name).collect::<Vec<_>>())
    }

    async fn renew_certificate(&self, peer_key: &str) -> Result<(String, String)> {
        // Get the certificate from the authenticated TLS connection
        let agents = self.agents.read().await;
        let agent = agents
            .get(peer_key)
            .ok_or_else(|| anyhow!("agent not found: {peer_key}"))?;
        let agent = agent.read().await;

        let certs = agent
            .channel
            .peer_identity()
            .ok_or_else(|| anyhow!("no peer identity available"))?
            .downcast::<Vec<rustls::pki_types::CertificateDer>>()
            .map_err(|_| anyhow!("unable to retrieve peer certificate"))?;
        let cert = certs
            .first()
            .ok_or_else(|| anyhow!("no certificate found in peer identity"))?;

        crate::tls::renew_ca_signed_certificate(cert.as_ref(), &self.tls_cert_config)
            .map_err(anyhow::Error::from)
    }

    #[cfg(feature = "web")]
    async fn get_pretrained_model(&self, name: &str) -> Result<Vec<u8>> {
        self.with_store(|store| {
            let model = store.pretrained_model(name)?;
            Ok(model.0)
        })
        .await
    }

    async fn get_agent_config(&self, peer: &str) -> Result<String> {
        let (agent, node_hostname) = peer
            .split_once('@')
            .ok_or(anyhow!("failed to get agent and host"))?;
        self.with_store(|store| {
            let result = store
                .node_map()
                .iter(Direction::Forward, None)
                .find_map(|res| {
                    if let Ok(n) = res
                        && let Some(profile) = n.profile
                        && profile.hostname == node_hostname
                    {
                        return Some(n.agents.into_iter().find(|a| a.key == agent));
                    }
                    None
                });
            match result {
                Some(Some(a)) => a
                    .config
                    .map(|c| c.to_string())
                    .ok_or(anyhow!(format!("{agent} config unavailable"),)),
                Some(None) => Err(anyhow!(format!("{agent} unregistered"))),
                None => Err(anyhow!(format!("{node_hostname} unregistered"),)),
            }
        })
        .await
    }

    async fn with_store<T, F>(&self, operation: F) -> Result<T>
    where
        F: FnOnce(&Store) -> Result<T>,
    {
        let store = self.store.read().await;
        operation(&store).map_err(|e| e.context("database error"))
    }
}

fn get_data_source(store: &Store, key: &protocol::DataSourceKey) -> Result<Option<DataSource>> {
    let map = store.data_source_map();
    let data_source = match key {
        protocol::DataSourceKey::Id(id) => {
            if let Some(ds) = map.get_by_id(*id).context("failed to read source info")? {
                ds
            } else {
                return Ok(None);
            }
        }
        protocol::DataSourceKey::Name(name) => {
            let Some(datasource) = map.get(name).context("failed to read source info")? else {
                return Ok(None);
            };
            datasource
        }
    };
    Ok(Some(data_source))
}

fn insert_data_source(store: &Store, data: &DataSource) -> Result<u32> {
    let map = store.data_source_map();
    let value = DataSource {
        id: u32::MAX,
        name: data.name.clone(),
        server_name: data.server_name.clone(),
        address: data.address,
        data_type: data.data_type,
        source: data.source.clone(),
        kind: data.kind.clone(),
        description: data.description.clone(),
    };
    map.put(value)
}

fn update_outliers(store: &Store, outliers: &[OutlierInfo]) -> Result<()> {
    let map = store.outlier_map();

    for outlier in outliers {
        map.insert(outlier)?;
    }
    Ok(())
}

fn clean_up_outliers(store: &Store, model_id: i32, criteria: i64) -> Result<usize> {
    let mut deleted = 0;
    let map = store.outlier_map();

    for res in map.get(model_id, None, Direction::Forward, None) {
        let outlier = res?;

        if outlier.is_saved {
            continue;
        }
        if outlier.timestamp > criteria {
            continue;
        }
        map.remove(&outlier)?;
        deleted += 1;
    }

    Ok(deleted)
}

fn protocol_tidb(tidb: Tidb) -> review_protocol::types::Tidb {
    use review_database as db;
    use review_protocol::types as pr;

    let kind = match tidb.kind {
        db::TidbKind::Ip => pr::TiKind::Ip,
        db::TidbKind::Url => pr::TiKind::Url,
        db::TidbKind::Token => pr::TiKind::Token,
        db::TidbKind::Regex => pr::TiKind::Regex,
    };
    let patterns = tidb
        .patterns
        .into_iter()
        .map(|r| pr::TiRule {
            rule_id: r.rule_id,
            category: Some(protocol_event_category(r.category)),
            name: r.name,
            description: r.description,
            references: r.references,
            samples: r.samples,
            signatures: r.signatures,
            confidence: None,
            kind: None,
        })
        .collect();
    review_protocol::types::Tidb {
        id: tidb.id,
        name: tidb.name,
        description: tidb.description,
        kind,
        category: Some(protocol_event_category(tidb.category)),
        version: tidb.version,
        patterns,
    }
}

fn protocol_event_category(
    category: review_database::types::EventCategory,
) -> review_protocol::types::EventCategory {
    use review_database::types as db;
    use review_protocol::types as pr;
    match category {
        db::EventCategory::Reconnaissance | db::EventCategory::Unknown => {
            pr::EventCategory::Reconnaissance
        }
        db::EventCategory::InitialAccess => pr::EventCategory::InitialAccess,
        db::EventCategory::Execution => pr::EventCategory::Execution,
        db::EventCategory::CredentialAccess => pr::EventCategory::CredentialAccess,
        db::EventCategory::Discovery => pr::EventCategory::Discovery,
        db::EventCategory::LateralMovement => pr::EventCategory::LateralMovement,
        db::EventCategory::CommandAndControl => pr::EventCategory::CommandAndControl,
        db::EventCategory::Exfiltration => pr::EventCategory::Exfiltration,
        db::EventCategory::Impact => pr::EventCategory::Impact,
        db::EventCategory::Collection => pr::EventCategory::Collection,
        db::EventCategory::DefenseEvasion => pr::EventCategory::DefenseEvasion,
        db::EventCategory::Persistence => pr::EventCategory::Persistence,
        db::EventCategory::PrivilegeEscalation => pr::EventCategory::PrivilegeEscalation,
        db::EventCategory::ResourceDevelopment => pr::EventCategory::ResourceDevelopment,
    }
}
