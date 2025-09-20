use std::{convert::TryInto, mem::size_of};

use async_graphql::connection::OpaqueCursor;
use async_graphql::{
    Context, InputObject, Object, Result,
    connection::{Connection, EmptyFields},
    types::ID,
};
use chrono::{DateTime, Utc};
use review_database::{self as database};
use tracing::info;

use super::{
    Role, RoleGuard,
    cluster::try_id_args_into_ints,
    customer::{Customer, HostNetworkGroup, HostNetworkGroupInput},
};
use crate::graphql::query_with_constraints;
use crate::info_with_username;

#[derive(Default)]
pub(super) struct NetworkQuery;

#[Object]
impl NetworkQuery {
    /// A list of networks.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn network_list(
        &self,
        ctx: &Context<'_>,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<OpaqueCursor<Vec<u8>>, Network, NetworkTotalCount, EmptyFields>> {
        info_with_username!(ctx, "Network configuration list retrieved");
        query_with_constraints(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move { load(ctx, after, before, first, last).await },
        )
        .await
    }

    /// A network for the given ID.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn network(&self, ctx: &Context<'_>, id: ID) -> Result<Network> {
        let i = id.as_str().parse::<u32>().map_err(|_| "invalid ID")?;

        let store = crate::graphql::get_store(ctx).await?;
        let map = store.network_map();
        let Some(inner) = map.get_by_id(i)? else {
            return Err("no such network".into());
        };
        info_with_username!(ctx, "Network configuration for {} retrieved", inner.name);
        Ok(Network { inner })
    }
}

#[derive(Default)]
pub(super) struct NetworkMutation;

#[Object]
impl NetworkMutation {
    /// Inserts a new network, returning the ID of the network.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))")]
    async fn insert_network(
        &self,
        ctx: &Context<'_>,
        name: String,
        description: String,
        networks: HostNetworkGroupInput,
        customer_ids: Vec<ID>,
        tag_ids: Vec<ID>,
    ) -> Result<ID> {
        let customer_ids = id_args_into_uints(&customer_ids)?;
        let tag_ids = id_args_into_uints(&tag_ids)?;
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.network_map();
        let entry = review_database::Network::new(
            name.clone(),
            description,
            networks.try_into()?,
            customer_ids,
            tag_ids,
        );
        let id = map.insert(entry)?;
        info_with_username!(ctx, "Network {name} has been registered");
        Ok(ID(id.to_string()))
    }

    /// Removes networks, returning the networks names that no longer exist.
    ///
    /// On error, some networks may have been removed.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))")]
    async fn remove_networks(
        &self,
        ctx: &Context<'_>,
        #[graphql(validator(min_items = 1))] ids: Vec<ID>,
    ) -> Result<Vec<String>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.network_map();

        let mut removed = Vec::with_capacity(ids.len());
        for id in ids {
            let i = id.as_str().parse::<u32>().map_err(|_| "invalid ID")?;
            let mut key = map.remove(i)?;

            let len = key.len();
            let name = if len > size_of::<u32>() {
                key.truncate(len - size_of::<u32>());
                match String::from_utf8(key) {
                    Ok(key) => key,
                    Err(e) => String::from_utf8_lossy(e.as_bytes()).into(),
                }
            } else {
                String::from_utf8_lossy(&key).into()
            };
            info_with_username!(ctx, "Network {name} has been deleted");
            removed.push(name);
        }
        Ok(removed)
    }

    /// Updates the given network.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))")]
    async fn update_network(
        &self,
        ctx: &Context<'_>,
        id: ID,
        old: NetworkUpdateInput,
        new: NetworkUpdateInput,
    ) -> Result<ID> {
        let i = id.as_str().parse::<u32>().map_err(|_| "invalid ID")?;

        let old_name = old.name.clone();
        let new_name = new.name.clone();
        let store = crate::graphql::get_store(ctx).await?;
        let mut map = store.network_map();
        map.update(i, &old.try_into()?, &new.try_into()?)?;
        info_with_username!(
            ctx,
            "Network {:?} has been updated to {:?}",
            old_name,
            new_name
        );
        Ok(id)
    }
}

#[derive(InputObject)]
struct NetworkUpdateInput {
    name: Option<String>,
    description: Option<String>,
    networks: Option<HostNetworkGroupInput>,
    customer_ids: Option<Vec<ID>>,
    tag_ids: Option<Vec<ID>>,
}

impl TryFrom<NetworkUpdateInput> for review_database::NetworkUpdate {
    type Error = async_graphql::Error;

    fn try_from(input: NetworkUpdateInput) -> Result<Self, Self::Error> {
        let customer_ids = try_id_args_into_ints::<u32>(input.customer_ids)?;
        let tag_ids = try_id_args_into_ints::<u32>(input.tag_ids)?;
        Ok(Self::new(
            input.name,
            input.description,
            input.networks.and_then(|v| v.try_into().ok()),
            customer_ids,
            tag_ids,
        ))
    }
}

pub(super) struct Network {
    inner: database::Network,
}

#[Object]
impl Network {
    async fn id(&self) -> ID {
        ID(self.inner.id.to_string())
    }

    async fn name(&self) -> &str {
        &self.inner.name
    }

    async fn description(&self) -> &str {
        &self.inner.description
    }

    async fn networks(&self) -> HostNetworkGroup<'_> {
        (&self.inner.networks).into()
    }

    #[graphql(name = "customerList")]
    async fn customer_ids(&self, ctx: &Context<'_>) -> Result<Vec<Customer>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.customer_map();
        let mut customers = Vec::new();

        for &id in &self.inner.customer_ids {
            #[allow(clippy::cast_sign_loss)] // u32 stored as i32 in database
            let Some(customer) = map.get_by_id(id)? else {
                continue;
            };
            customers.push(customer.into());
        }
        Ok(customers)
    }

    async fn tag_ids(&self) -> Vec<ID> {
        self.inner
            .tag_ids()
            .iter()
            .map(|&id| ID(id.to_string()))
            .collect()
    }

    async fn creation_time(&self) -> DateTime<Utc> {
        self.inner.creation_time
    }
}

impl From<database::Network> for Network {
    fn from(inner: database::Network) -> Self {
        Self { inner }
    }
}

pub(super) fn id_args_into_uints(ids: &[ID]) -> Result<Vec<u32>> {
    ids.iter()
        .map(|id| {
            let id = id.as_str().parse::<u32>().map_err(|_| "invalid ID")?;
            Ok::<_, async_graphql::Error>(id)
        })
        .collect::<Result<Vec<_>, _>>()
}

struct NetworkTotalCount;

#[Object]
impl NetworkTotalCount {
    /// The total number of edges.
    async fn total_count(&self, ctx: &Context<'_>) -> Result<usize> {
        let store = crate::graphql::get_store(ctx).await?;

        Ok(store.network_map().count()?)
    }
}

async fn load(
    ctx: &Context<'_>,
    after: Option<OpaqueCursor<Vec<u8>>>,
    before: Option<OpaqueCursor<Vec<u8>>>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<Connection<OpaqueCursor<Vec<u8>>, Network, NetworkTotalCount, EmptyFields>> {
    let store = crate::graphql::get_store(ctx).await?;
    let map = store.network_map();
    super::load_edges(&map, after, before, first, last, NetworkTotalCount)
}

#[cfg(test)]
mod tests {
    use crate::graphql::TestSchema;
    #[tokio::test]
    async fn remove_networks() {
        let schema = TestSchema::new().await;
        let res = schema
            .execute(r"{networkList{edges{node{name}}totalCount}}")
            .await;
        assert_eq!(
            res.data.to_string(),
            r"{networkList: {edges: [], totalCount: 0}}"
        );

        let res = schema
            .execute(
                r#"mutation {
                    insertNetwork(name: "n1", description: "", networks: {
                        hosts: [], networks: [], ranges: []
                    }, customerIds: [], tagIds: [])
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNetwork: "0"}"#);

        let res = schema
            .execute(r"{networkList{edges{node{name}}totalCount}}")
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{networkList: {edges: [{node: {name: "n1"}}], totalCount: 1}}"#
        );

        let res = schema
            .execute(r#"mutation { removeNetworks(ids: ["0"]) }"#)
            .await;
        assert_eq!(res.data.to_string(), r#"{removeNetworks: ["n1"]}"#);

        let res = schema
            .execute(r"{networkList{edges{node{name}}totalCount}}")
            .await;
        assert_eq!(
            res.data.to_string(),
            r"{networkList: {edges: [], totalCount: 0}}"
        );
    }

    #[tokio::test]
    async fn update_network() {
        let schema = TestSchema::new().await;
        let res = schema.execute(r"{networkList{totalCount}}").await;
        assert_eq!(res.data.to_string(), r"{networkList: {totalCount: 0}}");

        let res = schema
            .execute(
                r#"mutation {
                    insertNetwork(name: "n0", description: "", networks: {
                        hosts: ["1.1.1.1"], networks: [], ranges: []
                    }, customerIds: [], tagIds: [])
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNetwork: "0"}"#);

        let res = schema
            .execute(
                r#"mutation {
                updateNetwork(
                    id: "0",
                    old: {
                        name: "n0",
                        networks: {
                            hosts: ["1.1.1.1"],
                            networks: [],
                            ranges: []
                        }
                        customerIds: [],
                        tagIds: []
                    },
                    new: {
                        name: "n0",
                        networks: {
                            hosts: ["2.2.2.2"],
                            networks: [],
                            ranges: []
                        }
                        customerIds: [],
                        tagIds: []
                    }
                )
            }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{updateNetwork: "0"}"#);
    }

    #[tokio::test]
    async fn select_networks() {
        let schema = TestSchema::new().await;
        let res = schema
            .execute(
                r#"mutation {
                    insertNetwork(name: "n1", description: "", networks: {
                        hosts: [], networks: [], ranges: []
                    }, customerIds: [], tagIds: [0, 1, 2])
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNetwork: "0"}"#);
        let res = schema
            .execute(r"{networkList{edges{node{name tagIds}}totalCount}}")
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{networkList: {edges: [{node: {name: "n1", tagIds: ["0", "1", "2"]}}], totalCount: 1}}"#
        );
    }
}
