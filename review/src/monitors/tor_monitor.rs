use std::{sync::Arc, time::Duration};

use review_database::TorExitNode;
use tokio::{sync::RwLock, time};

use crate::Store;

// The TOR exit node list has entries like below:
//
// ExitNode EB750DD08C41C39B70680BD4278467A140BB2A07
// Published 2021-09-19 12:45:56
// LastStatus 2021-09-19 19:00:00
// ExitAddress 71.19.148.84 2021-09-19 19:54:50
// ExitAddress 198.98.53.192 2021-09-02 17:31:39
//
fn parse_fetched_list(body: &str) -> Vec<TorExitNode> {
    body.lines()
        .filter(|line| line.starts_with("ExitAddress"))
        .filter_map(|line| {
            let mut line = line.split_whitespace();
            line.next()?; // skip "ExitAddress"
            let ip_address = line.next()?.into();
            let updated_at = format!("{}T{}Z", line.next()?, line.next()?).parse().ok()?;
            Some(TorExitNode {
                ip_address,
                updated_at,
            })
        })
        .collect::<Vec<_>>()
}

async fn fetch_tor_exit_node_list() -> Result<String, reqwest::Error> {
    reqwest::get("https://check.torproject.org/exit-addresses")
        .await?
        .text()
        .await
}

pub async fn run(store: Arc<RwLock<Store>>, poll_interval: u32, manager: crate::agent::Manager) {
    let mut poll_interval = time::interval(Duration::from_secs((poll_interval * 60).into()));
    loop {
        poll_interval.tick().await;

        let exit_node_list = match fetch_tor_exit_node_list().await {
            Ok(body) => parse_fetched_list(&body),
            Err(e) => {
                tracing::error!("Failed to fetch the tor exit node list: {}", e);
                continue;
            }
        };

        if exit_node_list.is_empty() {
            continue;
        }

        let result = {
            let store = store.read().await;
            let map = store.tor_exit_node_map();
            map.replace_all(exit_node_list.into_iter())
        };
        if let Err(e) = result {
            tracing::error!("Failed to store the tor exit node list: {}", e);
        }

        if let Err(e) = manager.broadcast_tor_exit_node_list().await {
            tracing::error!("Failed to broad cast tor exit node list: {}", e);
        }
    }
}
