use anyhow::anyhow;
use bincode::Options;
use oinq::frame;

use super::Connection;
use crate::{
    client,
    types::{HostNetworkGroup, Process, ResourceUsage, SamplingPolicy, TrafficFilterRule},
};

/// The server API.
impl Connection {
    /// Fetches the list of processes running on the agent.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization/deserialization failed or
    /// communication with the client failed.
    pub async fn get_process_list(&self) -> anyhow::Result<Vec<Process>> {
        self.send_request(client::RequestCode::ProcessList, &())
            .await
    }

    /// Fetches the resource usage of an agent.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization/deserialization failed or
    /// communication with the client failed.
    pub async fn get_resource_usage(&self) -> anyhow::Result<ResourceUsage> {
        self.send_request::<(), (String, ResourceUsage)>(client::RequestCode::ResourceUsage, &())
            .await
            .map(|(_, usage)| usage)
    }

    /// Sends the allowlist for network addresses.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization failed or communication with the client failed.
    pub async fn send_allowlist(&self, allowlist: &HostNetworkGroup) -> anyhow::Result<()> {
        self.send_request(client::RequestCode::Allowlist, allowlist)
            .await
    }

    /// Sends the blocklist for network addresses.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization failed or communication with the client failed.
    pub async fn send_blocklist(&self, blocklist: &HostNetworkGroup) -> anyhow::Result<()> {
        self.send_request(client::RequestCode::Blocklist, blocklist)
            .await
    }

    /// Sends the config-update command.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization failed or communication with the client failed.
    pub async fn send_config_update_cmd(&self) -> anyhow::Result<()> {
        self.send_request(client::RequestCode::UpdateConfig, &())
            .await
    }

    /// Sends the traffic filtering rules.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization failed or communication with the client failed.
    pub async fn send_filtering_rules(&self, list: &[TrafficFilterRule]) -> anyhow::Result<()> {
        self.send_request(client::RequestCode::ReloadFilterRule, list)
            .await
    }

    /// Sends the internal network list.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization failed or communication with the client failed.
    pub async fn send_internal_network_list(&self, list: &HostNetworkGroup) -> anyhow::Result<()> {
        self.send_request(client::RequestCode::InternalNetworkList, list)
            .await
    }

    /// Sends the ping message.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization failed or communication with the client failed.
    pub async fn send_ping(&self) -> anyhow::Result<()> {
        self.send_request(client::RequestCode::EchoRequest, &())
            .await
    }

    /// Sends the reboot command.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization failed or communication with the client failed.
    pub async fn send_reboot_cmd(&self) -> anyhow::Result<()> {
        self.send_request(client::RequestCode::Reboot, &()).await
    }

    /// Sends the sampling policies.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization failed or communication with the client failed.
    pub async fn send_sampling_policies(&self, list: &[SamplingPolicy]) -> anyhow::Result<()> {
        self.send_request(client::RequestCode::SamplingPolicyList, list)
            .await
    }

    /// Sends the shutdown command.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization failed or communication with the client failed.
    pub async fn send_shutdown_cmd(&self) -> anyhow::Result<()> {
        self.send_request(client::RequestCode::Shutdown, &()).await
    }

    /// Sends a list of Tor exit nodes to the client.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization failed or communication with the client failed.
    pub async fn send_tor_exit_node_list(&self, list: &[String]) -> anyhow::Result<()> {
        self.send_request(client::RequestCode::TorExitNodeList, list)
            .await
    }

    /// Sends a list of trusted domains to the client.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization failed or communication with the client failed.
    pub async fn send_trusted_domain_list(&self, list: &[String]) -> anyhow::Result<()> {
        self.send_request(client::RequestCode::TrustedDomainList, list)
            .await
    }

    /// Sends a list of trusted user-agents to the client.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization failed or communication with the client failed.
    pub async fn send_trusted_user_agent_list(&self, list: &[String]) -> anyhow::Result<()> {
        self.send_request(client::RequestCode::TrustedUserAgentList, list)
            .await
    }

    /// Sends the given payload to the client.
    async fn send_request<T: serde::Serialize + ?Sized, S: serde::de::DeserializeOwned>(
        &self,
        request_code: client::RequestCode,
        payload: &T,
    ) -> anyhow::Result<S> {
        let Ok(mut buf) = bincode::serialize::<u32>(&request_code.into()) else {
            unreachable!("serialization of u32 into memory buffer should not fail")
        };
        let ser = bincode::DefaultOptions::new();
        buf.extend(ser.serialize(payload)?);

        let (mut send, mut recv) = self.conn.open_bi().await?;
        frame::send_raw(&mut send, &buf).await?;

        frame::recv::<Result<S, String>>(&mut recv, &mut buf)
            .await?
            .map_err(|e| anyhow!(e))
    }
}

#[cfg(test)]
mod tests {
    #[cfg(all(feature = "client", feature = "server"))]
    use {
        crate::{
            test::TEST_ENV,
            types::{HostNetworkGroup, SamplingKind, SamplingPolicy},
        },
        ipnet::IpNet,
        std::{
            net::{IpAddr, Ipv4Addr},
            time::Duration,
        },
    };

    #[cfg(all(feature = "client", feature = "server"))]
    // Define a constant IP address for tests
    const IP_ADDR_1: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

    #[cfg(all(feature = "client", feature = "server"))]
    // Shared handler for all tests
    struct TestHandler;

    #[cfg(all(feature = "client", feature = "server"))]
    #[async_trait::async_trait]
    impl crate::request::Handler for TestHandler {
        async fn allowlist(&mut self, list: HostNetworkGroup) -> Result<(), String> {
            if list.hosts == [IP_ADDR_1] {
                Ok(())
            } else {
                Err("unexpected domain list".to_string())
            }
        }

        async fn blocklist(&mut self, list: HostNetworkGroup) -> Result<(), String> {
            if list.hosts == [IP_ADDR_1] {
                Ok(())
            } else {
                Err("unexpected blocklist".to_string())
            }
        }

        async fn update_config(&mut self) -> Result<(), String> {
            Ok(())
        }

        async fn update_traffic_filter_rules(
            &mut self,
            rules: &[super::TrafficFilterRule],
        ) -> Result<(), String> {
            if rules.len() == 1 {
                Ok(())
            } else {
                Err("unexpected filtering rules".to_string())
            }
        }

        async fn internal_network_list(&mut self, list: HostNetworkGroup) -> Result<(), String> {
            if list.hosts == [IP_ADDR_1] {
                Ok(())
            } else {
                Err("unexpected internal network list".to_string())
            }
        }

        async fn process_list(&mut self) -> Result<Vec<super::Process>, String> {
            Ok(vec![super::Process {
                user: "test-user".to_string(),
                cpu_usage: 10.0,
                mem_usage: 20.0,
                start_time: 1_234_567_890,
                command: "test-command".to_string(),
            }])
        }

        async fn resource_usage(&mut self) -> Result<(String, super::ResourceUsage), String> {
            Ok((
                "test-host".to_string(),
                super::ResourceUsage {
                    cpu_usage: 0.5,
                    total_memory: 100,
                    used_memory: 50,
                    disk_used_bytes: 500,
                    disk_available_bytes: 500,
                },
            ))
        }

        async fn reboot(&mut self) -> Result<(), String> {
            Ok(())
        }

        async fn sampling_policy_list(
            &mut self,
            policies: &[super::SamplingPolicy],
        ) -> Result<(), String> {
            if policies.len() == 1 && policies[0].id == 42 {
                Ok(())
            } else {
                Err("unexpected sampling policies".to_string())
            }
        }

        async fn shutdown(&mut self) -> Result<(), String> {
            Ok(())
        }

        async fn tor_exit_node_list(&mut self, nodes: &[&str]) -> Result<(), String> {
            if nodes == ["192.168.1.1", "10.0.0.1"] {
                Ok(())
            } else {
                Err("unexpected tor exit node list".to_string())
            }
        }

        async fn trusted_domain_list(&mut self, domains: &[&str]) -> Result<(), String> {
            if domains == ["example.com", "test.org"] {
                Ok(())
            } else {
                Err("unexpected trusted domain list".to_string())
            }
        }

        async fn trusted_user_agent_list(&mut self, agents: &[&str]) -> Result<(), String> {
            if agents == ["Mozilla/5.0", "Chrome/91.0"] {
                Ok(())
            } else {
                Err("unexpected trusted user agent list".to_string())
            }
        }
    }

    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn get_resource_usage() {
        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let mut handler = TestHandler;
        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move {
            let (mut send, mut recv) = handler_conn.accept_bi().await.unwrap();

            crate::request::handle(&mut handler, &mut send, &mut recv).await
        });
        let server_res = server_conn.get_resource_usage().await;
        assert!(server_res.is_ok());
        let usage = server_res.unwrap();
        assert_eq!(usage.total_memory, 100);
        let client_res = client_handle.await.unwrap();
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }

    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn get_process_list() {
        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let mut handler = TestHandler;
        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move {
            let (mut send, mut recv) = handler_conn.accept_bi().await.unwrap();

            crate::request::handle(&mut handler, &mut send, &mut recv).await
        });
        let server_res = server_conn.get_process_list().await;
        assert!(server_res.is_ok());
        let processes = server_res.unwrap();
        assert_eq!(processes.len(), 1);
        assert_eq!(processes[0].user, "test-user");
        let client_res = client_handle.await.unwrap();
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }

    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn send_allowlist() {
        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let allowlist_to_send = HostNetworkGroup {
            hosts: vec![IP_ADDR_1],
            networks: vec![],
            ip_ranges: vec![],
        };

        let mut handler = TestHandler;
        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move {
            let (mut send, mut recv) = handler_conn.accept_bi().await.unwrap();

            crate::request::handle(&mut handler, &mut send, &mut recv).await
        });
        let server_res = server_conn.send_allowlist(&allowlist_to_send).await;
        assert!(server_res.is_ok());
        let client_res = client_handle.await.unwrap();
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }

    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn send_reboot_cmd() {
        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let mut handler = TestHandler;
        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move {
            let (mut send, mut recv) = handler_conn.accept_bi().await.unwrap();

            crate::request::handle(&mut handler, &mut send, &mut recv).await
        });
        let server_res = server_conn.send_reboot_cmd().await;
        assert!(server_res.is_ok());
        let client_res = client_handle.await.unwrap();
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }

    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn send_blocklist() {
        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let blocklist_to_send = HostNetworkGroup {
            hosts: vec![IP_ADDR_1],
            networks: vec![],
            ip_ranges: vec![],
        };

        let mut handler = TestHandler;
        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move {
            let (mut send, mut recv) = handler_conn.accept_bi().await.unwrap();

            crate::request::handle(&mut handler, &mut send, &mut recv).await
        });
        let server_res = server_conn.send_blocklist(&blocklist_to_send).await;
        assert!(server_res.is_ok());
        let client_res = client_handle.await.unwrap();
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }

    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn send_config_update_cmd() {
        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let mut handler = TestHandler;
        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move {
            let (mut send, mut recv) = handler_conn.accept_bi().await.unwrap();

            crate::request::handle(&mut handler, &mut send, &mut recv).await
        });
        let server_res = server_conn.send_config_update_cmd().await;
        assert!(server_res.is_ok());
        let client_res = client_handle.await.unwrap();
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }

    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn send_filtering_rules() {
        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let filtering_rules_to_send = vec![(
            "0.0.0.0/0".parse::<IpNet>().unwrap(),
            Some(vec![80]),
            Some(vec![6]),
        )];

        let mut handler = TestHandler;
        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move {
            let (mut send, mut recv) = handler_conn.accept_bi().await.unwrap();

            crate::request::handle(&mut handler, &mut send, &mut recv).await
        });
        let server_res = server_conn
            .send_filtering_rules(&filtering_rules_to_send)
            .await;
        assert!(server_res.is_ok());
        let client_res = client_handle.await.unwrap();
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }

    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn send_internal_network_list() {
        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let internal_network_list_to_send = HostNetworkGroup {
            hosts: vec![IP_ADDR_1],
            networks: vec![],
            ip_ranges: vec![],
        };

        let mut handler = TestHandler;
        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move {
            let (mut send, mut recv) = handler_conn.accept_bi().await.unwrap();

            crate::request::handle(&mut handler, &mut send, &mut recv).await
        });
        let server_res = server_conn
            .send_internal_network_list(&internal_network_list_to_send)
            .await;
        assert!(server_res.is_ok());
        let client_res = client_handle.await.unwrap();
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }

    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn send_sampling_policies() {
        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let sampling_policies_to_send = vec![SamplingPolicy {
            id: 42,
            kind: SamplingKind::Conn,
            interval: Duration::from_secs(60),
            period: Duration::from_secs(3600),
            offset: 0,
            src_ip: None,
            dst_ip: None,
            node: None,
            column: None,
        }];

        let mut handler = TestHandler;
        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move {
            let (mut send, mut recv) = handler_conn.accept_bi().await.unwrap();

            crate::request::handle(&mut handler, &mut send, &mut recv).await
        });
        let server_res = server_conn
            .send_sampling_policies(&sampling_policies_to_send)
            .await;
        assert!(server_res.is_ok());
        let client_res = client_handle.await.unwrap();
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }

    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn send_tor_exit_node_list() {
        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let tor_exit_node_list_to_send = vec!["192.168.1.1".to_string(), "10.0.0.1".to_string()];

        let mut handler = TestHandler;
        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move {
            let (mut send, mut recv) = handler_conn.accept_bi().await.unwrap();

            crate::request::handle(&mut handler, &mut send, &mut recv).await
        });
        let server_res = server_conn
            .send_tor_exit_node_list(&tor_exit_node_list_to_send)
            .await;
        assert!(server_res.is_ok());
        let client_res = client_handle.await.unwrap();
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }

    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn send_trusted_domain_list() {
        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let trusted_domain_list_to_send = vec!["example.com".to_string(), "test.org".to_string()];

        let mut handler = TestHandler;
        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move {
            let (mut send, mut recv) = handler_conn.accept_bi().await.unwrap();

            crate::request::handle(&mut handler, &mut send, &mut recv).await
        });
        let server_res = server_conn
            .send_trusted_domain_list(&trusted_domain_list_to_send)
            .await;
        assert!(server_res.is_ok());
        let client_res = client_handle.await.unwrap();
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }

    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn send_trusted_user_agent_list() {
        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let trusted_user_agent_list_to_send =
            vec!["Mozilla/5.0".to_string(), "Chrome/91.0".to_string()];

        let mut handler = TestHandler;
        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move {
            let (mut send, mut recv) = handler_conn.accept_bi().await.unwrap();

            crate::request::handle(&mut handler, &mut send, &mut recv).await
        });
        let server_res = server_conn
            .send_trusted_user_agent_list(&trusted_user_agent_list_to_send)
            .await;
        assert!(server_res.is_ok());
        let client_res = client_handle.await.unwrap();
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }

    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn send_ping() {
        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let mut handler = TestHandler;
        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move {
            let (mut send, mut recv) = handler_conn.accept_bi().await.unwrap();

            crate::request::handle(&mut handler, &mut send, &mut recv).await
        });
        let server_res = server_conn.send_ping().await;
        assert!(server_res.is_ok());
        let client_res = client_handle.await.unwrap();
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }

    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn send_shutdown_cmd() {
        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let mut handler = TestHandler;
        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move {
            let (mut send, mut recv) = handler_conn.accept_bi().await.unwrap();

            crate::request::handle(&mut handler, &mut send, &mut recv).await
        });
        let server_res = server_conn.send_shutdown_cmd().await;
        assert!(server_res.is_ok());
        let client_res = client_handle.await.unwrap();
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }
}
