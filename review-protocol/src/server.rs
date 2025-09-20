//! Server-specific protocol implementation.

#[cfg(feature = "server")]
mod api;
#[cfg(feature = "server")]
mod handler;

#[cfg(feature = "server")]
use std::net::SocketAddr;

#[cfg(any(feature = "client", feature = "server"))]
use num_enum::{FromPrimitive, IntoPrimitive};
#[cfg(feature = "server")]
use oinq::{
    frame,
    message::{send_err, send_ok},
};
#[cfg(feature = "server")]
use semver::{Version, VersionReq};

#[cfg(feature = "server")]
pub use self::handler::{Handler, handle};
#[cfg(feature = "server")]
use crate::{
    AgentInfo, HandshakeError, client, handle_handshake_recv_io_error,
    handle_handshake_send_io_error, types::Tidb,
};

/// Numeric representation of the message types that a server should handle.
#[cfg(any(feature = "client", feature = "server"))]
#[derive(Clone, Copy, Debug, Eq, FromPrimitive, IntoPrimitive, PartialEq)]
#[repr(u32)]
pub(crate) enum RequestCode {
    GetDataSource = 0,
    GetIndicator = 1,
    GetMaxEventIdNum = 2,
    GetModel = 3,
    GetModelNames = 4,
    InsertColumnStatistics = 5,
    InsertModel = 6,
    InsertTimeSeries = 7,
    RemoveModel = 8,
    RemoveOutliers = 9,
    UpdateClusters = 10,
    UpdateModel = 11,
    UpdateOutliers = 12,
    InsertEventLabels = 13,
    GetDataSourceList = 14,
    GetTidbPatterns = 15,
    InsertDataSource = 20,
    RenewCertificate = 23,
    GetTrustedDomainList = 24,
    GetOutliers = 25,
    GetTorExitNodeList = 26,
    GetInternalNetworkList = 31,
    GetAllowlist = 32,
    GetBlocklist = 33,
    GetPretrainedModel = 34,
    GetTrustedUserAgentList = 35,
    GetConfig = 36,

    /// Unknown request
    #[num_enum(default)]
    Unknown = u32::MAX,
}

#[cfg(feature = "server")]
/// A connection from a client.
#[derive(Clone, Debug)]
pub struct Connection {
    conn: quinn::Connection,
}

#[cfg(feature = "server")]
impl Connection {
    /// Creates a new connection from a QUIC connection from the `quinn` crate.
    #[must_use]
    pub fn from_quinn(conn: quinn::Connection) -> Self {
        Self { conn }
    }

    /// Returns the QUIC connection compatible with the `quinn` crate.
    ///
    /// This is for backward compatibility only and will be removed in a future
    /// release.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn as_quinn(&self) -> &quinn::Connection {
        &self.conn
    }

    /// Returns the cryptographic identity of the peer.
    ///
    /// This directly corresponds to the `peer_identity` method of the underlying
    /// `quinn::Connection`. In the future, this method may be removed in favor
    /// of this crate's own implementation to provide additional features.
    #[must_use]
    pub fn peer_identity(&self) -> Option<Box<dyn std::any::Any>> {
        self.conn.peer_identity()
    }

    /// Initiates an outgoing bidirectional stream.
    ///
    /// This directly corresponds to the `open_bi` method of the underlying
    /// `quinn::Connection`. In the future, this method may be removed in favor
    /// of this crate's own implementation to provide additional features.
    #[must_use]
    pub fn open_bi(&self) -> quinn::OpenBi<'_> {
        self.conn.open_bi()
    }

    #[cfg(test)]
    pub(crate) fn close(&self) {
        self.conn.close(0u32.into(), b"");
    }
}

#[cfg(feature = "server")]
/// Processes a handshake message and sends a response.
///
/// # Errors
///
/// Returns `HandshakeError` if the handshake failed.
///
/// # Panics
///
/// * panic if it failed to parse version requirement string.
pub async fn handshake(
    conn: &quinn::Connection,
    addr: SocketAddr,
    version_req: &str,
    highest_protocol_version: &str,
) -> Result<AgentInfo, HandshakeError> {
    let (mut send, mut recv) = conn
        .accept_bi()
        .await
        .map_err(HandshakeError::ConnectionLost)?;
    let mut buf = Vec::new();
    let mut agent_info = frame::recv::<AgentInfo>(&mut recv, &mut buf)
        .await
        .map_err(handle_handshake_recv_io_error)?;
    agent_info.addr = addr;
    let version_req = VersionReq::parse(version_req).expect("valid version requirement");
    let protocol_version = Version::parse(&agent_info.protocol_version).map_err(|_| {
        HandshakeError::IncompatibleProtocol(
            agent_info.protocol_version.clone(),
            version_req.to_string(),
        )
    })?;
    if version_req.matches(&protocol_version) {
        let highest_protocol_version =
            Version::parse(highest_protocol_version).expect("valid semver");
        if protocol_version <= highest_protocol_version {
            send_ok(&mut send, &mut buf, highest_protocol_version.to_string())
                .await
                .map_err(handle_handshake_send_io_error)?;
            Ok(agent_info)
        } else {
            send_err(&mut send, &mut buf, &highest_protocol_version)
                .await
                .map_err(handle_handshake_send_io_error)?;
            send.finish().ok();
            Err(HandshakeError::IncompatibleProtocol(
                protocol_version.to_string(),
                version_req.to_string(),
            ))
        }
    } else {
        send_err(&mut send, &mut buf, version_req.to_string())
            .await
            .map_err(handle_handshake_send_io_error)?;
        send.finish().ok();
        Err(HandshakeError::IncompatibleProtocol(
            protocol_version.to_string(),
            version_req.to_string(),
        ))
    }
}

#[cfg(feature = "server")]
/// Sends patterns from a threat-intelligence database.
///
/// # Errors
///
/// Returns an error if serialization failed or communication with the client failed.
#[deprecated(since = "0.8.1", note = "`handle` sends the response")]
pub async fn respond_with_tidb_patterns(
    send: &mut quinn::SendStream,
    patterns: &[(String, Option<Tidb>)],
) -> anyhow::Result<()> {
    use anyhow::Context;

    let mut buf = Vec::new();
    oinq::frame::send(send, &mut buf, Ok(patterns) as Result<_, &str>)
        .await
        .context("failed to send response")
}

#[cfg(feature = "server")]
/// Sends a list of trusted domains to the client.
///
/// # Errors
///
/// Returns an error if serialization failed or communication with the client failed.
#[deprecated(
    since = "0.8.1",
    note = "Use Connection::send_trusted_domain_list directly"
)]
pub async fn send_trusted_domain_list(
    conn: &quinn::Connection,
    list: &[String],
) -> anyhow::Result<()> {
    Connection::from_quinn(conn.clone())
        .send_trusted_domain_list(list)
        .await
}

#[cfg(feature = "server")]
/// Notifies the client that it should update its configuration.
///
/// # Errors
///
/// Returns an error if serialization failed or communication with the client failed.
pub async fn notify_config_update(conn: &quinn::Connection) -> anyhow::Result<()> {
    use anyhow::anyhow;

    let Ok(msg) = bincode::serialize::<u32>(&client::RequestCode::UpdateConfig.into()) else {
        unreachable!("serialization of u32 into memory buffer should not fail")
    };

    let (mut send, mut recv) = conn.open_bi().await?;
    frame::send_raw(&mut send, &msg).await?;

    let mut response = vec![];
    frame::recv::<Result<(), String>>(&mut recv, &mut response)
        .await?
        .map_err(|e| anyhow!(e))
}

#[cfg(test)]
mod tests {
    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn trusted_domain_list() {
        use crate::test::TEST_ENV;

        struct Handler {}

        #[async_trait::async_trait]
        impl crate::request::Handler for Handler {
            async fn trusted_domain_list(&mut self, domains: &[&str]) -> Result<(), String> {
                if domains == TRUSTED_DOMAIN_LIST {
                    Ok(())
                } else {
                    Err("unexpected domain list".to_string())
                }
            }
        }

        const TRUSTED_DOMAIN_LIST: &[&str] = &["example.com", "example.org"];

        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        // Test `server::send_trusted_domain_list`
        let domains_to_send = TRUSTED_DOMAIN_LIST
            .iter()
            .map(|&domain| domain.to_string())
            .collect::<Vec<_>>();

        let mut handler = Handler {};
        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move {
            let (mut send, mut recv) = handler_conn.accept_bi().await.unwrap();

            crate::request::handle(&mut handler, &mut send, &mut recv).await
        });
        let server_res = server_conn.send_trusted_domain_list(&domains_to_send).await;
        assert!(server_res.is_ok());
        let client_res = client_handle.await.unwrap();
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }

    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn notify_config_update() {
        use crate::test::TEST_ENV;

        struct Handler {}

        #[async_trait::async_trait]
        impl crate::request::Handler for Handler {
            async fn update_config(&mut self) -> Result<(), String> {
                Ok(())
            }
        }

        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let mut handler = Handler {};
        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move {
            let (mut send, mut recv) = handler_conn.accept_bi().await.unwrap();

            crate::request::handle(&mut handler, &mut send, &mut recv).await
        });
        let server_res = crate::server::notify_config_update(server_conn.as_quinn()).await;
        assert!(server_res.is_ok());
        let client_res = client_handle.await.unwrap();
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }
}
