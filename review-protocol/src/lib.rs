pub mod client;
#[cfg(feature = "client")]
pub mod frame;
#[cfg(feature = "client")]
pub mod request;
pub mod server;
#[cfg(all(test, any(feature = "client", feature = "server")))]
mod test;
pub mod types;

use std::net::SocketAddr;

use serde::{Deserialize, Serialize};
#[cfg(any(feature = "client", feature = "server"))]
use thiserror::Error;

use crate::types::Status;

/// The error type for a handshake failure.
#[cfg(any(feature = "client", feature = "server"))]
#[derive(Debug, Error)]
pub enum HandshakeError {
    #[error("connection closed by peer")]
    ConnectionClosed,
    #[error("connection lost")]
    ConnectionLost(#[from] quinn::ConnectionError),
    #[error("cannot receive a message: {0}")]
    ReadError(std::io::Error),
    #[error("cannot send a message")]
    WriteError(std::io::Error),
    #[error("arguments are too long")]
    MessageTooLarge,
    #[error("invalid message")]
    InvalidMessage,
    #[error("protocol version {0} is not supported; version {1} is required")]
    IncompatibleProtocol(String, String),
}

#[cfg(feature = "server")]
fn handle_handshake_send_io_error(e: std::io::Error) -> HandshakeError {
    if e.kind() == std::io::ErrorKind::InvalidData {
        HandshakeError::MessageTooLarge
    } else {
        HandshakeError::WriteError(e)
    }
}

#[cfg(feature = "server")]
fn handle_handshake_recv_io_error(e: std::io::Error) -> HandshakeError {
    match e.kind() {
        std::io::ErrorKind::InvalidData => HandshakeError::InvalidMessage,
        std::io::ErrorKind::UnexpectedEof => HandshakeError::ConnectionClosed,
        _ => HandshakeError::ReadError(e),
    }
}

/// Properties of an agent.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AgentInfo {
    pub app_name: String,
    pub version: String,
    pub protocol_version: String,
    pub addr: SocketAddr,
    pub status: Status,
}

/// Sends a unary request and returns the response.
///
/// # Errors
///
/// Returns an error if there was a problem sending the request or receiving the
/// response.
#[cfg(any(feature = "client", feature = "server"))]
pub async fn unary_request<I, O>(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    code: u32,
    input: I,
) -> std::io::Result<O>
where
    I: serde::Serialize,
    O: serde::de::DeserializeOwned,
{
    let mut buf = vec![];
    oinq::message::send_request(send, &mut buf, code, input).await?;

    oinq::frame::recv(recv, &mut buf).await
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "server")]
    use crate::test::{TOKEN, channel};

    #[cfg(feature = "server")]
    #[tokio::test]
    async fn handshake() {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        use crate::Status;

        const APP_NAME: &str = "oinq";
        const APP_VERSION: &str = "1.0.0";
        const PROTOCOL_VERSION: &str = env!("CARGO_PKG_VERSION");

        let _lock = TOKEN.lock().await;
        let channel = channel().await;
        let (server, client) = (channel.server, channel.client);

        let handle = tokio::spawn(async move {
            super::client::handshake(
                &client.conn,
                APP_NAME,
                APP_VERSION,
                PROTOCOL_VERSION,
                Status::Ready,
            )
            .await
        });

        let agent_info = super::server::handshake(
            &server.conn,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            PROTOCOL_VERSION,
            PROTOCOL_VERSION,
        )
        .await
        .unwrap();

        assert_eq!(agent_info.app_name, APP_NAME);
        assert_eq!(agent_info.version, APP_VERSION);
        assert_eq!(agent_info.protocol_version, PROTOCOL_VERSION);

        let res = tokio::join!(handle).0.unwrap();
        assert!(res.is_ok());
    }

    #[cfg(feature = "server")]
    #[tokio::test]
    async fn handshake_version_incompatible_err() {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        use crate::Status;

        const APP_NAME: &str = "oinq";
        const APP_VERSION: &str = "1.0.0";
        const PROTOCOL_VERSION: &str = env!("CARGO_PKG_VERSION");

        let _lock = TOKEN.lock().await;
        let channel = channel().await;
        let (server, client) = (channel.server, channel.client);

        let handle = tokio::spawn(async move {
            super::client::handshake(
                &client.conn,
                APP_NAME,
                APP_VERSION,
                PROTOCOL_VERSION,
                Status::Ready,
            )
            .await
        });

        let res = super::server::handshake(
            &server.conn,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            &format!("<{PROTOCOL_VERSION}"),
            PROTOCOL_VERSION,
        )
        .await;

        assert!(res.is_err());

        let res = tokio::join!(handle).0.unwrap();
        assert!(res.is_err());
    }

    #[cfg(feature = "server")]
    #[tokio::test]
    async fn handshake_incompatible_err() {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        use crate::Status;

        const APP_NAME: &str = "oinq";
        const APP_VERSION: &str = "1.0.0";
        const PROTOCOL_VERSION: &str = env!("CARGO_PKG_VERSION");

        let version_req = semver::VersionReq::parse(&format!(">={PROTOCOL_VERSION}")).unwrap();
        let mut highest_version = semver::Version::parse(PROTOCOL_VERSION).unwrap();
        highest_version.patch += 1;
        let mut protocol_version = highest_version.clone();
        protocol_version.minor += 1;

        let _lock = TOKEN.lock().await;
        let channel = channel().await;
        let (server, client) = (channel.server, channel.client);

        let handle = tokio::spawn(async move {
            super::client::handshake(
                &client.conn,
                APP_NAME,
                APP_VERSION,
                &protocol_version.to_string(),
                Status::Ready,
            )
            .await
        });

        let res = super::server::handshake(
            &server.conn,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            &version_req.to_string(),
            &highest_version.to_string(),
        )
        .await;

        assert!(res.is_err());

        let res = tokio::join!(handle).0.unwrap();
        assert!(res.is_err());
    }
}
