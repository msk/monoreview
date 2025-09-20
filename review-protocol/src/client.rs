//! Client-specific protocol implementation.

#[cfg(feature = "client")]
mod api;

#[cfg(any(feature = "client", all(test, feature = "server")))]
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

#[cfg(any(feature = "client", feature = "server"))]
use num_enum::{FromPrimitive, IntoPrimitive};
#[cfg(any(feature = "client", all(test, feature = "server")))]
use oinq::frame::{self};
#[cfg(feature = "client")]
pub use oinq::message::{send_err, send_ok, send_request};

#[cfg(any(feature = "client", all(test, feature = "server")))]
use crate::AgentInfo;

/// Numeric representation of the message types that a client should handle.
#[cfg(any(feature = "client", feature = "server"))]
#[derive(Clone, Copy, Debug, Eq, FromPrimitive, IntoPrimitive, PartialEq)]
#[repr(u32)]
pub(crate) enum RequestCode {
    /// Start DNS filtering
    DnsStart = 1,

    /// Stop DNS filtering
    DnsStop = 2,

    /// Reboot the host
    Reboot = 4,

    /// Reload the configuration
    ReloadConfig = 6,

    /// Fetch the TI database and reload it
    ReloadTi = 5,

    /// Collect resource usage stats
    ResourceUsage = 7,

    /// Update the list of tor exit nodes
    TorExitNodeList = 8,

    /// Update the list of sampling policies
    SamplingPolicyList = 9,

    /// Update traffic filter rules
    ReloadFilterRule = 10,

    /// Update Configuration
    UpdateConfig = 12,

    /// Delete the list of sampling policies
    DeleteSamplingPolicy = 13,

    /// Update the list of Internal network
    InternalNetworkList = 14,

    /// Update the list of allow
    Allowlist = 15,

    /// Update the list of block
    Blocklist = 16,

    /// Request Echo (for ping)
    EchoRequest = 17,

    /// Update the list of trusted User-agent
    TrustedUserAgentList = 18,

    /// Update the list of trusted domains
    TrustedDomainList = 0,

    /// Collect process list
    ProcessList = 19,

    /// Update the semi-supervised models
    SemiSupervisedModels = 20,

    /// Shutdown the host
    Shutdown = 21,

    /// Unknown request
    #[num_enum(default)]
    Unknown = u32::MAX,
}

#[cfg(feature = "client")]
/// A builder for creating a new endpoint.
#[derive(Debug)]
pub struct ConnectionBuilder {
    remote_name: String,
    remote_addr: SocketAddr,
    local_addr: IpAddr,
    app_name: String,
    app_version: String,
    protocol_version: String,
    status: crate::Status,
    roots: rustls::RootCertStore,
    cert: rustls::pki_types::CertificateDer<'static>,
    key: rustls::pki_types::PrivateKeyDer<'static>,
}

#[cfg(feature = "client")]
impl ConnectionBuilder {
    /// Creates a new builder with the remote address, certificate, and key.
    ///
    /// # Errors
    ///
    /// Returns an error if the certificate or key is invalid.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        remote_name: &str,
        remote_addr: SocketAddr,
        app_name: &str,
        app_version: &str,
        protocol_version: &str,
        status: crate::Status,
        cert: &[u8],
        key: &[u8],
    ) -> std::io::Result<Self> {
        let local_addr = if remote_addr.is_ipv6() {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        } else {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        };
        let cert = rustls_pemfile::certs(&mut std::io::Cursor::new(cert))
            .next()
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "no certificate")
            })??;
        let key = rustls_pemfile::private_key(&mut std::io::Cursor::new(key))
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "no private key")
            })?;
        Ok(Self {
            remote_name: remote_name.to_string(),
            remote_addr,
            local_addr,
            app_name: app_name.to_string(),
            app_version: app_version.to_string(),
            protocol_version: protocol_version.to_string(),
            status,
            roots: rustls::RootCertStore::empty(),
            cert,
            key,
        })
    }

    /// Sets the certificate for the connection.
    ///
    /// # Errors
    ///
    /// Returns an error if the certificate is invalid.
    pub fn cert(&mut self, cert: &[u8]) -> std::io::Result<&mut Self> {
        self.cert = rustls_pemfile::certs(&mut std::io::Cursor::new(cert))
            .next()
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "no certificate")
            })??;
        Ok(self)
    }

    /// Sets the private key for the connection.
    ///
    /// # Errors
    ///
    /// Returns an error if the key is invalid.
    pub fn key(&mut self, key: &[u8]) -> std::io::Result<&mut Self> {
        self.key = rustls_pemfile::private_key(&mut std::io::Cursor::new(key))
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "no private key")
            })?;
        Ok(self)
    }

    /// Sets the root certificates for the connection.
    ///
    /// # Errors
    ///
    /// Returns an error if any of the certificates are invalid.
    pub fn root_certs<I>(&mut self, certs: I) -> std::io::Result<&mut Self>
    where
        I: IntoIterator,
        I::Item: AsRef<[u8]>,
    {
        self.roots = rustls::RootCertStore::empty();
        for cert in certs {
            let cert = rustls_pemfile::certs(&mut std::io::Cursor::new(cert.as_ref()))
                .next()
                .ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid certificate")
                })??;
            self.roots
                .add(cert)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        }
        Ok(self)
    }

    /// Adds root certificates to the certificate store.
    ///
    /// It reads certificates from the given reader, filtering out any PEM
    /// sections.
    ///
    /// # Errors
    ///
    /// Returns an error if the reader is invalid or the certificates are
    /// invalid.
    pub fn add_root_certs(&mut self, rd: &mut dyn std::io::BufRead) -> std::io::Result<&mut Self> {
        for cert in rustls_pemfile::certs(rd) {
            let cert = cert?;
            self.roots
                .add(cert)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        }
        Ok(self)
    }

    /// Sets the local address to bind to.
    ///
    /// This is only necessary if the unspecified address (:: for IPv6 and
    /// 0.0.0.0 for IPv4) is not desired.
    pub fn local_addr(&mut self, addr: IpAddr) -> &mut Self {
        self.local_addr = addr;
        self
    }

    /// Connects to the server and performs a handshake.
    ///
    /// # Errors
    ///
    /// Returns an error if the connection fails or the server requires a different
    /// protocol version.
    #[cfg(feature = "client")]
    pub async fn connect(&self) -> std::io::Result<Connection> {
        use std::io;

        let endpoint = self.build_endpoint()?;
        let connecting = endpoint
            .connect(self.remote_addr, &self.remote_name)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let connection = connecting.await.map_err(|e| {
            // quinn (as of 0.11) provides automatic conversion from
            // `ConnectionError` to `ReadError`, and from `ReadError` to
            // `io::Error`. However, the conversion treats all `ConnectionError`
            // variants as `NotConnected`, which is too generic. We need to provide
            // more specific error messages.
            use quinn::ConnectionError;
            match e {
                ConnectionError::ApplicationClosed(e) => {
                    std::io::Error::new(io::ErrorKind::ConnectionAborted, e.to_string())
                }
                ConnectionError::CidsExhausted => io::Error::other("connection IDs exhausted"),
                ConnectionError::ConnectionClosed(e) => {
                    std::io::Error::new(io::ErrorKind::ConnectionAborted, e.to_string())
                }
                ConnectionError::LocallyClosed => {
                    io::Error::new(io::ErrorKind::NotConnected, "locally closed")
                }
                ConnectionError::Reset => io::Error::from(io::ErrorKind::ConnectionReset),
                ConnectionError::TimedOut => io::Error::from(io::ErrorKind::TimedOut),
                ConnectionError::TransportError(e) => {
                    std::io::Error::new(io::ErrorKind::InvalidData, e.to_string())
                }
                ConnectionError::VersionMismatch => {
                    io::Error::new(io::ErrorKind::ConnectionRefused, "version mismatch")
                }
            }
        })?;

        // A placeholder for the address of this agent. Will be replaced by the
        // server.
        //
        // TODO: This is unnecessary in handshake, and thus should be removed in the
        // future.
        let addr = if connection.remote_address().is_ipv6() {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
        } else {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
        };

        let agent_info = AgentInfo {
            app_name: self.app_name.clone(),
            version: self.app_version.clone(),
            protocol_version: self.protocol_version.clone(),
            status: self.status,
            addr,
        };

        let (mut send, mut recv) = connection.open_bi().await?;
        let mut buf = Vec::new();
        frame::send(&mut send, &mut buf, &agent_info).await?;
        match frame::recv::<Result<&str, &str>>(&mut recv, &mut buf).await? {
            Ok(_) => Ok(Connection {
                endpoint,
                connection,
            }),
            Err(e) => Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("server requires protocol version {e}"),
            )),
        }
    }

    /// Creates a new endpoint.
    ///
    /// # Errors
    ///
    /// Returns an error if the stored TLS configuration is invalid.
    fn build_endpoint(&self) -> std::io::Result<quinn::Endpoint> {
        use std::sync::Arc;
        use std::time::Duration;

        const KEEP_ALIVE_INTERVAL: Duration = Duration::from_millis(5_000);

        let tls_cfg = rustls::ClientConfig::builder()
            .with_root_certificates(self.roots.clone())
            .with_client_auth_cert(vec![self.cert.clone()], self.key.clone_key())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
        let mut transport = quinn::TransportConfig::default();
        transport.keep_alive_interval(Some(KEEP_ALIVE_INTERVAL));
        let mut config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(tls_cfg)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?,
        ));
        config.transport_config(Arc::new(transport));

        let mut endpoint = quinn::Endpoint::client(SocketAddr::new(self.local_addr, 0))?;
        endpoint.set_default_client_config(config);
        Ok(endpoint)
    }
}

#[cfg(feature = "client")]
/// A connection to a server.
#[derive(Clone, Debug)]
pub struct Connection {
    endpoint: quinn::Endpoint,
    connection: quinn::Connection,
}

#[cfg(feature = "client")]
impl Connection {
    /// Gets the local address of the connection.
    ///
    /// # Errors
    ///
    /// Returns an error if the call to the underlying
    /// [`local_addr`](quinn::Connection::local_addr) fails.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.endpoint.local_addr()
    }

    /// Gets the remote address of the connection.
    #[must_use]
    pub fn remote_addr(&self) -> SocketAddr {
        self.connection.remote_address()
    }

    /// If the connection is cloesd, returns the reason; otherwise, returns `None`.
    #[must_use]
    pub fn close_reason(&self) -> Option<std::io::Error> {
        self.connection.close_reason().map(Into::into)
    }

    /// Initiates an outgoing bidirectional stream.
    ///
    /// This directly corresponds to the `open_bi` method of the underlying
    /// `quinn::Connection`. In the future, this method may be removed in favor
    /// of this crate's own implementation to provide additional features.
    #[must_use]
    pub fn open_bi(&self) -> quinn::OpenBi<'_> {
        self.connection.open_bi()
    }

    /// Initiates an outgoing unidirectional stream.
    ///
    /// This directly corresponds to the `open_uni` method of the underlying
    /// `quinn::Connection`. In the future, this method may be removed in favor
    /// of this crate's own implementation to provide additional features.
    #[must_use]
    pub fn open_uni(&self) -> quinn::OpenUni<'_> {
        self.connection.open_uni()
    }

    /// Accepts an incoming bidirectional stream.
    ///
    /// This directly corresponds to the `accept_bi` method of the underlying
    /// `quinn::Connection`. In the future, this method may be removed in favor
    /// of this crate's own implementation to provide additional features.
    #[must_use]
    pub fn accept_bi(&self) -> quinn::AcceptBi<'_> {
        self.connection.accept_bi()
    }
}

/// Sends a handshake request and processes the response.
///
/// # Errors
///
/// Returns `HandshakeError` if the handshake failed.
#[cfg(test)]
#[cfg(feature = "server")]
pub(crate) async fn handshake(
    conn: &quinn::Connection,
    app_name: &str,
    app_version: &str,
    protocol_version: &str,
    status: crate::Status,
) -> Result<(), super::HandshakeError> {
    // A placeholder for the address of this agent. Will be replaced by the
    // server.
    //
    // TODO: This is unnecessary in handshake, and thus should be removed in the
    // future.

    use crate::{handle_handshake_recv_io_error, handle_handshake_send_io_error};
    let addr = if conn.remote_address().is_ipv6() {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    };

    let agent_info = AgentInfo {
        app_name: app_name.to_string(),
        version: app_version.to_string(),
        protocol_version: protocol_version.to_string(),
        status,
        addr,
    };

    let (mut send, mut recv) = conn.open_bi().await?;
    let mut buf = Vec::new();
    frame::send(&mut send, &mut buf, &agent_info)
        .await
        .map_err(handle_handshake_send_io_error)?;

    match frame::recv::<Result<&str, &str>>(&mut recv, &mut buf).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => Err(super::HandshakeError::IncompatibleProtocol(
            protocol_version.to_string(),
            e.to_string(),
        )),
        Err(e) => Err(handle_handshake_recv_io_error(e)),
    }
}
