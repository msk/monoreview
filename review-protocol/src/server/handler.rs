//! Requset handler for the server.

use std::{collections::HashSet, io};

use num_enum::FromPrimitive;
use oinq::request::parse_args;

use super::RequestCode;
use crate::types::{DataSource, DataSourceKey, HostNetworkGroup, Tidb};

/// A request handler that can handle a request to the server.
#[async_trait::async_trait]
pub trait Handler {
    async fn get_allowlist(&self) -> Result<HostNetworkGroup, String> {
        Err("not supported".to_string())
    }

    async fn get_blocklist(&self) -> Result<HostNetworkGroup, String> {
        Err("not supported".to_string())
    }

    async fn get_config(&self, _peer: &str) -> Result<String, String> {
        Err("not supported".to_string())
    }

    async fn get_data_source(
        &self,
        _key: &DataSourceKey<'_>,
    ) -> Result<Option<DataSource>, String> {
        Err("not supported".to_string())
    }

    async fn get_indicator(&self, _name: &str) -> Result<HashSet<Vec<String>>, String> {
        Err("not supported".to_string())
    }

    async fn get_internal_network_list(&self, _peer: &str) -> Result<HostNetworkGroup, String> {
        Err("not supported".to_string())
    }

    async fn get_model_names(&self) -> Result<Vec<String>, String> {
        Err("not supported".to_string())
    }

    async fn get_pretrained_model(&self, _name: &str) -> Result<Vec<u8>, String> {
        Err("not supported".to_string())
    }

    async fn get_tidb_patterns(
        &self,
        _db_names: &[(&str, &str)],
    ) -> Result<Vec<(String, Option<Tidb>)>, String> {
        Err("not supported".to_string())
    }

    async fn get_tor_exit_node_list(&self) -> Result<Vec<String>, String> {
        Err("not supported".to_string())
    }

    async fn get_trusted_domain_list(&self) -> Result<Vec<String>, String> {
        Err("not supported".to_string())
    }

    async fn get_trusted_user_agent_list(&self) -> Result<Vec<String>, String> {
        Err("not supported".to_string())
    }

    async fn renew_certificate(&self, _peer: &str) -> Result<(String, String), String> {
        Err("not supported".to_string())
    }
}

/// Handles requests to the server.
///
/// This handles only a subset of the requests that the server can receive. If
/// the request is not supported, the request code is returned to the caller.
///
/// # Errors
///
/// - There was an error reading from the stream.
/// - There was an error writing to the stream.
/// - An unknown request code was received.
/// - The arguments to the request were invalid.
pub async fn handle<H>(
    handler: &mut H,
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    peer: &str,
) -> io::Result<Option<(u32, Vec<u8>)>>
where
    H: Handler + Sync,
{
    let mut buf = Vec::new();
    loop {
        let (code, body) = match oinq::message::recv_request_raw(recv, &mut buf).await {
            Ok(res) => res,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e),
        };

        match RequestCode::from_primitive(code) {
            RequestCode::GetAllowlist => {
                parse_args::<()>(body)?;
                let result = handler.get_allowlist().await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::GetBlocklist => {
                parse_args::<()>(body)?;
                let result = handler.get_blocklist().await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::GetDataSource => {
                let data_source_key = parse_args::<DataSourceKey>(body)?;
                let result = handler.get_data_source(&data_source_key).await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::GetIndicator => {
                let name = parse_args::<String>(body)?;
                let result = handler.get_indicator(&name).await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::GetModelNames => {
                parse_args::<()>(body)?;
                let result = handler.get_model_names().await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::GetTidbPatterns => {
                let db_names = parse_args::<Vec<(&str, &str)>>(body)?;
                let result = handler.get_tidb_patterns(&db_names).await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::GetTorExitNodeList => {
                parse_args::<()>(body)?;
                let result = handler.get_tor_exit_node_list().await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::GetTrustedDomainList => {
                parse_args::<()>(body)?;
                let result = handler.get_trusted_domain_list().await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::GetTrustedUserAgentList => {
                parse_args::<()>(body)?;
                let result = handler.get_trusted_user_agent_list().await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::GetConfig => {
                parse_args::<()>(body)?;
                let result = handler.get_config(peer).await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::GetInternalNetworkList => {
                parse_args::<()>(body)?;
                let result = handler.get_internal_network_list(peer).await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::GetPretrainedModel => {
                let name = parse_args::<String>(body)?;
                let result = handler.get_pretrained_model(&name).await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::RenewCertificate => {
                let result = handler.renew_certificate(peer).await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::Unknown => {
                oinq::frame::send(
                    send,
                    &mut buf,
                    Err("unknown request code") as Result<(), &str>,
                )
                .await?;
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unknown request code",
                ));
            }
            _ => {
                return Ok(Some((code, body.into())));
            }
        }
    }
    Ok(None)
}
