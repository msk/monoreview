use std::sync::Arc;

use rustls::{
    RootCertStore, ServerConfig,
    pki_types::{CertificateDer, pem::PemObject},
    server::WebPkiClientVerifier,
};

use super::{TlsCertConfig, TlsError, key::read_private_key};

pub(crate) fn make_server_config(config: &TlsCertConfig) -> Result<ServerConfig, TlsError> {
    let cert_path = config.cert_path();
    let cert = CertificateDer::from_pem_file(cert_path).map_err(TlsError::Pem)?;
    let mut root = RootCertStore::empty();
    root.add(cert.clone())
        .map_err(|e| TlsError::InvalidCert(e.to_string()))?;
    let key_path = config.key_path();
    let key = read_private_key(key_path)?;
    let client_verifier = WebPkiClientVerifier::builder(root.into())
        .build()
        .map_err(|e| TlsError::Config(rustls::Error::Other(rustls::OtherError(Arc::new(e)))))?;

    ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(vec![cert], key)
        .map_err(TlsError::Config)
}
