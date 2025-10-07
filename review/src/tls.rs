#![allow(clippy::module_name_repetitions)]

mod certificate;
mod config;
mod error;
mod extensions;
mod key;
mod utils;

use std::path::PathBuf;

pub(crate) use certificate::{
    AgentCertificate, new_self_signed_certificate, renew_ca_signed_certificate,
    renew_self_signed_certificate, validate_certificate_count,
};
use error::TlsError;
#[cfg(feature = "web")]
use review_web::backend::{CertManager as WebCertManager, ParsedCertificate};

pub(crate) use self::config::make_server_config;
#[cfg(feature = "web")]
pub(crate) use self::key::read_private_key;

#[derive(Debug, Clone)]
pub struct TlsCertConfig {
    cert: PathBuf,
    key: PathBuf,
}

impl TlsCertConfig {
    pub fn new(cert: PathBuf, key: PathBuf) -> Self {
        Self { cert, key }
    }

    pub fn cert_path(&self) -> &PathBuf {
        &self.cert
    }

    pub fn key_path(&self) -> &PathBuf {
        &self.key
    }
}

#[cfg(feature = "web")]
pub struct CertManager {
    config: TlsCertConfig,
}

#[cfg(feature = "web")]
impl CertManager {
    pub fn new(config: TlsCertConfig) -> Self {
        Self { config }
    }
}

#[cfg(feature = "web")]
impl WebCertManager for CertManager {
    fn cert_path(&self) -> Result<PathBuf, anyhow::Error> {
        Ok(self.config.cert_path().clone())
    }

    fn key_path(&self) -> Result<PathBuf, anyhow::Error> {
        Ok(self.config.key_path().clone())
    }

    fn update_certificate(
        &self,
        cert: String,
        key: String,
    ) -> Result<Vec<ParsedCertificate>, anyhow::Error> {
        use rustls::pki_types::{PrivateKeyDer, pem::PemObject};
        use x509_parser::prelude::parse_x509_certificate;

        // Validate certificate
        let cert_der = rustls::pki_types::CertificateDer::from_pem_slice(cert.as_bytes())
            .map_err(|e| TlsError::InvalidCert(format!("Invalid certificate PEM: {e}")))?;
        let (_, x509) = parse_x509_certificate(cert_der.as_ref()).map_err(TlsError::X509Parse)?;
        if !x509.validity().is_valid() {
            anyhow::bail!("The certificate has expired or is not yet valid");
        }
        let cn = extensions::parse_cn(x509.subject());
        let san = extensions::parse_san(x509.extensions());
        if san.is_none() && cn.is_none() {
            anyhow::bail!("Subject Alternative Name and Common Name not found");
        }

        // Validate private key format and test key validity
        let key_der = PrivateKeyDer::from_pem_slice(key.as_bytes())
            .map_err(|_| TlsError::InvalidKey(rcgen::Error::CouldNotParseCertificate))?;
        let _key_pair =
            rcgen::KeyPair::try_from(key_der.secret_der()).map_err(TlsError::InvalidKey)?;

        let cert_path = self.config.cert_path();
        let key_path = self.config.key_path();
        utils::write_cert_key_to_file(cert_path, key_path, cert.as_bytes(), key.as_bytes())?;

        let parsed_certs = ParsedCertificate {
            subject_alternative_name: san,
            common_name: cn,
        };

        Ok(vec![parsed_certs])
    }
}
