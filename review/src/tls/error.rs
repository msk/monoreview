#[derive(Debug, thiserror::Error)]
#[allow(clippy::module_name_repetitions)]
pub enum TlsError {
    #[error("Failed to build a tls config: {0}")]
    Config(rustls::Error),
    #[error("Could not generate certificate: {0}")]
    GenerateCert(rcgen::Error),
    #[error("Could not generate Key: {0}")]
    GenerateKey(rcgen::Error),
    #[error("Invalid certificate: {0}")]
    InvalidCert(String),
    #[error("Invalid Private Key: {0}")]
    InvalidKey(rcgen::Error),
    #[error("Invalid Subject Alternative Name: {0}")]
    InvalidSan(String),
    #[error("Failed to read pem file: {0}")]
    Pem(rustls::pki_types::pem::Error),
    #[error("Failed to read {0}: {1}")]
    Read(String, std::io::Error),
    #[error("Certificate and key cannot be written to the same path")]
    SamePath,
    #[error("Failed to write certificate or key: {0}")]
    Write(std::io::Error),
    #[error("Invalid PEM-encoded certificate: {0}")]
    X509Parse(x509_parser::nom::Err<x509_parser::error::X509Error>),
    #[error("Certificate verification failed: {0}")]
    CertVerification(x509_parser::error::X509Error),
}
