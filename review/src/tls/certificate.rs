use std::path::{Path, PathBuf};

use rcgen::{
    CertificateParams, DistinguishedName, DnType, DnValue, KeyPair, date_time_ymd,
    string::Ia5String,
};
use rustls::pki_types::{CertificateDer, pem::PemObject};
use x509_parser::prelude::parse_x509_certificate;

use super::{
    TlsCertConfig, TlsError,
    extensions::{parse_cn, parse_cn_and_san, parse_extended_key_usages, parse_key_usages},
    key::read_private_key,
    utils::{date, write_cert_key_to_file, write_cert_to_file},
};

/// Generates self signed certificate.
/// Saves certificate and private key in `pem` format.
///
/// # Errors
///
/// * Certificate generation fails.
/// * Certificate save to file fails.
/// * Private key save to file fails.
pub fn new_self_signed_certificate(
    host: &str,
    cert_path: &PathBuf,
    key_path: &PathBuf,
) -> Result<(), TlsError> {
    let mut params = new_params();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, DnValue::Utf8String(host.to_string()));
    params.distinguished_name = dn;
    params.subject_alt_names = vec![rcgen::SanType::DnsName(
        Ia5String::try_from(host).map_err(|e| TlsError::InvalidSan(e.to_string()))?,
    )];
    params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    let key_pair = KeyPair::generate().map_err(TlsError::GenerateKey)?;

    let cert = params
        .self_signed(&key_pair)
        .map_err(TlsError::GenerateCert)?;
    write_cert_key_to_file(
        cert_path,
        key_path,
        cert.pem().as_bytes(),
        key_pair.serialize_pem().as_bytes(),
    )?;

    Ok(())
}

pub fn renew_self_signed_certificate(config: &TlsCertConfig) -> Result<(), TlsError> {
    let existing_cert = CertificateDer::from_pem_file(config.cert_path()).map_err(TlsError::Pem)?;
    let (_, x509) = parse_x509_certificate(&existing_cert).map_err(TlsError::X509Parse)?;

    let mut params = new_params();
    let (cn, san) = parse_cn_and_san(&x509);
    if let Some(cn) = cn {
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, DnValue::Utf8String(cn));
        params.distinguished_name = dn;
    }
    if let Some(san) = san {
        params.subject_alt_names = san;
    }

    params.key_usages = parse_key_usages(x509.extensions());
    params.extended_key_usages = parse_extended_key_usages(x509.extensions());

    let key_path = config.key_path();
    let key = read_private_key(key_path)?;
    let key_pair = KeyPair::try_from(key.secret_der()).map_err(TlsError::InvalidKey)?;
    let cert = params
        .self_signed(&key_pair)
        .map_err(TlsError::GenerateCert)?;
    let cert_path = config.cert_path();
    write_cert_to_file(cert_path, cert.pem().as_bytes())?;

    Ok(())
}

/// Renews a client certificate that was previously signed by REview's
/// certificate.
///
/// This function validates that the provided certificate was legitimately
/// issued by REview's certificate, then generates a new client certificate with
/// the same identity information (Common Name and Subject Alternative Names)
/// but with a new key pair and updated validity period.
///
/// The renewal process is designed for agent certificates that need to be
/// refreshed before expiration while maintaining the same identity. Note that
/// the function uses signature verification instead of full PKI validation,
/// making it suitable for renewal scenarios where the original certificate may
/// be expired.
///
/// # Errors
///
/// If failed to read or parse client or REview's certificate
/// If failed to generate new RSA key pair, serialize private key, etc.
/// If certificate verification failed (not signed by REview's certificate)
pub fn renew_ca_signed_certificate(
    cert: &[u8],
    config: &TlsCertConfig,
) -> Result<(String, String), TlsError> {
    let ca_cert_path = config.cert_path();
    let ca_cert_der = CertificateDer::from_pem_file(ca_cert_path).map_err(TlsError::Pem)?;
    let (_, x509) = parse_x509_certificate(cert).map_err(TlsError::X509Parse)?;
    let (_, ca_cert) = parse_x509_certificate(ca_cert_der.as_ref()).map_err(TlsError::X509Parse)?;

    // Verify certificate was signed by REview's certificate
    x509.verify_signature(Some(ca_cert.public_key()))
        .map_err(TlsError::CertVerification)?;

    let mut params = new_params();
    let (cn, san) = parse_cn_and_san(&x509);
    if let Some(cn) = cn {
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, DnValue::Utf8String(cn));
        params.distinguished_name = dn;
    }
    if let Some(san) = san {
        params.subject_alt_names = san;
    }
    params.key_usages = parse_key_usages(x509.extensions());
    params.extended_key_usages = parse_extended_key_usages(x509.extensions());
    let key_pair = KeyPair::generate().map_err(TlsError::GenerateKey)?;

    let ca_key_path = config.key_path();
    let ca_key_der = read_private_key(ca_key_path)?;
    let ca_key = KeyPair::try_from(ca_key_der.secret_der()).map_err(TlsError::InvalidKey)?;
    let issuer =
        rcgen::Issuer::from_ca_cert_der(&ca_cert_der, ca_key).map_err(TlsError::GenerateCert)?;
    let cert = params
        .signed_by(&key_pair, &issuer)
        .map_err(TlsError::GenerateCert)?;
    Ok((cert.pem(), key_pair.serialize_pem()))
}

fn new_params() -> CertificateParams {
    let mut params = CertificateParams::default();
    let (year, month, day) = date();
    params.not_before = date_time_ymd(year, month, day);
    params.not_after = date_time_ymd(year + 1, month, day);

    params
}

pub(crate) fn validate_certificate_count(cert_path: &Path) -> anyhow::Result<()> {
    use rustls::pki_types::{CertificateDer, pem::PemObject};

    let certs = CertificateDer::pem_file_iter(cert_path)
        .map_err(TlsError::Pem)?
        .map(|cert| Ok(cert.map_err(TlsError::Pem)?))
        .collect::<anyhow::Result<Vec<_>>>()?;

    if certs.is_empty() {
        anyhow::bail!("No certificate found");
    } else if certs.len() > 1 {
        anyhow::bail!("Multiple server certificates are not supported");
    }

    Ok(())
}

pub(crate) struct AgentCertificate {
    agent_info: Option<(String, String)>,
}

impl AgentCertificate {
    fn new(agent_info: Option<(String, String)>) -> Self {
        Self { agent_info }
    }

    pub(crate) fn agent_info(self) -> Option<(String, String)> {
        self.agent_info
    }

    pub(crate) fn parse(cert: &CertificateDer) -> Self {
        let Some((_, x509)) = parse_x509_certificate(cert.as_ref()).ok() else {
            return Self::new(None);
        };
        let Some(cn) = parse_cn(x509.subject()) else {
            return Self::new(None);
        };

        Self::new(validate_agent_info(&cn))
    }
}

/// Extracts the agent ID and host ID from the `cn` field of the X.509 certificate.
///
/// Returns an `Option` containing a tuple with the agent ID and host ID as
/// `String`, or `None` if the `cn` field does not contain both an agent ID and
/// host ID separated by an "@" symbol.
fn validate_agent_info(cn: &str) -> Option<(String, String)> {
    let splits: Vec<&str> = cn.split('@').collect();
    if splits.len() != 2 {
        return None;
    }
    let agent_id = splits.first()?;
    let host_id = splits.last()?;

    if agent_id.is_empty() || host_id.is_empty() {
        None
    } else {
        Some(((*agent_id).to_string(), (*host_id).to_string()))
    }
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    #[test]
    fn test_agent_info() {
        let cn = "agent@host";
        assert_eq!(
            Some(("agent".to_string(), "host".to_string())),
            validate_agent_info(cn)
        );

        let cn = "agenthost";
        assert!(validate_agent_info(cn).is_none());

        let cn = "agent@";
        assert!(validate_agent_info(cn).is_none());

        let cn = "@host";
        assert!(validate_agent_info(cn).is_none());

        let cn = "@";
        assert!(validate_agent_info(cn).is_none());

        let cn = "agent@host@";
        assert!(validate_agent_info(cn).is_none());
    }

    #[test]
    fn test_ca_certificate_renewal_workflow() {
        let temp_dir = TempDir::new().unwrap();

        // Generate self-signed certificate (CA)
        let ca_cert_path = temp_dir.path().join("ca.pem");
        let ca_key_path = temp_dir.path().join("ca_key.pem");
        new_self_signed_certificate("ca.example.com", &ca_cert_path, &ca_key_path).unwrap();

        // Generate client certificate signed by the CA
        let client_cert = create_client_certificate_signed_by_ca(&ca_cert_path, &ca_key_path);
        let (_, client_x509) = parse_x509_certificate(client_cert.as_ref()).unwrap();

        let ca_cert = CertificateDer::from_pem_file(&ca_cert_path).unwrap();
        let (_, ca_x509) = parse_x509_certificate(&ca_cert).unwrap();

        let ca_key_usages = parse_key_usages(ca_x509.extensions());
        let ca_ext_key_usages = parse_extended_key_usages(ca_x509.extensions());
        assert_eq!(ca_key_usages.len(), 1);
        assert!(ca_key_usages.contains(&rcgen::KeyUsagePurpose::DigitalSignature));
        assert_eq!(ca_ext_key_usages.len(), 1);
        assert!(ca_ext_key_usages.contains(&rcgen::ExtendedKeyUsagePurpose::ServerAuth));

        // client cert should be valid with the CA
        let result = client_x509.verify_signature(Some(ca_x509.public_key()));
        assert!(result.is_ok());

        // Renew the self-signed certificate (CA)
        let config = TlsCertConfig::new(ca_cert_path.clone(), ca_key_path.clone());
        renew_self_signed_certificate(&config).unwrap();

        // Verify that client certificate can still be validated by renewed CA
        let ca_cert = CertificateDer::from_pem_file(&ca_cert_path).unwrap();
        let (_, renewed_ca_x509) = parse_x509_certificate(ca_cert.as_ref()).unwrap();

        // client cert should still be valid with renewed CA
        let result = client_x509.verify_signature(Some(renewed_ca_x509.public_key()));
        assert!(result.is_ok());

        // Verify renewed ca certificate preserves key usages
        let ca_key_usages = parse_key_usages(renewed_ca_x509.extensions());
        let ca_ext_key_usages = parse_extended_key_usages(renewed_ca_x509.extensions());
        assert_eq!(ca_key_usages.len(), 1);
        assert!(ca_key_usages.contains(&rcgen::KeyUsagePurpose::DigitalSignature));
        assert_eq!(ca_ext_key_usages.len(), 1);
        assert!(ca_ext_key_usages.contains(&rcgen::ExtendedKeyUsagePurpose::ServerAuth));
    }

    #[test]
    fn test_client_certificate_renewal_workflow() {
        let temp_dir = TempDir::new().unwrap();

        // Create certificate with custom key usages
        let cert_path = temp_dir.path().join("client.pem");
        let key_path = temp_dir.path().join("client_key.pem");

        // Create a client certificate with different key usages
        let mut params = new_params();
        let mut dn = DistinguishedName::new();
        dn.push(
            DnType::CommonName,
            DnValue::Utf8String("client.example.com".to_string()),
        );
        params.distinguished_name = dn;

        // Set KU and EKU
        params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];

        let key_pair = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        write_cert_key_to_file(
            &cert_path,
            &key_path,
            cert.pem().as_bytes(),
            key_pair.serialize_pem().as_bytes(),
        )
        .unwrap();

        // Renew the certificate
        let config = TlsCertConfig::new(cert_path.clone(), key_path.clone());
        let (renewed_cert, _) = renew_ca_signed_certificate(cert.der().as_ref(), &config).unwrap();
        let renewed_cert = CertificateDer::from_pem_slice(renewed_cert.as_bytes()).unwrap();

        // Verify renewed certificate preserves KU and EKU
        let (_, renewed_x509) = parse_x509_certificate(renewed_cert.as_ref()).unwrap();
        let renewed_key_usages = parse_key_usages(renewed_x509.extensions());
        let renewed_ext_key_usages = parse_extended_key_usages(renewed_x509.extensions());

        assert_eq!(renewed_key_usages.len(), 1);
        assert!(renewed_key_usages.contains(&rcgen::KeyUsagePurpose::DigitalSignature));
        assert_eq!(renewed_ext_key_usages.len(), 1);
        assert!(renewed_ext_key_usages.contains(&rcgen::ExtendedKeyUsagePurpose::ClientAuth));
    }

    #[test]
    fn test_certificate_signature_validation_with_wrong_ca() {
        let temp_dir = TempDir::new().unwrap();

        // Create two different CA certificates
        let ca1_cert_path = temp_dir.path().join("ca1.pem");
        let ca1_key_path = temp_dir.path().join("ca1_key.pem");
        new_self_signed_certificate("ca1.example.com", &ca1_cert_path, &ca1_key_path).unwrap();
        let ca2_cert_path = temp_dir.path().join("ca2.pem");
        let ca2_key_path = temp_dir.path().join("ca2_key.pem");
        new_self_signed_certificate("ca2.example.com", &ca2_cert_path, &ca2_key_path).unwrap();

        // Create client certificate signed by CA2
        let client_cert = create_client_certificate_signed_by_ca(&ca2_cert_path, &ca2_key_path);
        let (_, client_x509) = parse_x509_certificate(client_cert.as_ref()).unwrap();

        let ca1_cert = CertificateDer::from_pem_file(&ca1_cert_path).unwrap();
        let (_, ca1_x509) = parse_x509_certificate(&ca1_cert).unwrap();

        let ca2_cert = CertificateDer::from_pem_file(&ca2_cert_path).unwrap();
        let (_, ca2_x509) = parse_x509_certificate(&ca2_cert).unwrap();

        // Try to validate with CA1 (should fail)
        let result = client_x509.verify_signature(Some(ca1_x509.public_key()));
        assert!(result.is_err());

        // Try to validate with CA2 (should succeed)
        let result = client_x509.verify_signature(Some(ca2_x509.public_key()));
        assert!(result.is_ok());
    }

    // Helper function to create a client certificate signed by the given CA
    fn create_client_certificate_signed_by_ca<'a>(
        ca_cert_path: &'a PathBuf,
        ca_key_path: &'a PathBuf,
    ) -> CertificateDer<'a> {
        let ca_cert_der = CertificateDer::from_pem_file(ca_cert_path).unwrap();
        let ca_key_der = read_private_key(ca_key_path).unwrap();
        let ca_key = KeyPair::try_from(ca_key_der.secret_der()).unwrap();

        let mut client_params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(
            DnType::CommonName,
            DnValue::Utf8String("agent@test-host".to_string()),
        );
        client_params.distinguished_name = dn;

        let client_key_pair = KeyPair::generate().unwrap();
        let issuer = rcgen::Issuer::from_ca_cert_der(&ca_cert_der, ca_key).unwrap();
        let client_cert = client_params.signed_by(&client_key_pair, &issuer).unwrap();

        CertificateDer::from_pem_slice(client_cert.pem().as_bytes()).unwrap()
    }
}
