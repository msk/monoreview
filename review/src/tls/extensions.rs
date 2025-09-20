use std::net::IpAddr;

use rcgen::{ExtendedKeyUsagePurpose, KeyUsagePurpose, SanType};
use x509_parser::prelude::{
    GeneralName, ParsedExtension, X509Certificate, X509Extension, X509Name,
};

// Convert x509_parser::extensions::GeneralName to rcgen::SanType
// rcgen::SanType only supports DnsName, IpAddress, and Rfc822Name
fn gns_to_sans(ext: &X509Extension) -> Option<Vec<SanType>> {
    match ext.parsed_extension() {
        ParsedExtension::SubjectAlternativeName(san) => Some(
            san.general_names
                .iter()
                .filter_map(|gn| match gn {
                    GeneralName::DNSName(n) => Some(SanType::DnsName((*n).try_into().ok()?)),
                    GeneralName::IPAddress(n) => {
                        let ip_addr = if n.len() == 4 {
                            Some(IpAddr::from([n[0], n[1], n[2], n[3]]))
                        } else if n.len() == 16 {
                            Some(IpAddr::from([
                                n[0], n[1], n[2], n[3], n[4], n[5], n[6], n[7], n[8], n[9], n[10],
                                n[11], n[12], n[13], n[14], n[15],
                            ]))
                        } else {
                            None
                        }?;
                        Some(SanType::IpAddress(ip_addr))
                    }
                    GeneralName::RFC822Name(n) => Some(SanType::Rfc822Name((*n).try_into().ok()?)),
                    _ => None,
                })
                .collect::<Vec<_>>(),
        ),
        _ => None,
    }
}

// Convert x509_parser::extensions::GeneralName to String
fn gns_to_strings(ext: &X509Extension) -> Option<Vec<String>> {
    let sans = match ext.parsed_extension() {
        ParsedExtension::SubjectAlternativeName(san) => Some(
            san.general_names
                .iter()
                .filter_map(|name| match name {
                    GeneralName::DNSName(name) => Some(format!("DNSName:{name}")),
                    GeneralName::IPAddress(n) => Some(format!("IPAddress:{n:?}")),
                    GeneralName::RFC822Name(n) => Some(format!("RFC822Name:{n}")),
                    _ => None,
                })
                .collect::<Vec<_>>(),
        ),
        _ => None,
    };
    sans.and_then(|sans| if sans.is_empty() { None } else { Some(sans) })
}

pub(super) fn parse_cn(subject: &X509Name) -> Option<String> {
    subject
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .map(ToString::to_string)
}

// This function returns `san` as rcgen::SanType
pub(super) fn parse_cn_and_san(cert: &X509Certificate) -> (Option<String>, Option<Vec<SanType>>) {
    let cn = parse_cn(cert.subject());
    let san = cert.extensions().iter().find_map(gns_to_sans);

    (cn, san)
}

// This function returns `san` as String
pub(super) fn parse_san(ext: &[X509Extension]) -> Option<Vec<String>> {
    ext.iter().find_map(gns_to_strings).and_then(
        |sans| {
            if sans.is_empty() { None } else { Some(sans) }
        },
    )
}

pub(super) fn parse_key_usages(extensions: &[X509Extension]) -> Vec<KeyUsagePurpose> {
    extensions
        .iter()
        .find_map(|ext| match ext.parsed_extension() {
            ParsedExtension::KeyUsage(ku) => {
                let mut usages = Vec::new();
                if ku.digital_signature() {
                    usages.push(KeyUsagePurpose::DigitalSignature);
                }
                if ku.non_repudiation() {
                    usages.push(KeyUsagePurpose::ContentCommitment);
                }
                if ku.key_encipherment() {
                    usages.push(KeyUsagePurpose::KeyEncipherment);
                }
                if ku.data_encipherment() {
                    usages.push(KeyUsagePurpose::DataEncipherment);
                }
                if ku.key_agreement() {
                    usages.push(KeyUsagePurpose::KeyAgreement);
                }
                if ku.key_cert_sign() {
                    usages.push(KeyUsagePurpose::KeyCertSign);
                }
                if ku.crl_sign() {
                    usages.push(KeyUsagePurpose::CrlSign);
                }
                if ku.encipher_only() {
                    usages.push(KeyUsagePurpose::EncipherOnly);
                }
                if ku.decipher_only() {
                    usages.push(KeyUsagePurpose::DecipherOnly);
                }
                if usages.is_empty() {
                    None
                } else {
                    Some(usages)
                }
            }
            _ => None,
        })
        .unwrap_or_default()
}

pub(super) fn parse_extended_key_usages(
    extensions: &[X509Extension],
) -> Vec<ExtendedKeyUsagePurpose> {
    extensions
        .iter()
        .find_map(|ext| match ext.parsed_extension() {
            ParsedExtension::ExtendedKeyUsage(eku) => {
                let mut usages = Vec::new();
                if eku.any {
                    usages.push(ExtendedKeyUsagePurpose::Any);
                }
                if eku.server_auth {
                    usages.push(ExtendedKeyUsagePurpose::ServerAuth);
                }
                if eku.client_auth {
                    usages.push(ExtendedKeyUsagePurpose::ClientAuth);
                }
                if eku.code_signing {
                    usages.push(ExtendedKeyUsagePurpose::CodeSigning);
                }
                if eku.email_protection {
                    usages.push(ExtendedKeyUsagePurpose::EmailProtection);
                }
                if eku.time_stamping {
                    usages.push(ExtendedKeyUsagePurpose::TimeStamping);
                }
                if eku.ocsp_signing {
                    usages.push(ExtendedKeyUsagePurpose::OcspSigning);
                }
                if usages.is_empty() {
                    None
                } else {
                    Some(usages)
                }
            }
            _ => None,
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use rcgen::{
        CertificateParams, DistinguishedName, DnType, DnValue, ExtendedKeyUsagePurpose, KeyPair,
        KeyUsagePurpose,
    };
    use x509_parser::prelude::parse_x509_certificate;

    use super::*;

    #[test]
    fn test_parse_key_usages() {
        use rustls::pki_types::{CertificateDer, pem::PemObject};
        use tempfile::TempDir;

        use crate::tls::certificate::new_self_signed_certificate;

        let temp_dir = TempDir::new().unwrap();
        let cert_path = temp_dir.path().join("test.pem");
        let key_path = temp_dir.path().join("test_key.pem");

        new_self_signed_certificate("localhost", &cert_path, &key_path).unwrap();

        let cert = CertificateDer::from_pem_file(&cert_path).unwrap();
        let (_, x509) = parse_x509_certificate(&cert).unwrap();

        let parsed_usages = parse_key_usages(x509.extensions());
        assert_eq!(parsed_usages.len(), 1);
        assert!(parsed_usages.contains(&KeyUsagePurpose::DigitalSignature));

        let parsed_ext_usages = parse_extended_key_usages(x509.extensions());
        assert_eq!(parsed_ext_usages.len(), 1);
        assert!(parsed_ext_usages.contains(&ExtendedKeyUsagePurpose::ServerAuth));
    }

    #[test]
    fn test_parse_key_usages_empty() {
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(
            DnType::CommonName,
            DnValue::Utf8String("localhost".to_string()),
        );
        params.distinguished_name = dn;

        let key_pair = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        let cert_der = cert.der();

        let (_, x509) = parse_x509_certificate(cert_der).unwrap();
        let parsed_usages = parse_key_usages(x509.extensions());
        assert!(parsed_usages.is_empty());
        let parsed_ext_usages = parse_extended_key_usages(x509.extensions());
        assert!(parsed_ext_usages.is_empty());
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn parse_certificate() {
        let cert = r"-----BEGIN CERTIFICATE-----
MIIEiDCCA3CgAwIBAgIRAMPFCaQf+UNqCgAAAAEmAkQwDQYJKoZIhvcNAQELBQAw
RjELMAkGA1UEBhMCVVMxIjAgBgNVBAoTGUdvb2dsZSBUcnVzdCBTZXJ2aWNlcyBM
TEMxEzARBgNVBAMTCkdUUyBDQSAxQzMwHhcNMjExMTI5MDMzNjM0WhcNMjIwMjIx
MDMzNjMzWjAZMRcwFQYDVQQDEw53d3cuZ29vZ2xlLmNvbTBZMBMGByqGSM49AgEG
CCqGSM49AwEHA0IABFMGHdMEPDM+Kb7aAcQDU5KQjwSUlsJX0EQtaWiyCN55oLhU
DA/VkjS1V12R+3nHjrTEroRLnCDgj7/RR5Ms36qjggJnMIICYzAOBgNVHQ8BAf8E
BAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDAYDVR0TAQH/BAIwADAdBgNVHQ4E
FgQUHP/PVkSurBjH2pmAbrQpL5/IwzUwHwYDVR0jBBgwFoAUinR/r4XN7pXNPZzQ
4kYU83E1HScwagYIKwYBBQUHAQEEXjBcMCcGCCsGAQUFBzABhhtodHRwOi8vb2Nz
cC5wa2kuZ29vZy9ndHMxYzMwMQYIKwYBBQUHMAKGJWh0dHA6Ly9wa2kuZ29vZy9y
ZXBvL2NlcnRzL2d0czFjMy5kZXIwGQYDVR0RBBIwEIIOd3d3Lmdvb2dsZS5jb20w
IQYDVR0gBBowGDAIBgZngQwBAgEwDAYKKwYBBAHWeQIFAzA8BgNVHR8ENTAzMDGg
L6AthitodHRwOi8vY3Jscy5wa2kuZ29vZy9ndHMxYzMvUXFGeGJpOU00OGMuY3Js
MIIBBAYKKwYBBAHWeQIEAgSB9QSB8gDwAHUAUaOw9f0BeZxWbbg3eI8MpHrMGyfL
956IQpoN/tSLBeUAAAF9afr8DAAABAMARjBEAiBhup4x6G6dSIKTfkK5ldcBGO3q
RvQq8k0gpUKfLHjN2QIgcQKUabrKX4hJnQ3y3hgYHDCtI7DMdPDb25LCBcq/csIA
dwApeb7wnjk5IfBWc59jpXflvld9nGAK+PlNXSZcJV3HhAAAAX1p+vwHAAAEAwBI
MEYCIQCorCQxk/daD8X03Pqg/HoK7AAtDYeuMYNW1X0HcuPPGgIhAJecPL48wDxC
ebB3ZKEGtSMg5Nv0Kn/4JHqW/Cb6V66SMA0GCSqGSIb3DQEBCwUAA4IBAQB3kaUo
6+6mnkc2sDxoUxNYhxqScoaNczL2BUBmQwYUkgTJHPJPqxkYbGZpXNxxy0NPphoi
ck9xb6rjF9C+dbENB8rY0QY5dh/nPv0XVY6IQsurk30Ieub1XNppTle/PdFmI8/J
ZDu6dtvOB1TxfaxAapYC3tGlcJJ4foQtT8GkPa3UCvdcbvmDKxGJmZhuHYs8oxAs
xxsP3k/FmSBe6nul7yMphG71qQVoU1hTrtOZ9TKvPrbdYZSu+NXIoNR9cXBzHHUb
C74KqXlMrDk9ApB452vL0yPAHSaUh9XwS7CaTMRtsQ9fjqNmMCf1/+2ORwjFdKhY
629MeJOhiP6IEz7g
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIITDCCBzSgAwIBAgIQUS3tMQs4oUbqeACcVVuhUTANBgkqhkiG9w0BAQsFADBR
MQswCQYDVQQGEwJVUzETMBEGA1UEChMKQXBwbGUgSW5jLjEtMCsGA1UEAxMkQXBw
bGUgUHVibGljIEVWIFNlcnZlciBSU0EgQ0EgMiAtIEcxMB4XDTIxMDkwODExNTI0
M1oXDTIyMTAwODExNTI0Mlowge8xHTAbBgNVBA8TFFByaXZhdGUgT3JnYW5pemF0
aW9uMRMwEQYLKwYBBAGCNzwCAQMTAlVTMRswGQYLKwYBBAGCNzwCAQITCkNhbGlm
b3JuaWExETAPBgNVBAUTCEMwODA2NTkyMQswCQYDVQQGEwJVUzETMBEGA1UECBMK
Q2FsaWZvcm5pYTESMBAGA1UEBxMJQ3VwZXJ0aW5vMRMwEQYDVQQKEwpBcHBsZSBJ
bmMuMSYwJAYDVQQLEx1tYW5hZ2VtZW50OmlkbXMuZ3JvdXAuMTIwODkyMDEWMBQG
A1UEAxMNd3d3LmFwcGxlLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
ggEBALjf6Li1rA0q2WjtwTY05eCtAe2K0RJU/nUS+bxEIqjet9XDS2MrEfDQxBCd
ed/UeR8k7S42FIksjJ2tGZk4vDc4y5wLvH6cePPAbHoMls72S1/rdPPtcnZUutaf
Nc0/7RK1KmoRqlUt1xteZgc/ZJEnuJAf54DtEln/vfsa8oRZrZFC8IPhRk5MCOVm
WkJJv6VWGP9b081xnD2dJS+wTSMa914aocmiBDyAgTYRxjPiTafuzUjhLslNo6+d
3U+g+Iho1cah0uo2XO39G0ZveFG7cOuGJpH1yDp0Jlz5h3zHspLgtPAiHSwpF+yg
OncKQ8nZIzSnMCFyMF1NwyAe6BcCAwEAAaOCBH8wggR7MAwGA1UdEwEB/wQCMAAw
HwYDVR0jBBgwFoAUUFWrQ6GvqUgrWsGih4kE5HoOytowegYIKwYBBQUHAQEEbjBs
MDIGCCsGAQUFBzAChiZodHRwOi8vY2VydHMuYXBwbGUuY29tL2FwZXZzcnNhMmcx
LmRlcjA2BggrBgEFBQcwAYYqaHR0cDovL29jc3AuYXBwbGUuY29tL29jc3AwMy1h
cGV2c3JzYTJnMTAxMDwGA1UdEQQ1MDOCDXd3dy5hcHBsZS5jb22CEHd3dy5hcHBs
ZS5jb20uY26CEGltYWdlcy5hcHBsZS5jb20wggESBgNVHSAEggEJMIIBBTAHBgVn
gQwBATCB+QYJYIZIAYb9bAIBMIHrMD4GCCsGAQUFBwIBFjJodHRwczovL3d3dy5h
cHBsZS5jb20vY2VydGlmaWNhdGVhdXRob3JpdHkvcHVibGljLzCBqAYIKwYBBQUH
AgIwgZsMgZhSZWxpYW5jZSBvbiB0aGlzIGNlcnRpZmljYXRlIGJ5IGFueSBwYXJ0
eSBhc3N1bWVzIGFjY2VwdGFuY2Ugb2YgdGhlIFJlbHlpbmcgUGFydHkgQWdyZWVt
ZW50IGZvdW5kIGF0IGh0dHBzOi8vd3d3LmFwcGxlLmNvbS9jZXJ0aWZpY2F0ZWF1
dGhvcml0eS9wdWJsaWMvLjAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEw
NQYDVR0fBC4wLDAqoCigJoYkaHR0cDovL2NybC5hcHBsZS5jb20vYXBldnNyc2Ey
ZzEuY3JsMB0GA1UdDgQWBBTM30WzNuYrQWqdUBaItCDb1kbHSDAOBgNVHQ8BAf8E
BAMCBaAwggHzBgorBgEEAdZ5AgQCBIIB4wSCAd8B3QB2ALvZ37wfinG1k5Qjl6qS
e0c4V5UKq1LoGpCWZDaOHtGFAAABe8VJ9ZkAAAQDAEcwRQIgUTik87P2Ah5POUWQ
qyq2M+Ov65QnD8v5TmmxD1Tz7XUCIQCtQBJxepx4cpiuJeZ2yFGmLNFkufLtAgAs
IrUoxmeVMgB1AKS5CZC0GFgUh7sTosxncAo8NZgE+RvfuON3zQ7IDdwQAAABe8VJ
9ZwAAAQDAEYwRAIgRxGOmKUnh7oXk+w8xrbUZCRJQAnp1tBXyS74QIdFwEUCIH1h
exezDZru8w0Wiuj+CyTnvaK1l6Y5sekiH89Fo54fAHUAUaOw9f0BeZxWbbg3eI8M
pHrMGyfL956IQpoN/tSLBeUAAAF7xUn1/AAABAMARjBEAiA9jm7OIqSTsyT6aJaB
Xsr91aoRQIbp4ITyb6H4Za2whwIgRFjsXURNOOTKexVUF2eo1XAbjNt9KI6KDmU+
V6z0y8MAdQApeb7wnjk5IfBWc59jpXflvld9nGAK+PlNXSZcJV3HhAAAAXvFSfWR
AAAEAwBGMEQCID+uJ4bUObaKsYRbuH4RZuqSFbdIUxQ8x3ecKtyo8MXkAiASsRiN
p1xFr1sxXLLKOzlqleL0jYdPG6xotLFP2cpYQDANBgkqhkiG9w0BAQsFAAOCAQEA
RB9OlF/oM0BmWdFibsGom7i+OTFe8+LnZNUvRqMuOymE5ZV+KN+8q7B24sDuYxNs
jT5vmzu4KmJOlA5tDQlsFlYEFrlqChkuWfhKk2n5yKqAHQ2CQF+vGG4glIE1JShb
1irAyuavMV4fyf20LM2ST7/vKCzSkBf5MOJJfX33GZ8bRHKrBqbqgj4i8ZuUst+B
fprsMXjaSq5thjNVk9sURM+kx1DNEs+cMXdvVf5hnxwEyctH3I/Xxv3w9FfDIDDj
l3/cNFFTy26eiSiUkqoKrcGi9yK+ZveE/RPdGparZNac5jU41PIb7meRM0LcP+/g
6v8HjGrPjpBPoPQtgyMjqA==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIII9DCCBtygAwIBAgITEgAU8ewjldVv3MTctwAAABTx7DANBgkqhkiG9w0BAQsF
ADBPMQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9u
MSAwHgYDVQQDExdNaWNyb3NvZnQgUlNBIFRMUyBDQSAwMTAeFw0yMTA3MjgyMTIy
MDZaFw0yMjA3MjgyMTIyMDZaMIGIMQswCQYDVQQGEwJVUzELMAkGA1UECBMCV0Ex
EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
bjEeMBwGA1UECxMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMRowGAYDVQQDExF3d3cu
bWljcm9zb2Z0LmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMnE
YTuMHAC05tDE3Xeql1wP18DqLF1YZ6z6vsnmS9FQg5HhjYW9d5JEpxldYfA26Rmu
SjzBnPIV6C9TsxSasdijXzMBGBXLMRN1Lqo8t+ULT0JAsmt0TjvhGTk7qAWOxx5W
gbEA+hZP12P1glre2E5LGORyf3/HDDHDJpoyVrJQcXTTxGGFrUaz8BxpSxnk3+p+
/b2hPxO70jt3vqtpgS+dJa9j9CsGm5f6QZdYFCNVL3HNk4ji36dQZd3Z01jjddgn
8eqG220HvEDL+tJY+q9/iz0fLd+rcDO/igCgpEfM3/gmz4b9xUB1MfexdFNX8zxq
7HBedJTQOSrYbcEupCMCAwEAAaOCBI0wggSJMIIBfAYKKwYBBAHWeQIEAgSCAWwE
ggFoAWYAdQApeb7wnjk5IfBWc59jpXflvld9nGAK+PlNXSZcJV3HhAAAAXrvCDQo
AAAEAwBGMEQCIGsG4F9acHkVtLDESPJxtX8xga3P+ib5mF86uhDdHdQyAiAIlmPH
81f0tFDjOT3QypOpS6W95Wv4AB7QpxQPkX5R+wB1AEHIyrHfIkZKEMahOglCh15O
MYsbA+vrS8do8JBilgb2AAABeu8INBYAAAQDAEYwRAIgYLmw/lgwOh/iFUG+ghFb
jH9odXbXMn9pH+6aoOwNpJoCIFOT/s390eZjaTM99x3B+7aF2iah+3NbIVRIO7eU
gCUJAHYARqVV63X6kSAwtaKJafTzfREsQXS+/Um4havy/HD+bUcAAAF67wg0VQAA
BAMARzBFAiEAvkCi3Cm3jnqCQFRVP4cinZcVZbMVsIsCdWq17Ql9W7gCIFsGi8PI
T+LMgAOXRfRyq4o5ffWlrF3RKPjpFm1XmcvaMCcGCSsGAQQBgjcVCgQaMBgwCgYI
KwYBBQUHAwIwCgYIKwYBBQUHAwEwPQYJKwYBBAGCNxUHBDAwLgYmKwYBBAGCNxUI
h9qGdYPu2QGCyYUbgbWeYYX062CBXbn4EIaR0HgCAWQCASUwgYcGCCsGAQUFBwEB
BHsweTBTBggrBgEFBQcwAoZHaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9t
c2NvcnAvTWljcm9zb2Z0JTIwUlNBJTIwVExTJTIwQ0ElMjAwMS5jcnQwIgYIKwYB
BQUHMAGGFmh0dHA6Ly9vY3NwLm1zb2NzcC5jb20wHQYDVR0OBBYEFAkmLKnc/2OR
QOdYZ+IIP3T26vFlMA4GA1UdDwEB/wQEAwIEsDCBmQYDVR0RBIGRMIGOghVwcml2
YWN5Lm1pY3Jvc29mdC5jb22CEWMucy1taWNyb3NvZnQuY29tgg1taWNyb3NvZnQu
Y29tghFpLnMtbWljcm9zb2Z0LmNvbYIYc3RhdGljdmlldy5taWNyb3NvZnQuY29t
ghF3d3cubWljcm9zb2Z0LmNvbYITd3d3cWEubWljcm9zb2Z0LmNvbTCBsAYDVR0f
BIGoMIGlMIGioIGfoIGchk1odHRwOi8vbXNjcmwubWljcm9zb2Z0LmNvbS9wa2kv
bXNjb3JwL2NybC9NaWNyb3NvZnQlMjBSU0ElMjBUTFMlMjBDQSUyMDAxLmNybIZL
aHR0cDovL2NybC5taWNyb3NvZnQuY29tL3BraS9tc2NvcnAvY3JsL01pY3Jvc29m
dCUyMFJTQSUyMFRMUyUyMENBJTIwMDEuY3JsMFcGA1UdIARQME4wQgYJKwYBBAGC
NyoBMDUwMwYIKwYBBQUHAgEWJ2h0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kv
bXNjb3JwL2NwczAIBgZngQwBAgIwHwYDVR0jBBgwFoAUtXYMMBHOx5JCTUzHXCzI
qQzoC2QwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMBMA0GCSqGSIb3DQEB
CwUAA4ICAQAVMIWmZCVQqfj7bJx9qruDL8/ylrr3axGTW38+QbP7a+705e8piKYA
oSLpwDnWs00JzLLfe55xE7b3veY5q88ZAcQfB34tvewp+2rYvTcvPq641TXloQlJ
an/90VgkCa2YsbSwWg4uldv0fjvbdZmRvm/fofrR45ySK8KK1SsNJ1Aa/3wuNCyj
L03dT3tf2pDymMaNj3PamyjClHsdYcWop3ZBbM/PiL0pY/a0YsqIUsUkpK93yC4E
+IkZkQDEEAeZHzoHlZv2moJSKL357z1wqS2tDTNGpX8NBvudKkUlnShJfu6MFn1m
vXONhYfpYpJ5t0DxFwhahPS7MKmp/sz7A5fO8b/nvyvwohvHHlI502Np7LdRWE1J
7bNmOcCK/gGVWU2VtZUyhJwGN104Aba61Jn8+mds8JagLPAwiB2Si7M1sfKHpacC
GTeO2N8v8WaBQw/hFLnXlV6c8C8QrYLWLxlmM+6pAlm9fHVU4RESJFseMJiJ66US
bKVIwfysnXZseCb5gbVI8v3d/qpPZSkpKfLs47spTDVKEqSBr8a2evyRJFzIZZ0v
MW9by1fTuByXk82Uyz6/MQ4x0Z/zflGSOyozpZFli7FMFbh4+Fpg6s5RgWVVep96
h4MER2f+ulxJ3j9wUxCa/BR6St/Ck6ZO+FL676uHMx3NMrrSVltSuA==
-----END CERTIFICATE-----";

        // crate::tls::parse_certificate cannot be used here as the certificate
        // above is already expired. The InvalidDateTime error is returned.
        let parsed_certs = x509_parser::prelude::Pem::iter_from_buffer(cert.as_bytes())
            .map(|pem| {
                let data = pem.unwrap();
                let (_, x509) = x509_parser::parse_x509_certificate(&data.contents).unwrap();
                let cn = parse_cn(x509.subject());
                let san = parse_san(x509.extensions());

                (cn, san)
            })
            .collect::<Vec<_>>();

        assert_eq!(parsed_certs.len(), 3);
        assert_eq!(parsed_certs[0].0, Some("www.google.com".to_string()));
        assert_eq!(
            parsed_certs[0].1,
            Some(vec!["DNSName:www.google.com".to_string()])
        );
        assert_eq!(parsed_certs[1].0, Some("www.apple.com".to_string()));
        assert_eq!(
            parsed_certs[1].1,
            Some(vec![
                "DNSName:www.apple.com".to_string(),
                "DNSName:www.apple.com.cn".to_string(),
                "DNSName:images.apple.com".to_string()
            ])
        );
        assert_eq!(parsed_certs[2].0, Some("www.microsoft.com".to_string()));
        assert_eq!(
            parsed_certs[2].1,
            Some(vec![
                "DNSName:privacy.microsoft.com".to_string(),
                "DNSName:c.s-microsoft.com".to_string(),
                "DNSName:microsoft.com".to_string(),
                "DNSName:i.s-microsoft.com".to_string(),
                "DNSName:staticview.microsoft.com".to_string(),
                "DNSName:www.microsoft.com".to_string(),
                "DNSName:wwwqa.microsoft.com".to_string()
            ])
        );
    }
}
