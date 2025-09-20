use std::{fs::read, path::PathBuf};

use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, pem::PemObject};

use super::TlsError;

pub fn read_private_key(path: &PathBuf) -> Result<PrivateKeyDer<'static>, TlsError> {
    let key = if let Some(true) = path.extension().map(|x| x == "der") {
        let key_file = read(path).map_err(|e| TlsError::Read("Private Key".to_string(), e))?;
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_file))
    } else {
        PrivateKeyDer::from_pem_file(path).map_err(TlsError::Pem)?
    };
    Ok(key)
}
