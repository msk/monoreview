#[cfg(any(feature = "client", feature = "server"))]
pub(crate) fn add_root_certs(
    store: &mut rustls::RootCertStore,
    rd: &mut dyn std::io::BufRead,
) -> std::io::Result<()> {
    for cert in rustls_pemfile::certs(rd) {
        let cert = cert?;
        store
            .add(cert)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    }
    Ok(())
}
