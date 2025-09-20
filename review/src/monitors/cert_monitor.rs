use std::{path::Path, sync::Arc};

use anyhow::{Context, Result};
use futures::{
    future::{self, Either},
    pin_mut,
};
use jiff::Timestamp;
use tokio::{
    sync::Notify,
    task::JoinHandle,
    time::{self, sleep},
};
use tracing::{error, info};

use crate::tls::TlsCertConfig;

pub fn monitor_loop(
    cert_reload: Arc<Notify>,
    config: TlsCertConfig,
) -> Result<Option<Arc<Notify>>> {
    let sleep_time = calculate_sleep_until_renewal(config.cert_path())?;
    let Some(mut sleep_time) = sleep_time else {
        return Ok(None);
    };
    let monitor_loop_shutdown_handle = Arc::new(Notify::new());
    let shutdown_handle = monitor_loop_shutdown_handle.clone();
    let monitor_loop: JoinHandle<Result<()>> = tokio::spawn(async move {
        loop {
            if sleep_time > 0 {
                let wait_shutdown = monitor_loop_shutdown_handle.notified();
                let sleep = sleep(time::Duration::from_secs(
                    sleep_time.try_into().expect("Must be positive integer"),
                ));
                pin_mut!(wait_shutdown, sleep);
                if let Either::Left(_) = future::select(wait_shutdown, sleep).await {
                    info!("Shutting down certs monitor");
                    monitor_loop_shutdown_handle.notify_one();
                    return Ok(());
                }
            }
            info!("Issuing a new certificate...");
            crate::tls::renew_self_signed_certificate(&config)?;
            cert_reload.notify_waiters();
            match calculate_sleep_until_renewal(config.cert_path())? {
                Some(new_sleep_time) => {
                    sleep_time = new_sleep_time;
                }
                None => anyhow::bail!("Invalid certificate"),
            }
        }
    });

    info!("Starting certs monitoring loop");
    tokio::spawn(async {
        match monitor_loop.await {
            Ok(Err(e)) => error!("Certs monitoring loop died: {:?}", e),
            Err(e) => error!(
                "Certs monitoring loop task failed to execute to completion: {:?}",
                e
            ),
            _ => (),
        }
    });
    Ok(Some(shutdown_handle))
}

fn calculate_sleep_until_renewal(cert_path: &Path) -> Result<Option<i64>> {
    use rustls::pki_types::{CertificateDer, pem::PemObject};

    let cert = CertificateDer::from_pem_file(cert_path)?;
    let (_, x509) = x509_parser::parse_x509_certificate(cert.as_ref())?;
    if !x509.validity().is_valid() {
        anyhow::bail!("The certificate has expired or is not yet valid");
    }
    let self_signed = x509.verify_signature(Some(x509.public_key())).is_ok();

    if self_signed {
        let not_after = x509.validity().not_after.timestamp();

        // Issue a new self-signed certificate one month prior to the expiration date
        let now = Timestamp::now();
        let expiration = Timestamp::from_second(not_after)
            .context("certificate expiration timestamp is invalid")?;
        let one_month = jiff::Span::new().seconds(30 * 24 * 60 * 60);
        let renewal_time = expiration
            .checked_sub(one_month)
            .context("certificate expiration timestamp is invalid")?;
        let sleep_time = renewal_time.as_second() - now.as_second();

        Ok(Some(sleep_time))
    } else {
        Ok(None)
    }
}
