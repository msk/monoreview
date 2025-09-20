use std::io::Write;

use chrono::Utc;
use syslog::{LogFormat, Severity};

#[derive(Clone, Debug)]
pub struct OrderedFormatter5424 {
    facility: syslog::Facility,
    hostname: String,
    process: String,
    pid: u32,
    pen: String,
}

impl OrderedFormatter5424 {
    pub fn new(facility: syslog::Facility, pen: &str) -> Self {
        Self {
            facility,
            hostname: roxy::hostname(),
            process: env!("CARGO_PKG_NAME").to_string(),
            pid: std::process::id(),
            pen: pen.to_string(),
        }
    }
}

// MSGID, EventKind, STRUCTURED-DATA
impl LogFormat<(String, String, String)> for OrderedFormatter5424 {
    fn format<W: Write>(
        &self,
        w: &mut W,
        severity: Severity,
        log_message: (String, String, String),
    ) -> syslog::Result<()> {
        let (message_id, kind, data) = log_message;

        write!(
            w,
            "<{}>1 {} {} {} {} {message_id} [{kind}@{} {data}]", // v1
            severity as u8 | self.facility as u8,
            Utc::now().to_rfc3339(),
            self.hostname,
            self.process,
            self.pid,
            self.pen,
        )
        .map_err(syslog::Error::from)
    }
}
