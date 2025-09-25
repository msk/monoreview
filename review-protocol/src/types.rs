//! Data types used by the protocol.

use std::{
    net::{IpAddr, SocketAddr},
    ops::RangeInclusive,
    time::Duration,
};

use ipnet::IpNet;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
pub use structured::ColumnStatistics;

/// The data source key, either a numeric ID or a name.
#[derive(Debug, Deserialize, Serialize)]
pub enum DataSourceKey<'a> {
    Id(u32),
    Name(&'a str),
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DataSource {
    pub id: u32,
    pub name: String,

    pub server_name: String,
    pub address: SocketAddr,

    pub data_type: DataType,
    pub source: String,
    pub kind: Option<String>,

    pub description: String,
}

/// The type of data that a data source provides.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, IntoPrimitive, TryFromPrimitive)]
#[serde(into = "u16", try_from = "u16")]
#[repr(u16)]
pub enum DataType {
    /// comma-separated values
    Csv = 0,
    /// line-based text data
    Log = 1,
    /// time series data
    TimeSeries = 2,
}

/// CPU, memory, and disk usage.
#[derive(Debug, Deserialize, Serialize)]
pub struct ResourceUsage {
    /// The average CPU usage in percent.
    pub cpu_usage: f32,

    /// The RAM size in bytes.
    pub total_memory: u64,

    /// The amount of used RAM in bytes.
    pub used_memory: u64,

    /// The disk space in bytes that is currently used.
    pub disk_used_bytes: u64,

    /// The disk space in bytes that is available to non-root users.
    pub disk_available_bytes: u64,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Process {
    pub user: String,
    pub cpu_usage: f32,
    pub mem_usage: f64,
    pub start_time: i64,
    pub command: String,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct HostNetworkGroup {
    pub hosts: Vec<IpAddr>,
    pub networks: Vec<IpNet>,
    pub ip_ranges: Vec<RangeInclusive<IpAddr>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[repr(u32)]
pub enum SamplingKind {
    Conn = 0,
    Dns = 1,
    Http = 2,
    Rdp = 3,
}

// A policy for time series sampling.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SamplingPolicy {
    pub id: u32,
    pub kind: SamplingKind,
    pub interval: Duration,
    pub period: Duration,
    pub offset: i32,
    pub src_ip: Option<IpAddr>,
    pub dst_ip: Option<IpAddr>,
    pub node: Option<String>,
    pub column: Option<u32>,
}

// IP address, port numbers, and protocols.
pub type TrafficFilterRule = (IpNet, Option<Vec<u16>>, Option<Vec<u16>>);

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[repr(u8)]
pub enum EventCategory {
    Reconnaissance = 1,
    InitialAccess = 2,
    Execution = 3,
    CredentialAccess = 4,
    Discovery = 5,
    LateralMovement = 6,
    CommandAndControl = 7,
    Exfiltration = 8,
    Impact = 9,
    Collection = 10,
    DefenseEvasion = 11,
    Persistence = 12,
    PrivilegeEscalation = 13,
    ResourceDevelopment = 14,
}

#[derive(Clone, Copy, Debug, Deserialize_repr, Eq, PartialEq, Serialize_repr)]
#[repr(u8)]
pub enum TiKind {
    Ip = 0,
    Url = 1,
    Token = 2,
    Regex = 3,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub enum RuleKind {
    Os,
    AgentSoftware,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TiRule {
    pub rule_id: u32,
    pub category: Option<EventCategory>,
    pub name: String,
    pub kind: Option<RuleKind>,
    pub description: Option<String>,
    pub references: Option<Vec<String>>,
    pub samples: Option<Vec<String>>,
    pub signatures: Option<Vec<String>>,
    pub confidence: Option<f32>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Tidb {
    pub id: u32,
    pub name: String,
    pub description: Option<String>,
    pub kind: TiKind,
    pub category: Option<EventCategory>,
    pub version: String,
    pub patterns: Vec<TiRule>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub enum Status {
    Ready,
    Idle,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ColumnStatisticsUpdate {
    pub cluster_id: String,
    pub column_statistics: Vec<ColumnStatistics>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TimeCount {
    pub time: chrono::NaiveDateTime,
    pub count: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TimeSeries {
    pub count_index: Option<usize>,
    pub series: Vec<TimeCount>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TimeSeriesUpdate {
    pub cluster_id: String,
    pub time_series: Vec<TimeSeries>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UpdateClusterRequest {
    pub cluster_id: String,
    pub detector_id: i32,
    pub signature: String,
    pub score: Option<f64>,
    pub size: i64,
    pub event_ids: Vec<(i64, String)>,
    pub status_id: i32,
    pub labels: Option<Vec<String>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OutlierInfo {
    pub id: i64,
    pub rank: i64,
    pub distance: f64,
    pub sensor: String,
}

#[derive(Serialize, Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[allow(clippy::module_name_repetitions)]
pub enum EventKind {
    DnsCovertChannel,
    HttpThreat,
    RdpBruteForce,
    RepeatedHttpSessions,
    ExtraThreat,
    TorConnection,
    DomainGenerationAlgorithm,
    FtpBruteForce,
    FtpPlainText,
    PortScan,
    MultiHostPortScan,
    NonBrowser,
    LdapBruteForce,
    LdapPlainText,
    ExternalDdos,
    CryptocurrencyMiningPool,
    BlocklistConn,
    BlocklistDns,
    BlocklistDceRpc,
    BlocklistFtp,
    BlocklistHttp,
    BlocklistKerberos,
    BlocklistLdap,
    BlocklistMqtt,
    BlocklistNfs,
    BlocklistNtlm,
    BlocklistRdp,
    BlocklistSmb,
    BlocklistSmtp,
    BlocklistSsh,
    BlocklistTls,
    WindowsThreat,
    NetworkThreat,
    LockyRansomware,
    SuspiciousTlsTraffic,
    BlocklistBootp,
    BlocklistDhcp,
    TorConnectionConn,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EventMessage {
    #[serde(with = "chrono::serde::ts_nanoseconds")]
    pub time: chrono::DateTime<chrono::Utc>,
    pub kind: EventKind,
    #[serde(with = "serde_bytes")]
    pub fields: Vec<u8>,
}
