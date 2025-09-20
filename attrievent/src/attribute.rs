use std::str::FromStr;

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use strum_macros::{Display, EnumIter, EnumString};

#[derive(Debug, Deserialize, Serialize, EnumString, PartialEq, EnumIter, Display, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum RawEventKind {
    Bootp,
    Conn,
    Dhcp,
    Dns,
    Ftp,
    Http,
    Kerberos,
    Ldap,
    Log,
    Mqtt,
    Network,
    Nfs,
    Ntlm,
    Rdp,
    Smb,
    Smtp,
    Ssh,
    Tls,
    Window,
}

#[derive(Debug, PartialEq)]
pub enum RawEventAttrKind {
    Bootp(BootpAttr),
    Conn(ConnAttr),
    Dhcp(DhcpAttr),
    Dns(DnsAttr),
    Ftp(FtpAttr),
    Http(HttpAttr),
    Kerberos(KerberosAttr),
    Ldap(LdapAttr),
    Log(LogAttr),
    Mqtt(MqttAttr),
    Network(NetworkAttr),
    Nfs(NfsAttr),
    Ntlm(NtlmAttr),
    Rdp(RdpAttr),
    Smb(SmbAttr),
    Smtp(SmtpAttr),
    Ssh(SshAttr),
    Tls(TlsAttr),
    Window(WindowAttr),
}

impl RawEventAttrKind {
    /// Creates a new `RawEventAttrKind` with the given `RawEventKind` and attribute name.
    ///
    /// # Errors
    ///
    /// Returns an error if `RawEventAttrKind` creation fails.
    pub fn from_kind_and_attr_name(
        raw_event_kind: &RawEventKind,
        attr_name: &str,
    ) -> Result<RawEventAttrKind> {
        macro_rules! handle_attr {
            ($attr:ident, $type:ident) => {
                $attr::from_str(attr_name).map(RawEventAttrKind::$type)
            };
        }

        let parse_result = match raw_event_kind {
            RawEventKind::Bootp => handle_attr!(BootpAttr, Bootp),
            RawEventKind::Conn => handle_attr!(ConnAttr, Conn),
            RawEventKind::Dhcp => handle_attr!(DhcpAttr, Dhcp),
            RawEventKind::Dns => handle_attr!(DnsAttr, Dns),
            RawEventKind::Ftp => handle_attr!(FtpAttr, Ftp),
            RawEventKind::Http => handle_attr!(HttpAttr, Http),
            RawEventKind::Kerberos => handle_attr!(KerberosAttr, Kerberos),
            RawEventKind::Ldap => handle_attr!(LdapAttr, Ldap),
            RawEventKind::Log => handle_attr!(LogAttr, Log),
            RawEventKind::Mqtt => handle_attr!(MqttAttr, Mqtt),
            RawEventKind::Network => handle_attr!(NetworkAttr, Network),
            RawEventKind::Nfs => handle_attr!(NfsAttr, Nfs),
            RawEventKind::Ntlm => handle_attr!(NtlmAttr, Ntlm),
            RawEventKind::Rdp => handle_attr!(RdpAttr, Rdp),
            RawEventKind::Smb => handle_attr!(SmbAttr, Smb),
            RawEventKind::Smtp => handle_attr!(SmtpAttr, Smtp),
            RawEventKind::Ssh => handle_attr!(SshAttr, Ssh),
            RawEventKind::Tls => handle_attr!(TlsAttr, Tls),
            RawEventKind::Window => handle_attr!(WindowAttr, Window),
        };
        parse_result.map_err(|e| anyhow!("Unknown attribute name: {e}"))
    }
}

#[derive(Debug, EnumString, PartialEq, EnumIter, Display)]
pub enum BootpAttr {
    #[strum(serialize = "Source IP")]
    SrcAddr,
    #[strum(serialize = "Source Port")]
    SrcPort,
    #[strum(serialize = "Destination IP")]
    DstAddr,
    #[strum(serialize = "Destination Port")]
    DstPort,
    #[strum(serialize = "Protocol Number")]
    Proto,
    #[strum(serialize = "Operation Code")]
    Op,
    #[strum(serialize = "Hardware Type")]
    Htype,
    #[strum(serialize = "Hop Count")]
    Hops,
    #[strum(serialize = "Transaction ID")]
    Xid,
    #[strum(serialize = "Client IP")]
    CiAddr,
    #[strum(serialize = "Your IP")]
    YiAddr,
    #[strum(serialize = "Server IP")]
    SiAddr,
    #[strum(serialize = "Gateway IP")]
    GiAddr,
    #[strum(serialize = "Client Hardware IP")]
    ChAddr,
    #[strum(serialize = "Server Hostname")]
    SName,
    #[strum(serialize = "Boot Filename")]
    File,
}

#[derive(Debug, EnumString, PartialEq, EnumIter, Display)]
pub enum ConnAttr {
    #[strum(serialize = "Source IP")]
    SrcAddr,
    #[strum(serialize = "Source Port")]
    SrcPort,
    #[strum(serialize = "Destination IP")]
    DstAddr,
    #[strum(serialize = "Destination Port")]
    DstPort,
    #[strum(serialize = "Protocol Number")]
    Proto,
    #[strum(serialize = "Connection State")]
    ConnState,
    #[strum(serialize = "Duration")]
    Duration,
    #[strum(serialize = "Service Name")]
    Service,
    #[strum(serialize = "Bytes Sent")]
    OrigBytes,
    #[strum(serialize = "Bytes Received")]
    RespBytes,
    #[strum(serialize = "Packets Sent")]
    OrigPkts,
    #[strum(serialize = "Packets Received")]
    RespPkts,
    #[strum(serialize = "Layer 2 Bytes Sent")]
    OrigL2Bytes,
    #[strum(serialize = "Layer 2 Bytes Received")]
    RespL2Bytes,
}

#[derive(Debug, EnumString, PartialEq, EnumIter, Display)]
pub enum DhcpAttr {
    #[strum(serialize = "Source IP")]
    SrcAddr,
    #[strum(serialize = "Source Port")]
    SrcPort,
    #[strum(serialize = "Destination IP")]
    DstAddr,
    #[strum(serialize = "Destination Port")]
    DstPort,
    #[strum(serialize = "Protocol Number")]
    Proto,
    #[strum(serialize = "Message Type")]
    MgsType,
    #[strum(serialize = "Client IP")]
    CiAddr,
    #[strum(serialize = "Your IP")]
    YiAddr,
    #[strum(serialize = "Server IP")]
    SiAddr,
    #[strum(serialize = "Gateway IP")]
    GiAddr,
    #[strum(serialize = "Subnet Mask")]
    SubNetMask,
    #[strum(serialize = "Routers")]
    Router,
    #[strum(serialize = "Domain Name Servers")]
    DomainNameServer,
    #[strum(serialize = "Request IP")]
    ReqIpAddr,
    #[strum(serialize = "Lease Time")]
    LeaseTime,
    #[strum(serialize = "Server ID")]
    ServerId,
    #[strum(serialize = "Parameter Request List")]
    ParamReqList,
    #[strum(serialize = "Message")]
    Message,
    #[strum(serialize = "Renewal Time")]
    RenewalTime,
    #[strum(serialize = "Rebinding Time")]
    RebindingTime,
    #[strum(serialize = "Class ID List")]
    ClassId,
    #[strum(serialize = "Client ID Type")]
    ClientIdType,
    #[strum(serialize = "Client ID List")]
    ClientId,
}

#[derive(Debug, EnumString, PartialEq, EnumIter, Display)]
pub enum DnsAttr {
    #[strum(serialize = "Source IP")]
    SrcAddr,
    #[strum(serialize = "Source Port")]
    SrcPort,
    #[strum(serialize = "Destination IP")]
    DstAddr,
    #[strum(serialize = "Destination Port")]
    DstPort,
    #[strum(serialize = "Protocol Number")]
    Proto,
    #[strum(serialize = "Query")]
    Query,
    #[strum(serialize = "Answer")]
    Answer,
    #[strum(serialize = "Transaction ID")]
    TransId,
    #[strum(serialize = "Round-Trip Time")]
    Rtt,
    #[strum(serialize = "Query Class")]
    QClass,
    #[strum(serialize = "Query Type")]
    QType,
    #[strum(serialize = "Response Code")]
    RCode,
    #[strum(serialize = "Authoritative Answer Flag")]
    AA,
    #[strum(serialize = "Truncation Flag")]
    TC,
    #[strum(serialize = "Recursion Desired Flag")]
    RD,
    #[strum(serialize = "Recursion Available Flag")]
    RA,
    #[strum(serialize = "Time to live")]
    Ttl,
}

#[derive(Debug, EnumString, PartialEq, EnumIter, Display)]
pub enum FtpAttr {
    #[strum(serialize = "Source IP")]
    SrcAddr,
    #[strum(serialize = "Source Port")]
    SrcPort,
    #[strum(serialize = "Destination IP")]
    DstAddr,
    #[strum(serialize = "Destination Port")]
    DstPort,
    #[strum(serialize = "Protocol Number")]
    Proto,
    #[strum(serialize = "Username")]
    User,
    #[strum(serialize = "Password")]
    Password,
    #[strum(serialize = "Command")]
    Command,
    #[strum(serialize = "Reply Code")]
    ReplyCode,
    #[strum(serialize = "Reply Message")]
    ReplyMsg,
    #[strum(serialize = "Passive Mode Flag")]
    DataPassive,
    #[strum(serialize = "Data Channel Source IP")]
    DataOrigAddr,
    #[strum(serialize = "Data Channel Destination IP")]
    DataRespAddr,
    #[strum(serialize = "Data Channel Destination Port")]
    DataRespPort,
    #[strum(serialize = "Filename")]
    File,
    #[strum(serialize = "File Size")]
    FileSize,
    #[strum(serialize = "File ID")]
    FileId,
}

#[derive(Debug, EnumString, PartialEq, EnumIter, Display)]
pub enum HttpAttr {
    #[strum(serialize = "Source IP")]
    SrcAddr,
    #[strum(serialize = "Source Port")]
    SrcPort,
    #[strum(serialize = "Destination IP")]
    DstAddr,
    #[strum(serialize = "Destination Port")]
    DstPort,
    #[strum(serialize = "Protocol Number")]
    Proto,
    #[strum(serialize = "HTTP Method")]
    Method,
    #[strum(serialize = "Host")]
    Host,
    #[strum(serialize = "URI")]
    Uri,
    #[strum(serialize = "Referer")]
    Referer,
    #[strum(serialize = "HTTP Version")]
    Version,
    #[strum(serialize = "User Agent")]
    UserAgent,
    #[strum(serialize = "Request Length")]
    RequestLen,
    #[strum(serialize = "Response Length")]
    ResponseLen,
    #[strum(serialize = "Status Code")]
    StatusCode,
    #[strum(serialize = "Status Message")]
    StatusMsg,
    #[strum(serialize = "Username")]
    Username,
    #[strum(serialize = "Password")]
    Password,
    #[strum(serialize = "Cookie")]
    Cookie,
    #[strum(serialize = "Content Encoding")]
    ContentEncoding,
    #[strum(serialize = "Content Type")]
    ContentType,
    #[strum(serialize = "Cache Control")]
    CacheControl,
    #[strum(serialize = "Request Filename")]
    OrigFilenames,
    #[strum(serialize = "Request MIME Types")]
    OrigMimeTypes,
    #[strum(serialize = "Response Filename")]
    RespFilenames,
    #[strum(serialize = "Response MIME Types")]
    RespMimeTypes,
    #[strum(serialize = "POST Body")]
    PostBody,
    #[strum(serialize = "Last State")]
    State,
}

#[derive(Debug, EnumString, PartialEq, EnumIter, Display)]
pub enum KerberosAttr {
    #[strum(serialize = "Source IP")]
    SrcAddr,
    #[strum(serialize = "Source Port")]
    SrcPort,
    #[strum(serialize = "Destination IP")]
    DstAddr,
    #[strum(serialize = "Destination Port")]
    DstPort,
    #[strum(serialize = "Protocol Number")]
    Proto,
    #[strum(serialize = "Client Time")]
    ClientTime,
    #[strum(serialize = "Server Time")]
    ServerTime,
    #[strum(serialize = "Error Code")]
    ErrorCode,
    #[strum(serialize = "Client Realm")]
    ClientRealm,
    #[strum(serialize = "Client Name Type")]
    CnameType,
    #[strum(serialize = "Client Name")]
    ClientName,
    #[strum(serialize = "Realm")]
    Realm,
    #[strum(serialize = "Service Name Type")]
    SnameType,
    #[strum(serialize = "Service Name")]
    ServiceName,
}

#[derive(Debug, EnumString, PartialEq, EnumIter, Display)]
pub enum LdapAttr {
    #[strum(serialize = "Source IP")]
    SrcAddr,
    #[strum(serialize = "Source Port")]
    SrcPort,
    #[strum(serialize = "Destination IP")]
    DstAddr,
    #[strum(serialize = "Destination Port")]
    DstPort,
    #[strum(serialize = "Protocol Number")]
    Proto,
    #[strum(serialize = "Message ID")]
    MessageId,
    #[strum(serialize = "Version")]
    Version,
    #[strum(serialize = "Operation Code")]
    Opcode,
    #[strum(serialize = "Result Code")]
    Result,
    #[strum(serialize = "Diagnostic Message")]
    DiagnosticMessage,
    #[strum(serialize = "Object")]
    Object,
    #[strum(serialize = "Argument")]
    Argument,
}

#[derive(Debug, EnumString, PartialEq, EnumIter, Display)]
pub enum MqttAttr {
    #[strum(serialize = "Source IP")]
    SrcAddr,
    #[strum(serialize = "Source Port")]
    SrcPort,
    #[strum(serialize = "Destination IP")]
    DstAddr,
    #[strum(serialize = "Destination Port")]
    DstPort,
    #[strum(serialize = "Protocol Number")]
    Proto,
    #[strum(serialize = "MQTT Protocol")]
    Protocol,
    #[strum(serialize = "Version")]
    Version,
    #[strum(serialize = "Client ID")]
    ClientId,
    #[strum(serialize = "Connection Acknowledgement Response")]
    ConnackReason,
    #[strum(serialize = "Subscription Request")]
    Subscribe,
    #[strum(serialize = "Subscription Acknowledgement Response")]
    SubackReason,
}

#[derive(Debug, EnumString, PartialEq, EnumIter, Display)]
pub enum NfsAttr {
    #[strum(serialize = "Source IP")]
    SrcAddr,
    #[strum(serialize = "Source Port")]
    SrcPort,
    #[strum(serialize = "Destination IP")]
    DstAddr,
    #[strum(serialize = "Destination Port")]
    DstPort,
    #[strum(serialize = "Protocol Number")]
    Proto,
    #[strum(serialize = "Read Files")]
    ReadFiles,
    #[strum(serialize = "Write Files")]
    WriteFiles,
}

#[derive(Debug, EnumString, PartialEq, EnumIter, Display)]
pub enum NtlmAttr {
    #[strum(serialize = "Source IP")]
    SrcAddr,
    #[strum(serialize = "Source Port")]
    SrcPort,
    #[strum(serialize = "Destination IP")]
    DstAddr,
    #[strum(serialize = "Destination Port")]
    DstPort,
    #[strum(serialize = "Protocol Number")]
    Proto,
    #[strum(serialize = "NTLM Protocol")]
    Protocol,
    #[strum(serialize = "Username")]
    Username,
    #[strum(serialize = "Hostname")]
    Hostname,
    #[strum(serialize = "Domain Name")]
    Domainname,
    #[strum(serialize = "Success Flag")]
    Success,
}

#[derive(Debug, EnumString, PartialEq, EnumIter, Display)]
pub enum RdpAttr {
    #[strum(serialize = "Source IP")]
    SrcAddr,
    #[strum(serialize = "Source Port")]
    SrcPort,
    #[strum(serialize = "Destination IP")]
    DstAddr,
    #[strum(serialize = "Destination Port")]
    DstPort,
    #[strum(serialize = "Protocol Number")]
    Proto,
    #[strum(serialize = "Cookie")]
    Cookie,
}

#[derive(Debug, EnumString, PartialEq, EnumIter, Display)]
pub enum SmbAttr {
    #[strum(serialize = "Source IP")]
    SrcAddr,
    #[strum(serialize = "Source Port")]
    SrcPort,
    #[strum(serialize = "Destination IP")]
    DstAddr,
    #[strum(serialize = "Destination Port")]
    DstPort,
    #[strum(serialize = "Protocol Number")]
    Proto,
    #[strum(serialize = "Command")]
    Command,
    #[strum(serialize = "Path")]
    Path,
    #[strum(serialize = "Service")]
    Service,
    #[strum(serialize = "Filename")]
    FileName,
    #[strum(serialize = "File Size")]
    FileSize,
    #[strum(serialize = "Resource Type")]
    ResourceType,
    #[strum(serialize = "File ID")]
    Fid,
    #[strum(serialize = "Create Time")]
    CreateTime,
    #[strum(serialize = "Access Time")]
    AccessTime,
    #[strum(serialize = "Write Time")]
    WriteTime,
    #[strum(serialize = "Change Time")]
    ChangeTime,
}

#[derive(Debug, EnumString, PartialEq, EnumIter, Display)]
pub enum SmtpAttr {
    #[strum(serialize = "Source IP")]
    SrcAddr,
    #[strum(serialize = "Source Port")]
    SrcPort,
    #[strum(serialize = "Destination IP")]
    DstAddr,
    #[strum(serialize = "Destination Port")]
    DstPort,
    #[strum(serialize = "Protocol Number")]
    Proto,
    #[strum(serialize = "Mail From")]
    MailFrom,
    #[strum(serialize = "Date")]
    Date,
    #[strum(serialize = "From")]
    From,
    #[strum(serialize = "To")]
    To,
    #[strum(serialize = "Subject")]
    Subject,
    #[strum(serialize = "Agent")]
    Agent,
    #[strum(serialize = "States")]
    State,
}

#[derive(Debug, EnumString, PartialEq, EnumIter, Display)]
pub enum SshAttr {
    #[strum(serialize = "Source IP")]
    SrcAddr,
    #[strum(serialize = "Source Port")]
    SrcPort,
    #[strum(serialize = "Destination IP")]
    DstAddr,
    #[strum(serialize = "Destination Port")]
    DstPort,
    #[strum(serialize = "Protocol Number")]
    Proto,
    #[strum(serialize = "Client")]
    Client,
    #[strum(serialize = "Server")]
    Server,
    #[strum(serialize = "Cipher Algorithm")]
    CipherAlg,
    #[strum(serialize = "MAC Algorithms")]
    MacAlg,
    #[strum(serialize = "Compression Algorithm")]
    CompressionAlg,
    #[strum(serialize = "Kex Exchange Algorithm")]
    KexAlg,
    #[strum(serialize = "Host Key Algorithm")]
    HostKeyAlg,
    #[strum(serialize = "HASSH Algorithms")]
    HasshAlgorithms,
    #[strum(serialize = "HASSH")]
    Hassh,
    #[strum(serialize = "HASSH Server Algorithm")]
    HasshServerAlgorithms,
    #[strum(serialize = "HASSH Server")]
    HasshServer,
    #[strum(serialize = "Client Signed Host Key Algorithm")]
    ClientShka,
    #[strum(serialize = "Server Signed Host Key Algorithm")]
    ServerShka,
}

#[derive(Debug, EnumString, PartialEq, EnumIter, Display)]
pub enum TlsAttr {
    #[strum(serialize = "Source IP")]
    SrcAddr,
    #[strum(serialize = "Source Port")]
    SrcPort,
    #[strum(serialize = "Destination IP")]
    DstAddr,
    #[strum(serialize = "Destination Port")]
    DstPort,
    #[strum(serialize = "Protocol Number")]
    Proto,
    #[strum(serialize = "Server Name")]
    ServerName,
    #[strum(serialize = "ALPN Protocol")]
    AlpnProtocol,
    #[strum(serialize = "JA3 Fingerprint")]
    Ja3,
    #[strum(serialize = "TLS Version")]
    Version,
    #[strum(serialize = "Client Cipher Suites")]
    ClientCipherSuites,
    #[strum(serialize = "Client Extensions")]
    ClientExtensions,
    #[strum(serialize = "Cipher")]
    Cipher,
    #[strum(serialize = "Extensions")]
    Extensions,
    #[strum(serialize = "JA3S Fingerprint")]
    Ja3s,
    #[strum(serialize = "Certificate Serial Number")]
    Serial,
    #[strum(serialize = "Subject Country")]
    SubjectCountry,
    #[strum(serialize = "Subject Organization Name")]
    SubjectOrgName,
    #[strum(serialize = "Common Name")]
    SubjectCommonName,
    #[strum(serialize = "Validity Start")]
    ValidityNotBefore,
    #[strum(serialize = "Validity End")]
    ValidityNotAfter,
    #[strum(serialize = "Subject Alternative Name")]
    SubjectAltName,
    #[strum(serialize = "Issuer Country")]
    IssuerCountry,
    #[strum(serialize = "Issuer Organization Name")]
    IssuerOrgName,
    #[strum(serialize = "Issuer Organization Unit Name")]
    IssuerOrgUnitName,
    #[strum(serialize = "Issuer Common Name")]
    IssuerCommonName,
    #[strum(serialize = "Last Alert Message")]
    LastAlert,
}

#[derive(Debug, EnumString, PartialEq, EnumIter, Display)]
pub enum LogAttr {
    #[strum(serialize = "Content")]
    Content,
}

#[derive(Debug, EnumString, PartialEq, EnumIter, Display)]
pub enum NetworkAttr {
    #[strum(serialize = "Source IP")]
    SrcAddr,
    #[strum(serialize = "Source Port")]
    SrcPort,
    #[strum(serialize = "Destination IP")]
    DstAddr,
    #[strum(serialize = "Destination Port")]
    DstPort,
    #[strum(serialize = "Protocol Number")]
    Proto,
    #[strum(serialize = "Content")]
    Content,
}

#[derive(Debug, EnumString, PartialEq, EnumIter, Display)]
pub enum WindowAttr {
    #[strum(serialize = "Service")]
    Service,
    #[strum(serialize = "Agent Name")]
    AgentName,
    #[strum(serialize = "Agent ID")]
    AgentId,
    #[strum(serialize = "Process GUID")]
    ProcessGuid,
    #[strum(serialize = "Process ID")]
    ProcessId,
    #[strum(serialize = "Image")]
    Image,
    #[strum(serialize = "User")]
    User,
    #[strum(serialize = "Content")]
    Content,
}

mod tests {

    #[test]
    #[allow(clippy::too_many_lines)]
    fn convert_to_protocol_attr_enum() {
        use crate::attribute::{
            BootpAttr, ConnAttr, DhcpAttr, DnsAttr, FtpAttr, HttpAttr, KerberosAttr, LdapAttr,
            LogAttr, MqttAttr, NetworkAttr, NfsAttr, NtlmAttr, RawEventAttrKind, RawEventKind,
            RdpAttr, SmbAttr, SmtpAttr, SshAttr, TlsAttr, WindowAttr,
        };

        const INVALID_ATTR_FIELD_NAME: &str = "invalid-attr-field";

        assert_eq!(
            RawEventAttrKind::from_kind_and_attr_name(
                &RawEventKind::Conn,
                &ConnAttr::OrigBytes.to_string()
            )
            .expect("The raw event type and attribute name are always valid."),
            RawEventAttrKind::Conn(ConnAttr::OrigBytes)
        );

        assert_eq!(
            RawEventAttrKind::from_kind_and_attr_name(
                &RawEventKind::Bootp,
                &BootpAttr::Op.to_string()
            )
            .expect("The raw event type and attribute name are always valid."),
            RawEventAttrKind::Bootp(BootpAttr::Op)
        );

        assert_eq!(
            RawEventAttrKind::from_kind_and_attr_name(
                &RawEventKind::Dhcp,
                &DhcpAttr::SubNetMask.to_string()
            )
            .expect("The raw event type and attribute name are always valid."),
            RawEventAttrKind::Dhcp(DhcpAttr::SubNetMask)
        );

        assert_eq!(
            RawEventAttrKind::from_kind_and_attr_name(
                &RawEventKind::Dns,
                &DnsAttr::Query.to_string()
            )
            .expect("The raw event type and attribute name are always valid."),
            RawEventAttrKind::Dns(DnsAttr::Query)
        );

        assert_eq!(
            RawEventAttrKind::from_kind_and_attr_name(
                &RawEventKind::Ftp,
                &FtpAttr::ReplyMsg.to_string()
            )
            .expect("The raw event type and attribute name are always valid."),
            RawEventAttrKind::Ftp(FtpAttr::ReplyMsg)
        );

        assert_eq!(
            RawEventAttrKind::from_kind_and_attr_name(
                &RawEventKind::Http,
                &HttpAttr::UserAgent.to_string()
            )
            .expect("The raw event type and attribute name are always valid."),
            RawEventAttrKind::Http(HttpAttr::UserAgent)
        );

        assert_eq!(
            RawEventAttrKind::from_kind_and_attr_name(
                &RawEventKind::Kerberos,
                &KerberosAttr::CnameType.to_string()
            )
            .expect("The raw event type and attribute name are always valid."),
            RawEventAttrKind::Kerberos(KerberosAttr::CnameType)
        );

        assert_eq!(
            RawEventAttrKind::from_kind_and_attr_name(
                &RawEventKind::Ldap,
                &LdapAttr::DiagnosticMessage.to_string()
            )
            .expect("The raw event type and attribute name are always valid."),
            RawEventAttrKind::Ldap(LdapAttr::DiagnosticMessage)
        );

        assert_eq!(
            RawEventAttrKind::from_kind_and_attr_name(
                &RawEventKind::Log,
                &LogAttr::Content.to_string()
            )
            .expect("The raw event type and attribute name are always valid."),
            RawEventAttrKind::Log(LogAttr::Content)
        );

        assert_eq!(
            RawEventAttrKind::from_kind_and_attr_name(
                &RawEventKind::Mqtt,
                &MqttAttr::SubackReason.to_string()
            )
            .expect("The raw event type and attribute name are always valid."),
            RawEventAttrKind::Mqtt(MqttAttr::SubackReason)
        );

        assert_eq!(
            RawEventAttrKind::from_kind_and_attr_name(
                &RawEventKind::Nfs,
                &NfsAttr::WriteFiles.to_string()
            )
            .expect("The raw event type and attribute name are always valid."),
            RawEventAttrKind::Nfs(NfsAttr::WriteFiles)
        );

        assert_eq!(
            RawEventAttrKind::from_kind_and_attr_name(
                &RawEventKind::Ntlm,
                &NtlmAttr::Domainname.to_string()
            )
            .expect("The raw event type and attribute name are always valid."),
            RawEventAttrKind::Ntlm(NtlmAttr::Domainname)
        );

        assert_eq!(
            RawEventAttrKind::from_kind_and_attr_name(
                &RawEventKind::Rdp,
                &RdpAttr::Cookie.to_string()
            )
            .expect("The raw event type and attribute name are always valid."),
            RawEventAttrKind::Rdp(RdpAttr::Cookie)
        );

        assert_eq!(
            RawEventAttrKind::from_kind_and_attr_name(
                &RawEventKind::Smb,
                &SmbAttr::ResourceType.to_string()
            )
            .expect("The raw event type and attribute name are always valid."),
            RawEventAttrKind::Smb(SmbAttr::ResourceType)
        );

        assert_eq!(
            RawEventAttrKind::from_kind_and_attr_name(
                &RawEventKind::Smtp,
                &SmtpAttr::MailFrom.to_string()
            )
            .expect("The raw event type and attribute name are always valid."),
            RawEventAttrKind::Smtp(SmtpAttr::MailFrom)
        );

        assert_eq!(
            RawEventAttrKind::from_kind_and_attr_name(
                &RawEventKind::Ssh,
                &SshAttr::CipherAlg.to_string()
            )
            .expect("The raw event type and attribute name are always valid."),
            RawEventAttrKind::Ssh(SshAttr::CipherAlg)
        );

        assert_eq!(
            RawEventAttrKind::from_kind_and_attr_name(
                &RawEventKind::Tls,
                &TlsAttr::Ja3.to_string()
            )
            .expect("The raw event type and attribute name are always valid."),
            RawEventAttrKind::Tls(TlsAttr::Ja3)
        );

        assert_eq!(
            RawEventAttrKind::from_kind_and_attr_name(
                &RawEventKind::Window,
                &WindowAttr::AgentId.to_string()
            )
            .expect("The raw event type and attribute name are always valid."),
            RawEventAttrKind::Window(WindowAttr::AgentId)
        );

        assert_eq!(
            RawEventAttrKind::from_kind_and_attr_name(
                &RawEventKind::Network,
                &NetworkAttr::Content.to_string()
            )
            .expect("The raw event type and attribute name are always valid."),
            RawEventAttrKind::Network(NetworkAttr::Content)
        );

        assert!(
            RawEventAttrKind::from_kind_and_attr_name(&RawEventKind::Conn, INVALID_ATTR_FIELD_NAME)
                .is_err()
        );
    }
}
