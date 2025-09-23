# REview - AI-based Cybersecurity Engine Management Server

REview is a central management server for AI-based cybersecurity engine,
providing comprehensive network security monitoring and analysis capabilities.
Built as a Rust workspace, it delivers high-performance cybersecurity event
processing with real-time threat detection.

## Features

- **High-Performance Database**: RocksDB for fast key-value storage and operations
- **Real-time Threat Detection**: Comprehensive monitoring for HTTP, network,
  and Windows-based threats
- **GraphQL API**: Modern API interface for data querying and system management
- **QUIC-based Communication**: Secure, efficient network protocols with mTLS
  support
- **Web Management Interface**: Complete web-based administration console
- **Advanced Security**: Network policies, trusted domains, and Tor exit node
  monitoring
- **Certificate Management**: Automatic certificate monitoring and validation
- **Statistical Analysis**: Machine learning model integration for threat
  analysis

## Architecture

### Core Components

- **review**: Main application server providing core management and monitoring
- **review-database**: Database layer with RocksDB backend
- **review-web**: Web interface and GraphQL API server
- **review-protocol**: Protocol definitions and communication interfaces
- **oinq**: QUIC-based network communication library
- **roxy**: Root privilege proxy for secure system administration
- **vinum**: Fast numerical computation library
- **attrievent**: Event attribute handling utilities

## Quick Start

### Building

```bash
# Build entire workspace
cargo build

# Build specific component
cargo build -p review

# Release build
cargo build --release

# Build web interface example
cargo build --example minireview
```

### Testing

```bash
# Run all tests
cargo test

# Test specific crate
cargo test -p review-database

# Run tests with output
cargo test -- --nocapture
```

### Development

```bash
# Check code quality
cargo clippy

# Format code
cargo fmt
```

## Configuration

Configure REview through environment variables:

### Database
- `REVIEW_DATA_DIR`: RocksDB storage directory (default: `./data`)

### Network
- `REVIEW_RPC_SRV_ADDR`: RPC server address (default: `localhost:38390`)
- `REVIEW_GRAPHQL_SRV_ADDR`: GraphQL API server address (default: `localhost:8000`)
- `REVIEW_HOSTNAME`: Certificate hostname (default: `localhost`)

### Security
- `REVIEW_CERT`: Certificate file path (default: `cert.pem`)
- `REVIEW_KEY`: Private key file path (default: `key.pem`)
- `REVIEW_CLIENT_CERT_PATH`: Client certificate path (default: `client_cert.pem`)
- `REVIEW_CLIENT_KEY_PATH`: Client key path (default: `client_key.pem`)
- `REVIEW_CA_CERTS`: Additional CA certificate files

### Application
- `REVIEW_HTDOCS_DIR`: Web application directory (default: `./htdocs`)
- `REVIEW_LOG_PATH`: Log file path (defaults to stdout)
- `REVIEW_IP2LOCATION`: IP2Location database file path
- `REVIEW_PEN`: IANA Private Enterprise Number (default: `0`)

### Backup & Maintenance
- `REVIEW_BACKUP_DIR`: Backup storage directory (default: `./backup`)
- `REVIEW_BACKUP_DURATION`: Backup period in days (default: `1`)
- `REVIEW_BACKUP_TIME`: Backup schedule time (default: `23:59:59`)
- `REVIEW_NUM_OF_BACKUPS_TO_KEEP`: Number of backups to retain (default: `5`)

### Security Features
- `REVIEW_JWT_EXPIRES_IN`: JWT expiration time in seconds
- `REVIEW_SYSLOG_TX`: Enable syslog transmission (default: `false`)
- `REVIEW_TOR_EXIT_NODE_POLL_INTERVAL`: Tor exit node polling interval in minutes

## Development Guidelines

- **Rust 2024**: All crates use the latest Rust edition
- **Error Handling**: Comprehensive use of `anyhow` and `thiserror`
- **Async Architecture**: Tokio-based async runtime throughout
- **Code Quality**: Clippy pedantic warnings enabled, `unwrap_used` warnings enforced
- **Logging**: Structured logging with `tracing` crate
