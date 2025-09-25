# Changelog

This file documents recent notable changes to this project. The format of this
file is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and
this project adheres to [Semantic
Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- The following client-side APIs to send requests to the server:
  - `Connection::get_model`
  - `Connection::get_model_names`
  - `Connection::insert_column_statistics`
  - `Connection::insert_model`
  - `Connection::insert_time_series`
  - `Connection::remove_model`
  - `Connection::update_clusters`
  - `Connection::update_model`
  - `Connection::update_outliers`
  - `Connection::insert_event_labels`
  - `Connection::insert_data_source`
  - `Connection::get_outliers`
- The following server-side APIs to handle requests from clients:
  - `Handler::get_model`
  - `Handler::get_model_names`
  - `Handler::insert_column_statistics`
  - `Handler::insert_model`
  - `Handler::insert_time_series`
  - `Handler::remove_model`
  - `Handler::update_clusters`
  - `Handler::update_model`
  - `Handler::update_outliers`
  - `Handler::insert_event_labels`
  - `Handler::insert_data_source`
  - `Handler::get_outliers`
- New types for machine learning and data processing:
  - `ColumnStatistics`, `ColumnStatisticsUpdate`
  - `TimeCount`, `TimeSeries`, `TimeSeriesUpdate`
  - `UpdateClusterRequest`
  - `OutlierInfo`
  - `EventMessage`

### Changed

- `server::Handler::handle` requires the `peer` argument, which uniquely
  identifies the client within the application.
- `server::Handler::renew_certificate` and
  `client::Connection::renew_certificate` now take no arguments. The server
  should use the identity from the connection.

## [0.12.0] - 2025-08-28

### Added

- Added `confidence` field of type `Option<f32>` to `TiRule` structure
- Added `kind` field to `TiRule` structure

### Changed

- `ResourceUsage` struct updated for Roxy 0.5.0 compatibility:
  - Memory fields now use bytes instead of KB
  - Replaced `total_disk_space`/`used_disk_space` with
    `disk_used_bytes`/`disk_available_bytes`
- Removed `Unknown` variant from `EventCategory` enum for MITRE compatibility
- Changed `category` fields in `TiRule` and `Tidb` structs to `Option<EventCategory>`

## [0.11.0] - 2025-06-21

### Changed

- Migrated to Rust 2024 edition. It requires a minimum of Rust 1.85.0.
- `server::Handler` handles requests from the following client-side APIs:
  - `Connection::get_model_names`
  - `Connection::get_tor_exit_node_list`
  - `Connection::get_trusted_domain_list`
  - `Connection::get_trusted_user_agent_list`
- Updated the naming conventions for "allowlist" and "blocklist" to use a single
  word instead of separate words. This change affects the following:
  - `AllowList` renamed to `Allowlist`
  - `BlockList` renamed to `Blocklist`
  - `*_allow_list` renamed to `*_allowlist`
  - `*_block_list` renamed to `*_blocklist`
- Modified `EventCategory` to include all MITRE categories - `Collection`,
  `DefenseEvasion`, `Persistence`, `PrivilegeEscalation`, `ResourceDevelopment`
  are added.

### Removed

- `server::Connection::as_quinn` was provided for backward-compatibility and has
  been removed. Server applications using review-protocol should now use the
  `server::Connection` struct directly.

## [0.10.0] - 2025-02-01

### Added

- The following client-side API to send a request to the server:
  - `Connection::get_indicator`

### Changed

- `server::Handler` handles requests from the following client-side APIs:
  - `Connection::get_allow_list`
  - `Connection::get_block_list`
  - `Connection::get_indicator`

## [0.9.0] - 2025-01-20

### Added

- The following server-side APIs to send data to the client:
  - `Connection::get_process_list`
  - `Connection::get_resource_usage`
  - `Connection::send_blocklist`
  - `Connection::send_config_update_cmd`
  - `Connection::send_filtering_rules`
  - `Connection::send_internal_network_list`
  - `Connection::send_ping_cmd`
  - `Connection::send_reboot_cmd`
  - `Connection::send_shutdown_cmd`
  - `Connection::send_sampling_policies`
  - `Connection::send_tor_exit_node_list`
  - `Connection::send_trusted_user_agent_list`

### Changed

- `Handler::sampling_policy_list` and `Handler::delete_sampling_policy` accept
  `[SamplingPolicy]` and `&[u32]`, respectively, instead of raw bytes. This
  makes the API more intuitive and moves serialization concerns from the agent
  to this crate where they belong.
- Updated `client::ConnectionBuilder` and `AgentInfo` structs to accomodate the
  new `status` field, to be used in the handshake process.
  - Introduced `Status` enum to represent the status of agents.

## [0.8.1] - 2024-11-15

### Added

- The server side should call `server::handle` to handle incoming requests from
  a client. This function takes a handler, which should implement the `Handler`
  trait. The handler currently handles the following requests:
  - `GetDataSource`
  - `GetTidbPatterns`
- Types required in the requests handled by `Handler`:
  - `DataSourceKey`, `DataType`, `DataSource`
- `client::Connection` provides the following functions to send requests to the
  server:
  - `get_data_source`
  - `get_pretrained_model`
  - `renew_certificate`

### Deprecated

- `server::send_trusted_domain_list` is deprecated. The server should now call
  `server::Connection::send_trusted_domain_list` to send the list of trusted
  domains to the client.
- `server::respond_with_tidb_patters` is deprecated. `server::handle` should be
  used to handle incoming requests from the client.

## [0.8.0] - 2024-10-11

### Added

- `server::Connection` encapsulates the QUIC connection from a client and
  provides a protocol-specific connection. This change improves encapsulation
  and makes the API more idiomatic to review-protocol. Currently it provides the
  following APIs:
  - `send_allowlist`
  - `send_trusted_domain_list`

### Changed

- Reverted the format change of `EventCategory` in the previous release to
  maintain compatibility with applications with their own deserialization logic.

## [0.7.0] - 2024-09-28

### Added

- `GetTidbPatterns` is handled by `client::get_tidb_patterns` at the client side
  and `server::respond_with_tidb_patterns` at the server side.

### Removed

- Removed the following config-related items:
  - `Config`, `HogConfig`, `PigletConfig` and `CrusherConfig`
  - `Handler::get_config` and `RequestCode::GetConfig`

## [0.6.0] - 2024-09-18

### Removed

- `client::handshake` was deprecated in version 0.4.1 and has been removed in
  this version. Applications using review-protocol should now create a
  `Connection` instance using `ConnectionBuilder` instead.

### Fixed

- Fixed the `request::Handler::trusted_domain_list` function to correctly parse
  the argument (#39).

## [0.5.0] - 2024-09-05

### Added

- Implemented new client API methods:
  - `get_allow_list`: Retrieves the list of allowed networks
  - `get_block_list`: Retrieves the list of blocked networks
  - `get_internal_network_list`: Retrieves the list of internal networks
  - `get_tor_exit_node_list`: Retrieves the list of Tor exit nodes
  - `get_trusted_domain_list`: Retrieves the list of trusted domains
  - `get_trusted_user_agent_list`: Retrieves the list of trusted user agents
- Implemented a new server API method:
  - `notify_config_update`: Notifies the client that its configuration has been
    updated

### Removed

- `Handler::set_config` is removed. The server should no longer sends a message
  that invokes this method. Instead, the server should sends a message that
  invokes `Handler::update_config`.

### Fixed

- `send_trusted_domain_list` no longer tries to receive a response twice,
  causing the "unexpected end of file" error.

## [0.4.2] - 2024-07-31

### Added

- Introduced a new method `open_uni` in the `Connection` struct. This method
  initiates an outgoing unidirectional stream and directly corresponds to the
  `open_uni` method of the underlying `quinn::Connection`. This addition is for
  backward-compatibility and will be removed when this crate provides all the
  necessary features without exposing quinn's types.

## [0.4.1] - 2024-07-30

### Added

- The `ConnectionBuilder` struct has been enhanced to allow for the setting of
  certificates, private keys, and root certificates. This includes new methods
  to set and replace these components:

  - `ConnectionBuilder::cert` sets the client certificate for the connection.
  - `ConnectionBuilder::key` sets the client's private key for the connection.
  - `root_certs` sets the root certificates for the connection.

  These additions provide more flexibility in managing secure connections by
  allowing certificates and keys to be updated dynamically.

- The `update_config` is added to the `request::Handler` trait. This function
  allows the server to notify agents to take actions to update their
  configuration.

### Deprecated

- The `handshake` function in the `client` module is deprecated. This function
  will be removed in the next major/minor release. Applications using
  review-protocol should now create a `Connection` instance using
  `ConnectionBuilder` instead of calling `quinn::Endpoint::connect` and
  `client::handshake` separately.
- The `reload_config` function in the `request::Handler` trait is deprecated.
  This function will be removed in the next major/minor release. Applications
  using review-protocol should now use the `update_config` function in the
  client API to make agents update their configuration.

## [0.4.0] - 2024-07-22

### Added

- New `ConnectionBuilder` struct in the `client` module for creating customized
  connections. This allows for more flexible configuration of TLS settings and
  root certificates.
  - `ConnectionBuilder::new` function to create a new builder with given remote
    and local configurations.
  - `ConnectionBuilder::add_root_certs` method to add root certificates to the
    endpoint's certificate store.
  - `ConnectionBuilder::local_addr` method to set a specific local address for
    binding.
  - `ConnectionBuilder::connect` method to construct the final `Connection`
    instance. This combines `quinn::Endpoint::connect` and
    `review-protocol::client::handshake`. This simplifies the connection process
    for applications using review-protocol, reducing code duplication.
    Applications using review-protocol should now create a `Connection` instance
    using `ConnectionBuilder` instead of calling `quinn::Endpoint::connect` and
    `client::handshake` separately.
- `Connection` struct in the `client` module. This provides a protocol-specific
  connection, improving encapsulation and making the API more idiomatic to
  review-protocol.
  - Methods like `local_addr`, `remote_addr`, `close_reason`, `open_bi`, and `accept_bi`
    to interact with the connection.
- Introduced `EventCategory` enum to categorize security events.
- New client API `get_config()` to fetch configuration from the server. This
  method allows clients to request and receive configuration data from the
  server. The format of the configuration is left to the caller to interpret.

### Changed

- The `handshake` function in the `client` module no longer returns the
  `SendStream` and `RecvStream` handles. These values were previously returned
  but not used by the caller, so they have been removed to simplify the
  function's return type.
- Minimized dependencies when only default features are used.
  - Made several dependencies optional and tied them to specific features.
    `anyhow`, `async-trait`, `num_enum`, `semver`, and `thiserror` are now
    optional dependencies.
  - Modified `unary_request` function to return `std::io::Result` instead of
    `anyhow::Result`.

### Removed

- Direct dependency on `quinn::Connection` in the public API. The `Connection`
  struct now encapsulates the `quinn::Connection` and `quinn::Endpoint`.
- Removed unused configurations and fields to streamline the crate and improve
  maintainability. These removals are based on the observation that these items
  were not being utilized by any applications depending on review-database.
  - `ReconvergeConfig` has been eliminated.
  - `review_address` field has been removed from `HogConfig`, `PigletConfig`,
    and `CrusherConfig`.

## [0.3.0] - 2024-05-28

### Added

- Added a public API that provides `frame` functionality to avoid exposing `oinq`'s
  `frame`. This change improves the modularity of the `review-protocol`.
- `server::send_trusted_domain_list` to facilitate sending the trusted domain
  list from the server to the client.

## Changed

- `HandshakeError::ReadError` now provides the underlying error as
  `std::io::Error`, which is more informative than the previous custom error
  type.
- Update `oinq` to version `0.13.0`. Updating to this version results in the
  following changes.
  - Bump dependencies.
    - Update quinn to version 0.11.
    - Update rustls to version 0.23.
    - Update rcgen to version 0.13.
  - Fixed the handling of the error types provided by `oinq`. `oinq` has
    changed from providing the `RecvError`/`SendError` error type to providing
    the `std::io::Error` error type. As a result, `review-protocol` has also
    been modified to `std::io::Error` or convert to the correct internally
    defined error type.

## [0.2.0] - 2024-04-04

### Added

- `AgentInfo` to represent the agent's information during the handshake process.
- `request::Handler`, `request::handle`, and other related types needed to
  implement a request handler.

### Changed

- `SendError::MessageTooLarge` no longer contains the underlying error,
  `std::num::TryFromIntError`, since it does not provide any useful information.
- Merge `SendError`'s `MessageTooLarge` and `SerializationFailure`, and
  `HandshakeError`'s `MessageTooLarge` and `SerializationFailure` into
  `MessageTooLarge`, since serialization into a memory buffer fails only when
  the message is too large.

## [0.1.2] - 2024-03-25

### Added

- Types used in the protocol:
  - `Process`
  - `TrafficFilterRule`
- `client::send_ok` and `client::send_err` methods to facilitate sending
  responses from the client to the server.

## [0.1.1] - 2024-03-21

### Added

- Types used in the protocol:
  - `Config`
  - `CrusherConfig`
  - `HogConfig`
  - `HostNetworkGroup`
  - `PigletConfig`
  - `ReconvergeConfig`
  - `ResourceUsage`
- `HandshakeError` for the handshake process.
- `frame` module for low-level protocol communication. This module provides the
  necessary communication primitives and ensures compatibility with the `oinq`
  crate until the protocol's full implementation.
- `client::send_request` method to facilitate initiating requests from the
  client to the server.

## [0.1.0] - 2024-03-15

### Added

- `unary_request` exchanges RPC-like messages between agents.
- The `request` module provides request handlers that an agent needs to
  implement.
- `client::handshake` implements the application-level handshake process for the
  client after a QUIC connection is established.

[Unreleased]: https://github.com/petabi/review-protocol/compare/0.12.0...main
[0.12.0]: https://github.com/petabi/review-protocol/compare/0.11.0...0.12.0
[0.11.0]: https://github.com/petabi/review-protocol/compare/0.10.0...0.11.0
[0.10.0]: https://github.com/petabi/review-protocol/compare/0.9.0...0.10.0
[0.9.0]: https://github.com/petabi/review-protocol/compare/0.8.1...0.9.0
[0.8.1]: https://github.com/petabi/review-protocol/compare/0.8.0...0.8.1
[0.8.0]: https://github.com/petabi/review-protocol/compare/0.7.0...0.8.0
[0.7.0]: https://github.com/petabi/review-protocol/compare/0.6.0...0.7.0
[0.6.0]: https://github.com/petabi/review-protocol/compare/0.5.0...0.6.0
[0.5.0]: https://github.com/petabi/review-protocol/compare/0.4.2...0.5.0
[0.4.2]: https://github.com/petabi/review-protocol/compare/0.4.1...0.4.2
[0.4.1]: https://github.com/petabi/review-protocol/compare/0.4.0...0.4.1
[0.4.0]: https://github.com/petabi/review-protocol/compare/0.3.0...0.4.0
[0.3.0]: https://github.com/petabi/review-protocol/compare/0.2.0...0.3.0
[0.2.0]: https://github.com/petabi/review-protocol/compare/0.1.2...0.2.0
[0.1.2]: https://github.com/petabi/review-protocol/compare/0.1.1...0.1.2
[0.1.1]: https://github.com/petabi/review-protocol/compare/0.1.0...0.1.1
[0.1.0]: https://github.com/petabi/review-protocol/tree/0.1.0
