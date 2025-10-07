# Changelog

This file documents recent notable changes to this project. The format of this
file is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and
this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Added log message on agent disconnection to enhance traceability and aid in
  debugging. The log message includes the agent's ID, hostname, and timestamp,
  matching the format used for agent connection logging.
- REview presents a client certificate in communication with other services.
- Added `TorConnectionConn` event detection for connection-level Tor network
  monitoring. This extends existing Tor detection capabilities beyond HTTP
  connections to include all connection types.
- Added `comprehensiveUserList` GraphQL query for system administrators to
  fetch all user accounts with security status information including account
  lock/suspension status, creation time, last signin time, and access
  restrictions.
- Added `removeAccountsExact` GraphQL mutation for removing accounts using exact
  username matching without normalization. This provides backward compatibility
  for accounts created before strict username validation was enforced.
- Implemented account lockout functionality for failed login attempts. Accounts
  are locked for 30 minutes after 5 consecutive failed login attempts to prevent
  brute force attacks.
- Added `confidence` field to `tidbRule` GraphQL API.
- Added `kind` field to `tidbRule` GraphQL API.
- Added `sensor` field to GraphQL objects for detection events based on
  multiple raw events (`PortScan`, `MultiHostPortScan`, `ExternalDdos`,
  `RdpBruteForce`, `FtpBruteForce`, `LdapBruteForce`).
- Added `start_time` and `end_time` fields to GraphQL objects for
  `RepeatedHttpSessions`.

### Changed

- Consolidated HTTP event fields for better consistency. The `orig_mime_types`
  and `resp_mime_types` fields are now unified into a single `mime_types` field.
  The `orig_filenames` and `resp_filenames` fields are consolidated into
  `filenames`. The `post_body` field is renamed to `body`.
- Changed the calculation of the disk usage to be aligned with df(1) output.
- Added safeguards to the `updateAccount` GraphQL mutation to prevent system
  administrators from demoting themselves and to block other roles from
  promoting themselves to system administrator.
- Updated the `removeAccounts` GraphQL mutation to prevent users from removing
  their own accounts.
- Enhanced `signedInAccountList` GraphQL API to include customer IDs in the
  `SignedInAccount` type.
- Updated `myAccount` GraphQL API to return the new `MyAccount` type instead of
  `Account`. The `MyAccount` type adds an `expire_times` field, which provides JWT
  expiration times for all active sessions of the current user.
- Changed the return type of the `removeTrustedUserAgents` GraphQL API from
  `Boolean` to `[String!]!`. The API now returns a list of removed user agents when
  all input agents are successfully deleted, or an error message if any agents
  could not be removed.
- Updated `removeAccounts` GraphQL mutation to use proper username validation
  and normalization (same as account creation), ensuring consistent handling
  of usernames across all account operations.
- Updated GraphQL APIs `insertFilter`, `replaceFilter`, `filterList`, and
  `filter` to reflect the addition of the `PeriodForSearch` field in the
  `Filter` structure from review-database.
- Updated GraphQL APIs `eventList` and `eventStream` to reflect the addition of
  the `confidence` field.
- Renamed a time-related GraphQL field in `BlocklistConn`,
  `TorConnectionConn`,`LockyRansomware`, `DnsCovertChannel`, and `TorConnection`
  from `session_end_time` and `duration` to `end_time` for consistency.
- The Agent API is not compatible with REview 0.44 and earlier versions.
- Restricted account creation and deletion permissions to System Administrators
  only. The `insertAccount`, `removeAccounts`, and `removeAccountsExact`
  GraphQL mutations now require the `SystemAdministrator` role instead of
  allowing both `SystemAdministrator` and `SecurityAdministrator` roles. This
  enhances system security by enforcing stricter role-based access control
  for sensitive account management operations.

### Fixed

- The RenewCertificate handler previously accepted any certificate from the
  request body, allowing compromised agents to renew other agents' certificates
  and impersonate them. Now it uses the identity information from the TLS
  connection in issuing a new certificate.
- Only unexpired JWT tokens are considered when checking parallelsession limits.
- Improved customer removal to prevent stale references in account and node
  tables.

## [0.44.0] - 2025-07-15

### Added

- Added `confidence` field to most Blocklist GraphQL objects for consistency
  with `BlocklistTls`. The field provides confidence scores for security
  detections across different protocol blocklists.
- Added `level` field to 27 detection event types that previously lacked
  ThreatLevel values. All blocklist and brute force events return Medium
  threat level, while plain text events return Low threat level.
- Supports the following event categories in TIDB:
  - Collection
  - Defense Evasion
  - Persistence
  - Privilege Escalation
  - Resource Development

### Changed

- Agent status is now updated in the database upon connection. This update does
  not affect the agent’s ability to communicate with the REview server,
  regardless of whether the update succeeds or fails.
- The `updateAccount` GraphQL mutation's `password` parameter type has been
  changed from `UpdatePassword` to `String`. The mutation now accepts the new
  password directly without requiring the old password, as
  `SystemAdministrators` do not have access to users' current passwords.
- Modified the GraphQL API to prevent additional System administrator accounts
  from being created during insert/update.

### Fixed

- Fixed a bug that REview doesn't accept outliers from REconverge due to
  incorrect time calculation.
- Fixed external service removal in `applyNode` mutation. When an external
  service's draft is set to `null`, the service is now properly removed from
  the node during application.

## [0.43.0] - 2025-06-25

### Added

- Introduced `myAccount` GraphQL API, which allows users of all roles to query
  their own account information.
- Enhanced `signedInAccountList` GraphQL API to include additional account
  details (`name`, `department`, `role`) in the `SignedInAccount` type, providing
  richer information about currently signed-in users.
- Added `updateMyAccount` GraphQL mutation that allows authenticated users to
  update their own account information including password, name, department,
  language, and theme settings. This enables user self-service account
  management for all user roles.
- Added username validation and normalization with the following rules:
  - No whitespace allowed
  - Only lowercase English letters, digits, and special characters
    (`.`, `-`, `_`) are allowed
  - No consecutive special characters or special characters at the end
  - Must start with a lowercase English letter
  - Length must be 3-30 characters
  - Uppercase letters are automatically converted to lowercase
- Added `level` and `learningMethod` fields to all detected event types:
  - Threat level: `HttpThreat` events return `LOW`, all others return `MEDIUM`
  - Learning method: `HttpThreat`, `NetworkThreat`, `WindowsThreat`, and
    `ExtraThreat` events return `UNSUPERVISED`, all others return
    `SEMI_SUPERVISED`
- Added `forceSignOut` GraphQL mutation to allow system administrators and
  security administrators to forcefully terminate all active sessions for any
  user, enhancing security management capabilities.

### Changed

- Restricted `updateAccount` GraphQL mutation access to `SystemAdministrator`
  role only for enhanced security. Previously accessible to both
  `SystemAdministrator` and `SecurityAdministrator` roles.
- When `REVIEW_LOG_PATH` is not set, the log will be written to standard output
  instead of the hardcoded path, /data/logs/apps.
- Replaced the `log_dir` configuration option with `log_path`. The `log_path`
  option requires a full file path, including the filename. If `log_path` is set
  and the file cannot be opened or created, REview will be termiated.
- `REVIEW_HOST_NAME` has been renamed to `REVIEW_HOSTNAME` for consistency with
  other usage.
- Updated the GraphQL APIs related to account to deal with the new field,
  `customer_ids`.
- Improved application shutdown performance by removing the backup process that
  occurred during shutdown. Backups are still performed periodically according
  to the configured schedule to ensure data integrity.
- Added `confidence` field to `BlocklistTls`.
- Changed the behavior of filtering in `EventListFilterInput` in the GraphQL
  API.
  - If the `sensors` field is provided, only events collected from the sensors
    are returned.
  - If the `sensors` field is not provided, the software filters events from
    sensors owned by the customers the user belongs to.
- The type of customer ID and tag ID in GraphQL APIs is now `ID` instead of
  `Int`. The affected GraphQL APIs are as follows:
  - Parameter type changes: `insertAccount`, `updateAccount`, `insertNetwork`,
    `updateNetwork`, `insertTriageResponse`, `updateTriageResponse`.
  - Return type changes: `account`, `accountList`, `triageResponse`,
    `triageResponseList`.
- `removeTrustedDomain` has been replaced with `removeTrustedDomains` to support
  multiple removals.
- Modified to use dedicated RFC5424 syslog formatter for the detected event.
- Renamed GraphQL field `lastTime` to `endTime` in all event types to better
  reflect its semantic meaning. This affects all event objects in the GraphQL
  schema, including but not limited to `PortScan`, `MultiHostPortScan`,
  `ExternalDdos`, `BlocklistConn`, `BlocklistTls`, `SuspiciousTlsTraffic`, and
  other event types in the `src/graphql/event/` modules.
- Renamed `BlockList` to `Blocklist` and `block_list` to `blocklist` in line
  with the Rust API Guidelines for acronyms/compound words. This affects GraphQL
  APIs such as `eventList` and `eventStream` and may cause breaking changes for
  clients relying on the old field name.
- Changed behavior of blocklist, allowlist and trusted user agents updates to
  automatically broadcast without manual apply.
  - As a result of this change, the following GraphQL APIs used for manual apply
    have been removed: `applyBlockNetworks`, `applyAllowNetworks`, `applyTrustedUserAgent`
  - The following GraphQL APIs have been updated to immediately broadcast
    changes, without requiring a separate apply step: `insertAllowNetwork`,
    `removeAllowNetworks`, `updateAllowNetwork`, `insertBlockNetwork`,
    `removeBlockNetworks`, `updateBlockNetwork`, `insertTrustedUserAgents`,
    `removeTrustedUserAgents`, `updateTrustedUserAgent`
- Renamed `host_names` field to `hostnames` in GraphQL types: `FilterInput`,
  `EventListFilterInput`, and `Filter`. This affects GraphQL APIs such as
  `insertFilter`, `replaceFilter`, `filter`, and `filterList`.
- Enhanced password security by preventing password reuse in `updateAccount` and
  `resetAdminPassword` GraphQL APIs.
  - The `updateAccount` API now requires password changes to provide both old
    and new password values using the format `{ old: "...", new: "..." }`
    instead of just the new password.
  - Both APIs now validate that the new password is different from the current
    password and reject changes that attempt to reuse the current password.
- Modified code related to the packet attribute triage. The scoring
  functionality for packet attribute triage was previously not implemented, but
  is now correctly supported on the review-database side. To reflect this,
  the related code has been updated accordingly.
  - A new field `raw_event_kind` of type `RawEventKind` has been added to `PacketAttrInput`.
  - The same field has also been added as a return field to `PacketAttr`, which
    is one of the types used in triage-related GraphQL API queries.
  - Introduced new enum variants (`UInteger`, `Vector`, `IpAddr`, `Bool`) to the
    `ValueKind` enum for strict type matching of packet attributes.
  - This changes affects GraphQL APIs such as `insertTriagePolicy`,
    `updateTriagePolicy` , `triagePolicyList`, and `triagePolicy`. They may
    introduce breaking changes for clients relying on the previous GraphQL schema.
- Modified code related to node management. The review-database has introduced
  the concept of "external service" to clearly distinguish applications that
  provide an API for interaction and operate outside the REview agent ecosystem,
  from directly connected agents over QUIC. To reflect this concept, the
  node-related code has been updated accordingly.
  - Added new structs `ExternalService` and `ExternalServiceSnapshot`, along
    with enums `ExternalServiceStatus` and `ExternalServiceKind`, to represent
    configuration for external services. The previously used `Giganto` struct,
    which was responsible for storing configuration for the DataStore, has been
    removed and replaced by `ExternalService`.
  - Replaced the `giganto` field of type `Option<GigantoInput>` in both
    `NodeInput` and `NodeDraftInput` with an `external_services` field of type
    `Vec<ExternalServiceInput>`. The `GigantoInput` struct, which was limited to
    handling input for the DataStore only, has been removed. Configuration input
    for all external services—including DataStore—is now provided through `ExternalServiceInput`.
  - Breaking changes have been introduced in the GraphQL APIs (`nodeStatusList`,
    `nodeList`, `node`, `insertNode`, `updateNodeDraft`, `applyNode`). So
    clients that use the affected APIs may need to update their code to maintain
    compatibility.

### Removed

- The following QUIC APIs are no longer supported and have been removed:
  - `GetIndicatorList`
  - `InsertIndicator`
  - `RemoveIndicator`
  - `InsertTidb`
  - `GetTidbList`
  - `RemoveTidb`
  - `UpdateTidb`
  - `GetTrustedUserAgentList`
- The `theme` and `language` GraphQL APIs are removed. Use the `myAccount`
  GraphQL API instead to retrieve equivalent information.

### Fixed

- Fixed a security issue where the `language`, `updateLanguage`, `theme`, and
  `updateTheme` APIs allowed changing another user's settings by providing a
  different `username` parameter.
  - The `username` parameter has been removed, and the APIs now extract the
    username from the JWT for authorization.
- Fixed a bug in the `updateNodeDraft` GraphQL API where adding a new agent to
  an already configured node could fail.
- Corrected the `peer` identifier logic in handling a connection from an agent.
  The identifier now correctly uses the unique agent key instead of the
  potentially non-unique app name. This resolves potential agent
  misidentification issues when used with QUIC APIs such as `GetConfig` and
  `GetInternalNetworkList`.
- Fixed event filtering by multiple IP addresses for `ExternalDdos`,
  `MultiHostPortScan`, and `RdpBruteForce`.
- Fixed an issue in event filtering in the GraphQL API that failed to filter
  events by `kinds`.
- Corrected instances of `referrer` to `referer` for the HTTP header field name
  to align with the official HTTP standard's spelling.
- Fixed the event stream query iterator performance issue by implementing
  dynamic advancement of stuck event time variables. Added
  `event_stuck_check_interval` parameter to `eventStream` to configure the
  check interval (defaults to 5 minutes). This prevents the iterator from
  getting stuck on old timestamps when certain event types become inactive
  for extended periods.

## [0.42.0] - 2025-02-01

### Added

- Added the `updateTrustedDomain` GraphQL API, allowing users to modify a
  trusted domain.
- The following GraphQL APIs now use a custom scalar, `IpAddress`, for IP
  addresses: `ipLocation`, `ipLocationList`, `insertAccount`, `updateAccount`,
  `insertSamplingPolicy`, and `updateSamplingPolicy`.

### Changed

- The syslog message format has been updated to include the `sensor` field
  instead of `source`. This change aligns with the updated terminology used in
  the system.
- The type of `WindowsThreat.clusterId` has been changed from `Int` to `String`
  to be consistent with other cluster IDs.
- The type of `Account.maxParallelSessions` has been changed from `StringNumber`
  to `Int` to reflect the actual data type.
- The value of `maxParallelSessions` in the GraphQL API should not exceed 255.
- The `insertNode` GraphQL API has been updated to make the `config` field
  optional for the `agents` parameter.
- The `cluster_id` field in the following event messages became optional:
  `ExtraThreat`, `HttpThreatFields`, `HttpThreat`, `NetworkThreat`, and
  `WindowsThreat`.
- `AgentManager::update_traffic_filter_rules` no longer leaves a log message
  when the operation is successful. This behavior is consistent with other
  successful operations in `AgentManager`.

### Removed

- Removed the agent API for resetting the admin password. Users should now use
  the `resetAdminPassword` mutation in the GraphQL API.

### Fixed

- Resolved an issue in the `applyNode` GraphQL API, where configuration values
  set to an empty string were not saved to the `config` in the database.
- The paginated GraphQL queries use different representations for cursors. The
  cursor values obtained from earlier versions of the API are not compatible
  with the new cursor values.
- Replaced the term source with sensor, where it refers to a device or software
  that captures or detects raw events. This update broadly affects GraphQL APIs
  that previously used source field as a parameter, and GraphQL APIs that return
  event, outlier, or triage related structs.
- When REview broadcasts the Tor exit node lists, it sends the list as
  `Vec<String>`. Previously, it incorrectly sent `Result<Vec<String>, String>`.
- Fixed an issue in the `updateNodeDraft` GraphQL API where configuration
  conversion failures were silently ignored, leading to incorrect None handling.

## [0.41.0] - 2024-11-20

### Added

- Added the `TimeSeriesGenerator` variant to the `AgentKind` enum, expanding
  its functionality.
- Added `signInWithNewPassword` GraphQL API. This new API allows users to sign
  in with a new password as part of enhanced security measures.
  - As part of this update, the `signIn` GraphQL API will now return an error if
    the account has never been signed in before. This change ensures that all
    users update their passwords upon their first login, strengthening account
    security.

### Changed

- Improved `applyNode` GraphQL API behavior. The `applyNode` GraphQL API has
  been updated to exclude notifying agents that operate with local configurations.
- Simplified `updateNodeDraft` API: The `updateNodeDraft` GraphQL API no longer
  requires the config field in `NodeDraftInput::agents`, streamlining its usage.
- Renamed `AgentKind` Enum Variants: Variants within the AgentKind enum have
  been renamed to improve clarity and usability.

### Fixed

- GraphQL API Enhancements for `samplingPolicy` and `samplingPolicyList`:
  Missing node fields have been added to the `samplingPolicy` and `samplingPolicyList`
  responses within the SamplingPolicy object. This ensures more complete and
  accurate API responses.

## [0.40.1] - 2024-10-07

### Fixed

- Corrected the version number in the binary. The previous version, 0.40.0, was
  yanked due to this issue.

## [0.40.0] - 2024-10-04 [YANKED]

### Added

- The `ipLocationList` GraphQL API that returns location information for multiple
  IP addresses.

### Changed

- The `nodeStatusList` GraphQL API response now includes `nameDraft`, `profile`,
  `profileDraft`, and `gigantoDraft`, offering a more comprehensive view of the
  node's status.

### Fixed

- An issue in the `applyNode` GraphQL API where agents could not be properly
  identified.
- A bug where statistics (minimum, maximum, mean, and standard deviation values)
  of integer fields in clustering were not being inserted into the database.

## [0.39.0] - 2024-09-29

### Changed

- The message format for `GetTidbPatterns` in the Agent API has been updated,
  replacing string fields with numeric fields to improve performance and reduce
  memory usage.

## [0.38.0] - 2024-09-19

### Changed

- Updated the syslog message format for detected events to conform to RFC 5424.
  The Private Enterprise Number (PEN) should now be set via the `REVIEW_PEN`
  environment variable.
- Changed the data type of `timestamp` for the AgentAPI GetOutliers from
  `Option<i64>` to `i64`, as the timestamp value always exists due to the recent
  database schema change.

### Fixed

- The AgentAPI GetOutliers now only returns outliers from the most recent batch
  for the given model, instead of all outliers in the store.

## [0.37.0] - 2024-09-05

### Added

- Introduced an agent API to retrieve the agent's configuration from the
  database. Use `client::Connection::get_config` for this. The hostname stored
  in the database must match the actual node's hostname, and each node's
  hostname must be unique to avoid conflicts.
- Limited the number of parallel sessions for a user via the
  `maxParallelSessions` argument in the `insertAccount` mutation.
- Added support for restricting user access to specific IP addresses using the
  `allowAccessFrom` argument in the `insertUser` mutation.
- Introduced new event types: `BlockListBootp`, `BlockListDhcp`, and
  `SuspiciousTlsTraffic`.
- Added the ability for users to specify a preferred language using the
  `language` argument in the `insertAccount` mutation, and update it using the
  `updateLanguage` mutation.

### Changed

- Syslog transmission for detected events can now be toggled on or off using the
  `syslog_tx` option in the settings.
- Updated the agent configuration process: the server now notifies the agent to
  update its configuration, and the agent retrieves it using
  `client::Connection::get_config`. This shift gives agents more autonomy and
  flexibility in managing their configurations.
- Updated admin account creation: credentials are now set via the `REVIEW_ADMIN`
  environment variable in `username:password` format, instead of using hardcoded
  values.
- Modified `Node` and `NodeProfile` fields and updated related CRUD APIs to
  align with the new schema.
- Added `category` fields to the Threat Intelligence (TI) database and event
  rules.
- Modified the `preserveOutliers` GraphQL API to return a list of outliers that
  were not marked as saved, replacing the previous count of successfully marked
  outliers.
- Changed GraphQL APIs to return `StringNumber` or `ID` for values exceeding
  `i32`, replacing integers in applicable APIs.
- Updated the `ping` field in the `NodeStatus` GraphQL API to return a `Float`
  (seconds) instead of an `Int` (microseconds) for improved precision.
- Refined the `applyNode` GraphQL API to match the new node and agent management
  process, including changes to the response format:
  - Removed the `successModules` field and added `gigantoDraft` to represent the
    draft configuration of the Giganto module.
  - If `gigantoDraft` is `None`, either the node does not have the Giganto
    module, or it should be disabled.
- Enhanced the `nodeStatusList` GraphQL API for improved node and agent
  management:
  - For nodes with the Manager module, the `ping` field now consistently returns
    `0.0` to indicate that the node is reachable.
  - Introduced the `agents` field, which provides detailed information about
    agents on the node, including `kind`, `storedStatus`, `config`, and `draft`
    attributes.
  - Replaced the `piglet`, `reconverge`, and `learner` status fields with the
    unified `storedStatus` field. The `config` and `draft` fields now replace
    `pigletConfig` and `hogConfig`, providing clear differentiation between
    active and draft configurations.

### Deprecated

- Deprecated the agent API for resetting the admin password. Users should
  transition to the `resetAdminPassword` mutation in the GraphQL API.

### Removed

- Removed the agent API for retrieving node settings. Users should now use the
  `nodeList` query in the GraphQL API to retrieve node information.
- Removed the process where the server directly sets the agent's configuration.
  The agent now autonomously retrieves its configuration using
  `Connection::get_config` when notified via `request::Handler::update_config`.

### Fixed

- Resolved an issue where the ping request to an agent could return a negative
  value due to system clock changes. The ping request now always returns a
  nonnegative value.
- Fixed an issue where sending a trusted domain list to an agent caused an
  "unexpected end of file" log message.

## [0.36.0] - 2024-04-25

### Added

- `Manager` implements `halt` to shutdown a host running an agent.
- Added `LockyRansomware` detection event.

### Changed

- GraphQL queries `accountList`, `allowNetworkList`, `blockNetworkList`,
  `categories`, `networkList`, `qualifiers`, `samplingPolicyList`,
  `loadRoundsByModel`, `statuses`, `templateList`, `torExitNodeList`,
  `triageResponseList`, `nodeStatusList`, `clusters`, `customerList`,
  `dataSourceList`, `eventList`, `roundsByCluster`, `trustedUserAgentList`,
  `trustedDomainList`, `rankedOutliers`, `savedOutliers`, `outliers`, `models`,
  `triagePolicyList`, `nodeList` now explicitly reject user input with
  combinations of (before, after), (first, before), and (last, after)
  parameters, following the GraphQL pagination documentation guidelines.
  This enhancement ensures better consistency and adherence to best practices in
  handling pagination requests.
- GraphQl queries `insertTidb` requires `dbfile` to be encoded string of `Tidb`
  instance that is serialized with `bincode::DefaultOptions::new().serialize`
  instead of `bincode::serialize`.
- GraphQl queries `updateTidb` requires `new` to be encoded string of `Tidb`
  instance that is serialized with `bincode::DefaultOptions::new().serialize`
  instead of `bincode::serialize`.
- Added the result of `get_config` of each module to `nodeStatusList` GraphQL API.
- Used `set_config` of `AgentManager`, instead of `send_and_recv` in `applyNode`
  GraphQL API.

### Fixed

- Fixed the `nodeStatusList` GraphQL API to return appropriate results for each field.

## [0.35.0] - 2024-03-18

### Added

- `Manager` implements the following methods:
  - `broadcast_crusher_sampling_policy`
  - `get_config`
  - `get_process_list`
  - `get_resource_usage`
  - `ping`
  - `reboot`
  - `set_config`
- Add `nodeShutdown` GraphQL API.
- Introduced `applyNode` GraphQL API, that applies draft values to modules and
  updates values in database. This API handles partial success of setting
  application settings, which may happen when a node carries multiple modules.
  The API returns the list of succeeded modules' names in
  `ApplyResult::success_modules`.

### Changed

- Users currently using REview versions earlier than 0.34.0 should
  take note that current version does not support direct migration from these
  earlier versions.
  - To ensure data integrity and avoid potential data loss, users are advised to
    follow a specific update sequence:
    1. Update to REview version 0.34.0 first.
    2. Subsequently, update to the latest version of REview.
- Updated the `ModelIndicator` GraphQL type. Added `name` field as the name of
  the model indicator.
- Changed the return type of `indicatorList` GraphQL query to `[ModelIndicator!]!`.
- GraphQL query `updateExpirationTime` returns an error if the expiration time
  is less than one second.
- `Node` struct now has `settings` and `settings_draft` of type `NodeSettings`,
  and `name` and `name_draft`. Upon initial insertion of `Node`, `name` must be
  provided, as it is used as the key of `Node` in the database. `name_draft` and
  `settings_draft` are introduced to support 2-step node-setting process, which
  is save & apply. `name_draft` and `settings_draft` fields mean that the data
  are only saved to the database. Once those are applied, the draft values are
  moved to `name`, and `settings`.
  - Renamed `updateNode` GraphQL API to `updateNodeDraft`, and modified
    parameter types. `old` to `NodeInput`, and `new` to `NodeDraftInput`.
  - `nodeStatusList` GraphQL API uses `hostname` from `Node`'s `settings` field.

### Removed

- Removed the obsoleted `ModelIndicatorOutput` GraphQL type. This type was
  previously used as return type of `indicatorList` GraphQL query. With
  advancements and improvements in our system, this type is no longer necessary
  and has been removed to streamline the codebase and enhance overall
  maintainability.

### Fixed

- Resolved an issue in the `processList` query function where applications were
  incorrectly identified by their agent ID instead of their application name.
  Previously, the function assumed the agent ID in the format
  "agent_id@hostname" directly corresponded to the application name, which was
  not always the case. This assumption did not support scenarios where multiple
  instances of the same application ran on the same host with unique agent IDs.
  The updated implementation now correctly identifies applications by their
  name, ensuring accurate application prioritization.

## [0.34.0] - 2024-02-27

### Added

- Added the following GraphQL API to access workflow tags:
  - 'workflowTagList'
  - 'insertWorkflowTag'
  - 'removeWorkflowTag'
  - 'updateWorkflowTag'

### Changed

- Users currently using review versions earlier than 0.33.0 should
  take note that current version does not support direct migration from these
  earlier versions.
  - To ensure data integrity and avoid potential data loss, users are advised to
    follow a specific update sequence:
    1. Update to review version 0.33.0 first.
    2. Subsequently, update to the latest version of review.

### Fixed

- We've resolved an issue in the GraphQL API where the ordering of edges was
  inconsistent when using `last`/`before` pagination arguments. According to the
  GraphQL Cursor Connections Specification, the order of edges should remain the
  same whether using `first`/`after` or `last`/`before`, provided all other
  arguments are equal. Previously, our API returned edges in reverse order when
  `last`/`before` was used, which was contrary to the specification.
- Resolved a critical bug in the GraphQL API endpoint `updateCluster` where the
  user-specified `status_id` was being overwritten when `qualifier_id` change is
  requested at the same time.
  - The issue has been addressed to ensure that the user-provided `status_id` is
    now properly respected and retained.
  - User expecting `status_id` change when `qualifier_id` is changed will need to
    specify desired `qualifier_id` while updating cluster.

## [0.33.0] - 2024-01-19

### Changed

- Users currently using review versions earlier than 0.32.0 should
  take note that current version does not support direct migration from these
  earlier versions.
  - To ensure data integrity and avoid potential data loss, users are advised to
    follow a specific update sequence:
    1. Update to review version 0.32.0 first.
    2. Subsequently, update to the latest version of review.
- Protocol version has been bumped to 0.27.0:
  - The `RequestCode::InsertTimeSeries` functionality has been enhanced to
  improve data representation.
    - This version now requires an updated version of `TimeSeriesUpdate`.
    - To facilitate better data management, the updated
      `RequestCode::InsertTimeSeries` now requires the inclusion of a `batch_ts`
      timestamp. This timestamp indicates the batch ID of the data, providing
      better context for the statistics represented.

## [0.32.0] - 2024-01-16

### Changed

- Change to use review-database 0.22.1, review-web 0.16.0.
- Protocol version has been bumped to 0.26.0:
  - Require `timestamp` to mark the statistics sent through
    `RequestCode::InsertColumnStatistics`. The `timestamp` should be the same as
    the one used to identify the `batch_info` of the data that the statistics
    represents.

## [0.31.0] - 2023-10-19

### Added

- Added `processList` graphql query to get the process list of a host.
- Add new block list events.
  - DCERPC: `BlockListDceRpc`
  - FTP: `BlockListFtp`
  - HTTP: `BlockListHttp`
  - KERBEROS: `BlockListKerberos`
  - LDAP: `BlockListLdap`
  - MQTT: `BlockListMqtt`
  - NFS: `BlockListNfs`
  - NTLM: `BlockListNtlm`
  - RDP: `BlockListRdp`
  - SMB: `BlockListSmb`
  - SMTP: `BlockListSmtp`
  - SSH: `BlockListSsh`
  - TLS: `BlockListTls`

### Changed

- Serialized Model objects, when transmitted or received via specific request
  codes, now require a 16-byte `MagicHeader`. This `MagicHeader` contains
  version and kind information, along with a fixed tag and format version.
  This modification is vital for verification purposes and ensures compatibility
  between different components of our system. The following requests and
  operations are affected by this change:
  - `RequestCode::InsertModel`: serialized `Model` data sent to `Review` through
  this request code should follow the new format.
  - `RequestCode::UpdateModel`: serialized `Model` data sent to `Review` through
  this request code should follow the new format.
  - `RequestCode::GetModel`: serialized `Model` data returned by `Review` after
  this request code, would follow the new format.
- Change to use review-database 0.20.0, review-web 0.14.4

### Fixed

- Fix outlier query to read outlier events from Rocks db.
- Fix to provide multiple Country codes and Customers for events with multiple addresses.
  - RdpBruteForce, MultiHostPortScan, ExternalDdos

## [0.30.0] - 2023-09-04

### Added

- New detected events have been added:
  - CONN: `BlockListConn`
  - DNS: `BlockListDns`

### Changed

- Fix to return `Ok(())` after outlier processing is done.
- Upon receiving a request with the `RequestCode::GetDataSOurce`, the agent
  method previously returned `Result<Option<DataSource>>` when the input was
  `name`, and it returned `Result<DataSource>` if the input was `id`. For the
  sake of consistency, it now returns `Result<Option<DataSource>>` for all
  cases.
- Modified `FtpBruteForce`, `LdapBruteForce`, `RdpBruteForce` events to align
  with the event fields provided by Hog.
  - `RdpBruteForce`:
    - change `dst_addr` to `dst_addrs` to inlclude all victim ip addresses.
    - `source` is removed because attacker can attacks multiple targets
      in different location.
    - `start_time`, `last_time` is added to accounts for how long an attack lasts.
  - `FtpBruteForce`, `LdapBruteForce`:
    - `source` is removed because attacker can attacks multiple targets
      in different location.
- Changed to GraphQL query `outliers` to read outlier events from RocksDB.

## [0.29.0] - 2023-07-06

### Added

- New detected events have been added:
  - FTP: `FtpBruteForce`, `FtpPlainText`
  - HTTP: `NonBrowser`
  - LDAP: `LdapBruteForce`, `LdapPlainText`
  - DNS: `CryptocurrencyMiningPool`
  - Session: `PortScan`, `MultiHostPortScan`, `ExternalDdos`

### Changed

- Modified the add and update model functions to require the `classification_id`
  parameter. `classification_id` marks the last time that the model is used for
  clustering. And it can be used to retrieve outliers stored for the corresponding
  clustering process.

## [0.28.0] - 2023-06-20

### Added

- Introduced `RequestCode::GetTrustedUserAgentList` to the QUIC API, a new
  request code designed to distribute the trusted user agent list.
- Added `broadcast_trusted_user_agent_list`, a new function that allows the
  broadcasting of the trusted user agent list to all currently connected
  Hogs.
- Included five new GraphQL API methods:
  - `trusted_user_agent_list`: This new method enables users to retrieve the
    trusted user agent list.
  - `insert_trusted_user_agents`: This newly added feature facilitates users to
    insert trusted user agents into the list.
  - `remove_trusted_user_agents`: Users are now provided with a method to
    delete trusted user agents from the list.
  - `update_trusted_user_agent`: This feature has been incorporated to allow
    users to update the details of a trusted user agent.
  - `apply_trusted_user_agent`: This novel method permits a list of trusted
    user agents to be applied to all `hog` associated with `REview`.

### Changed

- The `srcPort` and `dstPort` types in both `TorConnection` and
  `RepeatedHttpSessions` have undergone modification. Originally, these types
  were `!String`, but have now been transformed to `!Int`. This alteration aims
  to enhance data consistency and curtail errors related to data type
  mismatches.

## [0.27.2] - 2023-06-16

### Changed

- Enhanced the efficiency of the backup process. Backup and purge operations,
  previously performed during each migration to every version, are now only
  performed at the beginning and end of a multi-version migration. This
  modification significantly speeds up the backup process.
- During the backup process, outliers older than two weeks and not explicitly
  saved by the user are now deleted. This change reduces the space required for
  backups and further improves the speed of subsequent backups.
- Implemented a cleanup mechanism to remove stale outliers that are older than
  2 weeks and older than the current update timestamp, provided they have not
  been saved by the user upon receiving an update outlier request.

### Fixed

- Resolved an issue with the restore-from-backup operation which previously
  could lead to a corrupt database if interfered by other database operations.
  The fix involves holding an exclusive lock during the restore process,
  effectively excluding any interference and ensuring a successful restore.
- Reverted the accidental change made to the serialization of allow/block
  network in 0.27.1.

## [0.27.1] - 2023-06-10

### Changed

- The migration from the database version 0.6 to 0.7 has been improved for
  increased performance and memory usage. Previously, this method would first
  scan all outliers in the database, deserializing them into memory, and then
  traverse them again in reverse order to update each entry according to the
  new format of version 0.7. This two-pass approach could be memory intensive
  for large databases.

  The updated method now directly traverses outliers in the database in reverse
  order and updates each entry in a single pass. This reduces the memory
  footprint and increases efficiency by removing the initial full scan of
  outliers. This change is expected to significantly improve the speed and
  memory consumption of migrations from version 0.6 to 0.7, especially for
  larger databases.

## [0.27.0] - 2023-06-08

### Added

- Added new fields to the `Event` enum internal struct provided via GraphQL for
  enhanced `detect event filtering`. This will allow more detailed filtering
  capabilities in the GraphQL API.
- Introduced a `ping` field to `NodeStatus` struct, accessible via the
  `NodeStatusList` query. As part of this change, we updated the `status::load`
  function to include the `ping` field in the response of the `NodeStatusList`
  query. This enhancement allows users to retrieve the `ping` status of nodes
  using the GraphQL API.

### Changed

- Make the `review_web` crate optional and enabled by default, allowing users to
  disable it using the `--no-default-features` flag. Since both the `review` and
  `review_web` crates depend on the `review_database` crate, it is necessary to
  use the same version of the `review_database` crate for both. Disabling
  `review_web` removes the need to consider the `review_database` version when
  working on `review` or `review_database`.
- Updated the broadcasting data type for `get_internal_network_list`,
  `get_allow_list`, and `get_block_list` commands. Previously, these commands
  returned a `HostNetworkGroup` on success and an `anyhow::Result` on error. The
  update changes the return type to `Result<HostNetworkGroup, String>` for both
  successful operations and errors. This modification brings consistency with
  REview's other QUIC APIs and simplifies the handling of the return types,
  ensuring a uniform interface across all operations.
- Altered the model file naming convention: Files are now required to use the
  .tmm extension. The format has changed from `{model_name}-{timestamp}` to
  `{model_name}-{timestamp}.tmm`. This adjustment ensures consistency in model
  file formats and enhances our file identification and management system.
- Updated the logging mechanism to include a message `Migrating database to
  {version}` when a database migration starts. This change enhances the
  visibility and traceability of our database migrations, aiding in system
  maintenance and debugging efforts. from `HostNetworkGroup` to
  `Result<HostNetworkGroup, String>`

### Removed

- `RequestCode::UpdateAgentStatus`: This method has been removed from the QUIC
  API. The `RequestCode::UpdateAgentStatus` function has been deprecated since
  REview version 0.22.0 and as of version 0.27.0, it is officially removed.

## [0.26.0] - 2023-05-31

### Added

- A new request code has been added to the QUIC API to distribute pretrained
  model:
  - `RequestCode::GetPretrainedModel`: Retrieves the most recent pretrained model
    with `model_name` included in the request. The model should be stored under
    `{REVIEW_DATA_DIR}/pretrained/`. The file name for `model_name` should follow
    `{model_name}-{timestamp}` where `timestamp` is a UNIX timestamp (seconds
    since the epoch).

### Changed

- A single server certificate is mandatory. This simplifies the management of
  the server certificate and minimizes the possibility of issues. REview
  validates the number of server certificates at startup and displays an error
  if the certificate file is empty or has more than one. Note that if the
  certificate file is missing, REview generates a new certificate and uses it.

## [0.25.1] - 2023-05-25

### Added

- The `DomainGenerationAlgorithm` event in our `GraphQL` API query now includes
  a confidence field. This field will allow users to access and gauge the
  predictive certainty of the output.
- Two new GraphQL API methods have been added:
  - `applyAllowNetworks`: Applies the list of IP addresses that are always
    accepted as benign.
  - `applyBlockNetworks`: Applies the list of IP addresses that are always
- Three new request codes have been added to the QUIC API to facilitate the
  retrieval of various network lists:
  - `RequestCode::GetInternalNetworkList`: Returns the list of internal
    networks.
  - `RequestCode::GetAllowList`: Retrieves the list of IP addresses that are
    always accepted as benign.
  - `RequestCode::GetBlockList`: Fetches the list of IP addresses that are
    always considered suspicious.

### Changed

- The QUIC API now restricts the number of client certificates to a single one
  per connection. This change has been implemented to streamline the
  authentication process and maintain the consistency of connections.
  Previously, a client could connect to REview using multiple certificates,
  potentially causing unexpected behavior or complications. Now, if a client
  attempts to connect to REview with more than one certificate, an error will
  be returned, prompting the client to reconnect using a single certificate.
- The behavior when a new node is added or the customer of a node is changed,
  has been updated to broadcast the customer networks of the node.
- If the customer networks of a node are updated, the changes are now
  broadcast. This provides an additional layer of communication to keep the
  system up-to-date with changes.

## [0.25.0] - 2023-05-22

### Changed

- Removed `policy` field from `DataSource`. This change has been made to
  streamline the information flow and reduce redundancy in the data structure.
  If you were previously relying on this field, use `source` field instead.
- Enhanced the QUIC API's DGA event by adding a `confidence` field. This update
  is meant to provide users with a quantitative assessment of the reliability
  of DGA (Domain Generation Algorithm) detections.
- Modified the `time` field in `HttpThreatFields` via the QUIC API. Previously,
  this data was transmitted as `DateTime<Utc>`, but it has been updated to be
  transmitted as nanoseconds in `i64`.

### Fixed

- Resolved a bug in our syslog logging for DGA events. Prior to this fix, an
  "invalid event" was incorrectly being logged to syslog for DGA events.

## [0.24.1] - 2023-05-18

### Changed

- To request an agent to clear its filtering rules, REview will send an empty
  rule set to the agent.

## [0.24.0] - 2023-05-18

### Added

- Updates in GraphQL API:
  - The GraphQL API has been updated to reflect the new fields added to the
    `HttpThreat` event. These fields will now be exposed to clients utilizing
    the API, providing a more comprehensive view of HTTP threats.

### Changed

- Enhanced `HttpThreat` event structure:
  - The `HttpThreat` event now includes a wider range of fields associated with
    an HTTP request. Clients reporting such events are encouraged to include
    all the relevant information. These fields include `time`, `source`,
    `src_addr`, `src_port`, `dst_addr`, `dst_port`, `proto`, `duration`,
    `method`, `host`, `uri`, `referer`, `version`, `user_agent`, `request_len`,
    `response_len`, `status_code`, `status_msg`, `username`, `password`,
    `cookie`, `content_encoding`, `content_type`, `cache_control`, `db_name`,
    `rule_id`, `cluster_id`, `attack_kind`, and `confidence`.
  - Introduced `matched_to` field in the `HttpThreat` event. This field should
    contain the rules that match the HTTP request.

## [0.23.0] - 2023-05-16

### Changed

- Expanded `DnsCovertChannel` and `TorConnection` events with additional
  fields. The new structure of these events is as follows:
  - `DnsCovertChannel`
    - `source`: (`String`) Source of the event
    - `session_end_time`: (`DateTime<Utc>`) End time of the session, serialized
      with nanosecond precision
    - `src_addr`: (`IpAddr`) Source IP address
    - `src_port`: (`u16`) Source port
    - `dst_addr`: (`IpAddr`) Destination IP address
    - `dst_port`: (`u16`) Destination port
    - `proto`: (`u8`) Protocol number
    - `query`: (`String`) DNS query
    - `answer`: (`Vec<String>`) DNS answer
    - `trans_id`: (`u16`) Transaction ID
    - `rtt`: (`i64`) Round-trip time
    - `qclass`: (`u16`) Query class
    - `qtype`: (`u16`) Query type
    - `rcode`: (`u16`) Response code
    - `aa_flag`: (`bool`) Authoritative Answer flag
    - `tc_flag`: (`bool`) Truncation flag
    - `rd_flag`: (`bool`) Recursion Desired flag
    - `ra_flag`: (`bool`) Recursion Available flag
    - `ttl`: (`Vec<i32>`) Time to live
    - `confidence`: (`f32`) Confidence score of the event
  - `TorConnection`
    - `session_end_time`: (`DateTime<Utc>`) End time of the session, serialized
      with nanosecond precision
    - `source`: (`String`) Source of the event
    - `src_addr`: (`IpAddr`) Source IP address
    - `src_port`: (`u16`) Source port
    - `dst_addr`: (`IpAddr`) Destination IP address
    - `dst_port`: (`u16`) Destination port
    - `proto`: (`u8`) Protocol number
    - `method`: (`String`) HTTP method
    - `host`: (`String`) Host header
    - `uri`: (`String`) URI
    - `referrer`: (`String`) Referrer
    - `version`: (`String`) HTTP version
    - `user_agent`: (`String`) User-Agent header
    - `request_len`: (`usize`) Length of the request
    - `response_len`: (`usize`) Length of the response
    - `status_code`: (`u16`) HTTP status code
    - `status_msg`: (`String`) HTTP status message
    - `username`: (`String`) HTTP authentication username
    - `password`: (`String`) HTTP authentication password
    - `cookie`: (`String`) HTTP Cookie header
    - `content_encoding`: (`String`) Content-Encoding header
    - `content_type`: (`String`) Content-Type header
    - `cache_control`: (`String`) Cache-Control header
  Please ensure the events sent to review follow the new format.
- The default password hashing algorithm has been updated from PBKDF2 to
  Argon2. The previous algorithm, PBKDF2, was identified as being weaker than
  the current Open Web Application Security Project (OWASP) recommendations,
  utilizing fewer iterations than what is considered up-to-date and secure.
  This prompted the move to the more secure Argon2 algorithm. This change
  enhances the security of user data within our system by reducing the
  possibility of successful brute-force attacks. No action is required from the
  users. The system will automatically apply the new hashing algorithm during
  the next password change or reset.

### Fixed

- Resolved an issue where the `event_source` column was incorrectly set to
  `null` upon updating the `max_event_id_num` value. This fix ensures that the
  `event_source` column retains its original value during such updates.

## [0.22.0] - 2023-05-11

### Changed

- Improved the usage of host_id and agent_id by extracting them from the x509
  certificate instead of relying on the values transmitted by the agent. The
  implementation now validates the Common Name (cn) of the certificate provided
  by the agent to ensure it conforms to the "{agent_id}@{host_id}" format, where
  agent_id and host_id do not include '@'.

### Deprecated

- The `RequestCode::UpdateAgentStatus` has been deprecated and will
  be removed in a future release.

## [0.21.2] - 2023-05-08

### Added

- Added a GraphQL query, `rankedOutliers`, to retrieve outliers.

### Fixed

- Resolved an issue with the GraphQL query clusters that was introduced in version
  0.21.0. due to a database schema change. The clusters query is now functional again,
  allowing users to retrieve cluster data as expected.

## [0.21.1] - 2023-05-03

### Fixed

- Resolved a database migration error that occurred under specific conditions
  in version 0.18.0. This error prevented successful data migration for a subset
  of users.
  - If you experienced a database migration error with version 0.18.0, it is
    highly recommended that you update to version 0.21.1. This version includes
    the necessary fix for the migration error.
  - If you didn't encounter any issues during the database migration process in
    version 0.18.0, there is no immediate need to upgrade to version 0.21.1.
    However, we always recommend using the latest version of our software to
    ensure you benefit from all recent fixes and improvements.
  - If you are still using version 0.18.0 and have not yet begun your database
    migration, please refrain from doing so. Upgrade to version 0.21.1 first to
    avoid potential migration errors.

## [0.21.0] - 2023-05-02

### Changed

- GraphQL API `columnStatistics`: This query's parameters have been modified to
  support event source.
  - Replaced separate firstEventId: Int and lastEventId: Int parameters with a
    single eventRange: EventRangeInput parameter.
  - EventRangeInput is a new input type that includes the following required
    fields:
    - firstEventId: !Int (equivalent to the previous firstEventId parameter).
    - lastEventId: !Int (equivalent to the previous lastEventId parameter).
    - eventSource: !String (a new required field indicating the source of the
      events).
- A QUIC API for agents, `RemoveOutliers`, accepts `(i64, String)` as an
  outlier ID, rather than `i64`.

## [0.20.0] - 2023-04-27

### Changed

- `TrafficFilterRules` contains `port/protocol` to filter traffic in Piglet.

## [0.19.0] - 2023-04-24

### Added

- Add GraphQL API `preserveOutliers` to mark a list of provided outliers as
  `saved = true`.

### Changed

- Added `sensors`, `confidence`, and `learning_methods` to `EventFilter`.

### Fixed

- Fix total count in GraphQL API `savedOutliers` to only reflect outliers
  marked as `saved`.

## [0.18.0] - 2023-04-06

### Added

- Add GraphQL API `savedOutliers` to list outliers according to specification.

### Changed

- `UpdateOutliers` request and response are changed to reflect the distance
  between outlier and clusters.

## [0.17.0] - 2023-03-22

### Changed

- Change `sig` to `cluster_id` in event field received from REconverge.
- Load platforms root certificates rather than Mozilla's trusted root
  certificates for the connection between REview and Postgres.
- Provide detailed `DataSource` information for user, i.e. `server_name`,
  `address`, `policy`, etc.

### Removed

- `brokers` is removed from `DataSource` since `kafka` has been deprecated.

[Unreleased]: https://github.com/petabi/review/compare/0.44.0...main
[0.44.0]: https://github.com/petabi/review/compare/0.43.0...0.44.0
[0.43.0]: https://github.com/petabi/review/compare/0.42.0...0.43.0
[0.42.0]: https://github.com/petabi/review/compare/0.41.0...0.42.0
[0.41.0]: https://github.com/petabi/review/compare/0.40.1...0.41.0
[0.40.1]: https://github.com/petabi/review/compare/0.40.0...0.40.1
[0.40.0]: https://github.com/petabi/review/compare/0.39.0...0.40.0
[0.39.0]: https://github.com/petabi/review/compare/0.38.0...0.39.0
[0.38.0]: https://github.com/petabi/review/compare/0.37.0...0.38.0
[0.37.0]: https://github.com/petabi/review/compare/0.36.0...0.37.0
[0.36.0]: https://github.com/petabi/review/compare/0.35.0...0.36.0
[0.35.0]: https://github.com/petabi/review/compare/0.34.0...0.35.0
[0.34.0]: https://github.com/petabi/review/compare/0.33.0...0.34.0
[0.33.0]: https://github.com/petabi/review/compare/0.32.0...0.33.0
[0.32.0]: https://github.com/petabi/review/compare/0.31.0...0.32.0
[0.31.0]: https://github.com/petabi/review/compare/0.30.0...0.31.0
[0.30.0]: https://github.com/petabi/review/compare/0.29.0...0.30.0
[0.29.0]: https://github.com/petabi/review/compare/0.28.0...0.29.0
[0.28.0]: https://github.com/petabi/review/compare/0.27.2...0.28.0
[0.27.2]: https://github.com/petabi/review/compare/0.27.1...0.27.2
[0.27.1]: https://github.com/petabi/review/compare/0.27.0...0.27.1
[0.27.0]: https://github.com/petabi/review/compare/0.26.0...0.27.0
[0.26.0]: https://github.com/petabi/review/compare/0.25.1...0.26.0
[0.25.1]: https://github.com/petabi/review/compare/0.25.0...0.25.1
[0.25.0]: https://github.com/petabi/review/compare/0.24.1...0.25.0
[0.24.1]: https://github.com/petabi/review/compare/0.23.0...0.24.1
[0.24.0]: https://github.com/petabi/review/compare/0.23.0...0.24.0
[0.23.0]: https://github.com/petabi/review/compare/0.22.0...0.23.0
[0.22.0]: https://github.com/petabi/review/compare/0.21.2...0.22.0
[0.21.2]: https://github.com/petabi/review/compare/0.21.1...0.21.2
[0.21.1]: https://github.com/petabi/review/compare/0.21.0...0.21.1
[0.21.0]: https://github.com/petabi/review/compare/0.20.0...0.21.0
[0.20.0]: https://github.com/petabi/review/compare/0.19.0...0.20.0
[0.19.0]: https://github.com/petabi/review/compare/0.18.0...0.19.0
[0.18.0]: https://github.com/petabi/review/compare/0.17.0...0.18.0
[0.17.0]: https://github.com/petabi/review/compare/0.16.0...0.17.0
