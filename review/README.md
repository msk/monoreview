# REview

## Environment variables

- `REVIEW_BACKUP_DIR` - REview's database backup storage directory. The default
  path is the `backup` directory under the current directory.
- `REVIEW_BACKUP_DURATION` - The backup period in days. The default value is `1`.
- `REVIEW_BACKUP_TIME` - The backup schedule time in `%H:%M:%S` format. The default
  is `23:59:59`.
- `REVIEW_CA_CERTS` - Paths to additional CA certificate files to trust.
- `REVIEW_CERT` - REview's certificate file path. The default path is `cert.pem`
  in the current directory.
- `REVIEW_CLIENT_CERT_PATH` - The path to the client certificate file. The default
  path is `client_cert.pem` in the current directory.
- `REVIEW_CLIENT_KEY_PATH` - The path to the client private key file. The default
  path is `client_key.pem` in the current directory.
- `REVIEW_DATA_DIR` - REview's local storage directory. The default path is the
  `data` directory under the current directory.
- `REVIEW_DATABASE_URL` - PostgreSQL URI (e.g. `postgres://user:secret@localhost/db`).
  The default is `postgres://review@localhost/review`.
- `REVIEW_GRAPHQL_SRV_ADDR` - IP address and optional port number of the GraphQL
  API server (e.g. `127.0.0.1` or `127.0.0.1:8080`). The default is
  `localhost:8000`.
- `REVIEW_HOSTNAME` - The hostname used for the certificate. The client using
  the certificate need to use the name for making connection. The default is `localhost`.
- `REVIEW_HTDOCS_DIR` - The path to the Web app. The default path is the
  `htdocs` directory under the current directory.
- `REVIEW_IP2LOCATION` - The path to the IP2Location database (e.g.,
  `IP2LOCATION-DB6.BIN`).
- `REVIEW_JWT_EXPIRES_IN` - The expiration time in seconds before the JWT
  expires.
- `REVIEW_KEY` - REview's private key file path. The default path is `key.pem`
  in the current directory.
- `REVIEW_LOG_PATH` - REview's log file path, including the filename. REview should
  have write permission on this path. If not set, the log will be written to standard
  output.
- `REVIEW_NUM_OF_BACKUPS_TO_KEEP` - The number of backup files to retain. The default
  value is `5`.
- `REVIEW_PEN` - IANA assigned Private Enterprise Number (PEN) for the
  enterprise. The default is `0`.
- `REVIEW_RPC_SRV_ADDR` - IP address and optional port number of the RPC Server (e.g.
  `127.0.0.1` or `127.0.0.1:12345`). The default is `localhost:38390`.
- `REVIEW_SYSLOG_TX` - Turning on or off the Syslog transmission for detected
  events. The default is `false`.
- `REVIEW_TOR_EXIT_NODE_POLL_INTERVAL` - The polling interval of TorExitNodeList
  in minutes.

## Copyright

Copyright 2018-2025 Petabi, Inc.
