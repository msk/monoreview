# Changelog

This file documents recent notable changes to this project. The format of this
file is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and
this project adheres to [Semantic
Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.1] - 2025-06-05

### Added

- Implemented the `Copy` trait for `RawEventKind`.

## [0.2.0] - 2025-05-19

### Added

- Renamed `referrer` to `referer` for consistency with the HTTP header field
  name.

## [0.1.0] - 2024-12-20

### Added

- Added a new enum type `RawEventAttrKind`. This type is created using the raw event
  type and raw event's attribute name, which is later used by the triage to
  perform a comparison of values.

[0.2.1]: https://github.com/aicers/attrievent/tree/0.2.1
[0.2.0]: https://github.com/aicers/attrievent/tree/0.2.0
[0.1.0]: https://github.com/aicers/attrievent/tree/0.1.0
