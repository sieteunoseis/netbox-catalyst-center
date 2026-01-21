# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.0] - 2025-01-21

### Added

- **Device Import Feature**
  - Search Catalyst Center inventory by hostname, IP address, or MAC address
  - Wildcard support for searches (e.g., `switch*`, `192.168.*`)
  - Import devices from Catalyst Center into NetBox (one-way import)
  - Auto-detect device role from Catalyst Center device family
  - Duplicate detection shows devices already in NetBox
  - Maximum 25 devices per import batch

- **Import Page UI**
  - Dedicated import page under Catalyst Center menu
  - Search results with platform, serial number, and role information
  - Select/deselect devices for import
  - Choose default site and optionally override device role

### Changed

- Improved device role mapping using Catalyst Center device family (Wireless Controller, Switches and Hubs, Routers, etc.)
- Platform deduplication for devices with repeated platform IDs
- Updated navigation menu with Import Devices link

### Fixed

- Fixed incorrect device matching when hostname contains similar prefix to another device
- Fixed search returning no results for exact hostname/IP matches (DNAC API pagination)

## [1.0.1] - 2025-01-21

### Fixed
- Fixed version alignment between pyproject.toml and git tags
- Updated changelog with proper version history

## [1.0.0] - 2025-01-21

### Added

- **Network Device Integration**
  - Device Details Tab on Device detail pages showing Catalyst Center data
  - Reachability status display (Reachable, Ping Reachable, Unreachable)
  - Software version, platform, and series information
  - Compliance status for PSIRT, IMAGE, CONFIG, and EOX checks
  - Security advisories (PSIRT) with links to Cisco security portal
  - Sync functionality to update NetBox with IP address, serial number, and SNMP location

- **Wireless Client Support**
  - Real-time IP address lookup for wireless clients
  - Connection status with health score
  - Access point information including SSID and location
  - Signal quality metrics (RSSI, SNR, data rate)

- **Configuration**
  - Configurable device mappings to control which devices show the tab
  - Multi-strategy lookup: IP address, hostname, or fetch all with local filtering
  - API response caching to reduce load on Catalyst Center
  - SSL verification toggle for self-signed certificates

- **Settings Page**
  - View current configuration
  - Test connection button
  - Device mappings display

### Technical

- Built for NetBox 4.0+ (not compatible with NetBox 3.x)
- Python 3.10+ required
- Apache 2.0 license

[Unreleased]: https://github.com/sieteunoseis/netbox-catalyst-center/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/sieteunoseis/netbox-catalyst-center/compare/v1.0.1...v1.1.0
[1.0.1]: https://github.com/sieteunoseis/netbox-catalyst-center/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/sieteunoseis/netbox-catalyst-center/releases/tag/v1.0.0
