# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/sieteunoseis/netbox-catalyst-center/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/sieteunoseis/netbox-catalyst-center/releases/tag/v1.0.0
