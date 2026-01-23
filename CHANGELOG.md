# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.2] - 2025-01-23

### Changed

- Optimized database queries with `select_related()` and `prefetch_related()` for better performance

## [Unreleased]

### Added

- **Interface Sync from Catalyst Center** (GitHub Issue #1)
  - Sync network interfaces from Catalyst Center to NetBox
  - Creates new interfaces if they don't exist, updates existing ones
  - Syncs interface attributes: description, MAC address, MTU, speed, duplex, enabled status, **mode (access/tagged)**
  - Creates IP addresses for interfaces with IPs configured
  - Maps Catalyst Center interface types to NetBox types (1000base-t, 10gbase-x-sfpp, lag, virtual)
  - Sets LAG membership for interfaces that belong to port-channels
  - **Import page now includes "Sync Interfaces" option** to import all interfaces during device import
  - **Journal logging**: Creates device journal entry with CC interface data (JSON) after sync
- **POE Data Capture**
  - Interface API now captures POE fields from Catalyst Center (poe_enabled, poe_status, power values)
- **POE Sync Feature** (GitHub Issue #1)
  - New "Sync POE Data" option on device Catalyst Center tab
  - Fetches POE details from separate CC API endpoint (`/network-device/{id}/interface/poe-detail`)
  - Updates NetBox interface `poe_mode` (PSE for switch ports) and `poe_type` (802.3af/at/bt)
  - Maps IEEE class to NetBox POE types: class0-3→802.3af, class4→802.3at, class5-8→802.3bt
  - **Fallback to max_port_power**: For ports without connected devices, derives poe_type from port's maximum power capability
  - Creates journal entry with POE data after sync
  - **POE sync during import**: Automatically syncs POE data after interfaces are created during device import
  - **Import results show POE count**: Displays blue POE badge alongside interface count
- **Stack/Virtual Chassis Detection**
  - Detects stacked switches via `lineCardCount` or comma-separated serial/platform values
  - Shows "Stack (N)" badge on Catalyst Center tab for stacked devices
  - Displays per-member serial numbers and platforms for stacks
  - Deduplicates platform IDs (e.g., "C9300-48P, C9300-48P" → "C9300-48P")

### Changed

- Import now populates Platform (software type/version hierarchy)
- Import now populates custom fields (cc_device_id, cc_series, cc_role, cc_last_sync)
- Import now uses "other" interface type instead of "virtual" for Management interface
- Search results now include software_type field
- Sync UI now shows current NetBox value vs new CC value with visual comparison
- Sync UI highlights already-synced fields with green background and checkmark
- Sync checkboxes auto-unchecked when values already match

### Fixed

- Interface type mapping now correctly identifies subinterfaces (e.g., TenGigabitEthernet1/1/8.2012) as "virtual"
- Fixed bug where GigabitEthernet interfaces were incorrectly classified as 10GE due to "te" substring match
- Interface type detection now uses proper prefix matching instead of substring matching
- **Fixed interface type mapping priority**: Name-based detection now runs BEFORE speed-based detection
  - Prevents FortyGigabitEthernet/TenGigabitEthernet ports from being classified as 10base-t when CC reports low negotiated speed (e.g., disconnected ports)
  - Interface names are now definitive: FortyGigabitEthernet → 40gbase-x-qsfpp, TenGigabitEthernet → 10gbase-x-sfpp, etc.

## [1.2.0] - 2025-01-22

### Added

- **Extended Sync Functionality**
  - Sync Device Type from Catalyst Center platform ID (e.g., C9300-48P)
  - Sync Platform with hierarchy: software type (IOS-XE) as parent, version (17.9.4a) as child
  - Sync custom fields for Catalyst Center data:
    - `cc_device_id` - Catalyst Center UUID for linking to CC UI
    - `cc_series` - Device series (e.g., "Cisco Catalyst 9300 Series")
    - `cc_role` - Network role (ACCESS, DISTRIBUTION, CORE, BORDER ROUTER)
    - `cc_last_sync` - Timestamp of last sync from Catalyst Center
  - "Select All" button for sync options

- **Auto-Create Custom Fields**
  - Custom fields are automatically created when the plugin loads
  - Fields grouped under "Catalyst Center" in the device edit form
  - `ui_visible: if-set` - fields only show when populated

### Changed

- Improved sync UI with three columns: Basic Fields, Device Type & Platform, Custom Fields
- Device Type sync creates `Cisco/{platform_id}` for specific hardware tracking

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

[Unreleased]: https://github.com/sieteunoseis/netbox-catalyst-center/compare/v1.2.2...HEAD
[1.2.2]: https://github.com/sieteunoseis/netbox-catalyst-center/compare/v1.2.1...v1.2.2
[1.2.0]: https://github.com/sieteunoseis/netbox-catalyst-center/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/sieteunoseis/netbox-catalyst-center/compare/v1.0.1...v1.1.0
[1.0.1]: https://github.com/sieteunoseis/netbox-catalyst-center/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/sieteunoseis/netbox-catalyst-center/releases/tag/v1.0.0
