# NetBox Catalyst Center Plugin - Feature Roadmap

## Current Features (v1.0.0)
- [x] Network device lookup by hostname (case-insensitive)
- [x] Wireless client lookup by MAC address
- [x] Configurable device_mappings for tab visibility
- [x] Reachability status and collection status display
- [x] Software version, platform, serial number
- [x] Uptime, SNMP location/contact
- [x] Client health score and connection status
- [x] Signal quality (RSSI, SNR) for wireless clients
- [x] Top-level navigation menu
- [x] Settings page with test connection
- [x] Direct link to device in Catalyst Center (using deviceId)
- [x] **Sync from DNAC** - Selectable fields to sync to NetBox:
  - [x] Primary IP address (creates/assigns IP, sets as primary)
  - [x] Serial number
  - [x] SNMP Location (appended to device comments)
- [x] Multi-strategy device lookup: IP address → hostname → fetch all with local filtering
- [x] Case-insensitive hostname matching (DNAC API regex is case-sensitive)

---

## Planned Features

### High Priority

#### 1. Security Advisories
**API:** `GET /dna/intent/api/v1/security-advisory/device/{deviceId}`
- Show PSIRT vulnerabilities affecting the device
- Display advisory severity (Critical, High, Medium, Low)
- Link to Cisco security advisory details
- **Use case:** Compliance tracking, vulnerability management

#### 2. Compliance Status
**API:** `GET /dna/intent/api/v1/compliance/detail`
- Device compliance status (COMPLIANT, NON_COMPLIANT, IN_PROGRESS)
- Compliance types: RUNNING_CONFIG, PSIRT, IMAGE, EOX
- Show non-compliant items and remediation status
- **Use case:** Configuration drift detection, audit readiness

#### 3. Device Interfaces
**API:** `GET /dna/intent/api/v1/interface/network-device/{deviceId}`
- Live interface status from DNAC
- Interface speed, duplex, admin/oper status
- VLAN assignments, error counts
- Compare with NetBox interface data
- **Use case:** Troubleshooting, inventory validation

#### 4. Active Issues
**API:** `POST /dna/data/api/v1/assuranceIssues/query`
- Issues detected by DNAC assurance
- Severity and suggested remediation
- Issue categories (connectivity, performance, etc.)
- **Use case:** Proactive monitoring, alert correlation

---

### Medium Priority

#### 5. Device Modules/Inventory
**API:** `GET /dna/intent/api/v1/network-device/module`
- Hardware modules installed in device
- Part numbers, serial numbers
- Operational state (ok, unknown, etc.)
- **Use case:** Hardware inventory, spare planning

#### 6. Network Health Summary
**API:** `GET /dna/intent/api/v1/network-health`
- Overall health by device category (Access, Distribution, Core, Router, Wireless)
- Dashboard panel or summary widget
- **Use case:** NOC overview, health trending

#### 7. Site Health
**API:** `GET /dna/intent/api/v1/site-health`
- Health per site/building
- Wired/wireless client breakdown
- Application health metrics
- **Use case:** Site-level monitoring

#### 8. Physical Topology
**API:** `GET /dna/intent/api/v1/topology/physical-topology`
- Neighbor/connection information
- Link between devices
- Could visualize or compare with NetBox cables
- **Use case:** Topology validation

---

### Lower Priority / Future

#### 9. Client Health Aggregate
**API:** `GET /dna/intent/api/v1/client-health`
- Aggregate wireless/wired client health
- Breakdown by health category
- **Use case:** Wireless infrastructure monitoring

#### 10. Command Runner Integration
**API:** `POST /dna/intent/api/v1/network-device-poller/cli/read-request`
- Run show commands from NetBox
- Display output in tab
- **Use case:** Quick troubleshooting

#### 11. Path Trace
**API:** Various path trace endpoints
- Network route analysis between endpoints
- **Use case:** Connectivity troubleshooting

#### 12. Software Image Management (SWIM)
**API:** Various SWIM endpoints
- Current vs recommended image
- Upgrade compliance status
- **Use case:** Image standardization

---

## Implementation Notes

### API Reference
- Full spec: `/home/netcomm/biccapps-docker-compose/netbox/intent_api_2_3_7_9.json`
- Docs: https://developer.cisco.com/docs/dna-center/

### Authentication
- Already implemented: `/dna/system/api/v1/auth/token`
- Token caching: 50 minutes (expires at 60)

### Device ID Lookup
For endpoints requiring `deviceId`, we need to:
1. First call `/dna/intent/api/v1/network-device?hostname=X`
2. Extract the `id` field from response
3. Use that ID for subsequent calls

Consider caching device ID mappings.

### Template Structure
- `network_device_tab.html` - Main device info (current)
- Could add expandable sections or sub-tabs for:
  - Interfaces
  - Security Advisories
  - Compliance
  - Issues

### Configuration Options to Add
```python
"device_mappings": [...],
"show_security_advisories": True,
"show_compliance": True,
"show_interfaces": False,  # Can be slow for large devices
"show_issues": True,
```

---

## Known Issues / Bugs

- [x] ~~**CRITICAL: Hostname lookup not finding devices**~~ **FIXED**
  - DNAC API regex is case-sensitive - character classes don't work as expected
  - **Solution implemented:** Multi-strategy lookup:
    1. Try management IP lookup first (most reliable)
    2. Fetch all devices and filter locally with case-insensitive matching
  - Device list cached for 5 minutes to avoid repeated full fetches

- [x] ~~Need to handle devices not in DNAC inventory gracefully~~ **FIXED**
  - Shows informative error message when device not found
  - Tab still visible to show connection status

- [ ] Cache invalidation strategy for real-time data
- [ ] Rate limiting considerations for large NetBox instances

---

## References

- [Cisco Catalyst Center API Overview](https://developer.cisco.com/docs/dna-center/)
- [Health Monitoring API](https://developer.cisco.com/docs/dna-center/health-monitoring/)
- [NetBox Plugin Development](https://docs.netbox.dev/en/stable/plugins/development/)
