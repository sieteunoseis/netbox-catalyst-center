"""
Cisco Catalyst Center API Client

Handles authentication and API calls to Catalyst Center (formerly DNA Center).
"""

import logging

import requests
from django.conf import settings
from django.core.cache import cache

logger = logging.getLogger(__name__)


class CatalystCenterClient:
    """Client for interacting with Cisco Catalyst Center API."""

    def __init__(self, url, username, password, timeout=30, verify_ssl=False):
        """Initialize the Catalyst Center client."""
        self.base_url = url.rstrip("/")
        self.username = username
        self.password = password
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self._token = None

    def _get_token(self):
        """Authenticate and get API token."""
        if self._token:
            return self._token

        # Check cache first
        cache_key = f"catalyst_center_token_{self.base_url}"
        cached_token = cache.get(cache_key)
        if cached_token:
            self._token = cached_token
            return self._token

        try:
            auth_url = f"{self.base_url}/dna/system/api/v1/auth/token"
            response = requests.post(
                auth_url,
                auth=(self.username, self.password),
                headers={"Content-Type": "application/json"},
                verify=self.verify_ssl,
                timeout=self.timeout,
            )
            response.raise_for_status()
            self._token = response.json().get("Token")

            # Cache token for 50 minutes (tokens expire in 60 min)
            cache.set(cache_key, self._token, 3000)
            return self._token
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to authenticate to Catalyst Center: {e}")
            return None

    def _make_request(self, endpoint, params=None):
        """Make authenticated API request."""
        token = self._get_token()
        if not token:
            return {"error": "Failed to authenticate to Catalyst Center"}

        try:
            url = f"{self.base_url}{endpoint}"
            headers = {
                "X-Auth-Token": token,
                "Content-Type": "application/json",
            }
            response = requests.get(
                url,
                headers=headers,
                params=params,
                verify=self.verify_ssl,
                timeout=self.timeout,
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 401:
                # Token expired, clear and retry once
                self._token = None
                cache.delete(f"catalyst_center_token_{self.base_url}")
                return self._make_request(endpoint, params)
            logger.error(f"HTTP error from Catalyst Center: {e}")
            return {"error": f"HTTP {e.response.status_code}: {str(e)}"}
        except requests.exceptions.RequestException as e:
            logger.error(f"Request error to Catalyst Center: {e}")
            return {"error": str(e)}

    def _dedupe_platform(self, platform_id):
        """
        Deduplicate platform ID for stacked switches.

        Stacked switches report the same platform for each member (e.g., "C9300-48P, C9300-48P").
        This returns unique values only (e.g., "C9300-48P").
        """
        if not platform_id or "," not in platform_id:
            return platform_id

        parts = [p.strip() for p in platform_id.split(",")]
        seen = set()
        unique = []
        for p in parts:
            if p and p not in seen:
                seen.add(p)
                unique.append(p)
        return ", ".join(unique) if len(unique) > 1 else (unique[0] if unique else "")

    def get_client_detail(self, mac_address):
        """
        Get client details by MAC address.

        Args:
            mac_address: MAC address in format XX:XX:XX:XX:XX:XX or xxxxxxxxxxxx

        Returns:
            dict with client details or error
        """
        # Normalize MAC address format (Catalyst Center wants XX:XX:XX:XX:XX:XX)
        mac = mac_address.replace(":", "").replace("-", "").lower()
        if len(mac) == 12:
            mac_formatted = ":".join(mac[i : i + 2] for i in range(0, 12, 2))
        else:
            mac_formatted = mac_address

        # Check cache
        config = settings.PLUGINS_CONFIG.get("netbox_catalyst_center", {})
        cache_timeout = config.get("cache_timeout", 60)
        cache_key = f"catalyst_client_{mac_formatted}"

        cached = cache.get(cache_key)
        if cached:
            cached["cached"] = True
            return cached

        # Query Catalyst Center
        endpoint = "/dna/intent/api/v1/client-detail"
        params = {"macAddress": mac_formatted}

        result = self._make_request(endpoint, params)

        if "error" in result:
            return result

        # Parse the response
        detail = result.get("detail", {})

        if not detail:
            return {
                "error": "Client not found in Catalyst Center",
                "mac_address": mac_formatted,
            }

        # Extract relevant fields
        client_info = {
            "mac_address": mac_formatted,
            "ip_address": detail.get("hostIpV4"),
            "ipv6_address": detail.get("hostIpV6", []),
            "hostname": detail.get("hostName"),
            "device_type": detail.get("hostType"),  # WIRED or WIRELESS
            "connected": detail.get("connectionStatus") == "CONNECTED",
            "connection_status": detail.get("connectionStatus"),
            "health_score": detail.get("healthScore", []),
            "overall_health": None,
            "ssid": detail.get("ssid"),
            "frequency": detail.get("frequency"),
            "channel": detail.get("channel"),
            "ap_group": detail.get("apGroup"),
            "location": detail.get("location"),
            "connected_device": detail.get("connectedDevice", []),
            "vlan": detail.get("vlanId"),
            "last_updated": detail.get("lastUpdated"),
            "data_rate": detail.get("dataRate"),
            "rssi": detail.get("rssi"),
            "snr": detail.get("snr"),
            "cached": False,
        }

        # Extract overall health score - handle multiple API response formats
        health_score_data = detail.get("healthScore", [])

        # Format 1: Array of {healthType, score} objects
        if isinstance(health_score_data, list):
            for score in health_score_data:
                if isinstance(score, dict) and score.get("healthType") == "OVERALL":
                    client_info["overall_health"] = score.get("score")
                    break
            # If no OVERALL found, try first score or onboardingHealth
            if client_info["overall_health"] is None and health_score_data:
                if isinstance(health_score_data[0], dict):
                    client_info["overall_health"] = health_score_data[0].get("score")
                elif isinstance(health_score_data[0], (int, float)):
                    client_info["overall_health"] = health_score_data[0]

        # Format 2: Direct number
        elif isinstance(health_score_data, (int, float)):
            client_info["overall_health"] = health_score_data

        # Also check for 'onboardingHealth' and 'connectedHealth' as fallbacks
        if client_info["overall_health"] is None:
            onboarding = detail.get("onboardingHealth")
            connected = detail.get("connectedHealth")
            if isinstance(onboarding, (int, float)):
                client_info["overall_health"] = onboarding
            elif isinstance(connected, (int, float)):
                client_info["overall_health"] = connected

        # Extract connected AP/switch info
        if client_info["connected_device"]:
            device = (
                client_info["connected_device"][0]
                if isinstance(client_info["connected_device"], list)
                else client_info["connected_device"]
            )
            client_info["connected_device_name"] = device.get("name")
            # Handle both API response formats: mgmtIp (wireless) and managementIpAddress (wired)
            client_info["connected_device_ip"] = device.get("mgmtIp") or device.get("managementIpAddress")
            client_info["connected_interface"] = device.get("interfaceName")

        # Cache the result
        cache.set(cache_key, client_info, cache_timeout)

        return client_info

    def get_network_device(self, hostname, management_ip=None):
        """
        Get network device details by management IP or hostname.

        For Cisco infrastructure devices (voice gateways, APs, switches, etc.)
        that are in DNAC inventory.

        Args:
            hostname: Device hostname (with or without domain)
            management_ip: Optional management IP address (preferred lookup method)

        Returns:
            dict with device details or error
        """
        # Check cache
        config = settings.PLUGINS_CONFIG.get("netbox_catalyst_center", {})
        cache_timeout = config.get("cache_timeout", 60)
        cache_key = f"catalyst_device_{hostname}"

        cached = cache.get(cache_key)
        if cached:
            cached["cached"] = True
            return cached

        endpoint = "/dna/intent/api/v1/network-device"
        result = None

        # Strategy 1: Try management IP lookup first (most reliable)
        if management_ip:
            params = {"managementIpAddress": management_ip}
            result = self._make_request(endpoint, params)
            if "error" not in result and result.get("response"):
                logger.debug(f"Found device by management IP: {management_ip}")
            else:
                result = None  # Fall through to hostname lookup

        # Strategy 2: Fetch all devices and filter locally (case-insensitive)
        # This is the most reliable method since DNAC regex is case-sensitive
        if not result or not result.get("response"):
            base_hostname = hostname.lower().replace(".ohsu.edu", "")

            # Check if we have a cached device list
            all_devices_cache_key = "catalyst_all_devices"
            all_devices = cache.get(all_devices_cache_key)

            if not all_devices:
                # Fetch all devices from DNAC with pagination (default limit is 500)
                logger.debug("Fetching all devices from DNAC for local filtering")
                all_devices = []
                offset = 0
                page_size = 500
                max_pages = 20  # Safety limit: 10,000 devices max

                for _ in range(max_pages):
                    params = {"offset": offset, "limit": page_size}
                    page_result = self._make_request(endpoint, params)
                    if "error" in page_result:
                        break
                    page_devices = page_result.get("response", [])
                    if not page_devices:
                        break
                    all_devices.extend(page_devices)
                    logger.debug(f"Fetched page at offset {offset}: {len(page_devices)} devices")
                    if len(page_devices) < page_size:
                        break  # Last page
                    offset += page_size

                if all_devices:
                    # Cache for 5 minutes to avoid repeated full fetches
                    cache.set(all_devices_cache_key, all_devices, 300)
                    logger.debug(f"Cached {len(all_devices)} total devices")

            if all_devices:
                # Filter locally with case-insensitive matching
                for device in all_devices:
                    dnac_hostname = device.get("hostname", "").lower()
                    dnac_base = dnac_hostname.replace(".ohsu.edu", "")
                    if dnac_base == base_hostname or base_hostname in dnac_base:
                        result = {"response": [device]}
                        logger.debug(f"Found device by local filter: {device.get('hostname')}")
                        break

        if not result or "error" in result:
            return result if result else {"error": "No result from DNAC API"}

        response = result.get("response", [])
        base_hostname = hostname.lower().replace(".ohsu.edu", "")

        # Find matching device (case-insensitive comparison on our side)
        device_data = None

        if response:
            # If we searched by IP and got exactly one result, trust it
            if management_ip and len(response) == 1:
                device_data = response[0]
                logger.debug(f"Using single IP match result: {device_data.get('hostname')}")
            else:
                # Look for exact hostname match (case-insensitive)
                for device in response:
                    dnac_hostname = device.get("hostname", "").lower()
                    dnac_base = dnac_hostname.replace(".ohsu.edu", "")
                    if dnac_base == base_hostname:
                        device_data = device
                        logger.debug(f"Exact hostname match: {device.get('hostname')}")
                        break

                # If no exact match, look for hostname that starts with our search term
                # This prevents "admagw01" from incorrectly matching "admcap1n01"
                if not device_data:
                    for device in response:
                        dnac_hostname = device.get("hostname", "").lower()
                        dnac_base = dnac_hostname.replace(".ohsu.edu", "")
                        # Match if DNAC hostname starts with our hostname or vice versa
                        if dnac_base.startswith(base_hostname) or base_hostname.startswith(dnac_base):
                            device_data = device
                            logger.debug(f"Prefix hostname match: {device.get('hostname')}")
                            break

        if not device_data:
            # Build helpful error message with search context
            search_details = []
            if management_ip:
                search_details.append(f"IP: {management_ip}")
            search_details.append(f"Hostname: {hostname}")

            # Find similar hostnames to help troubleshoot
            similar_devices = []
            if all_devices:
                search_prefix = base_hostname[:3].lower() if len(base_hostname) >= 3 else base_hostname.lower()
                for device in all_devices[:500]:  # Limit scan
                    dnac_hostname = device.get("hostname", "").lower()
                    if dnac_hostname.startswith(search_prefix):
                        similar_devices.append(dnac_hostname)
                    if len(similar_devices) >= 5:
                        break

            error_msg = f"Device not found in Catalyst Center inventory. Searched by: {', '.join(search_details)}"
            if similar_devices:
                error_msg += f". Similar devices found: {', '.join(similar_devices)}"
            else:
                error_msg += ". No similar devices found with that prefix."

            return {"error": error_msg}

        # Extract relevant fields for network devices
        # Detect stack by checking for comma-separated platform/serial or lineCardCount
        platform_raw = device_data.get("platformId") or ""
        serial_raw = device_data.get("serialNumber") or ""
        line_card_count = device_data.get("lineCardCount")

        # Determine if this is a stack/virtual chassis
        is_stack = False
        stack_count = 1
        if line_card_count:
            try:
                lc_count = int(line_card_count)
                if lc_count > 1:
                    is_stack = True
                    stack_count = lc_count
            except (ValueError, TypeError):
                pass

        # Also check for comma-separated values (fallback detection)
        if not is_stack and ("," in platform_raw or "," in serial_raw):
            is_stack = True
            # Count stack members from serial numbers (most reliable)
            if "," in serial_raw:
                stack_count = len([s.strip() for s in serial_raw.split(",") if s.strip()])
            elif "," in platform_raw:
                stack_count = len([p.strip() for p in platform_raw.split(",") if p.strip()])

        # Build platform and serial lists for display
        platform_list = [p.strip() for p in platform_raw.split(",") if p.strip()] if platform_raw else []
        serial_list = [s.strip() for s in serial_raw.split(",") if s.strip()] if serial_raw else []

        device_info = {
            "is_network_device": True,
            "hostname": device_data.get("hostname"),
            "management_ip": device_data.get("managementIpAddress"),
            "device_type": device_data.get("type"),
            "device_family": device_data.get("family"),
            "platform": self._dedupe_platform(platform_raw),
            "platform_list": platform_list,
            "software_version": device_data.get("softwareVersion"),
            "software_type": device_data.get("softwareType"),
            "serial_number": serial_raw,
            "serial_list": serial_list,
            "mac_address": device_data.get("macAddress"),
            "uptime": device_data.get("upTime"),
            "uptime_seconds": device_data.get("uptimeSeconds"),
            "reachability_status": device_data.get("reachabilityStatus"),
            "reachability_failure_reason": device_data.get("reachabilityFailureReason"),
            "collection_status": device_data.get("collectionStatus"),
            "snmp_contact": device_data.get("snmpContact"),
            "snmp_location": device_data.get("snmpLocation"),
            "vendor": device_data.get("vendor"),
            "series": device_data.get("series"),
            "role": device_data.get("role"),
            "boot_time": device_data.get("bootDateTime"),
            "last_updated": device_data.get("lastUpdated"),
            "device_id": device_data.get("id"),
            # Stack/Virtual Chassis info
            "is_stack": is_stack,
            "stack_count": stack_count,
            "line_card_count": line_card_count,
            "line_card_id": device_data.get("lineCardId"),
            "cached": False,
        }

        # Determine connection status based on reachability
        reachability = device_data.get("reachabilityStatus", "").upper()
        device_info["connected"] = reachability in ("REACHABLE", "PING_REACHABLE")
        device_info["connection_status"] = reachability

        # Cache the result
        cache.set(cache_key, device_info, cache_timeout)

        return device_info

    def get_device_compliance(self, device_id):
        """
        Get compliance status for a device.

        Args:
            device_id: The Catalyst Center device UUID

        Returns:
            dict with compliance details
        """
        if not device_id:
            return {"error": "No device ID provided"}

        # Check cache
        config = settings.PLUGINS_CONFIG.get("netbox_catalyst_center", {})
        cache_timeout = config.get("cache_timeout", 60)
        cache_key = f"catalyst_compliance_{device_id}"

        cached = cache.get(cache_key)
        if cached:
            cached["cached"] = True
            return cached

        endpoint = "/dna/intent/api/v1/compliance/detail"
        params = {"deviceUuid": device_id}
        result = self._make_request(endpoint, params)

        if "error" in result:
            return result

        compliance_list = result.get("response", [])

        # Parse compliance records
        compliance_info = {
            "device_id": device_id,
            "compliance_records": [],
            "overall_status": "COMPLIANT",  # Assume compliant unless we find non-compliant
            "cached": False,
        }

        for record in compliance_list:
            comp_type = record.get("complianceType", "UNKNOWN")
            status = record.get("status", "UNKNOWN")
            state = record.get("state", "")
            last_sync = record.get("lastSyncTime")
            remediation = record.get("remediationSupported", False)

            compliance_info["compliance_records"].append(
                {
                    "type": comp_type,
                    "status": status,
                    "state": state,
                    "last_sync": last_sync,
                    "remediation_supported": remediation,
                }
            )

            # Update overall status if any non-compliant found
            if status == "NON_COMPLIANT":
                compliance_info["overall_status"] = "NON_COMPLIANT"

        # Cache the result
        cache.set(cache_key, compliance_info, cache_timeout)

        return compliance_info

    def get_device_security_advisories(self, device_id):
        """
        Get security advisories (PSIRTs) affecting a device.

        Args:
            device_id: The Catalyst Center device UUID

        Returns:
            dict with advisory details
        """
        if not device_id:
            return {"error": "No device ID provided"}

        # Check cache
        config = settings.PLUGINS_CONFIG.get("netbox_catalyst_center", {})
        cache_timeout = config.get("cache_timeout", 60)
        cache_key = f"catalyst_advisories_{device_id}"

        cached = cache.get(cache_key)
        if cached:
            cached["cached"] = True
            return cached

        endpoint = f"/dna/intent/api/v1/security-advisory/device/{device_id}"
        result = self._make_request(endpoint)

        if "error" in result:
            return result

        advisories_list = result.get("response", [])

        # Parse advisories
        advisory_info = {
            "device_id": device_id,
            "advisory_ids": [],
            "advisory_count": 0,
            "hidden_count": 0,
            "scan_status": "UNKNOWN",
            "last_scan_time": None,
            "cached": False,
        }

        if advisories_list:
            # API returns a single object with advisoryIds array
            advisory_data = advisories_list[0] if isinstance(advisories_list, list) else advisories_list
            advisory_info["advisory_ids"] = advisory_data.get("advisoryIds", [])
            advisory_info["advisory_count"] = len(advisory_info["advisory_ids"])
            advisory_info["hidden_count"] = advisory_data.get("hiddenAdvisoryCount", 0)
            advisory_info["scan_status"] = advisory_data.get("scanStatus", "UNKNOWN")
            advisory_info["last_scan_time"] = advisory_data.get("lastScanTime")

        # Cache the result
        cache.set(cache_key, advisory_info, cache_timeout)

        return advisory_info

    def get_device_interfaces(self, device_id):
        """
        Get all interfaces for a device from Catalyst Center.

        Args:
            device_id: The Catalyst Center device UUID

        Returns:
            dict with "interfaces" array or "error"
        """
        if not device_id:
            return {"error": "No device ID provided"}

        # Check cache
        config = settings.PLUGINS_CONFIG.get("netbox_catalyst_center", {})
        cache_timeout = config.get("cache_timeout", 60)
        cache_key = f"catalyst_interfaces_{device_id}"

        cached = cache.get(cache_key)
        if cached:
            cached["cached"] = True
            return cached

        endpoint = f"/dna/intent/api/v1/interface/network-device/{device_id}"
        result = self._make_request(endpoint)

        if "error" in result:
            return result

        interfaces_list = result.get("response", [])

        # Parse and normalize interface data
        interfaces = []
        for iface in interfaces_list:
            interface_data = {
                "id": iface.get("id"),
                "name": iface.get("portName"),
                "description": iface.get("description"),
                "mac_address": iface.get("macAddress"),
                "ip_address": iface.get("ipv4Address"),
                "ip_mask": iface.get("ipv4Mask"),
                "status": iface.get("status"),
                "admin_status": iface.get("adminStatus"),
                "speed": iface.get("speed"),  # In bps string like "1000000000"
                "duplex": iface.get("duplex"),
                "mtu": iface.get("mtu"),
                "port_type": iface.get("portType"),  # e.g., "Ethernet Port"
                "interface_type": iface.get("interfaceType"),  # e.g., "Physical"
                "port_mode": iface.get("portMode"),  # e.g., "access", "trunk", "routed"
                "native_vlan_id": iface.get("nativeVlanId"),
                "voice_vlan": iface.get("voiceVlan"),
                "vlan_id": iface.get("vlanId"),
                "media_type": iface.get("mediaType"),  # e.g., "10/100/1000BaseTX"
                "class_name": iface.get("className"),  # e.g., "EthernetInterface"
                "is_l3_interface": iface.get("isL3Interface"),
                "device_id": iface.get("deviceId"),
                "mapped_physical_interface_id": iface.get("mappedPhysicalInterfaceId"),
                "mapped_physical_interface_name": iface.get("mappedPhysicalInterfaceName"),
                # POE fields (may not be present for non-POE ports)
                "poe_enabled": iface.get("poeEnabled"),
                "poe_status": iface.get("poeStatus"),
                "poe_max_power": iface.get("maxAllocatedPower"),
                "poe_allocated_power": iface.get("allocatedPower"),
                "poe_power_drawn": iface.get("powerDrawn"),
            }
            interfaces.append(interface_data)

        interface_info = {
            "device_id": device_id,
            "interfaces": interfaces,
            "interface_count": len(interfaces),
            "cached": False,
        }

        # Cache the result
        cache.set(cache_key, interface_info, cache_timeout)

        return interface_info

    def get_device_poe_detail(self, device_id):
        """
        Get POE details for all interfaces on a device.

        This is a separate API call from get_device_interfaces because POE data
        is not included in the standard interface endpoint.

        Args:
            device_id: The Catalyst Center device UUID

        Returns:
            dict with "poe_interfaces" array or "error"
        """
        if not device_id:
            return {"error": "No device ID provided"}

        # Check cache (shorter timeout for POE data since it changes more frequently)
        config = settings.PLUGINS_CONFIG.get("netbox_catalyst_center", {})
        cache_timeout = min(config.get("cache_timeout", 60), 30)  # Max 30 seconds for POE
        cache_key = f"catalyst_poe_{device_id}"

        cached = cache.get(cache_key)
        if cached:
            cached["cached"] = True
            return cached

        endpoint = f"/dna/intent/api/v1/network-device/{device_id}/interface/poe-detail"
        result = self._make_request(endpoint)

        if "error" in result:
            return result

        poe_list = result.get("response", [])

        # Parse and normalize POE data
        poe_interfaces = []
        for poe in poe_list:
            poe_data = {
                "interface_name": poe.get("interfaceName"),
                "poe_oper_status": poe.get("poeOperStatus"),  # e.g., "on", "off", "fault"
                "allocated_power": poe.get("allocatedPower"),  # Watts allocated
                "max_port_power": poe.get("maxPortPower"),  # Max port power in Watts
                "port_power_drawn": poe.get("portPowerDrawn"),  # Actual power drawn in Watts
                "ieee_class": poe.get("ieeeClass"),  # e.g., "class0", "class4"
                "pd_device_type": poe.get("pdDeviceType"),  # Connected PD device type
                "pd_class": poe.get("pdClass"),  # PD class
                "poe_oper_mode": poe.get("poeOperMode"),  # e.g., "ieee_mode"
                "pse_oper_status": poe.get("pseOperStatus"),  # PSE operational status
                "four_pair_enabled": poe.get("fourPairEnabled"),  # 4-pair POE (802.3bt)
            }
            poe_interfaces.append(poe_data)

        poe_info = {
            "device_id": device_id,
            "poe_interfaces": poe_interfaces,
            "poe_port_count": len(poe_interfaces),
            "cached": False,
        }

        # Cache the result
        cache.set(cache_key, poe_info, cache_timeout)

        return poe_info

    def get_device_equipment(self, device_id):
        """
        Get equipment/transceiver details for a device.

        This returns information about installed SFP modules, line cards,
        and other equipment that can help determine interface media types.

        Args:
            device_id: The Catalyst Center device UUID

        Returns:
            dict with "equipment" array or "error"
        """
        if not device_id:
            return {"error": "No device ID provided"}

        # Check cache
        config = settings.PLUGINS_CONFIG.get("netbox_catalyst_center", {})
        cache_timeout = config.get("cache_timeout", 60)
        cache_key = f"catalyst_equipment_{device_id}"

        cached = cache.get(cache_key)
        if cached:
            cached["cached"] = True
            return cached

        endpoint = f"/dna/intent/api/v1/network-device/{device_id}/equipment"
        result = self._make_request(endpoint)

        if "error" in result:
            return result

        equipment_list = result.get("response", [])

        # Parse equipment data, focusing on transceivers
        equipment = []
        transceivers = {}  # Map interface name to transceiver info

        for eq in equipment_list:
            name = eq.get("name", "")
            description = eq.get("description", "")
            product_id = eq.get("productId", "")
            vendor_type = eq.get("vendorEquipmentType", "")

            eq_data = {
                "name": name,
                "description": description,
                "product_id": product_id,
                "vendor_type": vendor_type,
                "serial_number": eq.get("serialNumber", ""),
                "manufacturer": eq.get("manufacturer", ""),
            }
            equipment.append(eq_data)

            # If this is a transceiver (has interface name pattern), index it
            # Transceivers have names like "TenGigabitEthernet1/1/8" not "Container"
            if product_id and "Container" not in name:
                # Check if name looks like an interface
                if any(x in name for x in ["Ethernet", "Gigabit", "Channel"]):
                    transceivers[name] = {
                        "product_id": product_id,
                        "description": description,
                        "vendor_type": vendor_type,
                        "manufacturer": eq.get("manufacturer", ""),
                        "serial_number": eq.get("serialNumber", ""),
                    }

        equipment_info = {
            "device_id": device_id,
            "equipment": equipment,
            "transceivers": transceivers,
            "equipment_count": len(equipment),
            "transceiver_count": len(transceivers),
            "cached": False,
        }

        # Cache the result
        cache.set(cache_key, equipment_info, cache_timeout)

        return equipment_info

    def _detect_stack(self, device):
        """
        Detect if a device is a stack and return stack info.

        Args:
            device: Raw device data from Catalyst Center API

        Returns:
            tuple: (is_stack, stack_count, serial_list, platform_list)
        """
        platform_raw = device.get("platformId") or ""
        serial_raw = device.get("serialNumber") or ""
        line_card_count = device.get("lineCardCount")

        is_stack = False
        stack_count = 1

        # Check lineCardCount first (most reliable)
        if line_card_count:
            try:
                lc_count = int(line_card_count)
                if lc_count > 1:
                    is_stack = True
                    stack_count = lc_count
            except (ValueError, TypeError):
                pass

        # Fallback: check for comma-separated values
        if not is_stack and ("," in platform_raw or "," in serial_raw):
            is_stack = True
            if "," in serial_raw:
                stack_count = len([s.strip() for s in serial_raw.split(",") if s.strip()])
            elif "," in platform_raw:
                stack_count = len([p.strip() for p in platform_raw.split(",") if p.strip()])

        # Build lists
        platform_list = [p.strip() for p in platform_raw.split(",") if p.strip()] if platform_raw else []
        serial_list = [s.strip() for s in serial_raw.split(",") if s.strip()] if serial_raw else []

        return is_stack, stack_count, serial_list, platform_list

    def search_devices(self, search_type, search_value, limit=50):
        """
        Search for devices in Catalyst Center inventory.

        Args:
            search_type: "hostname", "ip", or "mac"
            search_value: Search term (supports * wildcard)
            limit: Maximum number of results to return

        Returns:
            dict with "devices" array or "error"
        """
        import re

        endpoint = "/dna/intent/api/v1/network-device"
        has_wildcard = "*" in search_value

        # If no wildcard and searching by hostname or IP, use DNAC API directly
        # This is much faster and handles all 5000+ devices
        if not has_wildcard and search_type in ("hostname", "ip"):
            if search_type == "hostname":
                # Try exact hostname match first
                result = self._make_request(f"{endpoint}?hostname={search_value}")
            else:  # ip
                result = self._make_request(f"{endpoint}?managementIpAddress={search_value}")

            if "error" in result:
                return result

            devices = result.get("response", [])
            matched_devices = []
            for device in devices:
                is_stack, stack_count, serial_list, platform_list = self._detect_stack(device)
                matched_devices.append(
                    {
                        "hostname": device.get("hostname"),
                        "management_ip": device.get("managementIpAddress"),
                        "serial_number": device.get("serialNumber"),
                        "serial_list": serial_list,
                        "mac_address": device.get("macAddress"),
                        "platform": self._dedupe_platform(device.get("platformId")),
                        "platform_list": platform_list,
                        "software_version": device.get("softwareVersion"),
                        "software_type": device.get("softwareType"),
                        "device_family": device.get("family"),
                        "series": device.get("series"),
                        "role": device.get("role"),
                        "reachability_status": device.get("reachabilityStatus"),
                        "snmp_location": device.get("snmpLocation"),
                        "device_id": device.get("id"),
                        "is_stack": is_stack,
                        "stack_count": stack_count,
                    }
                )

            return {
                "devices": matched_devices,
                "total_matched": len(matched_devices),
                "total_in_dnac": len(matched_devices),  # We don't know total without fetching all
            }

        # For wildcard searches or MAC, we need to fetch and filter locally
        # Convert user-friendly wildcard (*) to regex pattern for local filtering
        # First escape all regex special characters, then convert * wildcards to .*
        search_escaped = re.escape(search_value.lower())
        # Now convert escaped wildcards (\*) back to regex wildcards (.*)
        search_pattern = search_escaped.replace(r"\*", ".*")

        # Add anchors if no wildcards at start/end
        if not search_pattern.startswith(".*"):
            search_pattern = f"^{search_pattern}"
        if not search_pattern.endswith(".*"):
            search_pattern = f"{search_pattern}$"

        try:
            pattern = re.compile(search_pattern, re.IGNORECASE)
        except re.error:
            return {"error": f"Invalid search pattern: {search_value}"}

        # Fetch all devices with pagination (DNAC default limit is 500)
        all_devices_cache_key = "catalyst_all_devices_search"
        all_devices = cache.get(all_devices_cache_key)

        if not all_devices:
            all_devices = []
            offset = 1  # DNAC uses 1-based offset
            page_size = 500

            while True:
                result = self._make_request(f"{endpoint}?limit={page_size}&offset={offset}")
                if "error" in result:
                    if all_devices:  # Return what we have if we got some
                        break
                    return result

                page_devices = result.get("response", [])
                if not page_devices:
                    break

                all_devices.extend(page_devices)
                logger.debug(f"Fetched {len(page_devices)} devices, total so far: {len(all_devices)}")

                if len(page_devices) < page_size:
                    break  # Last page

                offset += page_size

                # Safety limit to avoid infinite loops
                if len(all_devices) > 10000:
                    logger.warning("Hit safety limit of 10000 devices")
                    break

            # Cache for 2 minutes
            cache.set(all_devices_cache_key, all_devices, 120)
            logger.info(f"Cached {len(all_devices)} devices from Catalyst Center")

        # Filter devices based on search type
        matched_devices = []
        for device in all_devices:
            match = False

            if search_type == "hostname":
                hostname = device.get("hostname", "") or ""
                # Also check without domain suffix
                hostname_base = hostname.lower().replace(".ohsu.edu", "")
                if pattern.search(hostname) or pattern.search(hostname_base):
                    match = True

            elif search_type == "ip":
                ip = device.get("managementIpAddress", "") or ""
                if pattern.search(ip):
                    match = True

            elif search_type == "mac":
                mac = device.get("macAddress", "") or ""
                # Normalize MAC format for comparison (remove separators)
                mac_normalized = mac.lower().replace(":", "").replace("-", "").replace(".", "")
                search_normalized = search_value.lower().replace(":", "").replace("-", "").replace(".", "")
                # Escape regex special chars, then convert wildcards
                search_escaped = re.escape(search_normalized).replace(r"\*", ".*")
                if not search_escaped.startswith(".*"):
                    search_escaped = f"^{search_escaped}"
                if not search_escaped.endswith(".*"):
                    search_escaped = f"{search_escaped}$"
                try:
                    mac_pattern = re.compile(search_escaped, re.IGNORECASE)
                    if mac_pattern.search(mac_normalized):
                        match = True
                except re.error:
                    pass

            if match:
                is_stack, stack_count, serial_list, platform_list = self._detect_stack(device)
                matched_devices.append(
                    {
                        "hostname": device.get("hostname"),
                        "management_ip": device.get("managementIpAddress"),
                        "serial_number": device.get("serialNumber"),
                        "serial_list": serial_list,
                        "mac_address": device.get("macAddress"),
                        "platform": self._dedupe_platform(device.get("platformId")),
                        "platform_list": platform_list,
                        "software_version": device.get("softwareVersion"),
                        "software_type": device.get("softwareType"),
                        "device_family": device.get("family"),
                        "series": device.get("series"),
                        "role": device.get("role"),
                        "reachability_status": device.get("reachabilityStatus"),
                        "snmp_location": device.get("snmpLocation"),
                        "device_id": device.get("id"),
                        "is_stack": is_stack,
                        "stack_count": stack_count,
                    }
                )

                if len(matched_devices) >= limit:
                    break

        return {
            "devices": matched_devices,
            "total_matched": len(matched_devices),
            "total_in_dnac": len(all_devices),
        }

    def test_connection(self):
        """Test connection to Catalyst Center."""
        token = self._get_token()
        if not token:
            return {"success": False, "error": "Failed to authenticate"}

        # Try to get a simple endpoint
        result = self._make_request("/dna/intent/api/v1/network-device/count")

        if "error" in result:
            return {"success": False, "error": result["error"]}

        device_count = result.get("response", 0)
        return {
            "success": True,
            "message": f"Connected successfully. {device_count} network devices in inventory.",
        }


def get_client():
    """Get configured Catalyst Center client instance."""
    config = settings.PLUGINS_CONFIG.get("netbox_catalyst_center", {})

    url = config.get("catalyst_center_url", "")
    username = config.get("catalyst_center_username", "")
    password = config.get("catalyst_center_password", "")
    timeout = config.get("timeout", 30)
    verify_ssl = config.get("verify_ssl", False)

    if not url or not username or not password:
        return None

    return CatalystCenterClient(
        url=url,
        username=username,
        password=password,
        timeout=timeout,
        verify_ssl=verify_ssl,
    )
