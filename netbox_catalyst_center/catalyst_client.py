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
            return {"error": "Client not found in Catalyst Center", "mac_address": mac_formatted}

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
                # Fetch all devices from DNAC (no filter)
                logger.debug("Fetching all devices from DNAC for local filtering")
                result = self._make_request(endpoint)
                if "error" not in result:
                    all_devices = result.get("response", [])
                    # Cache for 5 minutes to avoid repeated full fetches
                    cache.set(all_devices_cache_key, all_devices, 300)

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
            # Look for exact hostname match (case-insensitive)
            for device in response:
                dnac_hostname = device.get("hostname", "").lower()
                dnac_base = dnac_hostname.replace(".ohsu.edu", "")
                if dnac_base == base_hostname:
                    device_data = device
                    break

            # If no exact match, use first result that contains hostname
            if not device_data:
                for device in response:
                    dnac_hostname = device.get("hostname", "").lower()
                    if base_hostname in dnac_hostname:
                        device_data = device
                        break

            # Last resort - first result (for IP lookups)
            if not device_data and response:
                device_data = response[0]

        if not device_data:
            return {"error": f"Device '{hostname}' not found in Catalyst Center inventory"}

        # Extract relevant fields for network devices
        device_info = {
            "is_network_device": True,
            "hostname": device_data.get("hostname"),
            "management_ip": device_data.get("managementIpAddress"),
            "device_type": device_data.get("type"),
            "device_family": device_data.get("family"),
            "platform": device_data.get("platformId"),
            "software_version": device_data.get("softwareVersion"),
            "software_type": device_data.get("softwareType"),
            "serial_number": device_data.get("serialNumber"),
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
