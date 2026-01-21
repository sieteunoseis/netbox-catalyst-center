"""
Cisco Catalyst Center API Client

Handles authentication and API calls to Catalyst Center (formerly DNA Center).
"""

import requests
import logging
from functools import lru_cache
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
            mac_formatted = ":".join(mac[i:i+2] for i in range(0, 12, 2))
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
            device = client_info["connected_device"][0] if isinstance(client_info["connected_device"], list) else client_info["connected_device"]
            client_info["connected_device_name"] = device.get("name")
            # Handle both API response formats: mgmtIp (wireless) and managementIpAddress (wired)
            client_info["connected_device_ip"] = device.get("mgmtIp") or device.get("managementIpAddress")
            client_info["connected_interface"] = device.get("interfaceName")

        # Cache the result
        cache.set(cache_key, client_info, cache_timeout)

        return client_info

    def get_network_device(self, hostname):
        """
        Get network device details by hostname.

        For Cisco infrastructure devices (voice gateways, APs, switches, etc.)
        that are in DNAC inventory.

        Args:
            hostname: Device hostname (with or without domain)

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

        # Extract base hostname without domain
        base_hostname = hostname.lower().replace(".ohsu.edu", "")
        endpoint = "/dna/intent/api/v1/network-device"

        # DNAC API is case-sensitive but supports regex character classes
        # Build pattern like [Aa][Mm][Aa]agw01.* for case-insensitive matching
        case_insensitive_pattern = "".join(
            f"[{c.upper()}{c.lower()}]" if c.isalpha() else c
            for c in base_hostname
        )
        wildcard_pattern = f"{case_insensitive_pattern}.*"
        params = {"hostname": wildcard_pattern}
        result = self._make_request(endpoint, params)

        if "error" in result:
            return result

        response = result.get("response", [])

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

            # Last resort - first result
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
