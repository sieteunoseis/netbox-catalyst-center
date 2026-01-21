"""
NetBox Catalyst Center Plugin

Display Cisco Catalyst Center (DNA Center) client details in Device detail pages.
Shows real-time IP address, connected AP, health score, and connection status.
"""

from netbox.plugins import PluginConfig

__version__ = "1.0.0"


class CatalystCenterConfig(PluginConfig):
    """Plugin configuration for NetBox Catalyst Center integration."""

    name = "netbox_catalyst_center"
    verbose_name = "Catalyst Center"
    description = "Display Cisco Catalyst Center client details in device pages"
    version = __version__
    author = "sieteunoseis"
    author_email = "sieteunoseis@github.com"
    base_url = "catalyst-center"
    min_version = "4.0.0"

    # Required settings - plugin won't load without these
    required_settings = []

    # Default configuration values
    default_settings = {
        "catalyst_center_url": "",
        "catalyst_center_username": "",
        "catalyst_center_password": "",
        "timeout": 30,  # API timeout in seconds
        "cache_timeout": 60,  # Cache results for 60 seconds
        "verify_ssl": False,  # Skip SSL verification for self-signed certs

        # Device types to show tab for and lookup method
        # Format: list of dicts with manufacturer (regex), device_type (regex, optional), lookup method
        # lookup: "hostname" = network device lookup, "mac" = wireless client lookup
        #
        # Example:
        # "device_mappings": [
        #     {"manufacturer": "cisco.*", "lookup": "hostname"},  # All Cisco devices by hostname
        #     {"manufacturer": "vocera", "lookup": "mac"},  # Vocera badges by MAC
        #     {"manufacturer": "cisco", "device_type": ".*phone.*", "lookup": "mac"},  # Cisco phones by MAC
        # ]
        "device_mappings": [
            {"manufacturer": r"cisco", "lookup": "hostname"},  # Cisco devices by hostname
        ],
    }


config = CatalystCenterConfig
