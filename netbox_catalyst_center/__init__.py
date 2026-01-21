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
    }


config = CatalystCenterConfig
