"""
NetBox Catalyst Center Plugin

Display Cisco Catalyst Center (DNA Center) client details in Device detail pages.
Shows real-time IP address, connected AP, health score, and connection status.
"""

import logging

from netbox.plugins import PluginConfig

__version__ = "1.2.1"

logger = logging.getLogger(__name__)


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

    def ready(self):
        """Initialize plugin - create custom fields if they don't exist."""
        super().ready()
        self._ensure_custom_fields()

    def _ensure_custom_fields(self):
        """Create custom fields for Catalyst Center data if they don't exist."""
        from django.contrib.contenttypes.models import ContentType
        from django.db import OperationalError, ProgrammingError

        try:
            from dcim.models import Device
            from extras.models import CustomField, CustomFieldChoiceSet

            device_ct = ContentType.objects.get_for_model(Device)

            # Define custom fields
            fields_config = [
                {
                    "name": "cc_device_id",
                    "label": "CC Device ID",
                    "type": "text",
                    "description": "Catalyst Center device UUID for linking to CC UI",
                },
                {
                    "name": "cc_series",
                    "label": "CC Device Series",
                    "type": "text",
                    "description": "Device series from Catalyst Center (e.g., Cisco Catalyst 9300 Series)",
                },
                {
                    "name": "cc_role",
                    "label": "CC Network Role",
                    "type": "select",
                    "description": "Network role from Catalyst Center",
                    "choices": ["ACCESS", "DISTRIBUTION", "CORE", "BORDER ROUTER", "UNKNOWN"],
                },
                {
                    "name": "cc_last_sync",
                    "label": "CC Last Sync",
                    "type": "datetime",
                    "description": "When data was last synced from Catalyst Center",
                },
            ]

            for field_config in fields_config:
                # Handle select field with choice set
                choice_set = None
                if field_config["type"] == "select" and "choices" in field_config:
                    choice_set, _ = CustomFieldChoiceSet.objects.get_or_create(
                        name="CC Network Roles",
                        defaults={
                            "extra_choices": [
                                ["ACCESS", "Access"],
                                ["DISTRIBUTION", "Distribution"],
                                ["CORE", "Core"],
                                ["BORDER ROUTER", "Border Router"],
                                ["UNKNOWN", "Unknown"],
                            ]
                        },
                    )

                defaults = {
                    "label": field_config["label"],
                    "type": field_config["type"],
                    "description": field_config["description"],
                    "group_name": "Catalyst Center",
                    "ui_visible": "if-set",
                    "ui_editable": "yes",
                }
                if choice_set:
                    defaults["choice_set"] = choice_set

                cf, created = CustomField.objects.get_or_create(
                    name=field_config["name"],
                    defaults=defaults,
                )

                # Ensure field is assigned to Device model
                if device_ct not in cf.object_types.all():
                    cf.object_types.add(device_ct)

                if created:
                    logger.info(f"Created custom field: {field_config['name']}")

        except (OperationalError, ProgrammingError):
            # Database not ready (e.g., during migrations)
            pass
        except Exception as e:
            logger.warning(f"Could not create custom fields: {e}")


config = CatalystCenterConfig
