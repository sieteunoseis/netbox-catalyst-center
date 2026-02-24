"""
NetBox Catalyst Center Plugin

Display Cisco Catalyst Center client details in Device detail pages.
Shows real-time IP address, connected AP, health score, and connection status.
"""

import logging

from django.db.models.signals import post_migrate
from netbox.plugins import PluginConfig

__version__ = "1.4.2"

logger = logging.getLogger(__name__)


def create_custom_fields(sender, **kwargs):
    """Create custom fields for Catalyst Center data after migrations complete."""
    # Only run for this plugin's migrations
    if sender.name != "netbox_catalyst_center":
        return

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
                "choices": [
                    "ACCESS",
                    "DISTRIBUTION",
                    "CORE",
                    "BORDER ROUTER",
                    "UNKNOWN",
                ],
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
        # Strip domain from hostnames when matching NetBox devices to Catalyst Center
        # When True, "switch01" (NetBox) will match "switch01.example.com" (CC)
        "strip_domain": True,
        # Virtual Chassis: Import stacks as virtual chassis with separate devices per member
        # When enabled, stacks are imported as:
        # - One device per stack member (hostname.1, hostname.2, etc.)
        # - A Virtual Chassis linking all members
        # - Physical interfaces assigned to members based on slot (e.g., 2/0/1 -> member 2)
        # - Logical interfaces (VLANs, Loopbacks, Port-channels) assigned to master
        # When disabled (default), stacks are imported as single devices
        "enable_virtual_chassis": False,
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
            {
                "manufacturer": r"cisco",
                "lookup": "hostname",
            },  # Cisco devices by hostname
        ],
        # Endpoint types to show Catalyst Center tab for (requires netbox-endpoints plugin)
        # Format: list of dicts with manufacturer (regex), endpoint_type (regex, optional)
        # All endpoints use MAC lookup since they're wireless/wired clients
        #
        # Example:
        # "endpoint_mappings": [
        #     {"manufacturer": "vocera"},  # All Vocera endpoints
        #     {"manufacturer": "cisco", "endpoint_type": ".*phone.*"},  # Cisco phones
        # ]
        # If empty, shows tab for ALL endpoints with a MAC address
        "endpoint_mappings": [],
    }

    def ready(self):
        """Register signal to create custom fields after migrations."""
        super().ready()
        post_migrate.connect(create_custom_fields, sender=self)

        # Register endpoint view if netbox_endpoints is available
        self._register_endpoint_views()

    def _register_endpoint_views(self):
        """Register Catalyst Center tab for Endpoints if plugin is installed."""
        try:
            from django.shortcuts import render
            from netbox.views import generic
            from netbox_endpoints.models import Endpoint

            # Check if already registered
            from utilities.views import ViewTab, register_model_view, registry

            from .views import should_show_catalyst_tab_endpoint

            views_dict = registry.get("views", {})
            endpoint_views = views_dict.get("netbox_endpoints", {}).get("endpoint", [])
            if any(v.get("name") == "catalyst_center" for v in endpoint_views):
                return  # Already registered

            @register_model_view(Endpoint, name="catalyst_center", path="catalyst-center")
            class EndpointCatalystCenterView(generic.ObjectView):
                """Display Catalyst Center client details for an Endpoint."""

                queryset = Endpoint.objects.all()
                template_name = "netbox_catalyst_center/endpoint_tab.html"

                tab = ViewTab(
                    label="Catalyst Center",
                    weight=9000,
                    permission="netbox_endpoints.view_endpoint",
                    hide_if_empty=False,
                    visible=should_show_catalyst_tab_endpoint,
                )

                def get(self, request, pk):
                    endpoint = Endpoint.objects.get(pk=pk)
                    return render(
                        request,
                        self.template_name,
                        {
                            "object": endpoint,
                            "tab": self.tab,
                            "loading": True,
                        },
                    )

            logger.info("Registered Catalyst Center tab for Endpoint model")
        except ImportError:
            logger.debug("netbox_endpoints not installed, skipping endpoint view registration")
        except Exception as e:
            logger.warning(f"Could not register endpoint views: {e}")


config = CatalystCenterConfig
