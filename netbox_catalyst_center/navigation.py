"""
Navigation menu items for NetBox Catalyst Center Plugin
"""

from django.conf import settings
from netbox.plugins import PluginMenu, PluginMenuItem

_menu = PluginMenu(
    label="Catalyst Center",
    groups=(
        (
            "Devices",
            (
                PluginMenuItem(
                    link="plugins:netbox_catalyst_center:import_page",
                    link_text="Import Devices",
                    permissions=["dcim.add_device"],
                ),
                PluginMenuItem(
                    link="plugins:netbox_catalyst_center:comparison",
                    link_text="Inventory Comparison",
                    permissions=["dcim.view_device"],
                ),
            ),
        ),
        (
            "Configs",
            (
                PluginMenuItem(
                    link="plugins:netbox_catalyst_center:config_diff",
                    link_text="Config Diff",
                    permissions=["dcim.view_device"],
                ),
                PluginMenuItem(
                    link="plugins:netbox_catalyst_center:config_audit",
                    link_text="Config Audit",
                    permissions=["dcim.view_device"],
                ),
                PluginMenuItem(
                    link="plugins:netbox_catalyst_center:neighbor_discovery",
                    link_text="Neighbor Discovery",
                    permissions=["dcim.view_device"],
                ),
            ),
        ),
        (
            "Settings",
            (
                PluginMenuItem(
                    link="plugins:netbox_catalyst_center:settings",
                    link_text="Configuration",
                    permissions=["netbox_catalyst_center.configure_catalystcenter"],
                ),
            ),
        ),
    ),
    icon_class="mdi mdi-lan",
)


# top_level_menu=False puts this plugin's items under the shared "Plugins" menu
# (grouped by plugin name) instead of its own top-level sidebar menu.
if settings.PLUGINS_CONFIG.get("netbox_catalyst_center", {}).get("top_level_menu", True):
    menu = _menu
else:
    menu_items = tuple(item for group in _menu.groups for item in group.items)
