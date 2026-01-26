"""
Navigation menu items for NetBox Catalyst Center Plugin
"""

from netbox.plugins import PluginMenu, PluginMenuItem

menu = PluginMenu(
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
            "Settings",
            (
                PluginMenuItem(
                    link="plugins:netbox_catalyst_center:settings",
                    link_text="Configuration",
                    permissions=["dcim.view_device"],
                ),
            ),
        ),
    ),
    icon_class="mdi mdi-lan",
)
