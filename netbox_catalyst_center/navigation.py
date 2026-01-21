"""
Navigation menu items for NetBox Catalyst Center Plugin
"""

from netbox.plugins import PluginMenu, PluginMenuItem


menu = PluginMenu(
    label="Catalyst Center",
    groups=(
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
