"""
Navigation menu items for NetBox Catalyst Center Plugin
"""

from netbox.plugins import PluginMenuItem

menu_items = (
    PluginMenuItem(
        link="plugins:netbox_catalyst_center:settings",
        link_text="Settings",
        permissions=["dcim.view_device"],
    ),
)
