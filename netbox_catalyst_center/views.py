"""
Views for NetBox Catalyst Center Plugin

Registers custom tabs on Device detail views to show Catalyst Center client info.
Provides settings configuration UI.
"""

import re

from django.conf import settings
from django.contrib import messages
from django.http import JsonResponse
from django.shortcuts import render
from django.views import View

from dcim.models import Device
from netbox.views import generic
from utilities.views import ViewTab, register_model_view

from .forms import CatalystCenterSettingsForm
from .catalyst_client import get_client


def is_valid_mac(value):
    """Check if a value looks like a MAC address."""
    if not value:
        return False
    # Remove common separators and check if it's 12 hex characters
    cleaned = re.sub(r'[:\-\.]', '', value.lower())
    return bool(re.match(r'^[0-9a-f]{12}$', cleaned))


def get_device_mac(device):
    """Get the first valid MAC address from device interfaces."""
    for iface in device.interfaces.all():
        if iface.mac_address and is_valid_mac(str(iface.mac_address)):
            return str(iface.mac_address)
    return None


def get_device_lookup_method(device):
    """
    Determine the lookup method for a device based on configured mappings.

    Returns:
        tuple: (lookup_method, has_required_data)
        - lookup_method: "hostname", "mac", or None if no mapping matches
        - has_required_data: True if device has the data needed for lookup
    """
    config = settings.PLUGINS_CONFIG.get("netbox_catalyst_center", {})
    mappings = config.get("device_mappings", [])

    if not device.device_type:
        return None, False

    # Get device info for matching
    manufacturer = device.device_type.manufacturer
    manufacturer_slug = manufacturer.slug.lower() if manufacturer and manufacturer.slug else ""
    manufacturer_name = manufacturer.name.lower() if manufacturer and manufacturer.name else ""
    device_type_slug = device.device_type.slug.lower() if device.device_type.slug else ""
    device_type_model = device.device_type.model.lower() if device.device_type.model else ""

    # Check each mapping
    for mapping in mappings:
        manufacturer_pattern = mapping.get("manufacturer", "").lower()
        device_type_pattern = mapping.get("device_type", "").lower()
        lookup = mapping.get("lookup", "hostname")

        # Check manufacturer match (against both slug and name)
        manufacturer_match = False
        if manufacturer_pattern:
            try:
                if (re.search(manufacturer_pattern, manufacturer_slug, re.IGNORECASE) or
                    re.search(manufacturer_pattern, manufacturer_name, re.IGNORECASE)):
                    manufacturer_match = True
            except re.error:
                # Invalid regex, try literal match
                if manufacturer_pattern in manufacturer_slug or manufacturer_pattern in manufacturer_name:
                    manufacturer_match = True

        if not manufacturer_match:
            continue

        # Check device_type match if specified (against both slug and model)
        if device_type_pattern:
            device_type_match = False
            try:
                if (re.search(device_type_pattern, device_type_slug, re.IGNORECASE) or
                    re.search(device_type_pattern, device_type_model, re.IGNORECASE)):
                    device_type_match = True
            except re.error:
                if device_type_pattern in device_type_slug or device_type_pattern in device_type_model:
                    device_type_match = True

            if not device_type_match:
                continue

        # Mapping matches! Check if device has required data
        if lookup == "mac":
            mac = get_device_mac(device)
            return "mac", mac is not None
        else:  # hostname
            return "hostname", bool(device.name)

    return None, False


def should_show_catalyst_tab(device):
    """
    Determine if the Catalyst Center tab should be visible for this device.

    Shows tab if device matches any configured device_mapping and has
    the required data for the lookup method.
    """
    lookup_method, has_data = get_device_lookup_method(device)
    return lookup_method is not None and has_data


@register_model_view(Device, name="catalyst_center", path="catalyst-center")
class DeviceCatalystCenterView(generic.ObjectView):
    """Display Catalyst Center client details for a Device."""

    queryset = Device.objects.all()
    template_name = "netbox_catalyst_center/client_tab.html"

    tab = ViewTab(
        label="Catalyst Center",
        weight=9000,
        permission="dcim.view_device",
        hide_if_empty=False,
        visible=should_show_catalyst_tab,
    )

    def get(self, request, pk):
        """Handle GET request for the Catalyst Center tab."""
        device = Device.objects.get(pk=pk)

        client = get_client()
        config = settings.PLUGINS_CONFIG.get("netbox_catalyst_center", {})

        client_data = {}
        error = None

        if not client:
            error = "Catalyst Center not configured. Please configure the plugin in NetBox settings."
        else:
            # Determine lookup method based on device_mappings config
            lookup_method, has_data = get_device_lookup_method(device)

            if lookup_method == "hostname":
                # Network device - look up by hostname
                client_data = client.get_network_device(device.name)
                if "error" in client_data:
                    error = client_data.get("error")
                    client_data = {}
            elif lookup_method == "mac":
                # Wireless client - look up by MAC address
                mac_address = get_device_mac(device)
                if mac_address:
                    client_data = client.get_client_detail(mac_address)
                    if "error" in client_data:
                        error = client_data.get("error")
                        client_data = {}
                else:
                    error = "No MAC address found on device interfaces."
            else:
                # No matching device_mapping found
                error = (
                    "This device doesn't match any configured device_mappings. "
                    "Configure device_mappings in the plugin settings to enable lookups."
                )

        # Get Catalyst Center URL for external links
        catalyst_url = config.get("catalyst_center_url", "").rstrip("/")

        # Choose template based on data type
        if client_data.get("is_network_device"):
            template = "netbox_catalyst_center/network_device_tab.html"
        else:
            template = self.template_name

        return render(
            request,
            template,
            {
                "object": device,
                "tab": self.tab,
                "client_data": client_data,
                "error": error,
                "catalyst_url": catalyst_url,
            },
        )


class CatalystCenterSettingsView(View):
    """View for configuring Catalyst Center plugin settings."""

    template_name = "netbox_catalyst_center/settings.html"

    def get_current_config(self):
        """Get current plugin configuration."""
        return settings.PLUGINS_CONFIG.get("netbox_catalyst_center", {})

    def get(self, request):
        """Display the settings form."""
        config = self.get_current_config()
        form = CatalystCenterSettingsForm(initial=config)

        return render(
            request,
            self.template_name,
            {
                "form": form,
                "config": config,
            },
        )

    def post(self, request):
        """Handle settings form submission."""
        form = CatalystCenterSettingsForm(request.POST)

        if form.is_valid():
            messages.warning(
                request,
                "Settings must be configured in NetBox's configuration.py file. "
                "See the README for configuration instructions.",
            )
        else:
            messages.error(request, "Invalid settings provided.")

        return render(
            request,
            self.template_name,
            {
                "form": form,
                "config": self.get_current_config(),
            },
        )


class TestConnectionView(View):
    """Test connection to Catalyst Center API."""

    def post(self, request):
        """Test the Catalyst Center connection and return result."""
        client = get_client()

        if not client:
            return JsonResponse(
                {
                    "success": False,
                    "error": "Catalyst Center not configured",
                },
                status=400,
            )

        result = client.test_connection()

        if not result.get("success"):
            return JsonResponse(
                {
                    "success": False,
                    "error": result.get("error", "Unknown error"),
                },
                status=400,
            )

        return JsonResponse(
            {
                "success": True,
                "message": result.get("message"),
            }
        )
