"""
Views for NetBox Catalyst Center Plugin

Registers custom tabs on Device detail views to show Catalyst Center client info.
Provides settings configuration UI.
"""

import re

from dcim.models import Device
from django.conf import settings
from django.contrib import messages
from django.http import JsonResponse
from django.shortcuts import render
from django.views import View
from ipam.models import IPAddress
from netbox.views import generic
from utilities.views import ViewTab, register_model_view

from .catalyst_client import get_client
from .forms import CatalystCenterSettingsForm


def is_valid_mac(value):
    """Check if a value looks like a MAC address."""
    if not value:
        return False
    # Remove common separators and check if it's 12 hex characters
    cleaned = re.sub(r"[:\-\.]", "", value.lower())
    return bool(re.match(r"^[0-9a-f]{12}$", cleaned))


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
                if re.search(manufacturer_pattern, manufacturer_slug, re.IGNORECASE) or re.search(
                    manufacturer_pattern, manufacturer_name, re.IGNORECASE
                ):
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
                if re.search(device_type_pattern, device_type_slug, re.IGNORECASE) or re.search(
                    device_type_pattern, device_type_model, re.IGNORECASE
                ):
                    device_type_match = True
            except re.error:
                if device_type_pattern in device_type_slug or device_type_pattern in device_type_model:
                    device_type_match = True

            if not device_type_match:
                continue

        # Mapping matches! Return lookup type and check if device has required data
        # lookup can be:
        #   - "network_device" - tries ipAddress, then hostname, then fetches all (for Cisco infra)
        #   - "client" - uses MAC address only (for wireless clients like Vocera)
        #   - Legacy: "hostname", "ipAddress", "mac" still supported
        if lookup == "client" or lookup == "mac":
            # Wireless client lookup - MAC only
            mac = get_device_mac(device)
            return "client", mac is not None
        else:
            # Network device lookup - ipAddress > hostname > fetch all
            # Check if device has hostname or IP
            has_hostname = bool(device.name)
            has_ip = device.primary_ip4 is not None or device.primary_ip6 is not None
            return "network_device", (has_hostname or has_ip)

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

            if lookup_method == "network_device":
                # Network device lookup - tries IP first (most reliable), then hostname
                management_ip = None
                if device.primary_ip4:
                    management_ip = str(device.primary_ip4.address.ip)
                elif device.primary_ip6:
                    management_ip = str(device.primary_ip6.address.ip)

                client_data = client.get_network_device(device.name, management_ip=management_ip)
                if "error" in client_data:
                    error = client_data.get("error")
                    client_data = {}
                else:
                    # Fetch additional data if we have a device_id
                    device_id = client_data.get("device_id")
                    if device_id:
                        # Get compliance status
                        compliance_data = client.get_device_compliance(device_id)
                        if "error" not in compliance_data:
                            client_data["compliance"] = compliance_data

                        # Get security advisories
                        advisory_data = client.get_device_security_advisories(device_id)
                        if "error" not in advisory_data:
                            client_data["advisories"] = advisory_data
            elif lookup_method == "client":
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


class SyncDeviceFromDNACView(View):
    """Sync device data from Catalyst Center to NetBox."""

    def post(self, request, pk):
        """
        Sync selected fields from DNAC to NetBox device.

        Supports syncing: IP address, serial number, SNMP location (to comments).
        """
        import json

        try:
            device = Device.objects.get(pk=pk)
        except Device.DoesNotExist:
            return JsonResponse({"success": False, "error": "Device not found"}, status=404)

        # Parse sync options from request body
        try:
            body = json.loads(request.body) if request.body else {}
        except json.JSONDecodeError:
            body = {}

        sync_ip = body.get("sync_ip", True)  # Default to True for backwards compatibility
        sync_serial = body.get("sync_serial", False)
        sync_location = body.get("sync_location", False)

        client = get_client()
        if not client:
            return JsonResponse({"success": False, "error": "Catalyst Center not configured"}, status=400)

        # Get device data from DNAC
        lookup_method, _ = get_device_lookup_method(device)

        if lookup_method == "network_device":
            # Get management IP for lookup
            management_ip = None
            if device.primary_ip4:
                management_ip = str(device.primary_ip4.address.ip)
            elif device.primary_ip6:
                management_ip = str(device.primary_ip6.address.ip)

            dnac_data = client.get_network_device(device.name, management_ip=management_ip)
        elif lookup_method == "client":
            mac_address = get_device_mac(device)
            if mac_address:
                dnac_data = client.get_client_detail(mac_address)
            else:
                return JsonResponse({"success": False, "error": "No MAC address found"}, status=400)
        else:
            return JsonResponse({"success": False, "error": "Device not configured for DNAC lookup"}, status=400)

        if "error" in dnac_data:
            return JsonResponse({"success": False, "error": dnac_data["error"]}, status=400)

        changes = []
        device_changed = False

        # Sync IP address
        if sync_ip:
            dnac_ip = dnac_data.get("management_ip") or dnac_data.get("ip_address")
            if dnac_ip:
                ip_result = self._sync_ip_address(device, dnac_ip)
                if ip_result.get("error"):
                    return JsonResponse({"success": False, "error": ip_result["error"]}, status=400)
                changes.extend(ip_result.get("changes", []))
                if ip_result.get("changed"):
                    device_changed = True

        # Sync serial number
        if sync_serial:
            dnac_serial = dnac_data.get("serial_number")
            if dnac_serial and device.serial != dnac_serial:
                device.serial = dnac_serial
                changes.append(f"Serial: {dnac_serial}")
                device_changed = True

        # Sync SNMP location to comments
        if sync_location:
            dnac_location = dnac_data.get("snmp_location")
            if dnac_location:
                # Append to comments if not already there
                location_prefix = "SNMP Location: "
                if location_prefix not in (device.comments or ""):
                    if device.comments:
                        device.comments = f"{device.comments}\n\n{location_prefix}{dnac_location}"
                    else:
                        device.comments = f"{location_prefix}{dnac_location}"
                    changes.append("Added SNMP location to comments")
                    device_changed = True

        # Save device if any changes were made
        if device_changed:
            device.save()

        if not changes:
            return JsonResponse(
                {"success": True, "message": "No changes needed - device is already in sync", "changes": []}
            )

        return JsonResponse(
            {"success": True, "message": f"Synced {len(changes)} field(s) from Catalyst Center", "changes": changes}
        )

    def _sync_ip_address(self, device, dnac_ip):
        """Sync IP address from DNAC to device. Returns dict with changes and error."""
        ip_with_prefix = f"{dnac_ip}/32"
        existing_ip = IPAddress.objects.filter(address=ip_with_prefix).first()
        changes = []
        changed = False

        if existing_ip:
            # IP exists - check if it's assigned to this device
            if existing_ip.assigned_object and existing_ip.assigned_object.device == device:
                # Already assigned to this device, just set as primary if not already
                if device.primary_ip4 != existing_ip:
                    device.primary_ip4 = existing_ip
                    changes.append(f"Primary IP: {dnac_ip}")
                    changed = True
            else:
                # IP exists but assigned elsewhere or unassigned
                interface = device.interfaces.first()
                if not interface:
                    return {"error": f"IP {dnac_ip} exists but device has no interfaces to assign it to"}

                # Reassign the IP to this device's interface
                existing_ip.assigned_object = interface
                existing_ip.save()
                device.primary_ip4 = existing_ip
                changes.append(f"Primary IP: {dnac_ip} (reassigned)")
                changed = True
        else:
            # IP doesn't exist - create it
            interface = device.interfaces.first()
            if not interface:
                return {"error": "Device has no interfaces to assign IP to"}

            new_ip = IPAddress(
                address=ip_with_prefix,
                assigned_object=interface,
                description="Synced from Catalyst Center",
            )
            new_ip.save()
            device.primary_ip4 = new_ip
            changes.append(f"Primary IP: {dnac_ip} (created)")
            changed = True

        return {"changes": changes, "changed": changed}
