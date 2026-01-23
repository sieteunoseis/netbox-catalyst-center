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

    def get_context(self, form, config):
        """Build context with sites and roles for import feature."""
        from dcim.models import DeviceRole, Site

        return {
            "form": form,
            "config": config,
            "sites": Site.objects.all().order_by("name"),
            "roles": DeviceRole.objects.all().order_by("name"),
        }

    def get(self, request):
        """Display the settings form."""
        config = self.get_current_config()
        form = CatalystCenterSettingsForm(initial=config)

        return render(
            request,
            self.template_name,
            self.get_context(form, config),
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
            self.get_context(form, self.get_current_config()),
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

        Supports syncing: IP address, serial number, SNMP location, device type,
        platform (software type/version), and custom fields.
        """
        import json

        from dcim.models import DeviceType, Manufacturer, Platform

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
        sync_device_type = body.get("sync_device_type", False)
        sync_platform = body.get("sync_platform", False)
        sync_custom_fields = body.get("sync_custom_fields", False)

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

        # Sync Device Type from CC platform_id
        if sync_device_type:
            platform_id = dnac_data.get("platform")
            if platform_id:
                # Deduplicate platform if it contains duplicates (e.g., "C9800-40-K9, C9800-40-K9")
                if "," in platform_id:
                    platform_parts = [p.strip() for p in platform_id.split(",")]
                    seen = set()
                    unique_parts = []
                    for p in platform_parts:
                        if p and p not in seen:
                            seen.add(p)
                            unique_parts.append(p)
                    platform_id = unique_parts[0] if unique_parts else platform_id

                # Get or create Cisco manufacturer
                cisco_mfr, _ = Manufacturer.objects.get_or_create(
                    slug="cisco",
                    defaults={"name": "Cisco"},
                )

                # Get or create device type
                device_type, dt_created = DeviceType.objects.get_or_create(
                    manufacturer=cisco_mfr,
                    model=platform_id,
                    defaults={
                        "slug": platform_id.lower().replace(" ", "-").replace("/", "-"),
                    },
                )

                if device.device_type != device_type:
                    old_type = device.device_type.model if device.device_type else "None"
                    device.device_type = device_type
                    changes.append(f"Device Type: {old_type} → {platform_id}")
                    device_changed = True

        # Sync Platform (software type as parent, software version as child)
        if sync_platform:
            software_type = dnac_data.get("software_type")  # e.g., "IOS-XE", "IOS"
            software_version = dnac_data.get("software_version")  # e.g., "17.9.4a"

            if software_type and software_version:
                # Get or create parent platform (software type)
                parent_platform, _ = Platform.objects.get_or_create(
                    slug=software_type.lower().replace(" ", "-"),
                    defaults={
                        "name": software_type,
                    },
                )

                # Get or create child platform (software version under parent)
                child_slug = (
                    f"{software_type.lower()}-{software_version.lower()}".replace(" ", "-")
                    .replace("(", "")
                    .replace(")", "")
                )
                child_platform, _ = Platform.objects.get_or_create(
                    slug=child_slug,
                    defaults={
                        "name": software_version,
                        "parent": parent_platform,
                    },
                )

                # Update parent if it was created without one
                if child_platform.parent != parent_platform:
                    child_platform.parent = parent_platform
                    child_platform.save()

                if device.platform != child_platform:
                    old_platform = device.platform.name if device.platform else "None"
                    device.platform = child_platform
                    changes.append(f"Platform: {old_platform} → {software_type}/{software_version}")
                    device_changed = True

        # Sync custom fields
        if sync_custom_fields:
            cf_changes = self._sync_custom_fields(device, dnac_data)
            changes.extend(cf_changes)
            if cf_changes:
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

    def _sync_custom_fields(self, device, dnac_data):
        """Sync Catalyst Center custom fields. Returns list of change descriptions."""
        from django.utils import timezone

        changes = []

        # Map DNAC fields to custom fields
        field_mappings = {
            "cc_device_id": dnac_data.get("device_id"),
            "cc_series": dnac_data.get("series"),
            "cc_role": dnac_data.get("role"),
        }

        for cf_name, new_value in field_mappings.items():
            if new_value:
                current_value = device.custom_field_data.get(cf_name)
                if current_value != new_value:
                    device.custom_field_data[cf_name] = new_value
                    changes.append(f"{cf_name}: {new_value}")

        # Always update last sync time when syncing custom fields
        device.custom_field_data["cc_last_sync"] = timezone.now().isoformat()
        changes.append(f"cc_last_sync: {timezone.now().strftime('%Y-%m-%d %H:%M')}")

        return changes

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


class ImportPageView(View):
    """Dedicated page for searching and importing devices from Catalyst Center."""

    template_name = "netbox_catalyst_center/import.html"

    def get(self, request):
        """Display the import page."""
        from dcim.models import DeviceRole, Site

        config = settings.PLUGINS_CONFIG.get("netbox_catalyst_center", {})

        return render(
            request,
            self.template_name,
            {
                "config": config,
                "sites": Site.objects.all().order_by("name"),
                "roles": DeviceRole.objects.all().order_by("name"),
            },
        )


class SearchDevicesView(View):
    """Search for devices in Catalyst Center inventory."""

    def get(self, request):
        """
        Search for devices in Catalyst Center.

        Query parameters:
            search_type: "hostname", "ip", or "mac"
            search_value: Search term (supports * wildcard)
            limit: Maximum results (default 50)
        """
        search_type = request.GET.get("search_type", "hostname")
        search_value = request.GET.get("search_value", "").strip()
        limit = int(request.GET.get("limit", 50))

        if not search_value:
            return JsonResponse({"error": "Search value is required"}, status=400)

        if search_type not in ("hostname", "ip", "mac"):
            return JsonResponse({"error": "Invalid search type"}, status=400)

        client = get_client()
        if not client:
            return JsonResponse({"error": "Catalyst Center not configured"}, status=400)

        result = client.search_devices(search_type, search_value, limit)

        if "error" in result:
            return JsonResponse({"error": result["error"]}, status=400)

        # Check which devices already exist in NetBox
        devices = result.get("devices", [])
        for device in devices:
            hostname = device.get("hostname", "")
            serial = device.get("serial_number", "")

            # Check if device exists by hostname or serial
            existing = None
            if hostname:
                hostname_base = hostname.lower().replace(".ohsu.edu", "")
                existing = Device.objects.filter(name__iexact=hostname_base).first()
                if not existing:
                    existing = Device.objects.filter(name__iexact=hostname).first()

            if not existing and serial:
                existing = Device.objects.filter(serial=serial).first()

            device["exists_in_netbox"] = existing is not None
            device["netbox_device_id"] = existing.pk if existing else None
            device["netbox_device_url"] = existing.get_absolute_url() if existing else None

        return JsonResponse(result)


class ImportDevicesView(View):
    """Import devices from Catalyst Center to NetBox."""

    def post(self, request):
        """
        Import selected devices from Catalyst Center to NetBox.

        Request body (JSON):
            devices: Array of device objects from search results
            default_site_id: Site ID to assign devices to
            default_role_id: Device role ID (optional)
        """
        import json

        from dcim.models import DeviceRole, DeviceType, Interface, Manufacturer, Platform, Site

        try:
            body = json.loads(request.body) if request.body else {}
        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON"}, status=400)

        devices_to_import = body.get("devices", [])
        default_site_id = body.get("default_site_id")
        default_role_id = body.get("default_role_id")

        if not devices_to_import:
            return JsonResponse({"error": "No devices to import"}, status=400)

        # Enforce maximum import limit
        MAX_IMPORT_LIMIT = 25
        if len(devices_to_import) > MAX_IMPORT_LIMIT:
            return JsonResponse(
                {"error": f"Maximum {MAX_IMPORT_LIMIT} devices can be imported at a time"},
                status=400,
            )

        if not default_site_id:
            return JsonResponse({"error": "Default site is required"}, status=400)

        # Get default site
        try:
            default_site = Site.objects.get(pk=default_site_id)
        except Site.DoesNotExist:
            return JsonResponse({"error": "Site not found"}, status=400)

        # Get default role if specified
        default_role = None
        if default_role_id:
            try:
                default_role = DeviceRole.objects.get(pk=default_role_id)
            except DeviceRole.DoesNotExist:
                pass

        # Get or create Cisco manufacturer
        cisco_manufacturer, _ = Manufacturer.objects.get_or_create(
            slug="cisco",
            defaults={"name": "Cisco"},
        )

        results = {
            "created": [],
            "skipped": [],
            "errors": [],
        }

        for dnac_device in devices_to_import:
            hostname = dnac_device.get("hostname", "")
            serial = dnac_device.get("serial_number", "")
            platform = dnac_device.get("platform", "")
            management_ip = dnac_device.get("management_ip", "")
            software_type = dnac_device.get("software_type", "")
            software_version = dnac_device.get("software_version", "")

            # Deduplicate platform if it contains duplicates (e.g., "C9800-40-K9, C9800-40-K9")
            if platform and "," in platform:
                platform_parts = [p.strip() for p in platform.split(",")]
                # Remove duplicates while preserving order
                seen = set()
                unique_parts = []
                for p in platform_parts:
                    if p and p not in seen:
                        seen.add(p)
                        unique_parts.append(p)
                platform = ", ".join(unique_parts) if len(unique_parts) > 1 else unique_parts[0] if unique_parts else ""

            if not hostname:
                results["errors"].append({"device": dnac_device, "error": "No hostname"})
                continue

            # Normalize hostname (remove domain)
            hostname_base = hostname.replace(".ohsu.edu", "")

            # Check if device already exists
            existing = Device.objects.filter(name__iexact=hostname_base).first()
            if not existing and serial:
                existing = Device.objects.filter(serial=serial).first()

            if existing:
                results["skipped"].append(
                    {
                        "hostname": hostname_base,
                        "reason": "Already exists in NetBox",
                        "netbox_id": existing.pk,
                    }
                )
                continue

            # Get or create device type based on platform
            if platform:
                device_type, _ = DeviceType.objects.get_or_create(
                    manufacturer=cisco_manufacturer,
                    model=platform,
                    defaults={
                        "slug": platform.lower().replace(" ", "-").replace("/", "-"),
                    },
                )
            else:
                # Use generic type if platform unknown
                device_type, _ = DeviceType.objects.get_or_create(
                    manufacturer=cisco_manufacturer,
                    model="Unknown",
                    defaults={"slug": "cisco-unknown"},
                )

            # Determine device role from DNAC data if no default specified
            # Priority: device_family > role
            role = default_role
            if not role:
                device_family = dnac_device.get("device_family", "").lower()
                dnac_role = dnac_device.get("role", "").upper()

                # Family-based role mapping (most accurate)
                family_mapping = {
                    "wireless controller": "wireless-controller",
                    "switches and hubs": "access-switch",
                    "routers": "router",
                    "unified ap": "access-point",
                    "voice and telephony": "voice-gateway",
                }

                # Role-based mapping (fallback)
                role_mapping = {
                    "ACCESS": "access-switch",
                    "DISTRIBUTION": "distribution-switch",
                    "CORE": "core-switch",
                    "BORDER ROUTER": "router",
                    "UNKNOWN": "network-device",
                }

                # Try family first, then role
                role_slug = None
                for family_key, slug in family_mapping.items():
                    if family_key in device_family:
                        role_slug = slug
                        break

                if not role_slug:
                    role_slug = role_mapping.get(dnac_role, "network-device")

                role, _ = DeviceRole.objects.get_or_create(
                    slug=role_slug,
                    defaults={"name": role_slug.replace("-", " ").title()},
                )

            try:
                # Create or get platform if software info available
                device_platform = None
                if software_type and software_version:
                    # Get or create parent platform (software type)
                    parent_platform, _ = Platform.objects.get_or_create(
                        slug=software_type.lower().replace(" ", "-"),
                        defaults={"name": software_type},
                    )

                    # Get or create child platform (software version under parent)
                    child_slug = (
                        f"{software_type.lower()}-{software_version.lower()}".replace(" ", "-")
                        .replace("(", "")
                        .replace(")", "")
                    )
                    device_platform, _ = Platform.objects.get_or_create(
                        slug=child_slug,
                        defaults={
                            "name": software_version,
                            "parent": parent_platform,
                        },
                    )

                    # Update parent if it was created without one
                    if device_platform.parent != parent_platform:
                        device_platform.parent = parent_platform
                        device_platform.save()

                # Create the device
                new_device = Device(
                    name=hostname_base,
                    device_type=device_type,
                    role=role,
                    site=default_site,
                    serial=serial or "",
                    status="active",
                    platform=device_platform,
                    comments=f"Imported from Catalyst Center\nSNMP Location: {dnac_device.get('snmp_location', 'N/A')}",
                )
                new_device.save()

                # Populate custom fields
                from django.utils import timezone

                new_device.custom_field_data["cc_device_id"] = dnac_device.get("device_id", "")
                new_device.custom_field_data["cc_series"] = dnac_device.get("series", "")
                new_device.custom_field_data["cc_role"] = dnac_device.get("role", "")
                new_device.custom_field_data["cc_last_sync"] = timezone.now().isoformat()
                new_device.save()

                # Create a management interface (use 'other' type for management)
                mgmt_interface = Interface(
                    device=new_device,
                    name="Management",
                    type="other",
                )
                mgmt_interface.save()

                # Create IP address if available
                if management_ip:
                    ip_with_prefix = f"{management_ip}/32"
                    existing_ip = IPAddress.objects.filter(address=ip_with_prefix).first()

                    if existing_ip:
                        # IP exists - reassign to this device
                        existing_ip.assigned_object = mgmt_interface
                        existing_ip.save()
                        new_device.primary_ip4 = existing_ip
                    else:
                        # Create new IP
                        new_ip = IPAddress(
                            address=ip_with_prefix,
                            assigned_object=mgmt_interface,
                            description="Management IP from Catalyst Center",
                        )
                        new_ip.save()
                        new_device.primary_ip4 = new_ip

                    new_device.save()

                results["created"].append(
                    {
                        "hostname": hostname_base,
                        "netbox_id": new_device.pk,
                        "device_type": device_type.model,
                        "ip": management_ip,
                        "platform": f"{software_type}/{software_version}" if software_type else None,
                    }
                )

            except Exception as e:
                results["errors"].append(
                    {
                        "hostname": hostname_base,
                        "error": str(e),
                    }
                )

        return JsonResponse(
            {
                "success": True,
                "created_count": len(results["created"]),
                "skipped_count": len(results["skipped"]),
                "error_count": len(results["errors"]),
                "results": results,
            }
        )
