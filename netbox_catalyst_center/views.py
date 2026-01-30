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


def parse_interface_stack_member(interface_name):
    """
    Parse the stack member number from an interface name.

    Cisco stacked switches use interface naming like:
    - GigabitEthernet1/0/1 -> member 1
    - GigabitEthernet2/0/1 -> member 2
    - TenGigabitEthernet1/1/1 -> member 1

    The first number in the slot/port notation indicates the stack member.
    Logical interfaces (VLAN, Loopback, Tunnel, Port-channel, etc.) return None
    as they should be assigned to the master device.

    Args:
        interface_name: The interface name (e.g., "GigabitEthernet2/0/1")

    Returns:
        int: Stack member number (1-based), or None for logical interfaces
    """
    if not interface_name:
        return None

    # Logical/shared interfaces go to master (return None)
    # These are interfaces that don't belong to a specific stack member
    logical_prefixes = (
        "vlan",
        "loopback",
        "tunnel",
        "port-channel",
        "po",
        "nve",
        "bdi",
        "null",
        "mgmt",
        "management",
        "appgigabitethernet",  # App interfaces on controllers
        "stackport",  # Stack interconnect ports
        "stacksub",  # Stack sub-interfaces
        "cpu",  # CPU interfaces
        "ucse",  # UCS-E interfaces
        "embedded",  # Embedded service interfaces
        "internal",  # Internal interfaces
        "service",  # Service interfaces
        "async",  # Async interfaces
        "virtual",  # Virtual interfaces
        "pseudowire",  # Pseudowire interfaces
        "bvi",  # Bridge Virtual Interface
        "dialer",  # Dialer interfaces
        "virtual-access",  # Virtual access interfaces
        "virtual-template",  # Virtual template interfaces
    )
    iface_lower = interface_name.lower()
    if any(iface_lower.startswith(prefix) for prefix in logical_prefixes):
        return None

    # Subinterfaces (contain a dot) also go to master
    if "." in interface_name:
        return None

    # Physical interface pattern: InterfaceType<member>/<module>/<port>
    # Examples: GigabitEthernet1/0/1, TenGigabitEthernet2/1/1, FastEthernet1/0/1
    # The pattern captures the first number after the interface type name
    match = re.match(r"^[A-Za-z]+(\d+)/", interface_name)
    if match:
        return int(match.group(1))

    # If we can't parse the stack member, return None (goes to master as logical)
    # This is safer than guessing for unparseable interface names
    return None


def is_virtual_chassis_enabled():
    """Check if virtual chassis import is enabled in plugin configuration."""
    config = settings.PLUGINS_CONFIG.get("netbox_catalyst_center", {})
    return config.get("enable_virtual_chassis", False)


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
        device = (
            Device.objects.select_related("device_type__manufacturer", "platform", "primary_ip4", "primary_ip6")
            .prefetch_related("interfaces")
            .get(pk=pk)
        )

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

                # Use VC name for virtual chassis members (original hostname)
                lookup_hostname = device.virtual_chassis.name if device.virtual_chassis else device.name
                client_data = client.get_network_device(lookup_hostname, management_ip=management_ip)
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

        # For VC members, extract the member-specific serial for sync comparison
        if client_data and client_data.get("serial_number") and device.virtual_chassis and device.vc_position:
            serial_list = [s.strip() for s in client_data["serial_number"].split(",") if s.strip()]
            if device.vc_position <= len(serial_list):
                client_data["sync_serial_number"] = serial_list[device.vc_position - 1]
            else:
                client_data["sync_serial_number"] = client_data["serial_number"]
        elif client_data and client_data.get("serial_number"):
            # Non-VC device uses full serial
            client_data["sync_serial_number"] = client_data["serial_number"]

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
        platform (software type/version), custom fields, and interfaces.
        """
        import traceback

        try:
            device = Device.objects.get(pk=pk)
        except Device.DoesNotExist:
            return JsonResponse({"success": False, "error": "Device not found"}, status=404)

        try:
            return self._do_sync(request, device)
        except Exception as e:
            return JsonResponse(
                {
                    "success": False,
                    "error": f"Sync failed: {str(e)}",
                    "traceback": traceback.format_exc(),
                },
                status=500,
            )

    def _do_sync(self, request, device):
        """Internal method to perform the actual sync."""
        import json

        from dcim.models import DeviceType, Manufacturer, Platform

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
        sync_cc_id = body.get("sync_cc_id", False)
        sync_cc_series = body.get("sync_cc_series", False)
        sync_cc_role = body.get("sync_cc_role", False)
        sync_interfaces = body.get("sync_interfaces", False)
        overwrite_ips = body.get("overwrite_ips", False)
        sync_poe = body.get("sync_poe", False)

        client = get_client()
        if not client:
            return JsonResponse(
                {"success": False, "error": "Catalyst Center not configured"},
                status=400,
            )

        # Get device data from DNAC
        lookup_method, _ = get_device_lookup_method(device)

        if lookup_method == "network_device":
            # Get management IP for lookup
            management_ip = None
            if device.primary_ip4:
                management_ip = str(device.primary_ip4.address.ip)
            elif device.primary_ip6:
                management_ip = str(device.primary_ip6.address.ip)

            # Use VC name for virtual chassis members (original hostname)
            lookup_hostname = device.virtual_chassis.name if device.virtual_chassis else device.name
            dnac_data = client.get_network_device(lookup_hostname, management_ip=management_ip)
        elif lookup_method == "client":
            mac_address = get_device_mac(device)
            if mac_address:
                dnac_data = client.get_client_detail(mac_address)
            else:
                return JsonResponse({"success": False, "error": "No MAC address found"}, status=400)
        else:
            return JsonResponse(
                {"success": False, "error": "Device not configured for DNAC lookup"},
                status=400,
            )

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
            if dnac_serial:
                # For VC members, extract the serial for this specific member
                if device.virtual_chassis and device.vc_position:
                    serial_list = [s.strip() for s in dnac_serial.split(",") if s.strip()]
                    member_serial = (
                        serial_list[device.vc_position - 1] if device.vc_position <= len(serial_list) else ""
                    )
                    if member_serial and device.serial != member_serial:
                        device.serial = member_serial
                        changes.append(f"Serial: {member_serial}")
                        device_changed = True
                elif device.serial != dnac_serial:
                    # Non-VC device - use full serial (may be comma-separated for stacks)
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

        # Sync custom fields (individual fields)
        if sync_cc_id or sync_cc_series or sync_cc_role:
            cf_changes = self._sync_custom_fields(device, dnac_data, sync_cc_id, sync_cc_series, sync_cc_role)
            changes.extend(cf_changes)
            if cf_changes:
                device_changed = True

        # Save device if any changes were made
        if device_changed:
            device.save()

        # Sync interfaces (after device save, as interfaces are separate objects)
        if sync_interfaces:
            device_id = dnac_data.get("device_id")
            if device_id:
                try:
                    iface_result = self._sync_interfaces(device, client, device_id, overwrite_ips=overwrite_ips)
                    changes.extend(iface_result.get("changes", []))
                except Exception as e:
                    changes.append(f"Interfaces: error - {str(e)}")
            else:
                changes.append("Interfaces: skipped (no device ID)")

        # Sync POE data (separate API call)
        if sync_poe:
            device_id = dnac_data.get("device_id")
            if device_id:
                try:
                    poe_result = self._sync_poe(device, client, device_id)
                    changes.extend(poe_result.get("changes", []))
                except Exception as e:
                    changes.append(f"POE: error - {str(e)}")
            else:
                changes.append("POE: skipped (no device ID)")

        if not changes:
            return JsonResponse(
                {
                    "success": True,
                    "message": "No changes needed - device is already in sync",
                    "changes": [],
                }
            )

        return JsonResponse(
            {
                "success": True,
                "message": f"Synced {len(changes)} field(s) from Catalyst Center",
                "changes": changes,
            }
        )

    def _sync_custom_fields(self, device, dnac_data, sync_id=True, sync_series=True, sync_role=True):
        """Sync Catalyst Center custom fields. Returns list of change descriptions."""
        from django.utils import timezone
        from extras.models import Tag

        changes = []

        # Sync individual fields based on flags
        if sync_id:
            new_id = dnac_data.get("device_id")
            if new_id:
                current_value = device.custom_field_data.get("cc_device_id")
                if current_value != new_id:
                    device.custom_field_data["cc_device_id"] = new_id
                    changes.append(f"Catalyst Center ID: {new_id[:20]}...")

                # Add Catalyst Center tag when cc_device_id is synced
                cc_tag, _ = Tag.objects.get_or_create(
                    slug="catalyst-center",
                    defaults={
                        "name": "Catalyst Center",
                        "color": "00bcd4",  # Cisco teal
                        "description": "Device imported from or managed by Cisco Catalyst Center",
                    },
                )
                if cc_tag not in device.tags.all():
                    device.tags.add(cc_tag)
                    changes.append("Tag: catalyst-center (added)")

        if sync_series:
            new_series = dnac_data.get("series")
            if new_series:
                current_value = device.custom_field_data.get("cc_series")
                if current_value != new_series:
                    device.custom_field_data["cc_series"] = new_series
                    changes.append(f"Catalyst Center Series: {new_series}")

        if sync_role:
            new_role = dnac_data.get("role")
            if new_role:
                current_value = device.custom_field_data.get("cc_role")
                if current_value != new_role:
                    device.custom_field_data["cc_role"] = new_role
                    changes.append(f"Catalyst Center Role: {new_role}")

        # Update last sync time when any custom field is synced
        if changes:
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

    def _sync_interfaces(self, device, client, device_id, overwrite_ips=False):
        """
        Sync interfaces from Catalyst Center to NetBox device.

        Args:
            device: NetBox Device object
            client: Catalyst Center client
            device_id: Catalyst Center device ID
            overwrite_ips: If True, remove IPs on synced interfaces that aren't in CC data

        Returns dict with "changes" list.
        """
        from dcim.models import Interface

        changes = []

        # Fetch interfaces from CC
        iface_result = client.get_device_interfaces(device_id)
        if "error" in iface_result:
            changes.append(f"Interfaces: error - {iface_result['error']}")
            return {"changes": changes}

        cc_interfaces = iface_result.get("interfaces", [])
        if not cc_interfaces:
            changes.append("Interfaces: none found in CC")
            return {"changes": changes}

        # For VC members, filter interfaces to only those belonging to this member
        if device.virtual_chassis and device.vc_position:
            member_num = device.vc_position
            is_master = device.virtual_chassis.master == device
            filtered_interfaces = []
            for iface in cc_interfaces:
                iface_name = iface.get("name", "")
                slot_num = parse_interface_stack_member(iface_name)
                if slot_num == member_num:
                    # Physical interface belongs to this member
                    filtered_interfaces.append(iface)
                elif slot_num is None and is_master:
                    # Logical interface (VLAN, Loopback, Port-channel) - assign to master only
                    filtered_interfaces.append(iface)
            cc_interfaces = filtered_interfaces

        # Get existing interfaces on device - build lookup with both original and normalized names
        existing_interfaces = {}
        for iface in device.interfaces.all():
            existing_interfaces[iface.name] = iface
            # Also map normalized name to interface for matching
            normalized = self._normalize_interface_name(iface.name)
            if normalized != iface.name:
                existing_interfaces[normalized] = iface

        created_count = 0
        updated_count = 0
        skipped_count = 0

        # Track interfaces and their synced IPs for overwrite mode
        # Maps interface pk -> set of IP addresses (without prefix) synced from CC
        synced_interface_ips = {}

        for cc_iface in cc_interfaces:
            iface_name = cc_iface.get("name")
            if not iface_name:
                continue

            # Map CC interface type to NetBox type
            netbox_type = self._map_interface_type(cc_iface)

            # Check if interface exists - try both original and normalized name
            normalized_name = self._normalize_interface_name(iface_name)
            nb_iface = existing_interfaces.get(iface_name) or existing_interfaces.get(normalized_name)

            if nb_iface:
                iface_updated = False

                # Update type if different
                if nb_iface.type != netbox_type:
                    nb_iface.type = netbox_type
                    iface_updated = True

                # Update MAC if available and different
                cc_mac = self._normalize_mac(cc_iface.get("mac_address"))
                if cc_mac and str(nb_iface.mac_address).upper() != cc_mac:
                    nb_iface.mac_address = cc_mac
                    iface_updated = True

                # Update description if available
                cc_desc = cc_iface.get("description")
                if cc_desc and nb_iface.description != cc_desc:
                    nb_iface.description = cc_desc
                    iface_updated = True

                # Update MTU if available
                cc_mtu = self._convert_mtu(cc_iface.get("mtu"))
                if cc_mtu and nb_iface.mtu != cc_mtu:
                    nb_iface.mtu = cc_mtu
                    iface_updated = True

                # Update speed if available
                cc_speed = cc_iface.get("speed")
                if cc_speed:
                    speed_kbps = self._convert_speed_to_kbps(cc_speed)
                    if speed_kbps and nb_iface.speed != speed_kbps:
                        nb_iface.speed = speed_kbps
                        iface_updated = True

                # Update duplex if available
                cc_duplex = cc_iface.get("duplex")
                if cc_duplex:
                    nb_duplex = self._map_duplex(cc_duplex)
                    if nb_duplex and nb_iface.duplex != nb_duplex:
                        nb_iface.duplex = nb_duplex
                        iface_updated = True

                # Update enabled status
                admin_status = cc_iface.get("admin_status", "").upper()
                is_enabled = admin_status == "UP"
                if nb_iface.enabled != is_enabled:
                    nb_iface.enabled = is_enabled
                    iface_updated = True

                # Update mode (access/tagged/trunk) if available
                cc_port_mode = cc_iface.get("port_mode")
                if cc_port_mode:
                    nb_mode = self._map_port_mode(cc_port_mode)
                    if nb_mode and nb_iface.mode != nb_mode:
                        nb_iface.mode = nb_mode
                        iface_updated = True

                if iface_updated:
                    nb_iface.save()
                    updated_count += 1
                else:
                    skipped_count += 1

                # Sync IP address for existing interface (update mask if changed)
                ip_addr = cc_iface.get("ip_address")
                ip_mask = cc_iface.get("ip_mask")
                if ip_addr and ip_mask:
                    self._sync_interface_ip(nb_iface, ip_addr, ip_mask)
                    # Track this IP for overwrite mode
                    if nb_iface.pk not in synced_interface_ips:
                        synced_interface_ips[nb_iface.pk] = set()
                    synced_interface_ips[nb_iface.pk].add(ip_addr)
                elif overwrite_ips:
                    # Interface has no IP in CC, track for deletion
                    if nb_iface.pk not in synced_interface_ips:
                        synced_interface_ips[nb_iface.pk] = set()
            else:
                # Create new interface
                admin_status = cc_iface.get("admin_status", "").upper()
                is_enabled = admin_status == "UP"

                new_iface = Interface(
                    device=device,
                    name=iface_name,
                    type=netbox_type,
                    description=cc_iface.get("description") or "",
                    mtu=self._convert_mtu(cc_iface.get("mtu")),
                    enabled=is_enabled,
                )

                # Set MAC address (not accepted in constructor)
                cc_mac = self._normalize_mac(cc_iface.get("mac_address"))
                if cc_mac:
                    new_iface.mac_address = cc_mac

                # Set speed
                cc_speed = cc_iface.get("speed")
                if cc_speed:
                    new_iface.speed = self._convert_speed_to_kbps(cc_speed)

                # Set duplex
                cc_duplex = cc_iface.get("duplex")
                if cc_duplex:
                    new_iface.duplex = self._map_duplex(cc_duplex)

                # Set mode (access/tagged/trunk)
                cc_port_mode = cc_iface.get("port_mode")
                if cc_port_mode:
                    nb_mode = self._map_port_mode(cc_port_mode)
                    if nb_mode:
                        new_iface.mode = nb_mode

                new_iface.save()
                created_count += 1

                # Create IP address if available
                ip_addr = cc_iface.get("ip_address")
                ip_mask = cc_iface.get("ip_mask")
                if ip_addr and ip_mask:
                    self._create_interface_ip(new_iface, ip_addr, ip_mask)
                    # Track this IP for overwrite mode (new interfaces won't have IPs to delete)
                    if new_iface.pk not in synced_interface_ips:
                        synced_interface_ips[new_iface.pk] = set()
                    synced_interface_ips[new_iface.pk].add(ip_addr)

        # Set LAG membership for interfaces that belong to port-channels
        lag_count = 0
        # Re-fetch interfaces to get updated list including newly created ones
        all_interfaces = {iface.name: iface for iface in device.interfaces.all()}

        for cc_iface in cc_interfaces:
            mapped_lag_name = cc_iface.get("mapped_physical_interface_name")
            iface_name = cc_iface.get("name")

            if mapped_lag_name and iface_name and iface_name in all_interfaces:
                # Find the LAG interface
                if mapped_lag_name in all_interfaces:
                    lag_iface = all_interfaces[mapped_lag_name]
                    member_iface = all_interfaces[iface_name]

                    # Only set if not already set
                    if member_iface.lag != lag_iface:
                        member_iface.lag = lag_iface
                        member_iface.save()
                        lag_count += 1

        # If overwrite_ips is enabled, delete IPs on synced interfaces that aren't in CC data
        deleted_ip_count = 0
        if overwrite_ips and synced_interface_ips:
            from dcim.models import Interface

            for iface_pk, cc_ips in synced_interface_ips.items():
                try:
                    iface = Interface.objects.get(pk=iface_pk)
                    # Get all IPs currently assigned to this interface
                    for ip in iface.ip_addresses.all():
                        ip_addr_str = str(ip.address.ip)  # Get IP without prefix
                        if ip_addr_str not in cc_ips:
                            # This IP is not in CC data - delete it
                            ip.delete()
                            deleted_ip_count += 1
                except Interface.DoesNotExist:
                    pass

        # Summary
        summary_parts = []
        if created_count:
            summary_parts.append(f"{created_count} created")
        if updated_count:
            summary_parts.append(f"{updated_count} updated")
        if skipped_count:
            summary_parts.append(f"{skipped_count} unchanged")
        if lag_count:
            summary_parts.append(f"{lag_count} LAG members set")

        if summary_parts:
            changes.append(f"Interfaces: {', '.join(summary_parts)}")
        else:
            changes.append("Interfaces: no changes")

        # Add deleted IPs to changes if any
        if deleted_ip_count:
            changes.append(f"IPs removed: {deleted_ip_count} (not in Catalyst Center)")

        # Create journal entry with CC interface data
        self._create_interface_journal(device, cc_interfaces, created_count, updated_count)

        return {"changes": changes}

    def _sync_interfaces_virtual_chassis(self, master_device, member_devices, client, device_id):
        """
        Sync interfaces from Catalyst Center to Virtual Chassis member devices.

        Physical interfaces are assigned to member devices based on the slot number
        parsed from the interface name (e.g., GigabitEthernet2/0/1 -> member 2).
        Logical interfaces (VLANs, Loopbacks, Port-channels, etc.) are assigned to
        the master device.

        Args:
            master_device: The master device of the virtual chassis
            member_devices: Dict mapping vc_position to Device objects
            client: Catalyst Center client
            device_id: CC device ID

        Returns:
            dict with "changes" list
        """
        from dcim.models import Interface

        changes = []

        # Fetch interfaces from CC
        iface_result = client.get_device_interfaces(device_id)
        if "error" in iface_result:
            changes.append(f"Interfaces: error - {iface_result['error']}")
            return {"changes": changes}

        cc_interfaces = iface_result.get("interfaces", [])
        if not cc_interfaces:
            changes.append("Interfaces: none found in CC")
            return {"changes": changes}

        created_count = 0
        updated_count = 0
        skipped_count = 0

        # Track interfaces per device for LAG membership
        device_interfaces = {dev.pk: {} for dev in member_devices.values()}

        for cc_iface in cc_interfaces:
            iface_name = cc_iface.get("name")
            if not iface_name:
                continue

            # Determine which device this interface belongs to
            member_num = parse_interface_stack_member(iface_name)

            if member_num is None:
                # Logical interface goes to master
                target_device = master_device
            elif member_num in member_devices:
                target_device = member_devices[member_num]
            else:
                # Interface references a member we don't have - assign to master
                target_device = master_device

            # Map CC interface type to NetBox type
            netbox_type = self._map_interface_type(cc_iface)

            # Get existing interfaces on target device - build lookup with both original and normalized names
            existing_interfaces = {}
            for iface in target_device.interfaces.all():
                existing_interfaces[iface.name] = iface
                normalized = self._normalize_interface_name(iface.name)
                if normalized != iface.name:
                    existing_interfaces[normalized] = iface

            # Check if interface exists - try both original and normalized name
            normalized_name = self._normalize_interface_name(iface_name)
            nb_iface = existing_interfaces.get(iface_name) or existing_interfaces.get(normalized_name)

            if nb_iface:
                iface_updated = False

                # Update type if different
                if nb_iface.type != netbox_type:
                    nb_iface.type = netbox_type
                    iface_updated = True

                # Update MAC if available and different
                cc_mac = self._normalize_mac(cc_iface.get("mac_address"))
                if cc_mac and str(nb_iface.mac_address).upper() != cc_mac:
                    nb_iface.mac_address = cc_mac
                    iface_updated = True

                # Update description if available
                cc_desc = cc_iface.get("description")
                if cc_desc and nb_iface.description != cc_desc:
                    nb_iface.description = cc_desc
                    iface_updated = True

                # Update MTU if available
                cc_mtu = self._convert_mtu(cc_iface.get("mtu"))
                if cc_mtu and nb_iface.mtu != cc_mtu:
                    nb_iface.mtu = cc_mtu
                    iface_updated = True

                # Update speed if available
                cc_speed = cc_iface.get("speed")
                if cc_speed:
                    speed_kbps = self._convert_speed_to_kbps(cc_speed)
                    if speed_kbps and nb_iface.speed != speed_kbps:
                        nb_iface.speed = speed_kbps
                        iface_updated = True

                # Update duplex if available
                cc_duplex = cc_iface.get("duplex")
                if cc_duplex:
                    nb_duplex = self._map_duplex(cc_duplex)
                    if nb_duplex and nb_iface.duplex != nb_duplex:
                        nb_iface.duplex = nb_duplex
                        iface_updated = True

                # Update enabled status
                admin_status = cc_iface.get("admin_status", "").upper()
                is_enabled = admin_status == "UP"
                if nb_iface.enabled != is_enabled:
                    nb_iface.enabled = is_enabled
                    iface_updated = True

                # Update mode (access/tagged/trunk) if available
                cc_port_mode = cc_iface.get("port_mode")
                if cc_port_mode:
                    nb_mode = self._map_port_mode(cc_port_mode)
                    if nb_mode and nb_iface.mode != nb_mode:
                        nb_iface.mode = nb_mode
                        iface_updated = True

                if iface_updated:
                    nb_iface.save()
                    updated_count += 1
                else:
                    skipped_count += 1

                # Sync IP address for existing interface (update mask if changed)
                ip_addr = cc_iface.get("ip_address")
                ip_mask = cc_iface.get("ip_mask")
                if ip_addr and ip_mask:
                    self._sync_interface_ip(nb_iface, ip_addr, ip_mask)

                # Track for LAG membership
                device_interfaces[target_device.pk][iface_name] = nb_iface
            else:
                # Create new interface
                admin_status = cc_iface.get("admin_status", "").upper()
                is_enabled = admin_status == "UP"

                new_iface = Interface(
                    device=target_device,
                    name=iface_name,
                    type=netbox_type,
                    description=cc_iface.get("description") or "",
                    mtu=self._convert_mtu(cc_iface.get("mtu")),
                    enabled=is_enabled,
                )

                # Set MAC address
                cc_mac = self._normalize_mac(cc_iface.get("mac_address"))
                if cc_mac:
                    new_iface.mac_address = cc_mac

                # Set speed
                cc_speed = cc_iface.get("speed")
                if cc_speed:
                    new_iface.speed = self._convert_speed_to_kbps(cc_speed)

                # Set duplex
                cc_duplex = cc_iface.get("duplex")
                if cc_duplex:
                    new_iface.duplex = self._map_duplex(cc_duplex)

                # Set mode (access/tagged/trunk)
                cc_port_mode = cc_iface.get("port_mode")
                if cc_port_mode:
                    nb_mode = self._map_port_mode(cc_port_mode)
                    if nb_mode:
                        new_iface.mode = nb_mode

                new_iface.save()
                created_count += 1

                # Track for LAG membership
                device_interfaces[target_device.pk][iface_name] = new_iface

                # Create IP address if available
                ip_addr = cc_iface.get("ip_address")
                ip_mask = cc_iface.get("ip_mask")
                if ip_addr and ip_mask:
                    self._create_interface_ip(new_iface, ip_addr, ip_mask)

        # Set LAG membership for interfaces that belong to port-channels
        # Port-channels are logical interfaces assigned to master
        lag_count = 0
        master_interfaces = {iface.name: iface for iface in master_device.interfaces.all()}

        for cc_iface in cc_interfaces:
            mapped_lag_name = cc_iface.get("mapped_physical_interface_name")
            iface_name = cc_iface.get("name")

            if mapped_lag_name and iface_name:
                # Find which device has this interface
                member_iface = None
                for dev_ifaces in device_interfaces.values():
                    if iface_name in dev_ifaces:
                        member_iface = dev_ifaces[iface_name]
                        break

                # LAG interface should be on master
                lag_iface = master_interfaces.get(mapped_lag_name)

                if member_iface and lag_iface and member_iface.lag != lag_iface:
                    member_iface.lag = lag_iface
                    member_iface.save()
                    lag_count += 1

        # Summary
        summary_parts = []
        if created_count:
            summary_parts.append(f"{created_count} created")
        if updated_count:
            summary_parts.append(f"{updated_count} updated")
        if skipped_count:
            summary_parts.append(f"{skipped_count} unchanged")
        if lag_count:
            summary_parts.append(f"{lag_count} LAG members set")

        if summary_parts:
            changes.append(f"Interfaces: {', '.join(summary_parts)}")
        else:
            changes.append("Interfaces: no changes")

        # Create journal entry on master with CC interface data
        self._create_interface_journal(master_device, cc_interfaces, created_count, updated_count)

        return {"changes": changes}

    def _create_interface_journal(self, device, cc_interfaces, created_count, updated_count):
        """Create a journal entry on the device with CC interface sync data."""
        import json

        from extras.models import JournalEntry

        try:
            # Build summary of interfaces with key fields
            interface_summary = []
            for iface in cc_interfaces[:50]:  # Limit to first 50 to avoid huge entries
                summary = {
                    "name": iface.get("name"),
                    "status": iface.get("status"),
                    "speed": iface.get("speed"),
                    "duplex": iface.get("duplex"),
                    "mac": iface.get("mac_address"),
                    "ip": iface.get("ip_address"),
                    "type": iface.get("interface_type"),
                    "port_mode": iface.get("port_mode"),
                    "vlan": iface.get("vlan_id"),
                    "poe": iface.get("poe_enabled"),
                }
                # Remove None values for cleaner output
                summary = {k: v for k, v in summary.items() if v is not None}
                interface_summary.append(summary)

            # Create journal entry
            comments = "**Catalyst Center Interface Sync**\n\n"
            comments += f"- Created: {created_count}\n"
            comments += f"- Updated: {updated_count}\n"
            comments += f"- Total from CC: {len(cc_interfaces)}\n\n"
            comments += "**Interface Data (JSON):**\n```json\n"
            comments += json.dumps(interface_summary, indent=2)
            comments += "\n```"

            if len(cc_interfaces) > 50:
                comments += f"\n\n*Note: Showing first 50 of {len(cc_interfaces)} interfaces*"

            JournalEntry.objects.create(
                assigned_object=device,
                kind="info",
                comments=comments,
            )
        except Exception as e:
            # Don't fail the sync if journal creation fails
            import logging

            logging.getLogger(__name__).warning(f"Failed to create journal entry: {e}")

    def _map_interface_type(self, cc_iface):
        """Map Catalyst Center interface to NetBox interface type.

        Priority: name-based detection first (definitive), then speed-based fallback.
        Interface names like FortyGigabitEthernet are definitive regardless of
        current negotiated speed (which may be low if port is disconnected).
        """
        name = cc_iface.get("name", "").lower()
        iface_type = cc_iface.get("interface_type", "").lower()
        port_type = cc_iface.get("port_type", "").lower()
        speed = cc_iface.get("speed")

        # Subinterfaces (e.g., TenGigabitEthernet1/1/8.2012) are virtual
        # Check for "." followed by digits indicating a VLAN subinterface
        if re.match(r".+\.\d+$", name):
            return "virtual"

        # LAG / Port-channel
        if "port-channel" in name or name.split("/")[0] in ("po", "port-channel"):
            return "lag"

        # VLAN SVI
        if name.startswith("vlan") or (iface_type == "virtual" and "svi" in port_type):
            return "virtual"

        # Loopback
        if "loopback" in name or name.startswith("lo"):
            return "virtual"

        # Tunnel
        if "tunnel" in name:
            return "virtual"

        # Null interfaces
        if "null" in name:
            return "virtual"

        # BDI (Bridge Domain Interface)
        if name.startswith("bdi"):
            return "virtual"

        # NVE (Network Virtualization Edge)
        if name.startswith("nve"):
            return "virtual"

        # Bluetooth interfaces (IEEE 802.15.1)
        if name.startswith("bluetooth"):
            return "ieee802.15.1"

        # Name-based detection FIRST (interface names are definitive)
        # Extract the interface type prefix before any numbers
        name_prefix = re.sub(r"\d.*", "", name)  # Remove from first digit onwards

        # Check for specific high-speed interface types by name
        # These names definitively identify the port type regardless of negotiated speed
        if name_prefix in ("hundredgigabitethernet", "hundredgige", "hu"):
            return "100gbase-x-qsfp28"
        elif name_prefix in ("fortygigabitethernet", "fortygige", "fo"):
            return "40gbase-x-qsfpp"
        elif name_prefix in ("twentyfivegigabitethernet", "twentyfivegige", "twe"):
            return "25gbase-x-sfp28"
        elif name_prefix in ("tengigabitethernet", "tengige", "te"):
            return "10gbase-x-sfpp"
        elif name_prefix in ("fivegigabitethernet", "fivegige", "fi"):
            return "5gbase-t"
        elif name_prefix in ("twopointfivegigabitethernet", "twogige", "two"):
            return "2.5gbase-t"
        elif name_prefix in ("gigabitethernet", "gi", "ge"):
            return "1000base-t"
        elif name_prefix in ("fastethernet", "fa"):
            return "100base-tx"

        # For generic "ethernet" or unknown names, use speed-based detection
        if speed:
            try:
                speed_int = int(speed)
                if speed_int >= 100000000000:  # 100G+
                    return "100gbase-x-qsfp28"
                elif speed_int >= 40000000000:  # 40G
                    return "40gbase-x-qsfpp"
                elif speed_int >= 25000000000:  # 25G
                    return "25gbase-x-sfp28"
                elif speed_int >= 10000000000:  # 10G
                    return "10gbase-x-sfpp"
                elif speed_int >= 1000000000:  # 1G
                    return "1000base-t"
                elif speed_int >= 100000000:  # 100M
                    return "100base-tx"
                elif speed_int >= 10000000:  # 10M
                    return "10base-t"
            except (ValueError, TypeError):
                pass

        # Generic ethernet with no speed info
        if name_prefix in ("ethernet", "eth"):
            return "1000base-t"  # Default for generic "ethernet"

        # Default
        return "other"

    def _map_duplex(self, cc_duplex):
        """Map CC duplex to NetBox duplex."""
        if not cc_duplex:
            return None
        duplex_lower = cc_duplex.lower()
        if "full" in duplex_lower:
            return "full"
        elif "half" in duplex_lower:
            return "half"
        elif "auto" in duplex_lower:
            return "auto"
        return None

    def _convert_speed_to_kbps(self, speed_bps):
        """Convert speed from bps (string) to kbps (int)."""
        if not speed_bps:
            return None
        try:
            bps = int(speed_bps)
            return bps // 1000  # Convert bps to kbps
        except (ValueError, TypeError):
            return None

    def _convert_mtu(self, mtu_value):
        """Convert MTU to integer, handling string values from CC API."""
        if not mtu_value:
            return None
        try:
            return int(mtu_value)
        except (ValueError, TypeError):
            return None

    def _normalize_interface_name(self, name):
        """
        Normalize Cisco interface name from abbreviated to full form.

        Cisco devices may report abbreviated interface names (Lo0, Gi1/0/1)
        while NetBox may have full names (Loopback0, GigabitEthernet1/0/1).
        This normalizes to the full form for consistent matching.
        """
        if not name:
            return name

        import re

        # Map of abbreviated prefixes to full names
        # Order matters - check longer prefixes first
        prefix_map = [
            (r"^Tw(\d)", r"TwentyFiveGigE\1"),
            (r"^Te(\d)", r"TenGigabitEthernet\1"),
            (r"^Gi(\d)", r"GigabitEthernet\1"),
            (r"^Fa(\d)", r"FastEthernet\1"),
            (r"^Eth(\d)", r"Ethernet\1"),
            (r"^Lo(\d)", r"Loopback\1"),
            (r"^Vl(\d)", r"Vlan\1"),
            (r"^Po(\d)", r"Port-channel\1"),
            (r"^Tu(\d)", r"Tunnel\1"),
            (r"^Nv(\d)", r"nve\1"),
            (r"^mgmt(\d)", r"mgmt\1"),
        ]

        for pattern, replacement in prefix_map:
            if re.match(pattern, name, re.IGNORECASE):
                return re.sub(pattern, replacement, name, flags=re.IGNORECASE)

        return name

    def _normalize_mac(self, mac_address):
        """Normalize MAC address to NetBox format (AA:BB:CC:DD:EE:FF)."""
        if not mac_address:
            return None
        # Remove common separators and convert to uppercase
        cleaned = mac_address.upper().replace(":", "").replace("-", "").replace(".", "")
        if len(cleaned) != 12:
            return None
        # Format as AA:BB:CC:DD:EE:FF
        return ":".join(cleaned[i : i + 2] for i in range(0, 12, 2))

    def _map_port_mode(self, cc_port_mode):
        """
        Map CC port mode to NetBox interface mode.

        CC portMode: "access", "trunk", "routed", "dynamic auto", "dynamic desirable", etc.
        NetBox mode: "access", "tagged", "tagged-all"
        """
        if not cc_port_mode:
            return None

        mode_lower = cc_port_mode.lower()

        if mode_lower == "access":
            return "access"
        elif mode_lower == "trunk":
            return "tagged"
        elif mode_lower in ("routed", "layer3"):
            # L3 routed interfaces don't have a VLAN mode in NetBox
            return None
        elif "dynamic" in mode_lower:
            # Dynamic modes - could be either, default to tagged
            return "tagged"

        return None

    def _create_interface_ip(self, interface, ip_addr, ip_mask):
        """Create IP address and assign to interface (for new interfaces)."""
        self._sync_interface_ip(interface, ip_addr, ip_mask)

    def _sync_interface_ip(self, interface, ip_addr, ip_mask):
        """
        Sync IP address on interface - create or update as needed.

        If the IP already exists on this interface with a different prefix,
        update the prefix. If it exists elsewhere, reassign it. If it doesn't
        exist, create it.
        """
        import netaddr

        # Convert subnet mask to prefix length
        prefix_len = self._mask_to_prefix(ip_mask)
        if not prefix_len:
            return

        ip_with_prefix = f"{ip_addr}/{prefix_len}"

        # First check if this exact IP (with same prefix) already exists
        existing_ip = IPAddress.objects.filter(address=ip_with_prefix).first()
        if existing_ip:
            # Update assignment if not already assigned to this interface
            if existing_ip.assigned_object != interface:
                existing_ip.assigned_object = interface
                existing_ip.save()
            return

        # Check if the same IP address exists with a different prefix on this interface
        # NetBox stores IPs as network objects, so we need to find by the IP part
        for iface_ip in interface.ip_addresses.all():
            # Compare the IP address part (without prefix)
            if str(iface_ip.address.ip) == ip_addr:
                # Same IP, different prefix - update the prefix
                old_prefix = iface_ip.address.prefixlen
                if old_prefix != prefix_len:
                    # Update the address with new prefix
                    iface_ip.address = netaddr.IPNetwork(ip_with_prefix)
                    iface_ip.save()
                return

        # Check if IP exists elsewhere (different interface or unassigned)
        # Search for any IP that matches the address regardless of prefix
        for existing in IPAddress.objects.filter(address__startswith=f"{ip_addr}/"):
            if str(existing.address.ip) == ip_addr:
                # Found it - update prefix and reassign
                existing.address = netaddr.IPNetwork(ip_with_prefix)
                existing.assigned_object = interface
                existing.save()
                return

        # IP doesn't exist at all - create new
        new_ip = IPAddress(
            address=ip_with_prefix,
            assigned_object=interface,
            description="Synced from Catalyst Center",
        )
        new_ip.save()

    def _mask_to_prefix(self, mask):
        """Convert subnet mask to prefix length."""
        if not mask:
            return None
        try:
            # Count the number of 1 bits in the mask
            octets = mask.split(".")
            if len(octets) != 4:
                return None
            binary = "".join(format(int(octet), "08b") for octet in octets)
            return binary.count("1")
        except (ValueError, AttributeError):
            return None

    def _sync_poe(self, device, client, device_id):
        """
        Sync POE data from Catalyst Center to NetBox interfaces.

        This requires a separate API call to get POE details.
        Updates poe_mode and poe_type on matching interfaces.

        Returns dict with "changes" list.
        """
        changes = []

        # Fetch POE details from CC
        poe_result = client.get_device_poe_detail(device_id)
        if "error" in poe_result:
            changes.append(f"POE: error - {poe_result['error']}")
            return {"changes": changes}

        poe_interfaces = poe_result.get("poe_interfaces", [])
        if not poe_interfaces:
            changes.append("POE: no POE ports found")
            return {"changes": changes}

        # For VC members, filter POE interfaces to only those belonging to this member
        if device.virtual_chassis and device.vc_position:
            member_num = device.vc_position
            filtered_poe = []
            for poe_data in poe_interfaces:
                iface_name = poe_data.get("interface_name", "")
                slot_num = parse_interface_stack_member(iface_name)
                if slot_num == member_num:
                    filtered_poe.append(poe_data)
            poe_interfaces = filtered_poe

        # Get existing interfaces on device by name
        existing_interfaces = {iface.name: iface for iface in device.interfaces.all()}

        updated_count = 0
        skipped_count = 0
        interfaces_to_update = []

        for poe_data in poe_interfaces:
            iface_name = poe_data.get("interface_name")
            if not iface_name or iface_name not in existing_interfaces:
                skipped_count += 1
                continue

            nb_iface = existing_interfaces[iface_name]
            iface_updated = False

            # If a port appears in the POE API response, it's a POE-capable port
            # Set poe_mode to PSE (Power Sourcing Equipment) for all switch POE ports
            new_poe_mode = "pse"
            if nb_iface.poe_mode != new_poe_mode:
                nb_iface.poe_mode = new_poe_mode
                iface_updated = True

            # Map IEEE class to NetBox poe_type
            # CC ieee_class: "class0", "class1", "class2", "class3", "class4", "class5", "class6", etc.
            # NetBox poe_type: "type1-ieee802.3af", "type2-ieee802.3at", "type3-ieee802.3bt", "type4-ieee802.3bt"
            ieee_class = (poe_data.get("ieee_class") or "").lower()
            four_pair = poe_data.get("four_pair_enabled") or False
            max_port_power = poe_data.get("max_port_power")

            poe_type = None
            if ieee_class:
                # If device is connected, use IEEE class (most accurate)
                poe_type = self._map_poe_type(ieee_class, four_pair)
            elif max_port_power and not nb_iface.poe_type:
                # Fallback: derive from max port power (port capability) if not already set
                poe_type = self._map_poe_type_from_power(max_port_power)

            if poe_type and nb_iface.poe_type != poe_type:
                nb_iface.poe_type = poe_type
                iface_updated = True

            if iface_updated:
                interfaces_to_update.append(nb_iface)
                updated_count += 1
            else:
                skipped_count += 1

        # Bulk update all interfaces in a single database query
        if interfaces_to_update:
            from dcim.models import Interface

            Interface.objects.bulk_update(interfaces_to_update, ["poe_mode", "poe_type"])

        # Summary
        summary_parts = []
        if updated_count:
            summary_parts.append(f"{updated_count} updated")
        if skipped_count:
            summary_parts.append(f"{skipped_count} unchanged/skipped")

        if summary_parts:
            changes.append(f"POE: {', '.join(summary_parts)}")
        else:
            changes.append("POE: no changes")

        # Create journal entry with POE data
        self._create_poe_journal(device, poe_interfaces, updated_count)

        return {"changes": changes}

    def _map_poe_type(self, ieee_class, four_pair=False):
        """
        Map IEEE class to NetBox POE type.

        IEEE 802.3af (Type 1): class0-3, up to 15.4W
        IEEE 802.3at (Type 2): class4, up to 30W
        IEEE 802.3bt (Type 3): class5-6, up to 60W, 4-pair
        IEEE 802.3bt (Type 4): class7-8, up to 90-100W, 4-pair
        """
        ieee_class = ieee_class.lower().replace("class", "")

        try:
            class_num = int(ieee_class)
        except ValueError:
            return None

        if class_num <= 3:
            return "type1-ieee802.3af"
        elif class_num == 4:
            return "type2-ieee802.3at"
        elif class_num in (5, 6):
            return "type3-ieee802.3bt"
        elif class_num >= 7:
            return "type4-ieee802.3bt"

        return None

    def _map_poe_type_from_power(self, max_power):
        """
        Map max port power (watts) to NetBox POE type.

        Used as fallback when no device is connected (no ieee_class).
        This indicates the port's capability, not current delivery.

        Power thresholds:
        - Up to 15.4W: Type 1 (802.3af)
        - Up to 30W: Type 2 (802.3at / PoE+)
        - Up to 60W: Type 3 (802.3bt / PoE++)
        - Up to 90-100W: Type 4 (802.3bt / PoE++)
        """
        try:
            power = float(max_power)
        except (ValueError, TypeError):
            return None

        if power <= 15.4:
            return "type1-ieee802.3af"
        elif power <= 30:
            return "type2-ieee802.3at"
        elif power <= 60:
            return "type3-ieee802.3bt"
        elif power > 60:
            return "type4-ieee802.3bt"

        return None

    def _create_poe_journal(self, device, poe_interfaces, updated_count):
        """Create a journal entry on the device with POE sync data."""
        import json

        from extras.models import JournalEntry

        try:
            # Build summary of POE interfaces
            poe_summary = []
            for poe in poe_interfaces[:50]:  # Limit to first 50
                summary = {
                    "interface": poe.get("interface_name"),
                    "status": poe.get("poe_oper_status"),
                    "ieee_class": poe.get("ieee_class"),
                    "max_power": poe.get("max_port_power"),
                    "allocated": poe.get("allocated_power"),
                    "drawn": poe.get("port_power_drawn"),
                    "pd_type": poe.get("pd_device_type"),
                }
                # Remove None values
                summary = {k: v for k, v in summary.items() if v is not None}
                if summary.get("interface"):  # Only include if has interface name
                    poe_summary.append(summary)

            if not poe_summary:
                return

            # Create journal entry
            comments = "**Catalyst Center POE Sync**\n\n"
            comments += f"- Updated: {updated_count}\n"
            comments += f"- Total POE ports: {len(poe_interfaces)}\n\n"
            comments += "**POE Data (JSON):**\n```json\n"
            comments += json.dumps(poe_summary, indent=2)
            comments += "\n```"

            if len(poe_interfaces) > 50:
                comments += f"\n\n*Note: Showing first 50 of {len(poe_interfaces)} POE ports*"

            JournalEntry.objects.create(
                assigned_object=device,
                kind="info",
                comments=comments,
            )
        except Exception as e:
            import logging

            logging.getLogger(__name__).warning(f"Failed to create POE journal entry: {e}")


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

            # Also check for virtual chassis member devices (hostname.1, hostname.2, etc.)
            is_stack = device.get("is_stack", False)
            stack_count = device.get("stack_count", 1)
            if not existing and is_virtual_chassis_enabled() and is_stack and stack_count > 1:
                hostname_base = hostname.lower().replace(".ohsu.edu", "") if hostname else ""
                for member_num in range(1, stack_count + 1):
                    member_name = f"{hostname_base}.{member_num}"
                    existing = Device.objects.filter(name__iexact=member_name).first()
                    if existing:
                        break

            device["exists_in_netbox"] = existing is not None
            device["netbox_device_id"] = existing.pk if existing else None
            device["netbox_device_url"] = existing.get_absolute_url() if existing else None

        return JsonResponse(result)


def _import_as_virtual_chassis(
    dnac_device,
    hostname_base,
    device_type,
    role,
    default_site,
    device_platform,
    sync_interfaces,
):
    """
    Import a stacked device as a Virtual Chassis with multiple member devices.

    Creates:
    - One device per stack member (hostname.1, hostname.2, etc.)
    - A Virtual Chassis linking all members
    - Physical interfaces assigned to members based on slot number
    - Logical interfaces (VLANs, Loopbacks, etc.) assigned to master (member 1)

    Args:
        dnac_device: Device data from Catalyst Center
        hostname_base: Base hostname for the chassis
        device_type: NetBox DeviceType object
        role: NetBox DeviceRole object
        default_site: NetBox Site object
        device_platform: NetBox Platform object (or None)
        sync_interfaces: Whether to sync interfaces from CC

    Returns:
        dict with:
            - success: bool
            - chassis_name: Name of the virtual chassis
            - members: List of created member devices info
            - interface_count: Total interfaces synced
            - poe_count: Total POE interfaces updated
            - error: Error message if failed
    """
    from dcim.models import Device, Interface, VirtualChassis
    from django.db import transaction
    from django.utils import timezone
    from extras.models import Tag

    from .catalyst_client import get_client

    # Get or create Catalyst Center tag
    cc_tag, _ = Tag.objects.get_or_create(
        slug="catalyst-center",
        defaults={
            "name": "Catalyst Center",
            "color": "00bcd4",  # Cisco teal
            "description": "Device imported from or managed by Cisco Catalyst Center",
        },
    )

    stack_count = dnac_device.get("stack_count", 1)
    serial_list = dnac_device.get("serial_list", [])
    management_ip = dnac_device.get("management_ip", "")
    device_id = dnac_device.get("device_id", "")

    # Ensure we have enough serials for all members
    while len(serial_list) < stack_count:
        serial_list.append("")

    created_members = []
    master_device = None

    try:
        with transaction.atomic():
            # Create Virtual Chassis first (using hostname as the name)
            vc = VirtualChassis(
                name=hostname_base,
            )
            vc.save()

            # Create member devices
            for member_num in range(1, stack_count + 1):
                member_name = f"{hostname_base}.{member_num}"
                member_serial = serial_list[member_num - 1] if member_num <= len(serial_list) else ""

                # Check if this member already exists
                existing = Device.objects.filter(name__iexact=member_name).first()
                if existing:
                    continue

                member_device = Device(
                    name=member_name,
                    device_type=device_type,
                    role=role,
                    site=default_site,
                    serial=member_serial,
                    status="active",
                    platform=device_platform,
                    virtual_chassis=vc,
                    vc_position=member_num,
                    vc_priority=(255 if member_num == 1 else 128),  # Master gets highest priority
                    comments=(
                        f"Imported from Catalyst Center (Virtual Chassis member {member_num})\n"
                        f"SNMP Location: {dnac_device.get('snmp_location', 'N/A')}"
                    ),
                )
                member_device.save()

                # Populate custom fields
                member_device.custom_field_data["cc_device_id"] = device_id
                member_device.custom_field_data["cc_series"] = dnac_device.get("series", "")
                member_device.custom_field_data["cc_role"] = dnac_device.get("role", "")
                member_device.custom_field_data["cc_last_sync"] = timezone.now().isoformat()
                member_device.save()

                # Add Catalyst Center tag
                member_device.tags.add(cc_tag)

                created_members.append(
                    {
                        "name": member_name,
                        "netbox_id": member_device.pk,
                        "serial": member_serial,
                        "vc_position": member_num,
                    }
                )

                # First member is the master
                if member_num == 1:
                    master_device = member_device

            if not master_device:
                raise ValueError("Failed to create master device")

            # Set master on the virtual chassis and update member count
            vc.master = master_device
            vc.member_count = len(created_members)
            vc.save()

            # Create management interface on master device
            mgmt_interface = Interface(
                device=master_device,
                name="Management",
                type="other",
            )
            mgmt_interface.save()

            # Create IP address on master if available
            if management_ip:
                from ipam.models import IPAddress

                ip_with_prefix = f"{management_ip}/32"
                existing_ip = IPAddress.objects.filter(address=ip_with_prefix).first()

                if existing_ip:
                    existing_ip.assigned_object = mgmt_interface
                    existing_ip.save()
                    master_device.primary_ip4 = existing_ip
                else:
                    new_ip = IPAddress(
                        address=ip_with_prefix,
                        assigned_object=mgmt_interface,
                        description="Management IP from Catalyst Center",
                    )
                    new_ip.save()
                    master_device.primary_ip4 = new_ip

                master_device.save()

        # Sync interfaces if requested (outside transaction - external API call)
        interface_count = 0
        poe_count = 0
        if sync_interfaces and device_id:
            client = get_client()
            if client:
                try:
                    # Build a device lookup for each member by position
                    member_devices = {d.vc_position: d for d in Device.objects.filter(virtual_chassis=vc)}

                    sync_view = SyncDeviceFromDNACView()
                    iface_result = sync_view._sync_interfaces_virtual_chassis(
                        master_device, member_devices, client, device_id
                    )

                    for change in iface_result.get("changes", []):
                        if "created" in change:
                            parts = change.split()
                            for i, part in enumerate(parts):
                                if part == "created" and i > 0:
                                    try:
                                        interface_count = int(parts[i - 1])
                                    except ValueError:
                                        pass

                    # Sync POE data for all members
                    for member_device in member_devices.values():
                        try:
                            poe_result = sync_view._sync_poe(member_device, client, device_id)
                            for change in poe_result.get("changes", []):
                                if "updated" in change:
                                    parts = change.split()
                                    for i, part in enumerate(parts):
                                        if part == "updated" and i > 0:
                                            try:
                                                poe_count += int(parts[i - 1])
                                            except ValueError:
                                                pass
                        except Exception:
                            pass

                except Exception as e:
                    import logging

                    logging.getLogger(__name__).warning(
                        f"Failed to sync interfaces for virtual chassis {hostname_base}: {e}"
                    )

        return {
            "success": True,
            "chassis_name": hostname_base,
            "virtual_chassis_id": vc.pk,
            "members": created_members,
            "interface_count": interface_count,
            "poe_count": poe_count,
        }

    except Exception as e:
        return {
            "success": False,
            "error": str(e),
        }


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

        from dcim.models import (
            DeviceRole,
            DeviceType,
            Interface,
            Manufacturer,
            Platform,
            Site,
        )
        from extras.models import Tag

        try:
            body = json.loads(request.body) if request.body else {}
        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON"}, status=400)

        devices_to_import = body.get("devices", [])
        default_site_id = body.get("default_site_id")
        default_role_id = body.get("default_role_id")
        sync_interfaces = body.get("sync_interfaces", False)

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

        # Get or create Catalyst Center tag for imported devices
        cc_tag, _ = Tag.objects.get_or_create(
            slug="catalyst-center",
            defaults={
                "name": "Catalyst Center",
                "color": "00bcd4",  # Cisco teal
                "description": "Device imported from or managed by Cisco Catalyst Center",
            },
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

            # Also check for virtual chassis member devices (hostname.1, hostname.2, etc.)
            is_stack = dnac_device.get("is_stack", False)
            stack_count = dnac_device.get("stack_count", 1)
            if not existing and is_virtual_chassis_enabled() and is_stack and stack_count > 1:
                # Check if any virtual chassis member already exists
                for member_num in range(1, stack_count + 1):
                    member_name = f"{hostname_base}.{member_num}"
                    existing = Device.objects.filter(name__iexact=member_name).first()
                    if existing:
                        break

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

                # Check if this is a stack and virtual chassis mode is enabled
                is_stack = dnac_device.get("is_stack", False)
                stack_count = dnac_device.get("stack_count", 1)

                if is_virtual_chassis_enabled() and is_stack and stack_count > 1:
                    # Import as virtual chassis with multiple member devices
                    vc_result = _import_as_virtual_chassis(
                        dnac_device=dnac_device,
                        hostname_base=hostname_base,
                        device_type=device_type,
                        role=role,
                        default_site=default_site,
                        device_platform=device_platform,
                        sync_interfaces=sync_interfaces,
                    )

                    if vc_result.get("success"):
                        results["created"].append(
                            {
                                "hostname": hostname_base,
                                "netbox_id": (vc_result["members"][0]["netbox_id"] if vc_result["members"] else None),
                                "device_type": device_type.model,
                                "ip": management_ip,
                                "platform": (f"{software_type}/{software_version}" if software_type else None),
                                "interface_count": vc_result.get("interface_count", 0),
                                "poe_count": vc_result.get("poe_count", 0),
                                "virtual_chassis": True,
                                "virtual_chassis_id": vc_result.get("virtual_chassis_id"),
                                "member_count": len(vc_result.get("members", [])),
                            }
                        )
                    else:
                        results["errors"].append(
                            {
                                "hostname": hostname_base,
                                "error": vc_result.get("error", "Unknown error creating virtual chassis"),
                            }
                        )
                    continue

                # Create the device (single device mode - non-stack or VC disabled)
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

                # Add Catalyst Center tag
                new_device.tags.add(cc_tag)

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

                # Sync interfaces if requested
                interface_count = 0
                poe_count = 0
                if sync_interfaces:
                    device_id = dnac_device.get("device_id")
                    if device_id:
                        client = get_client()
                        if client:
                            try:
                                # Use the sync view's interface sync method
                                sync_view = SyncDeviceFromDNACView()
                                iface_result = sync_view._sync_interfaces(new_device, client, device_id)
                                # Parse interface count from result
                                for change in iface_result.get("changes", []):
                                    if "created" in change:
                                        # Extract number like "153 created"
                                        parts = change.split()
                                        for i, part in enumerate(parts):
                                            if part == "created" and i > 0:
                                                try:
                                                    interface_count = int(parts[i - 1])
                                                except ValueError:
                                                    pass

                                # Now sync POE data (interfaces exist, so POE can update them)
                                try:
                                    poe_result = sync_view._sync_poe(new_device, client, device_id)
                                    # Parse POE count from result
                                    for change in poe_result.get("changes", []):
                                        if "updated" in change:
                                            parts = change.split()
                                            for i, part in enumerate(parts):
                                                if part == "updated" and i > 0:
                                                    try:
                                                        poe_count = int(parts[i - 1])
                                                    except ValueError:
                                                        pass
                                except Exception as poe_err:
                                    import logging

                                    logging.getLogger(__name__).warning(
                                        f"Failed to sync POE for {hostname_base}: {poe_err}"
                                    )
                            except Exception as iface_err:
                                # Log but don't fail the import
                                import logging

                                logging.getLogger(__name__).warning(
                                    f"Failed to sync interfaces for {hostname_base}: {iface_err}"
                                )

                results["created"].append(
                    {
                        "hostname": hostname_base,
                        "netbox_id": new_device.pk,
                        "device_type": device_type.model,
                        "ip": management_ip,
                        "platform": (f"{software_type}/{software_version}" if software_type else None),
                        "interface_count": interface_count,
                        "poe_count": poe_count,
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


class InventoryComparisonView(View):
    """
    Dashboard view comparing NetBox inventory with Catalyst Center inventory.

    Shows:
    - Devices in CC but not in NetBox (missing from NetBox)
    - Devices in NetBox but not in CC (missing from CC)
    - Devices in both with data mismatches (serial, IP, etc.)
    """

    template_name = "netbox_catalyst_center/comparison.html"

    def get(self, request):
        """Display the inventory comparison dashboard with stats only."""
        from dcim.models import Device, Interface, Manufacturer, Site
        from django.utils import timezone
        from ipam.models import IPAddress

        client = get_client()

        # Initialize results - counts only, no device lists
        comparison = {
            "last_updated": timezone.now(),
            "error": None,
            # CC stats
            "cc_devices": 0,
            "cc_switches": 0,
            "cc_routers": 0,
            "cc_aps": 0,
            "cc_other": 0,
            "cc_interfaces": 0,
            "cc_sites": 0,
            "cc_health_score": 0,
            "cc_health_good": 0,
            "cc_health_fair": 0,
            "cc_health_bad": 0,
            # NetBox stats
            "nb_devices": 0,
            "nb_cisco_devices": 0,
            "nb_cc_managed_devices": 0,  # Devices with cc_device_id set
            "nb_cc_tagged_devices": 0,  # Devices with catalyst-center tag
            "nb_interfaces": 0,
            "nb_cisco_interfaces": 0,
            "nb_sites": 0,
            "nb_ips": 0,
        }

        # Get NetBox stats (fast Django ORM counts)
        cisco_manufacturers = Manufacturer.objects.filter(slug__icontains="cisco") | Manufacturer.objects.filter(
            name__icontains="cisco"
        )

        comparison["nb_devices"] = Device.objects.count()
        comparison["nb_cisco_devices"] = Device.objects.filter(
            device_type__manufacturer__in=cisco_manufacturers
        ).count()

        # Count devices that are actually managed by Catalyst Center
        # These have the cc_device_id custom field populated with a non-empty value
        # Note: JSON null values in PostgreSQL need special handling
        # We use a raw SQL condition to check for non-null, non-empty values
        comparison["nb_cc_managed_devices"] = Device.objects.extra(
            where=[
                "custom_field_data->>'cc_device_id' IS NOT NULL",
                "custom_field_data->>'cc_device_id' != ''",
            ]
        ).count()

        # Count devices with catalyst-center tag
        from extras.models import Tag
        cc_tag = Tag.objects.filter(slug="catalyst-center").first()
        if cc_tag:
            comparison["nb_cc_tagged_devices"] = Device.objects.filter(tags=cc_tag).count()

        comparison["nb_interfaces"] = Interface.objects.count()
        comparison["nb_cisco_interfaces"] = Interface.objects.filter(
            device__device_type__manufacturer__in=cisco_manufacturers
        ).count()
        comparison["nb_sites"] = Site.objects.count()
        comparison["nb_ips"] = IPAddress.objects.count()

        if not client:
            comparison["error"] = "Catalyst Center not configured"
            return render(request, self.template_name, {"comparison": comparison})

        # Fetch Catalyst Center stats (fast count endpoints only)
        try:
            # Device counts
            comparison["cc_devices"] = client._make_request("/dna/intent/api/v1/network-device/count").get(
                "response", 0
            )
            comparison["cc_switches"] = client._make_request(
                "/dna/intent/api/v1/network-device/count?family=Switches and Hubs"
            ).get("response", 0)
            comparison["cc_routers"] = client._make_request(
                "/dna/intent/api/v1/network-device/count?family=Routers"
            ).get("response", 0)
            comparison["cc_aps"] = client._make_request(
                "/dna/intent/api/v1/network-device/count?family=Unified AP"
            ).get("response", 0)
            comparison["cc_other"] = (
                comparison["cc_devices"] - comparison["cc_switches"] - comparison["cc_routers"] - comparison["cc_aps"]
            )

            # Interface and site counts
            comparison["cc_interfaces"] = client._make_request("/dna/intent/api/v1/interface/count").get("response", 0)
            comparison["cc_sites"] = client._make_request("/dna/intent/api/v1/site/count").get("response", 0)

            # Network health
            health_result = client._make_request("/dna/intent/api/v1/network-health")
            if "response" in health_result and health_result["response"]:
                health_data = health_result["response"][0]
                comparison["cc_health_score"] = health_data.get("healthScore", 0)
                comparison["cc_health_good"] = int(health_data.get("goodCount", 0))
                comparison["cc_health_fair"] = int(health_data.get("fairCount", 0))
                comparison["cc_health_bad"] = int(health_data.get("badCount", 0))

        except Exception as e:
            comparison["error"] = f"Failed to fetch from Catalyst Center: {e}"

        return render(request, self.template_name, {"comparison": comparison})
