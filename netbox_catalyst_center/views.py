"""
Views for NetBox Catalyst Center Plugin

Registers custom tabs on Device detail views to show Catalyst Center client info.
Provides settings configuration UI.
"""

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
    )

    def get(self, request, pk):
        """Handle GET request for the Catalyst Center tab."""
        device = Device.objects.get(pk=pk)

        # Get client from Catalyst Center using device name as MAC
        client = get_client()
        config = settings.PLUGINS_CONFIG.get("netbox_catalyst_center", {})

        client_data = {}
        error = None

        if not client:
            error = "Catalyst Center not configured. Please configure the plugin in NetBox settings."
        else:
            # Use device name as MAC address (for Vocera badges, name = MAC)
            mac_address = device.name

            # Try to look up by device name (which might be a MAC address)
            client_data = client.get_client_detail(mac_address)

            if "error" in client_data:
                error = client_data.get("error")
                client_data = {}

        # Get Catalyst Center URL for external links
        catalyst_url = config.get("catalyst_center_url", "").rstrip("/")

        return render(
            request,
            self.template_name,
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
