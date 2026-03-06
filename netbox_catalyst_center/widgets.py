"""Dashboard widgets for the NetBox Catalyst Center plugin."""

import logging

from django import forms
from django.template.loader import render_to_string
from django.utils.translation import gettext as _
from extras.dashboard.utils import register_widget
from extras.dashboard.widgets import DashboardWidget, WidgetConfigForm

from .catalyst_client import get_client

logger = logging.getLogger(__name__)


@register_widget
class CatalystCenterStatusWidget(DashboardWidget):
    """Dashboard widget showing device reachability and compliance from Catalyst Center."""

    default_title = _("Catalyst Center Health")
    description = _("Display device reachability and compliance summary from Catalyst Center.")
    template_name = "netbox_catalyst_center/widgets/catalyst_status.html"
    width = 4
    height = 3

    class ConfigForm(WidgetConfigForm):
        cache_timeout = forms.IntegerField(
            min_value=60,
            max_value=3600,
            initial=300,
            required=False,
            label=_("Cache timeout (seconds)"),
            help_text=_("How long to cache device data (60-3600 seconds)."),
        )

    def render(self, request):
        client = get_client()
        if not client:
            return render_to_string(
                self.template_name,
                {
                    "error": "Catalyst Center not configured. Set catalyst_center_url, username, and password in plugin settings."
                },
            )

        cache_timeout = self.config.get("cache_timeout", 300)
        summary = client.get_device_health_summary(cache_timeout=cache_timeout)

        if "error" in summary:
            return render_to_string(self.template_name, {"error": summary["error"]})

        return render_to_string(
            self.template_name,
            {
                "reachability": summary.get("reachability", {}),
                "compliance": summary.get("compliance", {}),
                "total": summary.get("total", 0),
                "cached": summary.get("cached", False),
                "cc_url": client.base_url,
            },
        )
