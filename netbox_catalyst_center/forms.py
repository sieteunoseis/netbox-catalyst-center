"""
Forms for NetBox Catalyst Center Plugin
"""

from django import forms


class CatalystCenterSettingsForm(forms.Form):
    """Form for Catalyst Center plugin settings."""

    catalyst_center_url = forms.URLField(
        label="Catalyst Center URL",
        required=True,
        help_text="Full URL to Catalyst Center (e.g., https://dnac.example.com)",
        widget=forms.URLInput(attrs={"class": "form-control", "placeholder": "https://dnac.example.com"}),
    )

    catalyst_center_username = forms.CharField(
        label="Username",
        required=True,
        help_text="Catalyst Center API username",
        widget=forms.TextInput(attrs={"class": "form-control"}),
    )

    catalyst_center_password = forms.CharField(
        label="Password",
        required=True,
        help_text="Catalyst Center API password",
        widget=forms.PasswordInput(attrs={"class": "form-control"}),
    )

    timeout = forms.IntegerField(
        label="API Timeout",
        required=False,
        initial=30,
        help_text="API request timeout in seconds",
        widget=forms.NumberInput(attrs={"class": "form-control"}),
    )

    cache_timeout = forms.IntegerField(
        label="Cache Timeout",
        required=False,
        initial=60,
        help_text="How long to cache API responses (seconds)",
        widget=forms.NumberInput(attrs={"class": "form-control"}),
    )

    verify_ssl = forms.BooleanField(
        label="Verify SSL",
        required=False,
        initial=False,
        help_text="Verify SSL certificates (disable for self-signed certs)",
        widget=forms.CheckboxInput(attrs={"class": "form-check-input"}),
    )
