"""
URL patterns for NetBox Catalyst Center Plugin
"""

from django.urls import path

from .views import CatalystCenterSettingsView, SyncDeviceFromDNACView, TestConnectionView

urlpatterns = [
    path("settings/", CatalystCenterSettingsView.as_view(), name="settings"),
    path("test-connection/", TestConnectionView.as_view(), name="test_connection"),
    path("sync-device/<int:pk>/", SyncDeviceFromDNACView.as_view(), name="sync_device"),
]
