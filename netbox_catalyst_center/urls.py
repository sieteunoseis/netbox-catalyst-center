"""
URL patterns for NetBox Catalyst Center Plugin
"""

from django.urls import path

from .views import (
    CatalystCenterSettingsView,
    ImportDevicesView,
    ImportPageView,
    InventoryComparisonView,
    SearchDevicesView,
    SyncDeviceFromDNACView,
    TestConnectionView,
)

urlpatterns = [
    path("settings/", CatalystCenterSettingsView.as_view(), name="settings"),
    path("import/", ImportPageView.as_view(), name="import_page"),
    path("comparison/", InventoryComparisonView.as_view(), name="comparison"),
    path("test-connection/", TestConnectionView.as_view(), name="test_connection"),
    path("sync-device/<int:pk>/", SyncDeviceFromDNACView.as_view(), name="sync_device"),
    path("search-devices/", SearchDevicesView.as_view(), name="search_devices"),
    path("import-devices/", ImportDevicesView.as_view(), name="import_devices"),
]
