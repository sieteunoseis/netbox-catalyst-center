"""
URL patterns for NetBox Catalyst Center Plugin
"""

from django.urls import path

from .views import (
    AddDeviceToInventoryView,
    AddDeviceToPnPView,
    CatalystCenterSettingsView,
    DeviceCatalystCenterContentView,
    ENDPOINTS_PLUGIN_INSTALLED,
    ExportPnPCSVView,
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
    path("device/<int:pk>/content/", DeviceCatalystCenterContentView.as_view(), name="device_content"),
    path("add-to-pnp/<int:pk>/", AddDeviceToPnPView.as_view(), name="add_to_pnp"),
    path("add-to-inventory/<int:pk>/", AddDeviceToInventoryView.as_view(), name="add_to_inventory"),
    path("export-pnp-csv/", ExportPnPCSVView.as_view(), name="export_pnp_csv"),
]

# Add endpoint URLs if netbox_endpoints is installed
if ENDPOINTS_PLUGIN_INSTALLED:
    from .views import EndpointCatalystCenterContentView, SyncEndpointFromDNACView

    urlpatterns.extend(
        [
            path("endpoint/<int:pk>/content/", EndpointCatalystCenterContentView.as_view(), name="endpoint_content"),
            path("sync-endpoint/<int:pk>/", SyncEndpointFromDNACView.as_view(), name="sync_endpoint"),
        ]
    )
