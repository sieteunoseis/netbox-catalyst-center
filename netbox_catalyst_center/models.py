from django.db import models


class CatalystCenter(models.Model):
    """Unmanaged model to register custom permissions for the Catalyst Center plugin."""

    class Meta:
        managed = False
        default_permissions = ()
        permissions = (
            ("configure_catalystcenter", "Can configure Catalyst Center plugin settings"),
        )
