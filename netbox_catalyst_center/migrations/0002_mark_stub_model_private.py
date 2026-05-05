"""Mark the unmanaged CatalystCenter permission-anchor model as private.

The model exists only to attach the `configure_catalystcenter` permission and
has no DB table. NetBox 4.5's /core/system/ view runs `Model.objects.count()`
for every public ObjectType, which crashes on the missing table. Flipping
`ObjectType.public = False` (matching the `_netbox_private = True` flag now
set on the model class) excludes it from that loop.
"""

from django.db import migrations


def mark_stub_model_private(apps, schema_editor):
    ContentType = apps.get_model("contenttypes", "ContentType")
    try:
        ct = ContentType.objects.get(app_label="netbox_catalyst_center", model="catalystcenter")
    except ContentType.DoesNotExist:
        return
    with schema_editor.connection.cursor() as cursor:
        cursor.execute(
            "UPDATE core_objecttype SET public = FALSE WHERE contenttype_ptr_id = %s",
            [ct.id],
        )


class Migration(migrations.Migration):

    dependencies = [
        ("netbox_catalyst_center", "0001_initial"),
    ]

    operations = [
        migrations.RunPython(mark_stub_model_private, reverse_code=migrations.RunPython.noop),
    ]
