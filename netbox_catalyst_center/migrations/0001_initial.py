from django.db import migrations


class Migration(migrations.Migration):

    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name="CatalystCenter",
            fields=[],
            options={
                "managed": False,
                "default_permissions": (),
                "permissions": (("configure_catalystcenter", "Can configure Catalyst Center plugin settings"),),
            },
        ),
    ]
