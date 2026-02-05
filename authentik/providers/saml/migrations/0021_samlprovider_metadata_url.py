# Generated migration for metadata_url field

from django.db import migrations, models

import authentik.lib.models


class Migration(migrations.Migration):

    dependencies = [
        ("authentik_providers_saml", "0020_samlprovider_logout_method_and_more"),
    ]

    operations = [
        migrations.AddField(
            model_name="samlprovider",
            name="metadata_url",
            field=models.TextField(
                blank=True,
                default="",
                help_text="URL to fetch SP metadata from. Used for initial import and refresh.",
                validators=[
                    authentik.lib.models.DomainlessURLValidator(schemes=("http", "https"))
                ],
                verbose_name="Metadata URL",
            ),
        ),
    ]
