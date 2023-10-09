# Generated by Django 4.2.2 on 2023-09-23 14:55

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('accounts', '0002_organization_address2_organization_city_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='TOTPDevice',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('secret_key', models.CharField(max_length=100)),
                ('confirmed', models.BooleanField(default=False)),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='accounts_totpdevice', to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
