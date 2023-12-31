# Generated by Django 4.2.2 on 2023-12-20 13:32

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('OTRisk', '0064_cyberphascenario_snapshot_attack_tree_text'),
    ]

    operations = [
        migrations.CreateModel(
            name='user_scenario_audit',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('scenario_text', models.TextField()),
                ('entered_at', models.DateTimeField(auto_now_add=True)),
                ('organization_id', models.PositiveIntegerField()),
                ('ip_address', models.GenericIPAddressField()),
                ('session_id', models.CharField(max_length=256)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
