# Generated by Django 4.2.2 on 2023-10-18 15:03

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('OTRisk', '0022_raactions_datamitigation_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='Audit',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('organization_id', models.PositiveIntegerField()),
                ('ip_address', models.GenericIPAddressField()),
                ('session_id', models.CharField(max_length=256)),
                ('timestamp', models.DateTimeField(auto_now_add=True)),
                ('user_action', models.CharField(choices=[('Edit', 'Edit'), ('Add New', 'Add New'), ('Delete', 'Delete'), ('Login', 'Login'), ('Logout', 'Logout'), ('Create Profile', 'Create Profile'), ('Generate Risk Assessment', 'Generate Risk Assessment')], max_length=50)),
                ('record_type', models.CharField(choices=[('Application', 'Application'), ('QRAW', 'QRAW'), ('CyberPHA', 'CyberPHA'), ('RiskRegister', 'RiskRegister'), ('ActionItem', 'ActionItem')], max_length=50)),
                ('record_id', models.PositiveIntegerField(blank=True, null=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'db_table': 'audit',
                'managed': True,
            },
        ),
    ]
