# Generated by Django 4.2.2 on 2023-10-07 18:41

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0003_totpdevice'),
        ('OTRisk', '0013_cyberphascenario_snapshot_id_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='cyberphascenario_snapshot',
            name='ID',
            field=models.AutoField(default=0, primary_key=True, serialize=False),
            preserve_default=False)
    ]
