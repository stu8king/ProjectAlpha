# Generated by Django 4.2.2 on 2023-11-04 18:17

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('OTRisk', '0032_alter_tblconsequence_options'),
    ]

    operations = [
        migrations.AddField(
            model_name='tblconsequence',
            name='industry',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, related_name='consequences', to='OTRisk.tblindustry'),
        ),
    ]