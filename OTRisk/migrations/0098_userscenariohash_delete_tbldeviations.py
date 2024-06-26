# Generated by Django 5.0.2 on 2024-02-19 12:15

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('OTRisk', '0097_delete_tblscenariorecommendations'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='UserScenarioHash',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('cyberphaID', models.IntegerField()),
                ('hash_value', models.CharField(max_length=64)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'unique_together': {('user', 'cyberphaID', 'hash_value')},
            },
        ),
        migrations.DeleteModel(
            name='tblDeviations',
        ),
    ]
