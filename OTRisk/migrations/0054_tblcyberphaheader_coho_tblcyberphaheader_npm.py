# Generated by Django 4.2.2 on 2023-12-02 12:18

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('OTRisk', '0053_rename_controltypedescription_securitycontrols_controldescription_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='tblcyberphaheader',
            name='coho',
            field=models.IntegerField(default=0),
        ),
        migrations.AddField(
            model_name='tblcyberphaheader',
            name='npm',
            field=models.IntegerField(default=0),
        ),
    ]
