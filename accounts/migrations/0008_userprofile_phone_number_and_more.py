# Generated by Django 4.2.2 on 2023-12-29 18:43

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0007_userprofile_jobtitle_userprofile_role_moderator_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='userprofile',
            name='phone_number',
            field=models.CharField(blank=True, max_length=15, null=True),
        ),
        migrations.AddField(
            model_name='userprofile',
            name='two_factor_confirmed',
            field=models.BooleanField(default=False),
        ),
    ]