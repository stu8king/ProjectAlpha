# Generated by Django 4.2.2 on 2023-10-31 18:43

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('OTRisk', '0030_tblcyberphaheader_sl_t'),
    ]

    operations = [
        migrations.AddField(
            model_name='cyberphascenario_snapshot',
            name='sl_a',
            field=models.PositiveSmallIntegerField(choices=[(0, 'SL 0: No security requirements or security protection necessary'), (1, 'SL 1: Protection against casual or coincidental violation'), (2, 'SL 2: Protection against intentional violation using simple means with low resources, generic skills and low motivation'), (3, 'SL 3: Protection against intentional violation using sophisticated means with moderate resources, IACS specific skills and moderate motivation'), (4, 'SL 4: Protection against intentional violation using sophisticated means with extended resources, IACS specific skills and high motivation')], default=0),
        ),
        migrations.AddField(
            model_name='tblcyberphascenario',
            name='sl_a',
            field=models.PositiveSmallIntegerField(choices=[(0, 'SL 0: No security requirements or security protection necessary'), (1, 'SL 1: Protection against casual or coincidental violation'), (2, 'SL 2: Protection against intentional violation using simple means with low resources, generic skills and low motivation'), (3, 'SL 3: Protection against intentional violation using sophisticated means with moderate resources, IACS specific skills and moderate motivation'), (4, 'SL 4: Protection against intentional violation using sophisticated means with extended resources, IACS specific skills and high motivation')], default=0),
        ),
    ]
