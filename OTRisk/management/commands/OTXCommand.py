from django.core.management.base import BaseCommand
from OTXv2 import OTXv2
from OTRisk.models import OTXThreats


class Command(BaseCommand):
    help = 'Fetch latest threats from OTX'

    def handle(self, *args, **options):
        otx = OTXv2('45d4d105ca17fadf9519b654a7d78d7226975e67f25777fb71ad17dd1348f5ea')
        pulses = otx.getall(include_indicators=True)

        for pulse in pulses:
            Threat.objects.create(
                name=pulse['name'],
                description=pulse['description'],
                indicators=[i['indicator'] for i in pulse['indicators']],
            )
