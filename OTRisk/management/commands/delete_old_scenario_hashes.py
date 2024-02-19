from django.core.management.base import BaseCommand
from django.utils import timezone
from datetime import timedelta

from models.Model_CyberPHA import UserScenarioHash


class Command(BaseCommand):
    help = 'Deletes UserScenarioHash records older than 5 days'

    def handle(self, *args, **kwargs):
        # Calculate the cutoff date
        cutoff_date = timezone.now() - timedelta(days=5)
        # Query and delete records older than the cutoff date
        old_records = UserScenarioHash.objects.filter(created_at__lt=cutoff_date)
        count = old_records.count()
        old_records.delete()
        self.stdout.write(self.style.SUCCESS(f'Successfully deleted {count} old records.'))
