# migrate_facilities.py

from django.core.management.base import BaseCommand
from accounts.models import UserProfile
from OTRisk.models.Model_CyberPHA import tblCyberPHAHeader, Facility, tblIndustry
from OTRisk.models.questionnairemodel import FacilityType
from django.utils.timezone import now

class Command(BaseCommand):
    help = 'Migrate facility data from tblCyberPHAHeader to Facility model and set the foreign key relationship.'

    def handle(self, *args, **kwargs):
        headers = tblCyberPHAHeader.objects.all()

        for header in headers:
            # Construct the facility address
            address_parts = [
                header.facilityAddress,
                header.facilityCity,
                header.facilityState,
                header.facilityCode,
                header.country
            ]
            address = ', '.join(part for part in address_parts if part)

            try:
                industry = tblIndustry.objects.get(Industry=header.Industry)
            except tblIndustry.DoesNotExist:
                self.stderr.write(f'Industry {header.Industry} does not exist. Skipping header ID {header.ID}.')
                continue

            try:
                facility_type = FacilityType.objects.get(FacilityType=header.FacilityType)
            except FacilityType.DoesNotExist:
                self.stderr.write(f'Facility Type {header.FacilityType} does not exist. Skipping header ID {header.ID}.')
                continue

            lat = header.facilityLat if header.facilityLat is not None else 0.0
            lon = header.facilityLong if header.facilityLong is not None else 0.0

            # Create or update the facility
            facility, created = Facility.objects.update_or_create(
                name=header.FacilityName,
                defaults={
                    'industry': industry,
                    'type': facility_type,
                    'employees': header.EmployeesOnSite,
                    'address': address,
                    'lat': lat,
                    'lon': lon,
                    'revenue': header.annual_revenue if header.annual_revenue is not None else 0,
                    'operating_cost': header.coho if header.coho is not None else 0,
                    'profit_margin': header.npm if header.npm is not None else 0,
                    'organization': UserProfile.objects.get(user_id=header.UserID).organization,
                }
            )

            # Ensure the Date field is set
            if header.Date is None:
                header.Date = now()

            # Update the header with the facility foreign key
            header.facility = facility
            header.save()

            if created:
                self.stdout.write(self.style.SUCCESS(f'Created facility for header ID {header.ID}'))
            else:
                self.stdout.write(self.style.SUCCESS(f'Updated facility for header ID {header.ID}'))

        self.stdout.write(self.style.SUCCESS('Migration completed successfully.'))