from django.db import models
from django.conf import settings
from accounts.models import UserProfile, Organization
from OTRisk.models.Model_CyberPHA import tblIndustry

class CustomConsequence(models.Model):
    user_profile = models.ForeignKey(UserProfile, on_delete=models.CASCADE, related_name='custom_consequences')
    organization = models.ForeignKey(Organization,
                                     on_delete=models.CASCADE)  # Organization is directly linked here for easier queries
    Consequence = models.TextField()  # This is a text field, but you can change the type based on your needs.
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True,
                                   related_name='created_consequences')

    def save(self, *args, **kwargs):
        # Ensure the organization is set from the user profile before saving
        if not self.organization and self.user_profile:
            self.organization = self.user_profile.organization
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.Consequence} (by {self.created_by.username})"


class tblConsequence(models.Model):
    ID = models.AutoField(primary_key=True)
    Consequence = models.TextField()
    industry = models.ForeignKey('tblIndustry', related_name='consequences', null=True, on_delete=models.CASCADE)

    class Meta:
        db_table = 'tblConsequences'
        managed = True

