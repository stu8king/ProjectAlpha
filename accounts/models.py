import json

from django.conf import settings
from django.db import models
from django.contrib.auth.models import User
from django.contrib.auth.models import AbstractUser
from django.utils import timezone
from django.db.models.signals import post_save
from django.dispatch import receiver

class TOTPDevice(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='accounts_totpdevice')
    secret_key = models.CharField(max_length=100)
    confirmed = models.BooleanField(default=False)


class PasswordResetCode(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    code = models.CharField(max_length=32)  # Assuming a 6-digit code, adjust as needed
    timestamp = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f"Reset code for {self.user.username}"

    class Meta:
        verbose_name = "Password Reset Code"
        verbose_name_plural = "Password Reset Codes"


class ActiveUserSession(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    session_key = models.CharField(max_length=40)

    class Meta:
        db_table = 'accounts_activeusersession'


class customer(models.Model):
    user = models.OneToOneField(User, null=True, on_delete=models.CASCADE, related_name='customer')
    customer_name = models.CharField(max_length=255)
    subscription_type = models.CharField(max_length=255)
    subscription_expiredate = models.DateTimeField()
    status = models.CharField(max_length=255)
    subscription_startdate = models.DateTimeField()

    class Meta:
        db_table = 'auth_customer'


class SubscriptionType(models.Model):
    USER_TYPE_CHOICES = [
        ('Individual', 'Individual'),
        ('Organization', 'Organization')
    ]

    name = models.CharField(max_length=255)
    description = models.TextField(null=True, blank=True)
    user_type = models.CharField(max_length=50, choices=USER_TYPE_CHOICES)
    max_assessments = models.PositiveIntegerField(null=True, blank=True)  # Null means unlimited
    max_users = models.PositiveIntegerField(null=True, blank=True)  # Null means unlimited
    duration = models.PositiveIntegerField(
        help_text="Duration in days")  # For monthly, it can be 30, for annual, it can be 365
    price = models.DecimalField(max_digits=10, decimal_places=2)  # Assuming you want to store the price as well
    duration_description = models.CharField(max_length=50)
    post_readonly_duration = models.CharField(max_length=50)
    max_pha = models.CharField(max_length=10)
    max_raw = models.CharField(max_length=10)
    add_feature_support = models.CharField(max_length=3)
    data_download_support = models.CharField(max_length=3)

    def __str__(self):
        return json.dumps({
            'id': self.id,
            'name': self.name,
            'max_users': self.max_users,
            'duration': self.duration,
            'description': self.description,
            'price': str(self.price)  # Convert the Decimal to a string
        })

    class Meta:
        db_table = 'accounts_subscriptiontype'


class Organization(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=255)
    address = models.TextField(null=True, blank=True)
    address2 = models.TextField(null=True, blank=True)
    city = models.TextField(null=True, blank=True)
    state = models.TextField(null=True, blank=True)
    zip = models.TextField(null=True, blank=True)
    country = models.TextField(null=True, blank=True)
    subscription_type = models.ForeignKey(SubscriptionType, on_delete=models.SET_NULL, null=True, blank=True)
    subscription_status = models.BooleanField(default=False)
    subscription_start = models.DateField(null=True, blank=True)
    subscription_end = models.DateField(null=True, blank=True)
    max_users = models.IntegerField(default=1, null=False)
    create_date = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE,
                                   related_name='organization_creators')
    last_updated = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'organization'
        managed = True

    def __str__(self):
        return self.name

    def is_subscription_active(self):
        if self.subscription_status and self.subscription_end:
            return self.subscription_end > timezone.now().date()
        return False

class OrganizationHistory(models.Model):
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE)
    action = models.CharField(max_length=50)  # e.g., 'Created', 'Updated'
    changed_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    change_date = models.DateTimeField(default=timezone.now)
    change_description = models.TextField()

    class Meta:
        db_table = 'organization_history'
        managed = True

    def __str__(self):
        return f"{self.organization.name} - {self.action} - {self.change_date}"


class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE)
    must_change_password = models.BooleanField(default=True)
    abuse_flag = models.BooleanField(default=False)

    class Meta:
        db_table = 'userprofile'
        managed = True


class FailedLoginAttempt(models.Model):
    username = models.CharField(max_length=255)
    ip_address = models.GenericIPAddressField()
    timestamp = models.DateTimeField()


class LoginAttempt(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True,
                             blank=True)  # null and blank for failed attempts where user might not be identified
    ip_address = models.GenericIPAddressField()
    timestamp = models.DateTimeField(auto_now_add=True)
    was_successful = models.BooleanField(default=False)
    reason = models.CharField(max_length=255, null=True, blank=True)  # Reason for failure, if any
