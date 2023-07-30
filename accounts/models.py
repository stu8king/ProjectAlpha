from django.db import models
from django.contrib.auth.models import User
from django.contrib.auth.models import AbstractUser
from django.utils import timezone


class customer(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='customer')
    customer_name = models.CharField(max_length=255)
    subscription_type = models.CharField(max_length=255)
    subscription_expiredate = models.DateTimeField()
    status = models.CharField(max_length=255)
    subscription_startdate = models.DateTimeField()

    class Meta:
        db_table = 'auth_customer'


class SubscriptionType(models.Model):
    name = models.CharField(max_length=255)
    description = models.TextField(null=True, blank=True)
    # other fields as necessary, such as price, duration, etc.


class Organization(models.Model):
    name = models.CharField(max_length=255)
    address = models.TextField(null=True, blank=True)
    subscription_type = models.ForeignKey(SubscriptionType, on_delete=models.SET_NULL, null=True, blank=True)
    subscription_status = models.BooleanField(default=False)
    subscription_start = models.DateField(null=True, blank=True)
    subscription_end = models.DateField(null=True, blank=True)

    class Meta:
        db_table = 'organization'
        managed = False

    def is_subscription_active(self):
        if self.subscription_status and self.subscription_end:
            return self.subscription_end > timezone.now().date()
        return False


class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE)

    class Meta:
        db_table = 'userprofile'
        managed = False
