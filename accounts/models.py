from django.db import models
from django.contrib.auth.models import User
from django.contrib.auth.models import AbstractUser
from django.utils import timezone
from django.db.models.signals import post_save
from django.dispatch import receiver


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

    def __str__(self):
        return self.name

    def is_subscription_active(self):
        if self.subscription_status and self.subscription_end:
            return self.subscription_end > timezone.now().date()
        return False


class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    organization = models.ForeignKey(Organization, on_delete=models.SET_NULL, null=True, blank=True)

    class Meta:
        db_table = 'userprofile'
        managed = False


@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        UserProfile.objects.create(user=instance)


@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    if hasattr(instance, 'customer'):
        instance.customer.save()


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
