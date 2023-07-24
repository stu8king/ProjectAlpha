from django.db import models
from django.contrib.auth.models import User
from django.contrib.auth.models import AbstractUser

class customer(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='customer')
    customer_name = models.CharField(max_length=255)
    subscription_type = models.CharField(max_length=255)
    subscription_expiredate = models.DateTimeField()
    status = models.CharField(max_length=255)
    subscription_startdate = models.DateTimeField()

    class Meta:
        db_table = 'auth_customer'
