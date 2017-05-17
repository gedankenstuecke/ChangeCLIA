from django.contrib.auth import get_user_model
from django.db import models

User = get_user_model()


class Profile(models.Model):
    US_STATUS_CHOICES = (
        ('C', 'US Citizen'),
        ('R', 'US Resident (non-citizen)'),
        ('O', 'Other')
    )
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    name = models.CharField('name', max_length=80, blank=False)
    twitter = models.CharField('twitter handle', max_length=15, blank=True)
    location = models.CharField(max_length=30, blank=True)
    us_status = models.CharField(max_length=1, choices=US_STATUS_CHOICES,
                                 blank=False, null=False)
    comments = models.TextField(max_length=500, blank=True)
