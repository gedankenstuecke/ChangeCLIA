from allauth.account.models import EmailAddress

from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import models

import tweepy

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
    followers = models.IntegerField(default=0)
    twitter_oauth_token = models.CharField(max_length=50, blank=True)
    twitter_oauth_token_secret = models.CharField(max_length=45, blank=True)
    location = models.CharField(max_length=30, blank=True)
    us_status = models.CharField(max_length=1, choices=US_STATUS_CHOICES,
                                 blank=False, null=False)
    comments = models.TextField(max_length=500, blank=True)

    def update_twitter_data(self):
        if not settings.TWEEPY_SETUP:
            return
        auth = tweepy.OAuthHandler(
            settings.TWEEPY_CONSUMER_TOKEN, settings.TWEEPY_CONSUMER_SECRET)
        oauth_token = settings.TWEEPY_OAUTH_TOKEN
        verifier = settings.TWEEPY_OAUTH_VERIFIER
        request_token = {'oauth_token': oauth_token,
                         'oauth_token_secret': verifier}
        auth.request_token = request_token
        api = tweepy.API(auth)
        user = api.get_user(self.twitter)
        if user:
            self.followers = user.followers_count
            self.location = user.location
            self.save()

    @property
    def emailaddress(self):
        ea = EmailAddress.objects.get(email=self.user.email)
        return ea
