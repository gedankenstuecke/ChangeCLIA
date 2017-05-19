import re

from allauth.account.models import EmailAddress

from django.conf import settings
from django.contrib.auth import get_user_model

import tweepy

def is_username_unique(username):
    User = get_user_model()
    try:
        User.objects.get(username__iexact=username)
        return False
    except User.DoesNotExist:
        return True
    return False


def make_unique_username(basename):
    username = basename
    i = 1
    while not is_username_unique(username):
        i += 1
        username = basename + str(i)
    return username


def new_user(email='', username=''):
    assert email or username
    User = get_user_model()
    if username:
        basename = username
    else:
        basename = email.split('@')[0]
    username = make_unique_username(basename)
    if email:
        if User.objects.filter(email=email):
            raise ValueError('Email "{}" not unique.'.format(email))
        else:
            user = User(username=username, email=email)
    else:
        user = User(username=username)
    user.save()

    # Set up email for allauth.
    if email:
        ea = EmailAddress(user=user, email=email, primary=True, verified=False)
        ea.user = user
        ea.save()

    return user


def get_tweepy_auth():
    return tweepy.OAuthHandler(
        settings.TWEEPY_CONSUMER_TOKEN, settings.TWEEPY_CONSUMER_SECRET)
