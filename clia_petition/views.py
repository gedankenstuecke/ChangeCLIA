from allauth.account import app_settings as account_settings
from allauth.account.models import EmailAddress
from allauth.account.utils import url_str_to_user_pk, complete_signup, send_email_confirmation

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import authenticate, get_user_model, login
from django.core.urlresolvers import reverse, reverse_lazy
from django.http import HttpResponseRedirect
from django.views.generic import FormView, View
from django.views.generic.detail import SingleObjectMixin

import tweepy

from .forms import SignatureForm, ProfileForm
from .models import Profile
from .utils import get_tweepy_auth, new_user

User = get_user_model()


class TokenLoginView(View):
    """
    Log in a user using the reset token as authentication.

    Tokens are invalidated after being used, and expire after 3 days.
    (Expiration time can be altered with settings.PASSWORD_RESET_TIMEOUT_DAYS.)
    """

    def _get_user(self, uidb36):
        try:
            pk = url_str_to_user_pk(uidb36)

            return User.objects.get(pk=pk)
        except (ValueError, User.DoesNotExist):
            return None

    def dispatch(self, request, *args, **kwargs):
        uidb36 = kwargs['uidb36']
        token = kwargs['token']
        self.reset_user = self._get_user(uidb36)
        user = authenticate(username=self.reset_user.username, token=token)
        if user:
            login(request, user)
            login_url = reverse('home')
            return HttpResponseRedirect(login_url)
        failed_login_url = reverse('token_login_fail')
        return HttpResponseRedirect(failed_login_url)


class TwitterReturnView(View):

    def get(self, request, *args, **kwargs):
        email = self.request.session.get('signature_email', '')
        name = self.request.session.get('signature_name', '')
        us_status = self.request.session.get('signature_us_status', '')
        comments = self.request.session.get('sigature_comments', '')

        oauth_token = self.request.GET['oauth_token']
        oauth_verifier = self.request.GET['oauth_verifier']
        auth = get_tweepy_auth()
        auth.request_token = {'oauth_token': oauth_token,
                              'oauth_token_secret': oauth_verifier}
        (token, token_secret) = auth.get_access_token(oauth_verifier)
        auth.set_access_token(token, token_secret)
        api = tweepy.API(auth)
        user_data = api.me()

        try:
            Profile.objects.get(twitter=user_data.screen_name)
            messages.error('Twitter user @{} has already signed!'.format(
                user_data.screen_name))
            return HttpResponseRedirect(reverse_lazy('home'))
        except:
            pass

        if request.user.is_authenticated:
            user = request.user
        else:
            if email:
                user = new_user(username=user_data.screen_name,
                                email=email)
                send_email_confirmation(request, user)
            else:
                user = new_user(username=user_data.screen_name)
            user.save()
            user.backend = 'clia_petition.backends.TrustedUserAuthenticationBackend'
            login(request, user)

        profile, _ = Profile.objects.get_or_create(user=user)
        if name:
            profile.name = name
        if us_status:
            profile.us_status = us_status
        if comments:
            profile.comments = comments

        profile.twitter = user_data.screen_name
        profile.followers = user_data.followers_count
        profile.twitter_oauth_token = token
        profile.twitter_oauth_token_secret = token_secret
        profile.save()

        return HttpResponseRedirect(reverse_lazy('home'))


class HomeView(FormView):
    template_name = "clia_petition/index.html"
    form_class = SignatureForm
    redirect_field_name = "next"
    success_url = reverse_lazy('home')

    def get_context_data(self, *args, **kwargs):
        context_data = super(HomeView, self).get_context_data(*args, **kwargs)

        auth = get_tweepy_auth()
        try:
            context_data['twitter_auth_url'] = auth.get_authorization_url()
        except tweepy.TweepError:
            pass

        sigs_by_date = Profile.objects.all().order_by(
            'user__date_joined').reverse()
        sigs_by_followers = Profile.objects.all().order_by(
            'followers').reverse()

        context_data['sigs_by_date'] = sigs_by_date
        context_data['sigs_by_followers'] = sigs_by_followers

        return context_data

    def post(self, request, *args, **kwargs):
        form = self.get_form()

        if self.request.POST['action'] == 'Sign with email':
            form.submit_action = 'email'
        elif self.request.POST['action'] == 'Sign with Twitter account':
            form.submit_action = 'twitter'
        else:
            form.submit_action = None

        if form.is_valid():
            return self.form_valid(form)
        else:
            return self.form_invalid(form)

    def form_valid(self, form):
        if form.submit_action == 'twitter':
            self.request.session['signature_email'] = self.request.POST['email']
            self.request.session['signature_name'] = self.request.POST['name']
            self.request.session['signature_us_status'] = self.request.POST['us_status']
            self.request.session['signature_comments'] = self.request.POST['comments']
            auth = get_tweepy_auth()
            url = auth.get_authorization_url()
            return HttpResponseRedirect(url)
        elif form.submit_action == 'email':
            user = new_user(email=form.cleaned_data['email'])
            user.save()
            profile = Profile(
                user=user,
                name=form.cleaned_data['name'],
                us_status=form.cleaned_data['us_status'],
                comments=form.cleaned_data['comments'])
            profile.save()
            return complete_signup(
                self.request,
                user,
                account_settings.EMAIL_VERIFICATION,
                self.get_success_url())


class ResendConfirmationView(View):

    def post(self, request, *args, **kwargs):
        send_email_confirmation(request, request.user)
        return HttpResponseRedirect(reverse_lazy('home'))


class ProfileEditView(SingleObjectMixin, FormView):
    template_name = 'clia_petition/edit.html'
    form_class = ProfileForm
    redirect_field_name = 'next'
    success_url = reverse_lazy('home')
    model = Profile

    def dispatch(self, *args, **kwargs):
        self.object = self.get_object()
        if self.object.id != self.request.user.profile.id:
            return HttpResponseRedirect(reverse_lazy('home'))
        return super(ProfileEditView, self).dispatch(*args, **kwargs)

    def get_initial(self):
        initial = super(ProfileEditView, self).get_initial()
        initial['email'] = self.object.user.email
        return initial

    def get_form_kwargs(self):
        kwargs = super(ProfileEditView, self).get_form_kwargs()
        kwargs['instance'] = self.get_object()
        return kwargs

    def form_valid(self, form):
        if self.object.user.email != form.cleaned_data['email']:
            ea_old = EmailAddress.objects.get(email=self.object.user.email)
            ea_old.primary = False
            user = self.object.user
            user.email = form.cleaned_data['email']
            user.save()
            ea_new, _ = EmailAddress.objects.get_or_create(
                user=user, email=user.email)
            ea_new.primary = True
            ea_new.save()
            if not ea_new.verified:
                send_email_confirmation(self.request, self.request.user)
        profile = self.object
        profile.name = form.cleaned_data['name']
        profile.us_status = form.cleaned_data['us_status']
        profile.comments = form.cleaned_data['comments']
        profile.save()
        profile.update_twitter_data()
        return super(ProfileEditView, self).form_valid(form)
