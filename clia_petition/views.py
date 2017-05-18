from allauth.account import app_settings as account_settings
from allauth.account.models import EmailAddress
from allauth.account.utils import url_str_to_user_pk, complete_signup, send_email_confirmation

from django.contrib import messages
from django.contrib.auth import authenticate, get_user_model, login
from django.core.urlresolvers import reverse, reverse_lazy
from django.http import HttpResponseRedirect
from django.views.generic import FormView, View
from django.views.generic.detail import SingleObjectMixin

from .forms import ProfileForm
from .models import Profile
from .utils import new_user

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


class HomeView(FormView):
    template_name = "clia_petition/index.html"
    form_class = ProfileForm
    redirect_field_name = "next"
    success_url = reverse_lazy('home')

    def form_valid(self, form):
        user = new_user(email=form.cleaned_data['email'])
        user.save()
        profile = Profile(
            user=user,
            name=form.cleaned_data['name'],
            twitter=form.cleaned_data['twitter'],
            location=form.cleaned_data['location'],
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
        profile.twitter = form.cleaned_data['twitter']
        profile.location = form.cleaned_data['location']
        profile.us_status = form.cleaned_data['us_status']
        profile.comments = form.cleaned_data['comments']
        profile.save()
        return super(ProfileEditView, self).form_valid(form)
