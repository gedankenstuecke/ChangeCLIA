from allauth.account.utils import url_str_to_user_pk

from django.contrib.auth import authenticate, get_user_model, login
from django.core.urlresolvers import reverse, reverse_lazy
from django.http import HttpResponseRedirect
from django.views.generic import FormView, View

from .forms import SignupForm

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
    form_class = SignupForm
    redirect_field_name = "next"
    success_url = reverse_lazy('home')

    def form_valid(self, form):
        # Do stuff here.
        return super(HomeView, self).form_valid(form)