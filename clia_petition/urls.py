"""clia_petition URL Configuration"""

from django.conf.urls import include, url
from django.contrib import admin
from django.views.generic import TemplateView

from clia_petition.views import HomeView, ProfileEditView, ResendConfirmationView, TokenLoginView

urlpatterns = [
    url(r'^admin/', admin.site.urls),
    url(r'^/?$', HomeView.as_view(), name='home'),
    url(r'^profile_edit/(?P<pk>[0-9]+)/$', ProfileEditView.as_view(), name='profile_edit'),
    url(r'^resend_confirmation/?', ResendConfirmationView.as_view(), name='resend_confirmation'),
    url(r'^account/', include('allauth.urls')),
    url(r"^token_login/(?P<uidb36>[0-9A-Za-z]+)-(?P<token>.+)/$",
        TokenLoginView.as_view(), name='token_login'),
    url(r'^token_login_fail/?$',
        TemplateView.as_view(template_name='clia_petition/token_login_fail.html'),
        name='token_login_fail'),
]
