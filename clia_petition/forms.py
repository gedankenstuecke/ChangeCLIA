from django.contrib.auth import get_user_model
from django import forms

from .models import Profile

User = get_user_model()

RADIO_WIDGET_CLASS = forms.RadioSelect().__class__


class BootstrapModelForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super(BootstrapModelForm, self).__init__(*args, **kwargs)
        for field in iter(self.fields):
            if self.fields[field].widget.__class__ != RADIO_WIDGET_CLASS:
                self.fields[field].widget.attrs.update({
                    'class': 'form-control'
                })


class SignatureForm(BootstrapModelForm):
    """
    Collect signature data.

    Signature completion requires either (a) email address, or (b) linked
    Twitter account.
    """
    email = forms.EmailField(
        help_text=("We won't share this! We use this to verify you, "
                   "and enable you to update or edit information."),
        required=False)

    us_status = forms.ChoiceField(
        choices=Profile.US_STATUS_CHOICES,
        widget=forms.RadioSelect())

    class Meta:
        model = Profile
        fields = ['name', 'email', 'us_status', 'comments']

    def clean_email(self):
        """
        Require nonblank and unique.
        """
        if 'email' in self.cleaned_data and self.cleaned_data['email']:
            email = self.cleaned_data['email']
        else:
            if self.submit_action == 'email':
                raise forms.ValidationError('Please specify an email address!')
            else:
                return ''

        try:
            user = User.objects.get(email=email)
            if self.instance and self.instance.user.id != user.id:
                raise forms.ValidationError(
                    "This email has already been used!")
        except User.DoesNotExist:
            pass
        return email


class ProfileForm(forms.ModelForm):
    email = forms.EmailField(help_text="Your email becomes an account: you can verify yourself, and update or edit your information. We won't share it.")
    us_status = forms.ChoiceField(choices=Profile.US_STATUS_CHOICES, widget=forms.RadioSelect())

    class Meta:
        model = Profile
        fields = ['name', 'email', 'us_status', 'comments']

    def clean_email(self):
        email = self.cleaned_data['email']
        try:
            user = User.objects.get(email=email)
            if self.instance and self.instance.user.id != user.id:
                raise forms.ValidationError(
                    "This email has already been used!")
        except User.DoesNotExist:
            pass
        return email

    def clean_twitter(self):
        twitter = self.cleaned_data['twitter']
        if twitter:
            try:
                profile = Profile.objects.get(twitter=twitter)
                if self.instance and self.instance.id != profile.id:
                    raise forms.ValidationError(
                        "This twitter account has already been used!")
            except Profile.DoesNotExist:
                pass
        return twitter
