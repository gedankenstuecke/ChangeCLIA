from django.contrib.auth import get_user_model
from django import forms

from .models import Profile

User = get_user_model()


class ProfileForm(forms.ModelForm):
    email = forms.EmailField(help_text="Your email becomes an account: you can verify yourself, and update or edit your information. We won't share it.")
    us_status = forms.ChoiceField(choices=Profile.US_STATUS_CHOICES, widget=forms.RadioSelect())

    class Meta:
        model = Profile
        fields = ['name', 'email', 'twitter', 'location', 'us_status', 'comments']

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
