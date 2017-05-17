from django import forms

from .models import Profile


class SignupForm(forms.ModelForm):
    email = forms.EmailField(help_text="Your email becomes an account: you can verify yourself, and update or edit your information. We won't share it.")
    us_status = forms.ChoiceField(choices=Profile.US_STATUS_CHOICES, widget=forms.RadioSelect())

    class Meta:
        model = Profile
        fields = ['name', 'email', 'twitter', 'location', 'us_status', 'comments']
