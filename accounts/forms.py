from django import forms
from .models import Organization

from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from .models import UserProfile, SubscriptionType, Organization
from django.contrib.auth.forms import PasswordChangeForm

from django import forms
from .models import SubscriptionType


class PasswordResetRequestForm(forms.Form):
    email = forms.EmailField()


class PasswordResetForm(forms.Form):
    token = forms.CharField()
    new_password = forms.CharField(widget=forms.PasswordInput())
    confirm_password = forms.CharField(widget=forms.PasswordInput())

    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get('new_password')
        confirm_password = cleaned_data.get('confirm_password')
        if password != confirm_password:
            self.add_error('confirm_password', 'Passwords do not match')


class SubscriptionForm(forms.ModelForm):
    email = forms.EmailField(label="Email Address (will be your username)")
    first_name = forms.CharField(label="First Name", max_length=30)
    last_name = forms.CharField(label="Last Name", max_length=30)
    organization_name = forms.CharField(label="Organization Name", max_length=255)
    organization_address = forms.CharField(label="Organization Address", max_length=255)
    organization_address2 = forms.CharField(label="Organization Address2", max_length=255)
    organization_city = forms.CharField(label="Organization City", max_length=255)
    organization_state = forms.CharField(label="Organization State", max_length=255)
    organization_zip = forms.CharField(label="Organization Zip/Post Code", max_length=255)
    organization_country = forms.CharField(label="Organization Country", max_length=255)
    subscription_type = forms.ModelChoiceField(queryset=SubscriptionType.objects.all(),
                                               label="Select Subscription Type", widget=forms.Select(
            attrs={'onchange': 'updateSubscriptionDetails(this.value);'}))

    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email', 'organization_name', 'organization_address', 'subscription_type']


class SetPasswordForm(forms.Form):
    password = forms.CharField(widget=forms.PasswordInput, label="Password")
    confirm_password = forms.CharField(widget=forms.PasswordInput, label="Confirm Password")

    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get("password")
        confirm_password = cleaned_data.get("confirm_password")

        if password != confirm_password:
            raise forms.ValidationError("Passwords do not match.")


class RegistrationForm(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput())
    password_confirm = forms.CharField(widget=forms.PasswordInput(), label="Confirm Password")
    subscription_type = forms.ModelChoiceField(queryset=SubscriptionType.objects.all())
    is_organization = forms.BooleanField(required=False, label="Register as an Organization")
    organization_name = forms.CharField(max_length=255, required=False)

    class Meta:
        model = User
        fields = ['username', 'email', 'first_name', 'last_name', 'password', 'password_confirm', 'subscription_type',
                  'is_organization',
                  'organization_name']

    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get("password")
        password_confirm = cleaned_data.get("password_confirm")

        if password != password_confirm:
            self.add_error('password_confirm', "Passwords do not match")

        return cleaned_data


class CustomUserCreationForm(UserCreationForm):
    first_name = forms.CharField(max_length=30, required=True)
    last_name = forms.CharField(max_length=30, required=True)
    email = forms.EmailField(required=True)
    organization = forms.CharField(max_length=100, required=True)
    is_superuser = forms.BooleanField(required=False)

    class Meta(UserCreationForm.Meta):
        model = User
        fields = ['username', 'first_name', 'last_name', 'email', 'organization', 'password1', 'password2']


class UserAdminForm(forms.ModelForm):
    organization = forms.ModelChoiceField(queryset=Organization.objects.all(), required=False)

    class Meta:
        model = User
        fields = '__all__'

    def __init__(self, *args, **kwargs):
        super(UserAdminForm, self).__init__(*args, **kwargs)
        if self.instance.pk:
            try:
                self.fields['organization'].initial = self.instance.userprofile.organization
            except UserProfile.DoesNotExist:
                pass

    def save(self, commit=True):
        user = super(UserAdminForm, self).save(commit=False)
        if commit:
            user.save()
            profile, created = UserProfile.objects.get_or_create(user=user)
            profile.organization = self.cleaned_data['organization']
            profile.save()
        return user

    class PasswordChangeCustomForm(PasswordChangeForm):
        old_password = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'form-control'}))
        new_password1 = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'form-control'}))
        new_password2 = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'form-control'}))


class StripePaymentForm(forms.Form):
    stripe_token = forms.CharField(max_length=255, widget=forms.HiddenInput)
