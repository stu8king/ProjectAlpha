from django import forms
from .models import Organization

from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from .models import UserProfile


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