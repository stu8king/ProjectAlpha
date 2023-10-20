from django import forms
from OTRisk.models.RiskScenario import RiskScenario
from OTRisk.models.Model_CyberPHA import vulnerability_analysis, tblAssetType, tblMitigationMeasures
from .models.raw import RAWorksheet, RAActions, MitreICSMitigations, RAWorksheetScenario
from .models.Model_Scenario import CustomScenario, CustomConsequence
import accounts
from django.contrib.auth.models import User
from accounts.models import UserProfile, Organization
from django.contrib.auth.password_validation import validate_password


class RAWorksheetScenarioForm(forms.ModelForm):
    class Meta:
        model = RAWorksheetScenario
        fields = '__all__'  # This includes all fields, but you can specify only the ones you need.


class VulnerabilityAnalysisForm(forms.ModelForm):
    description = forms.CharField(widget=forms.Textarea(attrs={'rows': 3}))
    asset_type = forms.ModelChoiceField(
        queryset=tblAssetType.objects.all(),
        widget=forms.Select(attrs={'class': 'select2'})
    )

    class Meta:
        model = vulnerability_analysis
        fields = '__all__'


class SQLQueryForm(forms.Form):
    query = forms.CharField(widget=forms.Textarea(attrs={'class': 'form-control', 'rows': 5}), label="SQL Query")


class ChangePasswordForm(forms.Form):
    password1 = forms.CharField(label="New Password", widget=forms.PasswordInput)
    password2 = forms.CharField(label="Confirm Password", widget=forms.PasswordInput)

    def clean(self):
        cleaned_data = super().clean()
        if cleaned_data.get('password1') != cleaned_data.get('password2'):
            raise forms.ValidationError("Passwords do not match!")


class UserProfileForm(forms.ModelForm):
    class Meta:
        model = UserProfile
        fields = '__all__'


class UserForm(forms.ModelForm):
    username = forms.CharField(widget=forms.TextInput(attrs={'class': 'form-control'}))
    first_name = forms.CharField(widget=forms.TextInput(attrs={'class': 'form-control'}))
    last_name = forms.CharField(widget=forms.TextInput(attrs={'class': 'form-control'}))
    email = forms.EmailField(widget=forms.EmailInput(attrs={'class': 'form-control'}))
    is_superuser = forms.BooleanField(required=False, widget=forms.CheckboxInput(attrs={'class': 'form-check-input'}))
    is_active = forms.BooleanField(required=False, widget=forms.CheckboxInput(attrs={'class': 'form-check-input'}))

    class Meta:
        model = User
        fields = ['username', 'first_name', 'last_name', 'email', 'is_superuser', 'is_active']


class CustomScenarioForm(forms.ModelForm):
    scenario = forms.CharField(
        widget=forms.Textarea(attrs={'class': 'form-control', 'rows': 3})  # 'rows' is optional, adjust as needed
    )

    class Meta:
        model = CustomScenario
        fields = ['scenario']

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user', None)  # Fetch the user and remove it from kwargs
        super().__init__(*args, **kwargs)

    def save(self, commit=True):
        instance = super().save(commit=False)
        if not instance.pk:  # Use pk instead of id for clarity
            instance.created_by = self.user
            instance.user_profile = accounts.models.UserProfile.objects.get(user=self.user)
        if commit:
            instance.save()
        return instance


class CustomConsequenceForm(forms.ModelForm):
    Consequence = forms.CharField(
        widget=forms.Textarea(attrs={'class': 'form-control', 'rows': 3})  # 'rows' is optional, adjust as needed
    )

    class Meta:
        model = CustomConsequence
        fields = ['Consequence']

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user', None)  # Fetch the user and remove it from kwargs
        super().__init__(*args, **kwargs)

    def save(self, commit=True):
        instance = super().save(commit=False)
        if not instance.pk:  # Use pk instead of id for clarity
            instance.created_by = self.user
            instance.user_profile = accounts.models.UserProfile.objects.get(user=self.user)
        if commit:
            instance.save()
        return instance


class RAActionsForm(forms.ModelForm):
    class Meta:
        model = RAActions
        fields = '__all__'


class RAWorksheetForm(forms.ModelForm):
    class Meta:
        model = RAWorksheet
        fields = ['cyberPHAID']


class LoginForm(forms.Form):
    username = forms.CharField()
    password = forms.CharField(widget=forms.PasswordInput)


class TeamMemberForm(forms.Form):
    first_name = forms.CharField(max_length=100)
    last_name = forms.CharField(max_length=100)
    title = forms.CharField(max_length=100)
    organization = forms.CharField(max_length=100)
    department = forms.CharField(max_length=100)
    notes = forms.CharField(max_length=100, required=False)


class RiskScenarioForm(forms.ModelForm):
    class Meta:
        model = RiskScenario
        fields = '__all__'


class ControlAssessmentForm(forms.Form):
    def __init__(self, *args, **kwargs):
        super(ControlAssessmentForm, self).__init__(*args, **kwargs)
        for mitigation in MitreICSMitigations.objects.all():
            self.fields[f'mitigation_{mitigation.id}'] = forms.IntegerField(
                label=mitigation.name,
                widget=forms.NumberInput(attrs={
                    'type': 'range',
                    'min': 0,
                    'max': 100,
                    'class': 'custom-range'
                })
            )


class OrganizationAdmin(forms.ModelForm):
    class Meta:
        model = Organization
        widgets = {
            'address': forms.TextInput(),
            'address2': forms.TextInput(),
            'city': forms.TextInput(),
            'state': forms.TextInput(),
            'zip': forms.TextInput(),
            'max_users': forms.TextInput(),
            'subscription_start': forms.DateInput(attrs={'type': 'date'}),
            'subscription_end': forms.DateInput(attrs={'type': 'date'})
        }
        exclude = ['subscription_type']

