from django import forms
from OTRisk.models.RiskScenario import RiskScenario
from OTRisk.models.post import Post, AssessmentTeam
from .models.raw import RAWorksheet, RAActions
from .models.Model_Scenario import CustomScenario, CustomConsequence
import accounts
from django.contrib.auth.models import User
from accounts.models import UserProfile
from django.contrib.auth.password_validation import validate_password


class UserForm(forms.ModelForm):
    username = forms.CharField(widget=forms.TextInput(attrs={'class': 'form-control'}))
    first_name = forms.CharField(widget=forms.TextInput(attrs={'class': 'form-control'}))
    last_name = forms.CharField(widget=forms.TextInput(attrs={'class': 'form-control'}))
    email = forms.EmailField(widget=forms.EmailInput(attrs={'class': 'form-control'}))

    class Meta:
        model = User
        fields = ['username', 'first_name', 'last_name', 'email']


class UserProfileForm(forms.ModelForm):
    class Meta:
        model = UserProfile
        fields = []


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


class AssessmentTeamForm(forms.ModelForm):
    class Meta:
        model = AssessmentTeam
        fields = ['FirstName', 'LastName', 'Title', 'Organization', 'Department', 'Notes']
        widgets = {
            'FirstName': forms.TextInput(attrs={'required': True}),
            'LastName': forms.TextInput(attrs={'required': True}),
            'Title': forms.TextInput(attrs={'required': True}),
            'Organization': forms.TextInput(attrs={'required': True}),
            'Department': forms.TextInput(attrs={'required': True}),
        }


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


class PostForm(forms.ModelForm):
    class Meta:
        model = Post
        fields = [
            'process_description',
            'hazardous_events',
            'causes',
            'consequences',
            'trigger_event',
            'layers_of_protection',
            'risk_ranking',
            'risk_reduction_measures',
            'risk_residual_level',
            'acceptability_criteria',
            'threats',
            'vulnerabilities',
            'impact_analysis',
            'likelihood_assessment',
            'risk_evaluation',
            'risk_mitigation',
            'submit_status',
            'facility',
            'business_unit',
            'project_name',
            'scope',
            'objective',
            'assumptions',
            'SystemName',
            'SystemDescription',
            'SystemScope',
            'SystemOwner',
        ]
