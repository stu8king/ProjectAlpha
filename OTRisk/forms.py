from django import forms
from OTRisk.models.RiskScenario import RiskScenario
from OTRisk.models.post import Post, AssessmentTeam
from .models.raw import RAWorksheet, RAActions


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
