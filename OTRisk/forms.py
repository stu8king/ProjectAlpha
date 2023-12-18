from django import forms
from django.forms import BaseModelFormSet, modelformset_factory

from OTRisk.models.RiskScenario import RiskScenario
from OTRisk.models.Model_CyberPHA import vulnerability_analysis, tblAssetType, tblMitigationMeasures, \
    OrganizationDefaults, tblIndustry, tblCyberPHAHeader
from .models.raw import RAWorksheet, RAActions, MitreICSMitigations, RAWorksheetScenario
from .models.Model_Scenario import CustomScenario, CustomConsequence
from .models.model_assessment import AssessmentFramework, AssessmentAnswer
import accounts
from django.contrib.auth.models import User
from accounts.models import UserProfile, Organization
from django.contrib.auth.password_validation import validate_password


class CyberSecurityScenarioForm(forms.Form):
    txtScenario = forms.CharField(
        widget=forms.Textarea(attrs={
            'class': 'form-control',
            'rows': '8',
            'placeholder': 'Enter a detailed cybersecurity scenario...',
            'style': 'resize: none; border: 3px #97979A; border-radius: 10px; box-shadow: inset 3px 3px 8px rgba(0, 0, 0, 0.5); padding: 20px; background-color: white',
            'spellcheck': 'true'
        }),
        required=True
    )

    def clean_txtScenario(self):
        data = self.cleaned_data['txtScenario']
        # Add your validation logic here (e.g., checking for minimum word count, specific keywords)
        return data


class OrganizationForm(forms.ModelForm):
    class Meta:
        model = Organization
        fields = '__all__'
        exclude = ('subscription_type',)


class QuestionnaireUploadForm(forms.Form):
    file = forms.FileField()


class AssessmentFrameworkForm(forms.ModelForm):
    class Meta:
        model = AssessmentFramework
        fields = ['name', 'description', 'version']  # Add any other fields that you wish to display in the form.


class NewAssessmentAnswerForm(forms.ModelForm):
    class Meta:
        model = AssessmentAnswer
        fields = ['response', 'effectiveness', 'weighting']


class EditAssessmentAnswerForm(forms.Form):
    response = forms.ChoiceField(
        choices=[(True, 'Yes'), (False, 'No')],
        widget=forms.RadioSelect,
        label="Response"
    )
    effectiveness = forms.IntegerField(
        min_value=0,
        max_value=100,
        required=False,
        label="Effectiveness",
        widget=forms.NumberInput(attrs={'placeholder': '0-100%'})
    )
    weighting = forms.ChoiceField(
        choices=[(1, 'Low'), (2, 'Medium'), (3, 'High')],
        label="Weighting"
    )

    def __init__(self, *args, **kwargs):
        question_id = kwargs.pop('question_id', None)
        super(EditAssessmentAnswerForm, self).__init__(*args, **kwargs)

        if question_id is not None:
            self.fields['response'].widget.attrs.update({'name': f'response_{question_id}'})


class OrganizationDefaultsForm(forms.ModelForm):
    class Meta:
        model = OrganizationDefaults
        exclude = ('organization',)  # Exclude the organization field from the form

    industry = forms.ModelChoiceField(
        queryset=tblIndustry.objects.all(),
        required=False,
        label="Industry",
        empty_label="Select Industry",
        widget=forms.Select(attrs={'class': 'form-control'})
    )
    impact_weight_safety = forms.IntegerField(
        widget=forms.NumberInput(attrs={
            'class': 'form-control',
            'min': 1,
            'max': 5,
            'type': 'number'
        }),
        required=True
    )
    impact_weight_danger = forms.IntegerField(
        widget=forms.NumberInput(attrs={
            'class': 'form-control',
            'min': 1,
            'max': 5,
            'type': 'number'
        }),
        required=True
    )
    impact_weight_data = forms.IntegerField(
        widget=forms.NumberInput(attrs={
            'class': 'form-control',
            'min': 1,
            'max': 5,
            'type': 'number'
        }),
        required=True
    )
    impact_weight_environment = forms.IntegerField(
        widget=forms.NumberInput(attrs={
            'class': 'form-control',
            'min': 1,
            'max': 5,
            'type': 'number'
        }),
        required=True
    )
    impact_weight_finance = forms.IntegerField(
        widget=forms.NumberInput(attrs={
            'class': 'form-control',
            'min': 1,
            'max': 5,
            'type': 'number'
        }),
        required=True
    )
    impact_weight_production = forms.IntegerField(
        widget=forms.NumberInput(attrs={
            'class': 'form-control',
            'min': 1,
            'max': 5,
            'type': 'number'
        }),
        required=True
    )
    impact_weight_regulation = forms.IntegerField(
        widget=forms.NumberInput(attrs={
            'class': 'form-control',
            'min': 1,
            'max': 5,
            'type': 'number'
        }),
        required=True
    )
    impact_weight_reputation = forms.IntegerField(
        widget=forms.NumberInput(attrs={
            'class': 'form-control',
            'min': 1,
            'max': 5,
            'type': 'number'
        }),
        required=True
    )
    impact_weight_supply = forms.IntegerField(
        widget=forms.NumberInput(attrs={
            'class': 'form-control',
            'min': 1,
            'max': 5,
            'type': 'number'
        }),
        required=True
    )

    def __init__(self, *args, **kwargs):
        super(OrganizationDefaultsForm, self).__init__(*args, **kwargs)
        self.fields['industry'].label_from_instance = lambda obj: "{}".format(obj.Industry)

        # Define currency fields
        currency_fields = ['annual_revenue', 'cyber_insurance', 'insurance_deductible']
        for field_name in currency_fields:
            if field_name in self.fields:
                self.fields[field_name].widget = forms.NumberInput(attrs={
                    'class': 'form-control',
                    'step': '0.01',  # Allows input to have two decimal places
                    'min': '0',  # Optional: ensures that the value is not negative
                    'type': 'text',  # Set as text to prevent spinner UI
                    'pattern': '^\d+(\.?\d{2})?$'  # Pattern for currency (optional)
                })

        # Add Bootstrap form-control class to all fields
        for field_name, field in self.fields.items():
            field.widget.attrs['class'] = 'form-control'


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
        fields = ['organization', 'must_change_password']


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
