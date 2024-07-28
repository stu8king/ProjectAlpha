from django import forms
from django.core.validators import MaxValueValidator
from django.forms import BaseModelFormSet, modelformset_factory

from OTRisk.models.RiskScenario import RiskScenario
from OTRisk.models.Model_CyberPHA import vulnerability_analysis, tblAssetType, tblMitigationMeasures, \
    OrganizationDefaults, tblIndustry, tblCyberPHAHeader, CybersecurityDefaults
from .models.raw import RAWorksheet, RAActions, MitreICSMitigations, RAWorksheetScenario, MitreICSTechniques
from .models.Model_Scenario import CustomConsequence
from .models.model_assessment import AssessmentFramework, AssessmentAnswer
import accounts
from django.contrib.auth.models import User
from accounts.models import UserProfile, Organization
from django.contrib.auth.password_validation import validate_password


class CyberSecurityScenarioForm(forms.Form):
    txtScenario = forms.CharField(
        widget=forms.Textarea(attrs={
            'class': 'form-control',
            'rows': '20',
            'placeholder': 'Enter a detailed cybersecurity scenario...',
            'style': 'resize: none; border: 3px #97979A; border-radius: 10px; box-shadow: inset 3px 3px 8px rgba(0, 0, 0, 0.5); padding: 20px; background-color: white',
            'spellcheck': 'true'
        }),
        required=True
    )
    txtConsequences = forms.CharField(
        widget=forms.Textarea(attrs={
            'class': 'form-control',
            'rows': '8',
            'placeholder': 'Scenario Consequences...',
            'style': 'resize: none; border: 3px #97979A; border-radius: 10px; box-shadow: inset 3px 3px 8px rgba(0, 0, 0, 0.5); padding: 20px; background-color: white',
            'spellcheck': 'true',
            'readonly': 'true'
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
        fields = ['response', 'effectiveness', 'weighting', 'remarks']
        widgets = {
            'remarks': forms.Textarea(attrs={'rows': 4, 'style': 'resize:none;', 'maxlength': '250'}),
        }


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


class CybersecurityDefaultsForm(forms.ModelForm):
    class Meta:
        model = CybersecurityDefaults
        fields = [
            'overall_aggregate_limit',
            'per_claim_limit',
            'deductible_amount',
            'first_party_coverage',
            'third_party_coverage',
            'security_event_liability',
            'privacy_regulatory_actions',
            'cyber_extortion_coverage',
            'data_breach_response_coverage',
            'business_interruption_coverage',
            'dependent_business_coverage',
            'data_recovery',
            'hardware_replacement',
            'reputation_harm',
            'media_liability',
            'pci_dss',
            'premium_base',
            'notification_period_days',
            'cancellation_terms_days',
        ]
        widgets = {
            'overall_aggregate_limit': forms.NumberInput(attrs={'class': 'form-control', 'step': '0.01'}),
            'per_claim_limit': forms.NumberInput(attrs={'class': 'form-control', 'step': '0.01'}),
            'deductible_amount': forms.NumberInput(attrs={'class': 'form-control', 'step': '0.01'}),
            'premium_base': forms.NumberInput(attrs={'class': 'form-control', 'step': '0.01'}),
            'notification_period_days': forms.NumberInput(attrs={'class': 'form-control'}),
            'cancellation_terms_days': forms.NumberInput(attrs={'class': 'form-control'}),
            'first_party_coverage': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'third_party_coverage': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'cyber_extortion_coverage': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'data_breach_response_coverage': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'business_interruption_coverage': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'privacy_regulatory_actions': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'security_event_liability': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'dependent_business_coverage': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'data_recovery': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'hardware_replacement': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'reputation_harm': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'media_liability': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'pci_dss': forms.CheckboxInput(attrs={'class': 'form-check-input'}),

        }
        validators = {
            'overall_aggregate_limit': [MaxValueValidator(999999999)],
            'per_claim_limit': [MaxValueValidator(999999999)],
            'deductible_amount': [MaxValueValidator(999999999)],
            'premium_base': [MaxValueValidator(999999999)],
            # Add validators for other numerical fields as necessary
        }


class OrganizationDefaultsForm(forms.ModelForm):
    class Meta:
        model = OrganizationDefaults
        exclude = (
            'organization', 'cyber_insurance', 'insurance_deductible', 'impact_weight_safety', 'impact_weight_danger',
            'impact_weight_data', 'impact_weight_supply', 'impact_weight_finance', 'impact_weight_production',
            'impact_weight_regulation', 'impact_weight_reputation',
            'impact_weight_environment', 'business_unit_lat', 'business_unit_lon'
        )

    industry = forms.ModelChoiceField(
        queryset=tblIndustry.objects.all(),
        required=False,
        label="Industry",
        empty_label="Select Industry",
        widget=forms.Select(attrs={'class': 'form-control'})
    )

    exalens_api_key = forms.CharField(
        required=False,
        widget=forms.TextInput(attrs={'class': 'form-control'}),
        label="API Key"
    )
    exalens_client_id = forms.CharField(
        required=False,
        widget=forms.TextInput(attrs={'class': 'form-control'}),
        label="Client ID"
    )
    exalens_ip_address = forms.CharField(
        required=False,
        widget=forms.TextInput(attrs={'class': 'form-control'}),
        label="IP Address"
    )
    business_unit_name = forms.CharField(
        required=False,
        widget=forms.TextInput(attrs={'class': 'form-control'}),
        label="Business Unit Name"
    )
    business_unit_address_line1 = forms.CharField(
        required=False,
        widget=forms.TextInput(attrs={'class': 'form-control'}),
        label="Address Line 1"
    )
    business_unit_address_line2 = forms.CharField(
        required=False,
        widget=forms.TextInput(attrs={'class': 'form-control'}),
        label="Address Line 2"
    )
    business_unit_address_line3 = forms.CharField(
        required=False,
        widget=forms.TextInput(attrs={'class': 'form-control'}),
        label="Address Line 3"
    )
    business_unit_city = forms.CharField(
        required=False,
        widget=forms.TextInput(attrs={'class': 'form-control'}),
        label="City"
    )
    business_unit_state = forms.CharField(
        required=False,
        widget=forms.TextInput(attrs={'class': 'form-control'}),
        label="State"
    )
    business_unit_country = forms.CharField(
        required=False,
        widget=forms.TextInput(attrs={'class': 'form-control'}),
        label="Country"
    )
    business_unit_postcode = forms.CharField(
        required=False,
        widget=forms.TextInput(attrs={'class': 'form-control'}),
        label="Postcode"
    )

    darktrace_public_key = forms.CharField(
        required=False,
        widget=forms.TextInput(attrs={'class': 'form-control'}),
        label="Public Key"
    )
    darktrace_private_key = forms.CharField(
        required=False,
        widget=forms.TextInput(attrs={'class': 'form-control'}),
        label="Private Key"
    )
    darktrace_host = forms.CharField(
        required=False,
        widget=forms.TextInput(attrs={'class': 'form-control'}),
        label="Host"
    )

    def __init__(self, *args, **kwargs):
        super(OrganizationDefaultsForm, self).__init__(*args, **kwargs)
        self.fields['industry'].label_from_instance = lambda obj: "{}".format(obj.Industry)

        currency_fields = ['annual_revenue', 'cyber_insurance', 'insurance_deductible']
        for field_name in currency_fields:
            if field_name in self.fields:
                self.fields[field_name].widget = forms.NumberInput(attrs={
                    'class': 'form-control',
                    'step': '0.01',
                    'min': '0',
                    'type': 'text',
                    'pattern': '^\d+(\.?\d{2})?$'
                })

        for field_name, field in self.fields.items():
            field.widget.attrs['class'] = 'form-control'

    def save(self, commit=True):
        instance = super(OrganizationDefaultsForm, self).save(commit=False)
        instance.cyber_insurance = 0
        instance.insurance_deductible = 0
        if commit:
            instance.save()
        return instance




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
    password = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'form-control'}), label="Password")


class ChangePasswordForm(forms.Form):
    password1 = forms.CharField(label="New Password", widget=forms.PasswordInput)
    password2 = forms.CharField(label="Confirm Password", widget=forms.PasswordInput)

    def clean(self):
        cleaned_data = super().clean()
        if cleaned_data.get('password1') != cleaned_data.get('password2'):
            raise forms.ValidationError("Passwords do not match!")


class UserProfileForm(forms.ModelForm):
    jobtitle = forms.CharField(
        widget=forms.TextInput(attrs={'class': 'form-control'}),  # Applying Bootstrap class
        max_length=100,
        required=False  # Set to True if this field is required
    )
    max_scenario_count = forms.IntegerField(
        widget=forms.NumberInput(attrs={'class': 'form-control'}),
        required=False,  # Set to True if this field is required
        initial=10,  # Default value or use a sensible default for your use case
        help_text='Maximum number of scenario analyses allowed for the user.'
    )

    class Meta:
        model = UserProfile
        fields = ['organization', 'must_change_password', 'jobtitle', 'role_moderator', 'role_readonly',
                  'max_scenario_count']


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


class scenario_sim(forms.Form):
    # Other fields as before...
    industry = forms.ModelChoiceField(
        queryset=tblIndustry.objects.all().order_by('Industry'),
        label='Industry/Sector',
        to_field_name='Industry'
    )
    incident_type = forms.ModelChoiceField(
        queryset=MitreICSTechniques.objects.all().order_by('SourceName'),
        label='Type of Incident',
        to_field_name='SourceName'
    )
    company_name = forms.CharField(label='Company Name', max_length=100)

    company_size = forms.IntegerField(label='Number of Employees')
    annual_revenue = forms.DecimalField(label='Annual Revenue')
    location = forms.CharField(label='Geographic Location', max_length=100)
    contact_info = forms.EmailField(label='Contact Email')
    scenario_description = forms.CharField(
        label='Scenario Description',
        widget=forms.Textarea
    )
    incident_date = forms.DateField(label='Date of Incident')
    incident_duration = forms.DurationField(label='Duration of Incident')
    it_infrastructure = forms.CharField(
        label='IT Infrastructure Details',
        widget=forms.Textarea
    )
    systems_affected = forms.CharField(
        label='Types of Systems Affected',
        widget=forms.Textarea
    )
    security_measures = forms.CharField(
        label='Security Measures in Place',
        widget=forms.Textarea
    )
    security_software = forms.CharField(
        label='Security Software/Tools in Use',
        widget=forms.Textarea
    )
    immediate_impact = forms.CharField(
        label='Immediate Impact of Incident',
        widget=forms.Textarea
    )
    direct_costs = forms.DecimalField(label='Known Direct Costs')
    customer_data_affected = forms.CharField(
        label='Customer Data Affected',
        widget=forms.Textarea
    )
    employee_data_affected = forms.CharField(
        label='Employee Data Affected',
        widget=forms.Textarea
    )
    response_steps = forms.CharField(
        label='Response Steps Taken',
        widget=forms.Textarea
    )
    recovery_time = forms.DurationField(label='Time to Identify and Contain')
    system_status = forms.CharField(label='Current Status of Systems', max_length=100)
    external_assistance = forms.CharField(
        label='External Assistance Sought',
        widget=forms.Textarea
    )
