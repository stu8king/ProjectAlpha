import decimal
import os
from pptx import Presentation
from pptx.util import Inches
import requests
from io import BytesIO
from django.contrib.auth.models import User
from django.core.exceptions import ObjectDoesNotExist
from django.core.serializers import serialize
from django.forms import formset_factory, modelformset_factory
from django.shortcuts import get_object_or_404
from django.template.loader import render_to_string
from django.utils.crypto import get_random_string
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from django.db.models import Subquery, OuterRef, Count, IntegerField, Case, When, Value, Prefetch

import OTRisk.forms
from OTRisk.models.RiskScenario import RiskScenario, tblScenarioRecommendations
from OTRisk.models.Model_Scenario import tblConsequence
from OTRisk.models.questionnairemodel import Questionnaire, FacilityType
from OTRisk.models.ThreatAssessment import ThreatAssessment
from OTRisk.models.raw import RAWorksheet, RAWorksheetScenario, RAActions, MitreICSMitigations, RawControlList, \
    QRAW_Safeguard
from django.db.models import F, Count, Avg, Case, When, Value, CharField, Sum
from django.db.models.functions import Ceil

from accounts import models
from accounts.views import get_client_ip
from django.http import JsonResponse, HttpResponse, HttpResponseForbidden, HttpResponseRedirect
from django.utils import timezone
from django.core import serializers
from OTRisk.models.Model_Workshop import tblWorkshopNarrative, tblWorkshopInformation
from OTRisk.models.Model_CyberPHA import tblCyberPHAHeader, tblRiskCategories, \
    tblControlObjectives, \
    tblThreatIntelligence, tblMitigationMeasures, tblScenarios, tblSafeguards, tblThreatSources, tblThreatActions, \
    tblNodes, tblUnits, tblZones, tblCyberPHAScenario, tblIndustry, auditlog, tblStandards, MitreControlAssessment, \
    CyberPHAScenario_snapshot, Audit, PHAControlList, SECURITY_LEVELS, OrganizationDefaults, scenario_compliance, \
    ScenarioConsequences, APIKey, ScenarioBuilder, PHA_Safeguard
from django.shortcuts import render, redirect
from .dashboard_views import get_user_organization_id
from django.contrib.auth.decorators import login_required
from .forms import LoginForm, OrganizationDefaultsForm, CyberSecurityScenarioForm, scenario_sim
from datetime import date, datetime
import json
import openai, math
import requests, re
from xml.etree import ElementTree as ET
from .raw_views import qraw, openai_assess_risk, GetTechniquesView, raw_action, check_vulnerabilities, rawreport, \
    raw_from_walkdown, save_ra_action, get_rawactions, ra_actions_view, UpdateRAAction, reports, reports_pha, \
    create_or_update_raw_scenario, analyze_raw_scenario, analyze_sim_scenario, generate_sim_attack_tree, \
    analyze_sim_consequences, update_workflow
from .dashboard_views import dashboardhome
from .pha_views import iotaphamanager, facility_risk_profile, get_headerrecord, scenario_analysis, phascenarioreport, \
    getSingleScenario, pha_report, scenario_vulnerability, add_vulnerability, get_asset_types, calculate_effectiveness, \
    generate_ppt, analyze_scenario, assign_cyberpha_to_group, fetch_groups, fetch_all_groups, retrieve_scenario_builder
from .report_views import pha_reports, get_scenario_report_details, qraw_reports, get_qraw_scenario_report_details
from .forms import CustomScenarioForm, CustomConsequenceForm, OrganizationAdmin
from .models.Model_Scenario import CustomScenario, CustomConsequence
from accounts.models import Organization, OrganizationHistory
from accounts.models import UserProfile
from .forms import UserForm, UserProfileForm, ChangePasswordForm
import secrets
import string
from django.core.mail import send_mail, EmailMultiAlternatives
from django.contrib.auth.decorators import user_passes_test
from django.db import connection, transaction
from django.urls import reverse
from OTRisk.forms import SQLQueryForm, ControlAssessmentForm, AssessmentFrameworkForm, NewAssessmentAnswerForm, \
    EditAssessmentAnswerForm, QuestionnaireUploadForm, OrganizationForm
from .models.model_assessment import AssessmentFramework, AssessmentQuestion, SelfAssessment, AssessmentAnswer
import csv
from django.contrib import messages
import chardet

app_name = 'OTRisk'


# Add Organization View
@login_required
def organization_form_view(request):
    organizations = Organization.objects.all()
    selected_org = request.GET.get('org_id', None)

    if request.method == 'POST':
        if selected_org:
            organization = Organization.objects.get(id=selected_org)
            form = OrganizationForm(request.POST, instance=organization)
        else:
            form = OrganizationForm(request.POST)
            form.instance.created_by = request.user

        if form.is_valid():
            organization = form.save()
            # Record the action in OrganizationHistory
            action = "Created" if not selected_org else "Updated"
            change_description = ", ".join(
                [f"{key}: {value}" for key, value in request.POST.items() if key != 'csrfmiddlewaretoken'])
            OrganizationHistory.objects.create(
                organization=organization,
                action=action,
                changed_by=request.user,
                change_description=change_description
            )
            return redirect('OTRisk:organization_form')
    else:
        form = OrganizationForm(instance=Organization.objects.get(id=selected_org) if selected_org else None)

    return render(request, 'OTRisk/org_form.html',
                  {'form': form, 'organizations': organizations, 'selected_org': selected_org})


def load_organizations(request):
    organizations = Organization.objects.all()
    return JsonResponse(list(organizations.values('id', 'name')), safe=False)


def get_organization_defaults(request, organization_id):
    # Ensure this view handles only GET requests
    if request.method == 'GET':
        # Retrieve the OrganizationDefaults record
        org_defaults = get_object_or_404(OrganizationDefaults, organization_id=organization_id)
        industry_name = tblIndustry.objects.get(id=org_defaults.industry_id).Industry if org_defaults.industry else None
        # Prepare the data to send back
        data = {
            'industry': industry_name,
            'language': org_defaults.language,
            'annual_revenue': org_defaults.annual_revenue,
            'cyber_insurance': org_defaults.cyber_insurance,
            'insurance_deductible': org_defaults.insurance_deductible,
            'employees': org_defaults.employees,
            'impact_weight_safety': org_defaults.impact_weight_safety,
            'impact_weight_danger': org_defaults.impact_weight_danger,
            'impact_weight_environment': org_defaults.impact_weight_environment,
            'impact_weight_production': org_defaults.impact_weight_production,
            'impact_weight_finance': org_defaults.impact_weight_finance,
            'impact_weight_reputation': org_defaults.impact_weight_reputation,
            'impact_weight_regulation': org_defaults.impact_weight_regulation,
            'impact_weight_data': org_defaults.impact_weight_data,
            'impact_weight_supply': org_defaults.impact_weight_supply
        }

        # Return the data as JSON
        return JsonResponse(data)

    # Handle non-GET requests
    else:
        return JsonResponse({'error': 'GET request required'}, status=400)


###########################
###########################
# function to update the total BIA score from all scenarios associated with a given cyberPHAID
def update_bia_scenarios(cyber_pha_id, user):
    # Fetch the CyberPHAHeader record
    try:
        cyber_pha_header = tblCyberPHAHeader.objects.get(ID=cyber_pha_id)
    except tblCyberPHAHeader.DoesNotExist:
        # Handle the case where the record does not exist
        return

    # Fetch the organization defaults for the user's organization
    try:
        user_profile = UserProfile.objects.get(user=user)
        organization_defaults = OrganizationDefaults.objects.get(organization=user_profile.organization)
    except (UserProfile.DoesNotExist, OrganizationDefaults.DoesNotExist):
        # Handle cases where UserProfile or OrganizationDefaults does not exist
        return

    # Extract the impact weightings from OrganizationDefaults
    impact_fields_weightings = {
        'impactSafety': organization_defaults.impact_weight_safety,
        'impactDanger': organization_defaults.impact_weight_danger,
        'impactEnvironment': organization_defaults.impact_weight_environment,
        'impactProduction': organization_defaults.impact_weight_production,
        'impactFinance': organization_defaults.impact_weight_finance,
        'impactReputation': organization_defaults.impact_weight_reputation,
        'impactRegulation': organization_defaults.impact_weight_regulation,
        'impactData': organization_defaults.impact_weight_data,
        'impactSupply': organization_defaults.impact_weight_supply
    }

    # Calculate the weighted sum of each impact field
    weighted_impacts = {
        field: Avg(field) * weight
        for field, weight in impact_fields_weightings.items()
    }

    # Aggregate the weighted sums from related scenarios
    weighted_averages = tblCyberPHAScenario.objects.filter(
        CyberPHA=cyber_pha_header,
        Deleted=0  # Assuming you only want to include non-deleted scenarios
    ).aggregate(**weighted_impacts)

    # Calculate the total of all weightings
    total_weighting = sum(impact_fields_weightings.values())

    # Calculate the overall weighted average impact score
    total_weighted_avg_score = sum(weighted_averages.values()) / total_weighting

    # Update the bia_scenarios field in the CyberPHAHeader record
    cyber_pha_header.bia_scenarios = total_weighted_avg_score
    cyber_pha_header.save()


###########################
###########################

# Assessment framework Code
#########################
@login_required
def assessment_report_view(request, assessment_id):
    # Get the SelfAssessment object or 404
    self_assessment = get_object_or_404(SelfAssessment, pk=assessment_id)

    # Get all answers related to the self assessment
    answers = AssessmentAnswer.objects.filter(selfassessment=self_assessment)

    # Pie Chart Data: Count of 'Yes' and 'No' answers
    yes_count = answers.filter(response=True).count()
    no_count = answers.filter(response=False).count()
    pie_data = {'Yes': yes_count, 'No': no_count}

    # Bar Graph Data: % of 'Yes' answers for each category
    bar_data = {}
    categories = AssessmentQuestion.objects.filter(
        framework=self_assessment.framework
    ).values_list('category', flat=True).distinct()

    for category in categories:
        category_questions = AssessmentQuestion.objects.filter(framework=self_assessment.framework, category=category)
        total_questions = category_questions.count()
        yes_questions = answers.filter(question__in=category_questions, response=True).count()
        if total_questions > 0:
            yes_percentage = (yes_questions / total_questions) * 100
            bar_data[category] = yes_percentage
        else:
            bar_data[category] = 0

    # Data for 'No' and 'Yes' answer tables
    no_answers = answers.filter(response=False)
    yes_answers = answers.filter(response=True)

    # Pass data to context for rendering in the template
    context = {
        'self_assessment': self_assessment,
        'pie_data': pie_data,
        'bar_data': bar_data,
        'no_answers': no_answers,
        'yes_answers': yes_answers,
    }

    return render(request, 'assessment_report.html', context)


@login_required
def upload_questionnaire(request):
    if request.method == 'POST':
        form = QuestionnaireUploadForm(request.POST, request.FILES)
        if form.is_valid():
            file = request.FILES['file']
            # Detect file encoding
            raw_data = file.read()
            result = chardet.detect(raw_data)
            encoding = result['encoding']

            # Decode file using detected encoding
            try:
                decoded_file = raw_data.decode(encoding)
            except UnicodeDecodeError:
                # Handle decode error, perhaps set a default encoding or return an error message
                messages.error(request, "Error decoding the file. Please ensure it is a valid CSV file.")
                return render(request, 'upload_questionnaire.html', {'form': form})

            reader = csv.reader(decoded_file.splitlines())

            # Process the first row for framework details
            try:
                with transaction.atomic():
                    first_row = next(reader)
                    if len(first_row) < 3:
                        messages.error(request, "Framework row must have at least 3 columns.")
                        return render(request, 'upload_questionnaire.html', {'form': form})

                    framework_name, description, version = first_row[:3]
                    owner_organization_id = request.session.get('user_organization')

                    if not owner_organization_id:
                        messages.error(request, "No organization information in session.")
                        return render(request, 'upload_questionnaire.html', {'form': form})

                    framework, created = AssessmentFramework.objects.get_or_create(
                        name=framework_name, defaults={'description': description, 'version': version,
                                                       'owner_organization': owner_organization_id}
                    )

                    # Process the remaining rows for questions
                    for row in reader:
                        if len(row) < 4:
                            # Log or handle the error for rows with insufficient columns
                            continue  # Skipping this row

                        text, guidance, section_reference, category = row[:4]
                        AssessmentQuestion.objects.create(
                            framework=framework,
                            text=text,
                            guidance=guidance,
                            section_reference=section_reference,
                            category=category
                        )

                    messages.success(request, "Questionnaire uploaded successfully.")
                    return redirect('OTRisk:list_frameworks')

            except StopIteration:
                # Handle the case where the CSV is empty or only has a header
                messages.error(request, "The uploaded file is empty or not properly formatted.")
                return render(request, 'upload_questionnaire.html', {'form': form})

    else:
        form = QuestionnaireUploadForm()

    return render(request, 'upload_questionnaire.html', {'form': form})


@login_required
def fetch_updated_assessments(request):
    assessments = SelfAssessment.objects.filter(organization_id=get_user_organization_id(request))
    data = []

    for assessment in assessments:
        assessment_data = {
            'id': assessment.id,
            'framework_name': assessment.framework.name,
            'name': assessment.name,
            'date_created': assessment.date_created.strftime("%Y-%m-%d %H:%M:%S"),
            'date_modified': assessment.date_modified.strftime("%Y-%m-%d %H:%M:%S")
        }
        data.append(assessment_data)

    return JsonResponse({'assessments': data})


@csrf_exempt
def update_assessment_name(request):
    if request.method == 'POST':
        assessment_id = request.POST.get('assessment_id')
        new_name = request.POST.get('new_name')

        assessment = SelfAssessment.objects.get(id=assessment_id)
        assessment.name = new_name
        assessment.save()

        return JsonResponse({'status': 'success', 'message': 'Name updated successfully'})
    return JsonResponse({'status': 'error', 'message': 'Invalid request'})


@login_required
def list_frameworks(request):
    frameworks = AssessmentFramework.objects.all()
    # Retrieve the assessments completed by the user
    completed_assessments = SelfAssessment.objects.filter(organization_id=get_user_organization_id(request))
    return render(request, 'list_frameworks.html', {
        'frameworks': frameworks,
        'completed_assessments': completed_assessments
    })


@login_required
def edit_assessment(request, assessment_id):
    # Retrieve the existing SelfAssessment or redirect if not found
    self_assessment = get_object_or_404(SelfAssessment, pk=assessment_id, user=request.user,
                                        organization_id=get_user_organization_id(request))
    framework = self_assessment.framework  # Get the associated framework
    questions = AssessmentQuestion.objects.filter(framework=self_assessment.framework)

    # Build a dictionary of existing answers for this assessment
    existing_answers = {answer.question.id: answer for answer in self_assessment.answers.all()}
    # Variables to calculate scores
    total_questions = questions.count()
    yes_count = 0
    total_effectiveness = 0

    if request.method == 'POST':
        for question in questions:
            response_key = f'response_{question.id}'
            effectiveness_key = f'effectiveness_{question.id}'
            weighting_key = f'weighting_{question.id}'

            # Get the data from POST request using the unique keys
            response = request.POST.get(response_key) == 'True'
            effectiveness = request.POST.get(effectiveness_key, '0').isdigit() and int(
                request.POST.get(effectiveness_key, '0')) or None
            weighting = request.POST.get(weighting_key, '1').isdigit() and int(
                request.POST.get(weighting_key, '1')) or 1

            # Check if an answer already exists
            if question.id in existing_answers:
                answer = existing_answers[question.id]
                answer.response = response
                answer.effectiveness = effectiveness
                answer.weighting = weighting
            else:
                # Create a new answer if it does not exist
                answer = AssessmentAnswer.objects.create(
                    question=question,
                    response=response,
                    effectiveness=effectiveness,
                    weighting=weighting,
                )
                self_assessment.answers.add(answer)  # Add the new answer to the m2m field

            answer.save()  # Save the answer

            if response:
                yes_count += 1
                total_effectiveness += effectiveness or 0

        # Update score fields in self_assessment
        self_assessment.score_number = yes_count
        if total_questions > 0:
            self_assessment.score_percent = int((yes_count / total_questions) * 100)
            self_assessment.score_effective = int(
                (total_effectiveness / (total_questions * 100)) * 100)
        else:
            self_assessment.score_percent = 0
            self_assessment.score_effective = 0

        self_assessment.save()  # Save the SelfAssessment to update the 'date_modified' field
        return redirect('OTRisk:list_frameworks')

    # For GET request, initialize the forms with existing answer data
    answer_forms = []
    for question in questions:
        answer = existing_answers.get(question.id)
        # Initialize form data based on the existing answer if it exists
        form_data = {
            'effectiveness': answer.effectiveness if answer and answer.response else 0,
            'weighting': answer.weighting if answer else 1,
        }
        if answer is not None:
            form_data['response'] = answer.response

        form = EditAssessmentAnswerForm(initial=form_data, question_id=question.id)
        answer_forms.append((question, form))

    # Render the form with the context
    context = {
        'assessment_id': assessment_id,
        'answer_forms': answer_forms,
        'framework_description': framework.description,
    }
    return render(request, 'assessment_questions.html', context)


# views.py

@login_required
def assessment_questions(request, framework_id):
    # Retrieve the framework or return 404 if not found
    framework = get_object_or_404(AssessmentFramework, pk=framework_id)
    questions = framework.assessmentquestion_set.all()

    # Initialize the formset for the given framework's questions
    AnswerFormSet = modelformset_factory(
        AssessmentAnswer,
        form=NewAssessmentAnswerForm,
        fields=('response', 'effectiveness', 'weighting'),
        extra=len(questions),
        can_delete=False
    )
    formset = AnswerFormSet(
        request.POST or None,
        queryset=AssessmentAnswer.objects.none()  # No pre-existing answers for a new assessment
    )

    # if request.method == 'POST' and formset.is_valid():
    #    print(request.POST)
    #    # Create a new SelfAssessment instance
    #    self_assessment = SelfAssessment.objects.create(user=request.user, framework=framework)

    # Save the formset instances and associate them with the new self_assessment
    #    instances = formset.save(commit=False)
    #    for instance, form in zip(instances, formset.forms):
    # Extract the question ID from the form prefix
    #        question_id = request.POST.get(f"{form.prefix}-question")
    #        question = get_object_or_404(AssessmentQuestion, pk=question_id)
    #        instance.question = question  # Link the instance to the question
    #        instance.selfassessment = self_assessment  # Link to the self_assessment
    #        instance.save()  # Now save the instance

    #    return redirect('OTRisk:list_frameworks')

    # Prepare the data for rendering the forms alongside the questions
    # zipped_questions_forms = zip(questions, formset)

    return redirect('OTRisk:list_frameworks')


# return render(request, 'OTRisk/assessment_questions.html', {
#     'framework': framework,
#     'formset': formset,
#     'questions': questions,
#     'zipped_questions_forms': zipped_questions_forms,
#     'is_new_assessment': True,  # This is always True since it's for new assessments
# })


@login_required
def start_assessment(request, framework_id):
    # Get the framework
    framework = get_object_or_404(AssessmentFramework, pk=framework_id)
    # Start a new assessment for this framework and user
    new_self_assessment = SelfAssessment.objects.create(user=request.user, framework=framework)
    # Redirect to the assessment questions view with the new self_assessment id
    return redirect('OTRisk:assessment_questions', self_assessment_id=new_self_assessment.id)


def save_assessment(request, framework_id):
    if request.method == 'POST':
        user = request.user
        framework = AssessmentFramework.objects.get(id=framework_id)
        self_assessment, created = SelfAssessment.objects.get_or_create(user=user, framework=framework)

        for question in framework.assessmentquestion_set.all():
            answer_data = {
                'response': request.POST.get(f'response_{question.id}'),
                'effectiveness': request.POST.get(f'effectiveness_{question.id}'),
                'weighting': request.POST.get(f'weighting_{question.id}')
            }
            answer, created = AssessmentAnswer.objects.get_or_create(question=question, defaults=answer_data)
            if not created:
                for field, value in answer_data.items():
                    setattr(answer, field, value)
                answer.save()
            self_assessment.answers.add(answer)
        return redirect('some_view_to_redirect_to')


def select_framework(request, framework_id):
    # Get the selected framework or return 404 if not found
    framework = get_object_or_404(AssessmentFramework, pk=framework_id)
    # Get the organization associated with the current user
    user_profile = UserProfile.objects.get(user=request.user)
    organization = user_profile.organization_id

    # Create a new SelfAssessment for this framework, the current user, and the organization
    self_assessment = SelfAssessment.objects.create(
        user=request.user,
        framework=framework,
        organization_id=organization
    )

    # Redirect to the assessment questions page for the new SelfAssessment
    return redirect('OTRisk:assessment_questions', framework_id=framework_id)


#########################
#########################


@login_required
def setup_org(request):
    user_organization = request.user.userprofile.organization
    defaults_instance, created = OrganizationDefaults.objects.get_or_create(organization=user_organization)

    if request.method == 'POST':
        form = OrganizationDefaultsForm(request.POST, instance=defaults_instance)
        if form.is_valid():
            # Set the organization to the current user's organization and save
            org_defaults = form.save(commit=False)
            org_defaults.organization = user_organization
            org_defaults.save()
            request.session['language'] = request.POST.get('language')
            return redirect('OTRisk:setup_org')
    else:
        form = OrganizationDefaultsForm(instance=defaults_instance)
    return render(request, 'org_setup.html', {'form': form})


@login_required
def edit_org(request):
    # Get the current user's organization
    user_organization = request.user.userprofile.organization
    # Get the OrganizationDefaults instance for the current organization
    try:
        defaults_instance = OrganizationDefaults.objects.get(organization=user_organization)
    except OrganizationDefaults.DoesNotExist:
        # Redirect to setup page if defaults do not exist
        return redirect('OTRisk:setup_org')

    if request.method == 'POST':
        form = OrganizationDefaultsForm(request.POST, instance=defaults_instance)
        if form.is_valid():
            form.save()
            return redirect('OTRisk:setup_org')
    else:
        form = OrganizationDefaultsForm(instance=defaults_instance)
    return render(request, 'org_setup.html', {'form': form})


@login_required
def execute_sql(request):
    if not request.user.is_superuser:
        return HttpResponseForbidden("You don't have permission to access this page.")

    results = None
    if request.method == 'POST':
        form = SQLQueryForm(request.POST)
        if form.is_valid():
            query = form.cleaned_data.get('query')
            with connection.cursor() as cursor:
                cursor.execute(query)
                results = cursor.fetchall()
    else:
        form = SQLQueryForm()

    return render(request, 'OTRisk/execute_sql.html', {'form': form, 'results': results})


def edit_user_profile(request, user_id):
    profile = get_object_or_404(UserProfile, user_id=user_id)
    if request.method == "POST":
        form = UserProfileForm(request.POST, instance=profile)
        if form.is_valid():
            form.save()
            return redirect('OTRisk:user_admin')
    else:
        form = UserProfileForm(instance=profile)
    return render(request, 'OTRisk/edit_user_profile.html', {'form': form})


def edit_organization(request, org_id):
    organization = get_object_or_404(Organization, id=org_id)
    if request.method == "POST":
        form = OrganizationForm(request.POST, instance=organization)
        if form.is_valid():
            form.save()
            return redirect('OTRisk:user_admin')
    else:
        form = OrganizationForm(instance=organization)
    return render(request, 'OTRisk/edit_organization.html', {'form': form})


@user_passes_test(lambda u: u.is_staff or u.is_superuser)  # Allow access for both is_staff and is_superuser
def user_admin(request):
    org_name = None  # Default value
    # If the user is staff, return all user records.
    if request.user.is_staff:
        users = User.objects.prefetch_related(
            Prefetch('userprofile', to_attr='user_profile')
        ).all()

    # If user is not staff but is a superuser, return users from the same organization.
    elif request.user.is_superuser:
        user_org = UserProfile.objects.get(user=request.user).organization
        users = User.objects.filter(userprofile__organization=user_org).prefetch_related(
            Prefetch('userprofile', to_attr='user_profile')
        )

    return render(request, 'OTRisk/user_admin.html', {'users': users})


@user_passes_test(lambda u: u.is_staff)
def edit_user(request, user_id):
    user = User.objects.get(id=user_id)
    if request.method == 'POST':
        form = UserForm(request.POST, instance=user)
        if form.is_valid():
            form.save()
            return redirect('OTRisk:user_admin')
    else:
        form = UserForm(instance=user)
    return render(request, 'OTRisk/edit_user.html', {'form': form})


@user_passes_test(lambda u: u.is_staff or u.is_superuser)
def change_password(request, user_id):
    target_user = User.objects.get(id=user_id)

    # If the current user is an 'is_staff' user, they have permission to change any user's password.
    if request.user.is_staff:
        pass
    # If the current user is a 'is_superuser', they can only change the password of users within their organization.
    elif request.user.is_superuser:
        if target_user.userprofile.organization != request.user.userprofile.organization:
            return HttpResponseForbidden("You don't have permission to change the password for this user.")
    else:
        return HttpResponseForbidden("You don't have permission to change the password.")

    # Generate a secure random password
    password = get_random_string(length=10,
                                 allowed_chars="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()")

    # Set the target user's password
    target_user.set_password(password)
    target_user.save()

    # Set the must_change_password flag for the target user
    profile = target_user.userprofile
    profile.must_change_password = True
    profile.save()

    # Email the new password to the target user
    subject = 'Your new password'
    message = f'Hello {target_user.username},\n\nYour new password is: {password}\n\nPlease login and change it immediately.'
    send_mail(subject, message, 'support@iotarisk.com', [target_user.email])

    # Send a confirmation message to the current user/administrator
    message = "Password reset successfully and email sent to user!"
    return render(request, 'OTRisk/user_admin.html', {'message': message})


def generate_password(length=12):
    alphabet = string.ascii_letters + string.digits
    password = ''.join(secrets.choice(alphabet) for i in range(length))
    return password


def send_password_email(user_email, password):
    subject = 'Welcome to iOTa. Your Temporary Password'
    message = f'Thank you for creating an account on. Your userid is {user_email}. Your temporary password is: {password}   - You will be required to change it upon first login. After setting a password, the first time you log in you will be required to set up two-factor authentication using an Authenticator app (you will need to download and install an authenticator app from the App Store if you do not already have one).  '
    from_email = 'admin@iotarisk.com'  # Replace with your email
    recipient_list = [user_email]
    context = {
        'password': password,
        'logo_url': 'https://www.iotarisk.com/staticfiles/images/iota%20-%20white%201.png',
        'login_url': 'https://www.iotarisk.com'
    }
    html_content = render_to_string('OTRisk/welcome_email.html', context)

    msg = EmailMultiAlternatives(subject, html_content, from_email, recipient_list)
    msg.attach_alternative(html_content, "text/html")
    msg.send()


@login_required
def disable_user(request, user_id):
    try:
        user_to_disable = User.objects.get(pk=user_id)
        if user_to_disable != request.user:
            user_to_disable.is_active = False
            user_to_disable.save()
            return JsonResponse({'success': True})
        else:
            return JsonResponse({'success': False, 'error': 'Cannot disable yourself.'})
    except User.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'User not found.'})


def enable_user(request, user_id):
    print(request.POST)
    try:
        user_to_enable = User.objects.get(pk=user_id)
        if user_to_enable != request.user:
            user_to_enable.is_active = True
            user_to_enable.save()
            return JsonResponse({'success': True})
        else:
            return JsonResponse({'success': False, 'error': 'Cannot disable yourself.'})
    except User.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'User not found.'})


@login_required
def delete_user(request, user_id):
    try:
        user_to_delete = User.objects.get(pk=user_id)
        if user_to_delete != request.user:
            user_to_delete.delete()
            return JsonResponse({'success': True})
        else:
            return JsonResponse({'success': False, 'error': 'Cannot delete yourself.'})
    except User.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'User not found.'})


@login_required
def admin_users(request):
    current_user_profile = UserProfile.objects.get(user=request.user)
    organization = current_user_profile.organization

    # Calculate the number of available licenses
    total_users = UserProfile.objects.filter(organization=organization).count()
    max_users = organization.max_users
    available_licenses = max_users - total_users

    # Check if the user is a staff member
    is_staff_user = request.user.is_staff

    if is_staff_user:
        # Staff user can view and edit all user profiles
        user_profiles = UserProfile.objects.all()
    else:
        # Non-staff users can only view and edit user profiles in their organization
        user_profiles = UserProfile.objects.filter(organization=organization)

    user_profiles = UserProfile.objects.filter(organization=organization)

    user_form = UserForm(request.POST or None)
    profile_form = UserProfileForm(request.POST or None)

    if request.method == 'POST':
        user_form = UserForm(request.POST)
        profile_data = request.POST.copy()
        if not request.user.is_staff:
            # If the user is not staff, add the current user's organization to the form data
            profile_data['organization'] = current_user_profile.organization.id

        profile_form = UserProfileForm(profile_data)

        if user_form.is_valid():
            password = generate_password()

            # First, save the User model
            user = user_form.save(commit=False)
            user.set_password(password)  # Set the password correctly
            user.last_login = None  # Set last_login to Non
            user.is_superuser = user_form.cleaned_data.get('is_superuser', False)
            user.is_active = True
            user.save()

            if profile_form.is_valid():
                # Now save the UserProfile model
                user_profile = profile_form.save(commit=False)
                user_profile.user = user
                user_profile.save()

                send_password_email(user.email, password)
                # Redirect to a success page or wherever you want
                return redirect('/OTRisk/admin_users')
            else:
                pass
        else:
            pass

    else:
        user_form = UserForm()
        profile_form = UserProfileForm()
        current_user_profile = UserProfile.objects.get(user=request.user)
        organization = current_user_profile.organization
        user_profiles = UserProfile.objects.filter(organization=organization)

    return render(request, 'admin_users.html',
                  {'user_form': user_form, 'profile_form': profile_form, 'user_profiles': user_profiles,
                   'is_staff_user': is_staff_user, 'available_licenses': available_licenses})


def add_or_update_consequence(request, consequence_id=None):
    # Start by setting scenario to None
    consequence = None

    # If there's a scenario_id from URL parameters, fetch the scenario
    if consequence_id:
        consequence = CustomConsequence.objects.get(pk=consequence_id)

    # Fetch post_scenario_id from POST data, if present
    post_consequence_id = request.POST.get('consequence_id')
    if post_consequence_id:
        consequence = CustomConsequence.objects.get(pk=post_consequence_id)

    # Check the organization for security
    if consequence and consequence.organization_id != request.session['user_organization']:
        return redirect('some_error_page_or_home')

    # Handle the form submission
    if request.method == 'POST':
        form = CustomConsequenceForm(request.POST, instance=consequence, user=request.user)
        if form.is_valid():
            consequence_instance = form.save(commit=False)
            organization_id = request.session['user_organization']
            consequence_instance.organization = Organization.objects.get(pk=organization_id)
            consequence_instance.save()
            return redirect('OTRisk:add_consequence')
    else:
        form = CustomConsequenceForm(instance=consequence)

    # Display the template
    organization_id = request.session['user_organization']
    consequences = CustomConsequence.objects.filter(organization_id=organization_id)

    # Ensure that scenario_id is passed to the template
    return render(request, 'OTRisk/custom_consequence.html',
                  {'form': form, 'consequences': consequences, 'consequence_id': consequence_id or post_consequence_id})


def delete_consequence(request, consequence_id):
    consequence = CustomConsequence.objects.get(pk=consequence_id)
    if consequence.organization != request.user.userprofile.organization:
        return redirect('OTRisk:add_consequence')
    consequence.delete()
    return redirect('OTRisk:add_consequence')


### - end of customer scenario code ###

def add_or_update_scenario(request, scenario_id=None):
    # Start by setting scenario to None
    scenario = None

    # If there's a scenario_id from URL parameters, fetch the scenario
    if scenario_id:
        scenario = CustomScenario.objects.get(pk=scenario_id)

    # Fetch post_scenario_id from POST data, if present
    post_scenario_id = request.POST.get('scenario_id')
    if post_scenario_id:
        scenario = CustomScenario.objects.get(pk=post_scenario_id)

    # Check the organization for security
    if scenario and scenario.organization_id != request.session['user_organization']:
        return redirect('some_error_page_or_home')

    # Handle the form submission
    if request.method == 'POST':
        form = CustomScenarioForm(request.POST, instance=scenario, user=request.user)
        if form.is_valid():
            scenario_instance = form.save(commit=False)
            organization_id = request.session['user_organization']
            scenario_instance.organization = Organization.objects.get(pk=organization_id)
            scenario_instance.save()
            return redirect('OTRisk:add_scenario')
    else:
        form = CustomScenarioForm(instance=scenario)

    # Display the template
    organization_id = request.session['user_organization']
    scenarios = CustomScenario.objects.filter(organization_id=organization_id)

    # Ensure that scenario_id is passed to the template
    return render(request, 'OTRisk/custom_scenario.html',
                  {'form': form, 'scenarios': scenarios, 'scenario_id': scenario_id or post_scenario_id})


def delete_scenario(request, scenario_id):
    scenario = CustomScenario.objects.get(pk=scenario_id)
    if scenario.organization != request.user.userprofile.organization:
        return redirect('OTRisk:add_scenario')
    scenario.delete()
    return redirect('OTRisk:add_scenario')


### - end of customer scenario code ###

def get_consequences(request):
    consequences = tblConsequence.objects.all()
    data = [{'id': c.id, 'Consequence': c.Consequence} for c in consequences]
    return JsonResponse({'consequences': data})


@login_required()
def scenarioreport(request):
    cyberphaid = request.GET.get('hdnID', 0)

    scenarios = tblCyberPHAScenario.objects.filter(CyberPHA=cyberphaid, Deleted=0)
    scenarioheader = tblCyberPHAHeader.objects.get(ID=cyberphaid)
    avg_impactsafety = scenarios.aggregate(Avg('impactSafety'))['impactSafety__avg']
    avg_impactDanger = scenarios.aggregate(Avg('impactDanger'))['impactDanger__avg']
    avg_impactProduction = scenarios.aggregate(Avg('impactProduction'))['impactProduction__avg']
    avg_impactFinance = scenarios.aggregate(Avg('impactFinance'))['impactFinance__avg']
    avg_impactReputation = scenarios.aggregate(Avg('impactReputation'))['impactReputation__avg']
    avg_impactEnvironment = scenarios.aggregate(Avg('impactEnvironment'))['impactEnvironment__avg']
    avg_impactRegulation = scenarios.aggregate(Avg('impactRegulation'))['impactRegulation__avg']
    avg_impactData = scenarios.aggregate(Avg('impactData'))['impactData__avg']
    avg_uel = scenarios.aggregate(Avg('UEL'))['UEL__avg']
    avg_rru = scenarios.aggregate(Avg('RRU'))['RRU__avg']
    avg_sm = scenarios.aggregate(Avg('SM'))['SM__avg']
    avg_mel = scenarios.aggregate(Avg('MEL'))['MEL__avg']
    avg_rrm = scenarios.aggregate(Avg('RRM'))['RRM__avg']
    avg_sa = scenarios.aggregate(Avg('SA'))['SA__avg']
    avg_MELa = scenarios.aggregate(Avg('MELA'))['MELA__avg']
    avg_rra = scenarios.aggregate(Avg('RRa'))['RRa__avg']

    return render(request, 'scenarioreport.html', {
        'scenarios': scenarios,
        'scenarioheader': scenarioheader,
        'avg_impactsafety': avg_impactsafety,
        'avg_impactDanger': avg_impactDanger,
        'avg_impactProduction': avg_impactProduction,
        'avg_impactFinance': avg_impactFinance,
        'avg_impactReputation': avg_impactReputation,
        'avg_impactEnvironment': avg_impactEnvironment,
        'avg_impactRegulation': avg_impactRegulation,
        'avg_impactData': avg_impactData,
        'avg_uel': avg_uel,
        'avg_sm': avg_sm,
        'avg_rru': avg_rru,
        'avg_mel': avg_mel,
        'avg_rrm': avg_rrm,
        'avg_sa': avg_sa,
        'avg_MELa': avg_MELa,
        'avg_rra': avg_rra
    })


@login_required()
def save_or_update_cyberpha(request):
    if request.method == 'POST':

        # Get the form data
        cyberphaid = request.POST.get('cyberpha')
        cyberpha_header = tblCyberPHAHeader.objects.get(pk=cyberphaid)
        scenario = request.POST.get('scenario')

        # Convert 'exposed_system' to a boolean value
        exposed_system_value = request.POST.get('exposed_system', 'off')
        exposed_system = exposed_system_value.lower() == 'true'

        weak_credentials_value = request.POST.get('weak_credentials', 'off')
        weak_credentials = weak_credentials_value.lower() == 'true'

        threatclass = request.POST.get('threatSource')
        threataction = request.POST.get('threatAction')
        countermeasures = request.POST.get('mitigationMeasures')
        riskcategory = request.POST.get('riskCategory')
        consequence = request.POST.get('consequence')
        impactsafety = request.POST.get('safety')
        impactdanger = request.POST.get('life')
        impactproduction = request.POST.get('production')
        impactfinance = request.POST.get('financial')
        impactreputation = request.POST.get('reputation')
        impactenvironment = request.POST.get('environment')
        impactregulation = request.POST.get('regulatory')
        impactdata = request.POST.get('data')
        impactsupply = request.POST.get('supply')
        sm = request.POST.get('sm')
        mel = request.POST.get('mel')
        rrm = request.POST.get('rrm')
        sa = request.POST.get('sa')
        mela = request.POST.get('mela')
        rra = request.POST.get('rra')
        uel_threat = request.POST.get('uel_threat')
        uel_exposure = request.POST.get('uel_exposure')
        uel_vuln = request.POST.get('uel_vuln')
        uel = request.POST.get('uel')
        rru = request.POST.get('rru')
        sl = request.POST.get('sl')
        recommendations = request.POST.get('recommendations')
        justifySafety = request.POST.get('justifySafety')
        justifyLife = request.POST.get('justifyLife')
        justifyProduction = request.POST.get('justifyProduction')
        justifyFinance = request.POST.get('justifyFinance')
        justifyReputation = request.POST.get('justifyReputation')
        justifyEnvironment = request.POST.get('justifyEnvironment')
        env_contaminant = request.POST.get('env_contaminant')
        env_ecosystem = request.POST.get('env_ecosystem')
        env_contamination = request.POST.get('env_contamination')
        env_population = request.POST.get('env_population')
        env_wildlife = request.POST.get('env_wildlife')
        justifyRegulation = request.POST.get('justifyRegulation')
        justifyData = request.POST.get('dataRegulation')
        justifySupply = request.POST.get('justifySupply')
        sle_median_string = request.POST.get('sle_median')
        sle_low_string = request.POST.get('sle_low')
        sle_high_string = request.POST.get('sle_high')
        ale_median_string = request.POST.get('ale_median')
        ale_low_string = request.POST.get('ale_low')
        ale_high_string = request.POST.get('ale_high')
        aro = request.POST.get('aro')
        ale = request.POST.get('ale')
        outage = request.POST.get('outage')
        if outage:  # Check if outage is not None or an empty string
            outage = outage[0].upper() + outage[1:]
        outageDuration = request.POST.get('outageDuration')
        outageCost = request.POST.get('outageCost')
        probability = request.POST.get('probability')
        risk_register_str = request.POST.get('risk_register')
        risk_register_bool = risk_register_str.lower() == "true"
        sis_outage_str = request.POST.get('sis_outage')
        sis_compromise_str = request.POST.get('sis_compromise')
        sis_outage = sis_outage_str.lower() == 'true'
        sis_compromise = sis_compromise_str.lower() == 'true'
        safety_hazard = request.POST.get('safety_hazard')
        likelihood = request.POST.get('likelihood')
        frequency = request.POST.get('frequency')
        snapshot = request.POST.get('snapshot')
        compliance_map = request.POST.get('compliance_map')
        ThreatClass = request.POST.get('threatSource')
        dangerScope = request.POST.get('dangerScope')
        ai_bia_score = request.POST.get('ai_bia_score')
        attack_tree_text = request.POST.get('attack_tree_text')
        scenario_status = request.POST.get('scenario_status')
        if ai_bia_score in ('NaN', ''):
            ai_bia_score = 0
        else:
            ai_bia_score = ai_bia_score
        try:
            control_effectiveness = int(float(request.POST.get('control_effectiveness', '0')))
        except ValueError:
            control_effectiveness = 0

        sl_a = request.POST.get('sl_a')

        if outageDuration in ('NaN', ''):
            outageDuration = 0
        else:
            outageDuration = int(outageDuration)

        if outageCost in ('NaN', ''):
            outageCost = 0
        else:
            outageCost = int(outageCost)

        countermeasureCosts = 0

        # Initialize sle to a default value
        sle = 0
        sle_medium = 0
        sle_low = 0
        sle_high = 0
        # Check if sle_string is not None and not 'NaN'
        if sle_low_string and sle_low_string != 'NaN':
            try:
                # Remove dollar signs, commas, and decimal portion, then convert to integer
                sle_low = int(float(sle_low_string.replace('$', '').replace(',', '')))
            except ValueError:
                # Handle the error appropriately, e.g., set a default value or log the error
                sle_low = 0

        if sle_median_string and sle_median_string != 'NaN':
            try:
                # Remove dollar signs, commas, and decimal portion, then convert to integer
                sle_medium = int(float(sle_median_string.replace('$', '').replace(',', '')))
            except ValueError:
                # Handle the error appropriately, e.g., set a default value or log the error
                sle_medium = 0

        if sle_high_string and sle_high_string != 'NaN':
            try:
                # Remove dollar signs, commas, and decimal portion, then convert to integer
                sle_high = int(float(sle_high_string.replace('$', '').replace(',', '')))
            except ValueError:
                # Handle the error appropriately, e.g., set a default value or log the error
                sle_high = 0

        ale_medium = 0
        ale_low = 0
        ale_high = 0
        # Check if sle_string is not None and not 'NaN'
        if ale_low_string and ale_low_string != 'NaN':
            try:
                # Remove dollar signs, commas, and decimal portion, then convert to integer
                ale_low = int(float(ale_low_string.replace('$', '').replace(',', '')))
            except ValueError:
                # Handle the error appropriately, e.g., set a default value or log the error
                ale_low = 0

        if ale_median_string and ale_median_string != 'NaN':
            try:
                # Remove dollar signs, commas, and decimal portion, then convert to integer
                ale_medium = int(float(ale_median_string.replace('$', '').replace(',', '')))
            except ValueError:
                # Handle the error appropriately, e.g., set a default value or log the error
                ale_medium = 0

        if ale_high_string and ale_high_string != 'NaN':
            try:
                # Remove dollar signs, commas, and decimal portion, then convert to integer
                ale_high = int(float(ale_high_string.replace('$', '').replace(',', '')))
            except ValueError:
                # Handle the error appropriately, e.g., set a default value or log the error
                ale_high = 0

        deleted = 0
        org_id = get_user_organization_id(request)

        if snapshot == '1':
            scenario_id_value = int(request.POST.get('scenarioID'))
            scenario_instance = tblCyberPHAScenario.objects.get(pk=scenario_id_value)

            snapshot_record = CyberPHAScenario_snapshot(
                CyberPHA=cyberphaid,
                ScenarioID=scenario_id_value,
                Scenario=scenario,
                exposed_system=exposed_system,
                weak_credentials=weak_credentials,
                ThreatClass=threatclass,
                ThreatAction=' ',
                Countermeasures=' ',
                RiskCategory=riskcategory,
                Consequence='',
                impactSafety=impactsafety,
                impactDanger=impactdanger,
                impactProduction=impactproduction,
                impactFinance=impactfinance,
                impactReputation=impactreputation,
                impactEnvironment=impactenvironment,
                impactRegulation=impactregulation,
                impactData=impactdata,
                impactSupply=impactsupply,
                recommendations=recommendations,
                SM=sm,
                MEL=mel,
                RRM=rrm,
                SA=sa,
                MELA=mela,
                RRa=rra,
                UEL=uel,
                uel_threat=uel_threat,
                uel_exposure=uel_exposure,
                uel_vuln=uel_vuln,
                RRU=rru,
                sl=sl,
                Deleted=deleted,
                justifySafety='',
                justifyLife='',
                justifyProduction='',
                justifyFinancial='',
                justifyReputation='',
                justifyEnvironment=justifyEnvironment,
                env_contaminant=env_contaminant,
                env_ecosystem=env_ecosystem,
                env_contamination=env_contamination,
                env_population=env_population,
                env_wildlife=env_wildlife,
                justifyRegulation='',
                justifyData='',
                justifySupply='',
                userID=request.user.id,
                sle=sle_medium,
                sle_low=sle_low,
                sle_high=sle_high,
                ale_median=ale_medium,
                ale_low=ale_low,
                ale_high=ale_high,
                aro=aro,
                ale=ale,
                countermeasureCosts=countermeasureCosts,
                outage=outage,
                outageDuration=0,
                outageCost=0,
                probability=probability,
                risk_register=risk_register_bool,
                sis_outage=sis_outage,
                sis_compromise=sis_compromise,
                safety_hazard=safety_hazard,
                snapshot_date=timezone.now(),
                timestamp=timezone.now(),
                risk_open_date=timezone.now(),
                risk_close_date=timezone.now(),
                risk_owner='',
                risk_response='',
                organizationID=org_id,
                control_effectiveness=control_effectiveness,
                likelihood=likelihood,
                frequency=frequency,
                sl_a=sl_a,
                dangerScope=dangerScope,
                compliance_map=compliance_map,
                attack_tree_text=attack_tree_text

            )
            snapshot_record.save()
        else:
            scenario_id = request.POST.get('scenarioID')
            defaults = {
                'Scenario': scenario,
                'exposed_system': exposed_system,
                'weak_credentials': weak_credentials,
                'ThreatAction': '',
                'ThreatClass': ThreatClass,
                'Countermeasures': '',
                'RiskCategory': riskcategory,
                'Consequence': '',
                'impactSafety': impactsafety,
                'impactDanger': impactdanger,
                'impactProduction': impactproduction,
                'impactFinance': impactfinance,
                'impactReputation': impactreputation,
                'impactEnvironment': impactenvironment,
                'impactRegulation': impactregulation,
                'impactData': impactdata,
                'impactSupply': impactsupply,
                'recommendations': recommendations,
                'SM': sm,
                'MEL': mel,
                'RRM': rrm,
                'SA': sa,
                'MELA': mela,
                'RRa': rra,
                'UEL': uel,
                'uel_threat': uel_threat,
                'uel_exposure': uel_exposure,
                'uel_vuln': uel_vuln,
                'RRU': rru,
                'sl': sl,
                'Deleted': deleted,
                'justifySafety': justifySafety,
                'justifyLife': justifyLife,
                'justifyProduction': justifyProduction,
                'justifyFinancial': justifyFinance,
                'justifyReputation': justifyReputation,
                'justifyEnvironment': justifyEnvironment,
                'env_contaminant': env_contaminant,
                'env_ecosystem': env_ecosystem,
                'env_contamination': env_contamination,
                'env_population': env_population,
                'env_wildlife': env_wildlife,
                'justifyRegulation': justifyRegulation,
                'justifyData': justifyData,
                'justifySupply': justifySupply,
                'userID': request.user,
                'sle': sle_medium,
                'sle_low': sle_low,
                'sle_high': sle_high,
                'ale_median': ale_medium,
                'ale_low': ale_low,
                'ale_high': ale_high,
                'aro': aro,
                'ale': ale,
                'countermeasureCosts': countermeasureCosts,
                'outage': outage,
                'outageDuration': outageDuration,
                'outageCost': outageCost,
                'probability': probability,
                'risk_register': risk_register_bool,
                'sis_outage': sis_outage,
                'sis_compromise': sis_compromise,
                'safety_hazard': safety_hazard,
                'timestamp': timezone.now(),
                'risk_open_date': timezone.now(),
                'risk_close_date': '2099-01-01',
                'control_effectiveness': control_effectiveness,
                'likelihood': 0 if likelihood == '' else likelihood,
                'frequency': decimal.Decimal('0.0') if frequency == '' else frequency,
                'sl_a': 0 if sl_a == '' else sl_a,
                'dangerScope': dangerScope,
                'ai_bia_score': 0 if ai_bia_score is None else ai_bia_score,
                'compliance_map': compliance_map,
                'attack_tree_text': attack_tree_text,
                'scenario_status': scenario_status

            }

            # If scenario_id is '0', create a new record, otherwise update the existing one
            if scenario_id == '0':
                # Set ID to None to create a new record
                cyberpha_entry = tblCyberPHAScenario.objects.create(CyberPHA=cyberpha_header, **defaults)
                scenario_instance = cyberpha_entry
            else:
                # Convert scenario_id to an integer and update the existing record
                cyberpha_entry, created = tblCyberPHAScenario.objects.update_or_create(
                    defaults=defaults,
                    CyberPHA=cyberpha_header,
                    ID=int(scenario_id)  # Assumes scenario_id is always a valid integer
                )
                scenario_instance = cyberpha_entry
            # Delete existing records in ScenarioConsequences for the given scenario
            ScenarioConsequences.objects.filter(scenario=scenario_instance).delete()

            # Retrieve validated consequences from the request
            validated_consequences = request.POST.getlist('validated_consequences')
            # Process each validated consequence
            for consequence_text in validated_consequences:
                # Create or update the consequence in ScenarioConsequences model
                ScenarioConsequences.objects.update_or_create(
                    scenario=scenario_instance,
                    consequence_text=consequence_text,
                    defaults={'is_validated': True}
                )
            scenario_id_value = cyberpha_entry.ID

            scenarioID = cyberpha_entry.pk
            scenario_instance = get_object_or_404(tblCyberPHAScenario, pk=scenario_id)

            # Delete existing safeguards for this scenario
            PHA_Safeguard.objects.filter(scenario=scenario_instance).delete()

            # Process and save new safeguards
            safeguard_index = 0
            while True:
                safeguard_description_key = f'safeguards[{safeguard_index}][description]'
                safeguard_type_key = f'safeguards[{safeguard_index}][type]'

                # Check if these keys exist in the POST data
                if safeguard_description_key in request.POST and safeguard_type_key in request.POST:
                    safeguard_description = request.POST.get(safeguard_description_key)
                    safeguard_type = request.POST.get(safeguard_type_key)
                    print(scenario_instance)
                    # Create new PHA_Safeguard record
                    PHA_Safeguard.objects.create(
                        scenario=scenario_instance,
                        safeguard_description=safeguard_description,
                        safeguard_type=safeguard_type
                    )
                    safeguard_index += 1
                else:
                    # Break the loop if no more safeguards are found
                    break

            request.session['cyberPHAID'] = cyberphaid  # Set the session variable

            # lastly, update the overall BIA score for the cyberpha
            update_bia_scenarios(cyberphaid, request.user)

            # Log the user activity
            write_to_audit(
                request.user,
                f'Updated cyberPHA: {cyberpha_header}. Saved scenario: {scenario}',
                get_client_ip(request)
            )

        # Call the assess_cyberpha function
        return assess_cyberpha(request, cyberPHAID=cyberphaid)


def set_active_cyberpha(request):
    active_cyberpha = request.POST.get('active_cyberpha')
    request.session['active_cyberpha'] = active_cyberpha
    request.session.save()
    return JsonResponse({'status': 'success'})


def update_session(request):
    active_cyberpha = request.POST.get('active_cyberpha')
    request.session['active-cyberpha'] = active_cyberpha
    return JsonResponse({'status': 'success'})


def get_mitigation_measures(request):
    mitigation_measures = tblMitigationMeasures.objects.values_list('ControlObjective', flat=True)
    return JsonResponse(list(mitigation_measures), safe=False)


@login_required()
def assess_cyberpha(request, cyberPHAID=None):
    if cyberPHAID:
        active_cyberpha = cyberPHAID
    else:
        active_cyberpha = request.GET.get('active_cyberpha', None)
        if active_cyberpha is None:
            active_cyberpha = request.session.get('cyberPHAID', 0)

    organization_id = request.session['user_organization']

    try:
        pha_record = tblCyberPHAHeader.objects.get(ID=active_cyberpha)
    # if the record doesn't exist then the user is trying to access a record via manipulating the url - throw them out of the system
    except tblCyberPHAHeader.DoesNotExist:

        request.session.flush()
        return redirect('OTRisk:logout')

    if active_cyberpha is None:
        active_cyberpha = request.session.get('cyberPHAID', 0)

    try:

        record_owner_organization = UserProfile.objects.get(user=pha_record.UserID).organization_id

        # Fetch the organization associated with the currently logged-in user
        user_organization = UserProfile.objects.get(user=request.user).organization_id

        # Check if the logged-in user's organization matches the record's owner's organization
        if user_organization != record_owner_organization:
            request.session.flush()
            return redirect('OTRisk:logout')  # Redirect to logout path which will then redirect to login
    except (tblCyberPHAHeader.DoesNotExist, UserProfile.DoesNotExist):
        # Handle if the provided active_cyberpha does not match any record or if the UserProfile doesn't exist for a user.
        # For instance, you can log out the user or raise a 404 error.
        pass

    # industry_id = tblIndustry.objects.get(Industry=pha_record.Industry).id

    # scenarios = tblScenarios.objects.all()
    # tbl_scenarios = tblScenarios.objects.filter(industry_id=industry_id)
    # tbl_scenarios = tblScenarios.objects.all()

    # Get custom scenarios for the current user's organization
    custom_scenarios = CustomScenario.objects.filter(organization_id=organization_id)
    # Convert querysets to lists of dictionaries
    # tbl_scenarios_list = [{'ID': obj.ID, 'Scenario': obj.Scenario} for obj in tbl_scenarios]
    # custom_scenarios_list = [{'ID': obj.id, 'Scenario': obj.scenario} for obj in custom_scenarios]
    # Combine these lists
    # combined_scenarios = tbl_scenarios_list + custom_scenarios_list
    control_objectives = tblControlObjectives.objects.all()
    mitigation_measures = tblMitigationMeasures.objects.all()
    threat_intelligence = tblThreatIntelligence.objects.all().order_by('ThreatDescription')
    risk_categories = tblRiskCategories.objects.all().order_by('CategoryName')
    safeguards = tblSafeguards.objects.order_by('Safeguard').values('Safeguard').distinct()
    threatsources = tblThreatSources.objects.all().order_by('ThreatSource')
    threatactions = tblThreatActions.objects.all().order_by('ThreatAction')
    # consequenceList = tblConsequence.objects.all().order_by('Consequence')
    standardslist = tblStandards.objects.all().order_by('standard')
    scenario_status = tblCyberPHAScenario.SCENARIO_STATUSES

    control_objectives = [json.loads(obj.ControlObjective) for obj in control_objectives]
    active_cyberpha_id = request.GET.get('active_cyberpha')
    description = ''
    if active_cyberpha_id is not None:
        try:
            # Retrieve the Description value from the database based on the active-cyberpha_id
            description = tblCyberPHAHeader.objects.get(ID=active_cyberpha_id).Description
        except tblCyberPHAHeader.DoesNotExist:
            pass

    response = JsonResponse({'message': 'Success'})
    response['Access-Control-Allow-Origin'] = '*'  # Set the CORS header

    clicked_row_facility_name = request.session.get('clickedRowFacilityName', None)
    saved_scenarios = tblCyberPHAScenario.objects.filter(CyberPHA=active_cyberpha, Deleted=0)
    MitreControlAssessment_results = MitreControlAssessment.objects.filter(cyberPHA_id=active_cyberpha)
    control_assessments_data = serializers.serialize('json', MitreControlAssessment_results)
    scenario_form = CyberSecurityScenarioForm(request.POST)

    return render(request, 'OTRisk/phascenariomgr.html', {
        # 'scenarios': combined_scenarios,
        'control_objectives': control_objectives,
        'mitigation_measures': mitigation_measures,
        'threat_intelligence': threat_intelligence,
        'risk_categories': risk_categories,
        'description': description,
        'safeguards': safeguards,
        'threatsources': threatsources,
        'threatactions': threatactions,
        'clicked_row_facility_name': clicked_row_facility_name,
        'saved_scenarios': saved_scenarios,
        'standardslist': standardslist,
        'MitreControlAssessment_results': control_assessments_data,
        'SECURITY_LEVELS': SECURITY_LEVELS,
        'scenario_form': scenario_form,
        'scenario_status': scenario_status
    })


@login_required
def cyber_pha_manager(request):
    tblCyberPHAList = tblCyberPHAHeader.objects.filter(Deleted=0).order_by('ID')[::-1]
    facilityTypes = FacilityType.objects.all().order_by('FacilityType')
    nodes = tblNodes.objects.all().order_by('NodeType')
    units = tblUnits.objects.all().order_by('PlantUnits')
    zones = tblZones.objects.all().order_by('PlantZone')
    industry = tblIndustry.objects.all().order_by('Industry')

    active_cyberpha = request.session.get('active-cyberpha', 0)  # Retrieve the active-cyberpha from session

    return render(request, 'CyberPHAManager.html', {'tblCyberPHAList': tblCyberPHAList,
                                                    'facilityTypes': facilityTypes,
                                                    'nodes': nodes,
                                                    'units': units,
                                                    'zones': zones,
                                                    'industry': industry})


def PHAeditmode(request, id):
    record = tblCyberPHAHeader.objects.get(ID=id)
    formattedStartDate = record.AssessmentStartDate.strftime('%Y-%m-%d')
    formattedEndDate = record.AssessmentEndDate.strftime('%Y-%m-%d')
    data = {
        'PHALeader': record.PHALeader,
        'PHALeaderEmail': record.PHALeaderEmail,
        'FacilityOwner': record.FacilityOwner,
        'Notes': record.Notes,
        'FacilityName': record.FacilityName,
        'AssessmentUnit': record.AssessmentUnit,
        'AssessmentNode': record.AssessmentNode,
        'AssessmentZone': record.AssessmentZone,
        'FacilityType': record.FacilityType,
        'Industry': record.Industry,
        'EmployeesOnSite': record.EmployeesOnSite,
        'AssessmentStartDate': formattedStartDate,
        'AssessmentEndDate': formattedEndDate,
        'facilityAddress': record.facilityAddress,
    }
    return JsonResponse(data)


def deletecyberpha(request, cyberpha_id):
    # does a virtual delete
    cyber_pha = tblCyberPHAHeader.objects.get(ID=cyberpha_id)
    cyber_pha.Deleted = 1
    cyber_pha.save()
    return redirect('OTRisk:cyber_pha_manager')


@login_required()
def deletescenario(request, scenarioid, cyberPHAID):
    scenario_to_del = tblCyberPHAScenario.objects.get(ID=scenarioid)
    scenario_to_del.Deleted = 1
    scenario_to_del.timestamp = timezone.now()
    scenario_to_del.save()

    return redirect('OTRisk:cyberpha_id', cyberPHAID=cyberPHAID)


def save_cyberpha(request):
    if request.method == 'POST':
        recordid = request.POST.get('recordId')
        facility_type = request.POST.get('facilityType')
        facility_name = request.POST.get('plantName')
        phaleader = request.POST.get('leader')
        leader_email = request.POST.get('email')
        facility_owner = request.POST.get('facilityLeader')
        facility_scope = request.POST.get('facilityScope')
        notes = request.POST.get('txtComment')
        assessment_unit = request.POST.get('unit')
        assessment_zone = request.POST.get('zone')
        assessment_node = request.POST.get('node')
        emps = request.POST.get('siteemps')
        startDate = request.POST.get('txtstartdate')
        enddate = request.POST.get('txtenddate')
        userid = request.user
        Industry = request.POST.get('industry')
        facilityAddress = request.POST.get('txtfacilityAddress')

        if recordid and int(recordid) > 0:
            # recordId is present and greater than 0. Update existing record.
            tblCyberPHAHeader.objects.filter(ID=recordid).update(
                FacilityName=facility_name,
                PHALeader=phaleader,
                PHALeaderEmail=leader_email,
                FacilityOwner=facility_owner,
                FacilityScope=facility_scope,
                Notes=notes,
                AssessmentUnit=assessment_unit,
                AssessmentNode=assessment_node,
                AssessmentZone=assessment_zone,
                FacilityType=facility_type,
                Industry=Industry,
                EmployeesOnSite=emps,
                AssessmentStartDate=startDate,
                AssessmentEndDate=enddate,
                UserID=userid,
                AssessmentStatus="Open",
                facilityAddress=facilityAddress,
                Deleted=0
            )
            request.session['active-cyberpha'] = recordid
        else:
            # No valid recordId. Create new record.
            new_cyber_pha = tblCyberPHAHeader(
                FacilityName=facility_name,
                PHALeader=phaleader,
                PHALeaderEmail=leader_email,
                FacilityOwner=facility_owner,
                FacilityScope=facility_scope,
                Notes=notes,
                AssessmentUnit=assessment_unit,
                AssessmentNode=assessment_node,
                AssessmentZone=assessment_zone,
                FacilityType=facility_type,
                Industry=Industry,
                EmployeesOnSite=emps,
                AssessmentStartDate=startDate,
                AssessmentEndDate=enddate,
                UserID=userid,
                AssessmentStatus="Open",
                facilityAddress=facilityAddress,
                Deleted=0
            )
            new_cyber_pha.save()
            request.session['active-cyberpha'] = new_cyber_pha.ID

        return redirect('OTRisk:cyber_pha_manager')

    tblCyberPHAList = tblCyberPHAHeader.objects.all().order_by('ID')[::-1]
    return render(request, 'CyberPHAManager.html', {'tblCyberPHAList': tblCyberPHAList})


def getFacilityTypes(request):
    facility_types = FacilityType.objects.order_by('FacilityTypes')
    return render(request, 'walkdown.html', {'facility_types': facility_types})


def fill_raw_from_table(request, id):
    try:
        worksheet = RAWorksheet.objects.get(ID=id)
        data = {
            'RATitle': worksheet.RATitle,
            'RADescription': worksheet.RADescription,
            'RADate': worksheet.RADate,
            'RASynopsis': worksheet.RASynopsis,
            'BusinessUnit': worksheet.BusinessUnit,
            'EmployeeCount': worksheet.EmployeeCount,
            'BusinessUnitType': worksheet.BusinessUnitType,
            'RegulatoryOversight': worksheet.RegulatoryOversight,
            'RATrigger': worksheet.RATrigger,
            'StatusFlag': worksheet.StatusFlag,
        }
        request.session['raworksheetid'] = id
        return JsonResponse(data)
    except RAWorksheet.DoesNotExist:
        return JsonResponse({'error': 'RAWorksheet not found'})


def set_session_variable(request, name, value):
    request.session[name] = value
    return JsonResponse({'success': f'Session variable {name} set'})


def get_actions(request):
    actions = RAActions.objects.filter(RAWorksheetID=request.session['raworksheetid']).values(
        'ID', 'actionTitle', 'actionOwner', 'actionEffort', 'actionCost'
    )
    actions_list = list(actions)

    return JsonResponse(actions_list, safe=False)


# saves a new action item on riskassess.html
def save_raw_actions(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        new_action = RAActions(
            RAWorksheetID=request.session['raworksheetid'],
            actionTitle=data.get('actionTitle', ''),
            actionDescription=data.get('actionDescription', ''),
            actionOwner=data.get('actionOwner', ''),
            actionDate=data.get('actionTargetDate', ''),
            actionEffort=data.get('actionEffort', ''),
            actionCost=data.get('actionCost', ''),
        )
        new_action.save()
        request.session['CurrentAction'] = new_action.ID
        return JsonResponse({"action_id": new_action.ID}, status=201)
    else:
        return JsonResponse({"error": "Invalid method"}, status=400)


def get_scenarios(request):
    raw_id = request.GET.get('raw_id', None)

    # Fetch scenarios
    scenarios = RAWorksheetScenario.objects.filter(RAWorksheetID=raw_id)
    scenarios_json = serialize('json', scenarios)

    # Fetch and serialize safeguards for each scenario
    safeguards_data = {}
    for scenario in scenarios:
        safeguards = QRAW_Safeguard.objects.filter(scenario=scenario)
        # Serialize each set of safeguards and add to the safeguards_data dictionary
        # Use scenario.ID to correctly reference the primary key
        safeguards_data[scenario.ID] = json.loads(serialize('json', safeguards))

    print(scenarios_json)
    # Return both serialized lists in the response
    response_data = {
        'scenarios': json.loads(scenarios_json),
        'safeguards': safeguards_data
    }

    return JsonResponse(response_data, safe=False)


# saves a new scenario on riskassess.html
def save_raw_scenario(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        new_scenario = RAWorksheetScenario(
            RAWorksheetID=request.session['raworksheetid'],
            ScenarioDescription=data.get('scenario1', ''),
            ScenarioType=data.get('scenarioType', ''),
            ThreatScore=int(data.get('threatscore', '')),
            VulnScore=int(data.get('vulnerabilityscore', '')),
            ReputationScore=int(data.get('reputationscore', '')),
            OperationScore=data.get('operationalscore', ''),
            SafetyScore=int(data.get('safetyscore', '')),
            DataScore=int(data.get('datascore', '')),
            SupplyChainScore=int(data.get('supplychainscore', '')),
            RiskScore=int(data.get('riskscore', '')),
            RiskStatus=data.get('riskstatus', ''),
        )
        new_scenario.save()
        request.session['CurrentScenario'] = new_scenario.ID

        return JsonResponse({"scenario_id": new_scenario.ID}, status=201)
    else:
        return JsonResponse({"error": "Invalid method"}, status=400)


@csrf_exempt
def get_ra_worksheet(request, id):
    ra_worksheet = RAWorksheet.objects.filter(ID=id).first()
    data = serializers.serialize('json', [ra_worksheet])
    return JsonResponse(data, safe=False)


def save_or_update_tblRAWorksheet(request):
    if request.method == 'POST':
        if 'addNewRA' in request.POST:
            # Clear the session variable and redirect to the same view
            request.session['raworksheetid'] = -1
            return redirect('OTRisk:save_or_update_tblRAWorksheet')

        try:
            raworksheetid = request.session.get('raworksheetid', -1)
            if raworksheetid == -1:
                # Creating a new record
                raworksheet = RAWorksheet()
            else:
                # Updating an existing record
                raworksheet = RAWorksheet.objects.get(ID=raworksheetid)

            raworksheet.RATitle = request.POST.get('title', '')
            raworksheet.RADescription = request.POST.get('description', '')
            raworksheet.RADate = request.POST.get('date', '')
            raworksheet.RASynopsis = request.POST.get('synopsis', '')
            raworksheet.UserID = 1
            raworksheet.StatusFlag = request.POST.get('StatusFlag', '')
            raworksheet.RATrigger = request.POST.get('RATrigger', '')
            raworksheet.AssessorName = ""
            raworksheet.BusinessUnit = request.POST.get('BusinessUnit', '')
            raworksheet.BusinessUnitType = request.POST.get('BusinessUnitType', '')
            raworksheet.EmployeeCount = int(request.POST.get('EmployeeCount', '0'))
            raworksheet.RegulatoryOversight = request.POST.get('RegulatoryOversight', '')
            raworksheet.save()

            # Updating session variable
            request.session['raworksheetid'] = raworksheet.ID

        except Exception as e:
            # Production ready error handling would be more specific to your application
            return HttpResponse(f"An error occurred: {str(e)}")

    raworksheetid = request.session.get('raworksheetid', -1)
    if raworksheetid != -1:
        raworksheet = RAWorksheet.objects.get(ID=raworksheetid)
    else:
        raworksheet = None

    context = {'raworksheet': raworksheet, }
    return render(request, 'OTRisk/riskassess.html', context)


def risk_register_data(request):
    with connection.cursor() as cursor:
        cursor.execute('''
            SELECT
                tblRAWorksheet.ID,
                tblRAWorksheet.RATitle,
                tblRAWorksheet.RADate,
                tblRAWorksheet.BusinessUnit,
                tblRAWorksheet.StatusFlag,
                COUNT(*) AS scenario_count,
                AVG(tblRAWorksheetScenario.RiskScore) AS Risk
            FROM
                tblRAWorksheet
            LEFT JOIN
                tblRAWorksheetScenario ON tblRAWorksheetScenario.RAWorksheetID = tblRAWorksheet.ID
            GROUP BY
                tblRAWorksheet.ID, tblRAWorksheet.RATitle, tblRAWorksheet.RADate, tblRAWorksheet.StatusFlag
        ''')
        data = cursor.fetchall()

    # Format the data into a list of dictionaries
    result = []
    for row in data:
        risk = row[6]
        risk_status = "--"  # Default value

        if risk is not None and risk >= 0:
            if risk > 85:
                risk_status = "H"
            elif risk > 65:
                risk_status = "M/H"
            elif risk > 40:
                risk_status = "M"
            elif risk > 25:
                risk_status = "L/M"
            else:
                risk_status = "L"

        item = {
            'ID': row[0],
            'RATitle': row[1],
            'RADate': row[2],
            'BusinessUnit': row[3],
            'StatusFlag': row[4],
            'scenario_count': row[5],
            'risk_status': risk,
            'RiskStatus': risk_status
        }
        result.append(item)

    return JsonResponse(result, safe=False)


def risk_assessment(request):
    data = {}
    if request.method == 'POST':
        if 'saveData' in request.POST:
            rawsaved = request.session.get('rawsaved', 0)
            if rawsaved == 0:
                # Create new RAWorksheet record
                ra_title = request.POST.get('title', '')
                ra_description = request.POST.get('description', '')
                ra_date = request.POST.get('date', '')
                ra_synopsis = request.POST.get('synopsis', '')
                ra_trigger = request.POST.get('RATrigger', '')
                ra_status = request.POST.get('StatusFlag', '')

                # Save RAWorksheet record
                raw_worksheet = RAWorksheet(
                    RATitle=ra_title,
                    RADescription=ra_description,
                    RADate=ra_date,
                    RASynopsis=ra_synopsis,
                    RATrigger=ra_trigger,
                    StatusFlag=ra_status
                )
                raw_worksheet.save()

                raw_current_record = raw_worksheet.ID

                # Save the first row (index 1) separately

                scenario_description = request.POST.get('scenario1', '')

                threat_code = request.POST.get('threat1', '')

                vuln_code = request.POST.get('vulnerability1', '')
                reputation_code = request.POST.get('reputation1', '')
                financial_code = request.POST.get('financial1', '')
                operational_code = request.POST.get('operational1', '')
                safety_code = request.POST.get('safety1', '')
                risk_score = float(request.POST.get('risk1', ''))
                comments = request.POST.get('comments1', '')
                scenario_priority = request.POST.get('weight1', '')

                ra_worksheet_scenario = RAWorksheetScenario(
                    RAWorksheetID=raw_current_record,
                    ScenarioDescription=scenario_description,
                    ThreatCode=threat_code,
                    VulnCode=vuln_code,
                    ReputationCode=reputation_code,
                    FinancialCode=financial_code,
                    OperationalCode=operational_code,
                    SafetyCode=safety_code,
                    RiskScore=risk_score,
                    Comments=comments,
                    ScenarioPriority=scenario_priority
                )
                ra_worksheet_scenario.save()

                # Save RAWorksheetScenario records
                row_count = int(request.POST.get('hdnRowCount'))

                for i in range(2, row_count + 2):
                    scenario_description = request.POST.get('scenario{}'.format(i), '')
                    threat_code = request.POST.get('threat{}'.format(i), '')
                    vuln_code = request.POST.get('vulnerability{}'.format(i), '')
                    reputation_code = request.POST.get('reputation{}'.format(i), '')
                    financial_code = request.POST.get('financial{}'.format(i), '')
                    operational_code = request.POST.get('operational{}'.format(i), '')
                    safety_code = request.POST.get('safety{}'.format(i), '')
                    risk_score = float(request.POST.get('risk{}'.format(i), ''))
                    comments = request.POST.get('comments{}'.format(i), '')
                    scenario_priority = request.POST.get('weight{}'.format(i), '')

                    ra_worksheet_scenario = RAWorksheetScenario(
                        RAWorksheetID=raw_current_record,
                        ScenarioDescription=scenario_description,
                        ThreatCode=threat_code,
                        VulnCode=vuln_code,
                        ReputationCode=reputation_code,
                        FinancialCode=financial_code,
                        OperationalCode=operational_code,
                        SafetyCode=safety_code,
                        RiskScore=risk_score,
                        Comments=comments,
                        ScenarioPriority=scenario_priority
                    )
                    ra_worksheet_scenario.save()

                request.session['rawsaved'] = 1
                request.session['rawcurrentrecord'] = raw_current_record
                data['saved_label'] = f"New risk assessment saved with record id: {raw_current_record}"

            else:
                # Update existing RAWorksheet and RAWorksheetScenario records
                raw_current_record = request.session.get('rawcurrentrecord', None)
                if raw_current_record:
                    ra_title = request.POST.get('title', '')
                    ra_description = request.POST.get('description', '')
                    ra_date = request.POST.get('date', '')
                    ra_synopsis = request.POST.get('synopsis', '')

                    RAWorksheet.objects.filter(ID=raw_current_record).update(
                        RATitle=ra_title,
                        RADescription=ra_description,
                        RADate=ra_date,
                        RASynopsis=ra_synopsis
                    )

                    row_count = int(request.POST.get('rowCount', 0))
                    for i in range(2, row_count + 2):
                        scenario_description = request.POST.get('scenario{}'.format(i), '')
                        threat_code = request.POST.get('threat{}'.format(i), '')
                        vuln_code = request.POST.get('vulnerability{}'.format(i), '')
                        reputation_code = request.POST.get('reputation{}'.format(i), '')
                        financial_code = request.POST.get('financial{}'.format(i), '')
                        operational_code = request.POST.get('operational{}'.format(i), '')
                        safety_code = request.POST.get('safety{}'.format(i), '')
                        risk_score = request.POST.get('risk{}'.format(i), '')
                        comments = request.POST.get('comments{}'.format(i), '')
                        scenario_priority = request.POST.get('weight{}'.format(i), '')

                        scenario = get_object_or_404(RAWorksheetScenario, RAWorksheetID=raw_current_record, ID=i)
                        scenario.ScenarioDescription = scenario_description
                        scenario.ThreatCode = threat_code
                        scenario.VulnCode = vuln_code
                        scenario.ReputationCode = reputation_code
                        scenario.FinancialCode = financial_code
                        scenario.OperationalCode = operational_code
                        scenario.SafetyCode = safety_code
                        scenario.RiskScore = risk_score
                        scenario.Comments = comments
                        scenario.ScenarioPriority = scenario_priority
                        scenario.save()

    else:
        # Initialize session variables
        request.session['rawsaved'] = 0
        request.session['rawcurrentrecord'] = None

    # Retrieve the data to be displayed back to the user
    data['ra_title'] = request.POST.get('title', '')
    data['ra_description'] = request.POST.get('description', '')
    data['ra_date'] = request.POST.get('date', '')
    data['ra_synopsis'] = request.POST.get('synopsis', '')
    data['ra_trigger'] = request.POST.get('RATrigger', '')
    data['ra_status'] = request.POST.get('StatusFlag', '')
    data['scenarios'] = RAWorksheetScenario.objects.filter(RAWorksheetID=request.session.get('rawcurrentrecord'))

    return render(request, 'riskassess.html', data)


def save_threat(request):
    if request.method == 'POST':
        threat_update_flag = int(request.POST.get('ThreatUpdateFlag', '0'))
        threat_id = int(request.POST.get('ThreatAssessmentID'))

        if threat_update_flag == 0:
            # Add a new record
            threat = ThreatAssessment()
        elif threat_update_flag == 1:
            # Update an existing record
            threat = ThreatAssessment.objects.get(ThreatAssessmentID=threat_id)
        else:
            # Invalid update flag, handle as needed
            return redirect('threat_form')  # Redirect back to the form

        # threat.ThreatAssessmentID = threat_id
        threat.post_id = request.session.get('post_id')
        threat.ThreatType = request.POST.get('ThreatType')
        threat.ThreatImpactDescription = request.POST.get('ThreatImpactDescription')
        threat.ThreatImpactScore = int(request.POST.get('ThreatImpactScore'))
        threat.ThreatLikelihoodDescription = request.POST.get('ThreatLikelihoodDescription')
        threat.ThreatLikelihoodScore = int(request.POST.get('ThreatLikelihoodScore'))
        threat.IndustryAttackHistory = request.POST.get('IndustryAttackHistory')
        threat.HasAttackedYesNo = request.POST.get('HasAttackedYesNo')
        threat.HasBusinessImpactYesNo = request.POST.get('HasBusinessImpactYesNo')
        threat.AttackExpectedYesNo = request.POST.get('AttackExpectedYesNo')
        threat.KnownExposureYesNo = request.POST.get('KnownExposureYesNo')
        threat.Comments = request.POST.get('Comments')
        threat.OverallThreatRatingHML = request.POST.get('OverallThreatRatingHML')

        threat.save()

    return render(request, 'OTRisk/threatassess.html')


@csrf_exempt
def save_scenario(request):
    if request.method == 'POST':
        # Retrieve the scenario data from the POST request
        scenario_description = request.POST.get('scenario_description')
        consequence_analysis = request.POST.get('consequence_analysis')
        threat_source = request.POST.get('threat_source')
        threat_action = request.POST.get('threat_action')
        countermeasures = request.POST.get('countermeasures')
        severity = request.POST.get('severity')
        frequency = request.POST.get('frequency')
        exposure = request.POST.get('exposure')
        resilience = request.POST.get('resilience')
        input_rru = request.POST.get('input_rru')
        unmitigated_likelihood = request.POST.get('unmitigated_likelihood')
        severity_index = request.POST.get('severity_index')
        mitigate_severity = request.POST.get('mitigate_severity')
        mitigated_exposure = request.POST.get('mitigated_exposure')
        residual_risk_mitigated = request.POST.get('residual_risk_mitigated')
        after_action_severity = request.POST.get('after_action_severity')
        after_action_exposure = request.POST.get('after_action_exposure')
        residual_risk_after_action = request.POST.get('residual_risk_after_action')

        # Retrieve the post_id from the session variable
        post_id = request.session.get('post_id')

        if post_id is not None:
            try:
                scenario = RiskScenario.objects.get(post_id=post_id)

                # Update the existing scenario record
                scenario.ScenarioDescription = scenario_description
                scenario.ConsequenceAnalysis = consequence_analysis
                scenario.ThreatScore = threat_source
                scenario.ThreatAction = threat_action
                scenario.Countermeasures = countermeasures
                scenario.Severity = severity
                scenario.Frequency = frequency
                scenario.Exposure = exposure
                scenario.Resilience = resilience
                scenario.RRu = input_rru
                scenario.UEL = unmitigated_likelihood
                scenario.SI = severity_index
                scenario.Sm = mitigate_severity
                scenario.MEL = mitigated_exposure
                scenario.RRm = residual_risk_mitigated
                scenario.Sa = after_action_severity
                scenario.MELa = after_action_exposure
                scenario.RRa = residual_risk_after_action
                scenario.save()

                # Return success response
                return JsonResponse({'success': True, 'current_scenario': scenario.id})

            except RiskScenario.DoesNotExist:
                # Create a new scenario record
                scenario = RiskScenario(
                    post_id=post_id,
                    ScenarioDescription=scenario_description,
                    ConsequenceAnalysis=consequence_analysis,
                    ThreatScore=threat_source,
                    ThreatAction=threat_action,
                    Countermeasures=countermeasures,
                    Severity=severity,
                    Frequency=frequency,
                    Exposure=exposure,
                    Resilience=resilience,
                    RRu=input_rru,
                    UEL=unmitigated_likelihood,
                    SI=severity_index,
                    Sm=mitigate_severity,
                    MEL=mitigated_exposure,
                    RRm=residual_risk_mitigated,
                    Sa=after_action_severity,
                    MELa=after_action_exposure,
                    RRa=residual_risk_after_action
                )
                scenario.save()

                # Return success response
                return JsonResponse({'success': True, 'current_scenario': scenario.id})

        else:
            # Handle the post_id not set in session variable
            return JsonResponse({'success': False, 'message': 'post_id not set in session variable.'})

    else:
        # Handle invalid request method
        return JsonResponse({'success': False, 'message': 'Invalid request method.'})


@csrf_exempt
def save_recommendation(request):
    if request.method == 'POST':
        recommendation = request.POST.get('recommendation')
        post_id = request.session.get('post_id')

        if recommendation and post_id:
            try:
                current_scenario = RiskScenario.objects.get(post_id=post_id)
                current_scenario_id = current_scenario.id

                # Save the recommendation for the current scenario
                scenario_recommendation = tblScenarioRecommendations(
                    RiskPostID=current_scenario_id,
                    Recommendation=recommendation
                )
                scenario_recommendation.save()

                # Return success response
                return JsonResponse({'success': True, 'current_scenario_id': current_scenario_id})

            except RiskScenario.DoesNotExist:
                # Handle scenario not found
                return JsonResponse({'success': False, 'message': 'Scenario not found.'})

        else:
            # Handle missing recommendation or post_id
            return JsonResponse({'success': False, 'message': 'Missing recommendation or post_id.'})

    else:
        # Handle invalid request method
        return JsonResponse({'success': False, 'message': 'Invalid request method.'})


def workshop_setup(request):
    if request.method == 'POST':
        workshop_type = request.POST.get('workshoptype')
        workshop_start_date = request.POST.get('workshopstartdate')
        workshop_name = request.POST.get('workshopname')
        workshop_objectives = request.POST.get('workshopobjectives')

        new_workshop = tblWorkshopInformation(
            WorkshopStartDate=workshop_start_date,
            WorkshopName=workshop_name,
            WorkshopObjectives=workshop_objectives,
            WorkshopType=workshop_type
        )

        new_workshop.save()
        new_workshop_id = new_workshop.ID

        return redirect('OTRisk:workshop', workshop_id=new_workshop_id)

    workshops = tblWorkshopInformation.objects.all()
    return render(request, 'OTRisk/workshop.html', {'workshops': workshops})


def workshop(request, workshop_id=None):
    # Get all distinct TopSections
    top_sections = tblWorkshopNarrative.objects.values('TopSection').distinct()

    sections = []
    for top_section in top_sections:
        # For each TopSection, get all related questions
        if workshop_id is not None:
            # If a workshop_id is provided, filter questions for that workshop
            questions = tblWorkshopNarrative.objects.filter(TopSection=top_section['TopSection'],
                                                            WorkshopID=workshop_id)
        else:
            # If no workshop_id is provided, get all questions for the TopSection
            questions = tblWorkshopNarrative.objects.filter(TopSection=top_section['TopSection'])

        # Append a dictionary to the sections list for each TopSection
        sections.append({
            'TopSection': top_section['TopSection'],
            'questions': questions,
        })

    return render(request, 'OTRisk/workshop.html', {'sections': sections})
    # return render(request, 'OTRisk/workshop.html', {'workshop': workshop, 'sections': sections})


def add_walkthrough(request):
    facility_types = FacilityType.objects.all()
    return render(request, 'OTRisk/walkthrough.html', {'facility_types': facility_types})


def walkthrough_questionnaire(request, facility_type_id):
    query_results = Questionnaire.objects \
        .values('id', 'title', 'description', 'questionthemes__QuestionTheme',
                'questionthemes__questions__questionnumber', 'questionthemes__questions__questiontext') \
        .filter(id=F('questionthemes__fkQuestionnaireID'),
                questionthemes__id=F('questionthemes__questions__ThemeID'),
                fkFacilityType_id=facility_type_id) \
        .distinct()
    row_count = len(query_results)

    facility_type = get_object_or_404(FacilityType, id=facility_type_id)

    return render(request, 'OTRisk/walkthroughQuestionnaire.html',
                  {'facility_type': facility_type, 'query_results': query_results})


def walkthrough_questionnaire_details(request, questionnaire_id):
    # Add your logic here to retrieve the questionnaire details and render the template
    return render(request, 'OTRisk/walkthroughQuestionnaire.html', {'questionnaire_id': questionnaire_id})


def write_to_audit(user_id, user_action, user_ip):
    try:
        user_profile = UserProfile.objects.get(user=user_id)

        audit_log = auditlog(
            user=user_id,
            timestamp=timezone.now(),
            user_action=user_action,
            user_ipaddress=user_ip,
            user_profile=user_profile
        )
        audit_log.save()
    except UserProfile.DoesNotExist:
        # Handle the case where UserProfile does not exist for the user
        pass


def get_mitigations(request):
    mitigations = MitreICSMitigations.objects.all()
    return render(request, 'OTRisk/iotaphamanager.html', {'mitigations': mitigations})


def save_control_assessment(request):
    if request.method == "POST":
        # Get the cyberPHA_id from the POST data
        cyberPHA_id = request.POST.get('cyberPHA')

        try:
            # Try to retrieve the corresponding tblCyberPHAHeader instance
            record = tblCyberPHAHeader.objects.get(ID=cyberPHA_id)
        except tblCyberPHAHeader.DoesNotExist:
            # If the record does not exist, return an error message
            return JsonResponse({"status": "error", "message": "Invalid cyberPHA ID!"})

        for field_name, response_value in request.POST.items():
            # Check if the field name starts with 'M' and has digits, indicating it's a control field
            if field_name.startswith('M') and field_name[1:].isdigit():
                control_id = field_name  # Use the id value directly from the field name
                weighting_field_name = f'weighting_{control_id}'
                weighting_value = request.POST.get(weighting_field_name)
                if weighting_value == '':
                    weighting_value = 5  # hard coding a median value if no value for the weighting has been set
                # Save or update the response in the MitreControlAssessment model
                MitreControlAssessment.objects.update_or_create(
                    control_id=control_id,
                    cyberPHA=record,
                    defaults={'effectiveness_percentage': response_value,
                              'weighting': weighting_value}
                )

        # Save the record to the database
        record.save()
        control_effectiveness = math.ceil(calculate_effectiveness(cyberPHA_id))
        # Return a success message as a JSON response
        return JsonResponse({
            "status": "success",
            "message": "Record saved/updated successfully!",
            "control_effectiveness": control_effectiveness
        })

    # Handle the case when the request method is not POST
    form = ControlAssessmentForm()
    return render(request, 'iotaphamanager.html', {'form': form})


@login_required()
def risk_register(request):
    weights = {
        'impactSafety': 0.2,
        'impactDanger': 0.15,
        'impactProduction': 0.15,
        'impactFinance': 0.1,
        'impactReputation': 0.1,
        'impactEnvironment': 0.1,
        'impactRegulation': 0.05,
        'impactData': 0.1,
        'impactSupply': 0.05
    }
    weighted_sum = sum(F(impact) * weight for impact, weight in weights.items())

    current_user_profile = UserProfile.objects.get(user=request.user)

    org_id = get_user_organization_id(request)

    # Fetch the data and the computed score
    data = tblCyberPHAScenario.objects.filter(
        risk_register=True,
        CyberPHA__UserID__in=User.objects.filter(userprofile__organization_id=org_id).values_list('id', flat=True)
    ).select_related('CyberPHA').annotate(
        business_impact_analysis_score=Ceil(weighted_sum * 10),  # Multiply by 10 to scale the score to 100
        business_impact_analysis_code=Case(
            When(business_impact_analysis_score__lt=20, then=Value('Low')),
            When(business_impact_analysis_score__lt=40, then=Value('Low/Medium')),
            When(business_impact_analysis_score__lt=60, then=Value('Medium')),
            When(business_impact_analysis_score__lt=80, then=Value('Medium/High')),
            default=Value('High'),
            output_field=CharField()
        ),
        snapshots=Case(
            When(
                pk__in=Subquery(
                    CyberPHAScenario_snapshot.objects.filter(
                        ScenarioID=OuterRef('ID')
                    ).values('ScenarioID')
                ),
                then=Value(1)
            ),
            default=Value(0),
            output_field=IntegerField()
        )

    ).values(
        'ID',
        'CyberPHA__FacilityName',
        'CyberPHA__AssessmentUnit',
        'CyberPHA__FacilityType',
        'CyberPHA__Industry',
        'Scenario',
        'RRa',
        'CyberPHA__AssessmentStartDate',
        'CyberPHA__AssessmentEndDate',
        'probability',
        'sle',
        'sle_low',
        'sle_high',
        'business_impact_analysis_score',  # Include the computed score in the returned data
        'business_impact_analysis_code',  # Include the computed code in the returned data
        'snapshots',
        'CyberPHA__ID'
    )

    bia_data_with_id = [
        {'x': idx + 1, 'value': item['business_impact_analysis_score'], 'id': item['ID']} for idx, item in
        enumerate(data)
    ]

    sle_sum = tblCyberPHAScenario.objects.filter(
        risk_register=True,
        CyberPHA__UserID__in=User.objects.filter(userprofile__organization_id=org_id).values_list('id', flat=True)
    ).aggregate(Sum('sle'))

    sle_low_sum = tblCyberPHAScenario.objects.filter(
        risk_register=True,
        CyberPHA__UserID__in=User.objects.filter(userprofile__organization_id=org_id).values_list('id', flat=True)
    ).aggregate(Sum('sle_low'))

    sle_high_sum = tblCyberPHAScenario.objects.filter(
        risk_register=True,
        CyberPHA__UserID__in=User.objects.filter(userprofile__organization_id=org_id).values_list('id', flat=True)
    ).aggregate(Sum('sle_high'))

    for item in data:
        item['snapshots'] = item.get('snapshots', 0)
    # Convert the probability field to an integer for each item in data
    for item in data:
        try:
            item['probability'] = int(item['probability'].strip('%'))
        except ValueError:
            item['probability'] = 0

        # Define likelihoods and probabilities
    likelihoods = ['Low', 'Low/Medium', 'Medium', 'Medium/High', 'High']
    probabilities = ['Low', 'Low/Medium', 'Medium', 'Medium/High', 'High']

    # Create a dictionary to store the counts
    heatmap_counts = {
        'Low': {'Low': 0, 'Low/Medium': 0, 'Medium': 0, 'Medium/High': 0, 'High': 0},
        'Low/Medium': {'Low': 0, 'Low/Medium': 0, 'Medium': 0, 'Medium/High': 0, 'High': 0},
        'Medium': {'Low': 0, 'Low/Medium': 0, 'Medium': 0, 'Medium/High': 0, 'High': 0},
        'Medium/High': {'Low': 0, 'Low/Medium': 0, 'Medium': 0, 'Medium/High': 0, 'High': 0},
        'High': {'Low': 0, 'Low/Medium': 0, 'Medium': 0, 'Medium/High': 0, 'High': 0}
    }

    # Update the counts based on the data
    for item in data:
        prob_category = ''
        if item['probability'] < 25:
            prob_category = 'Low'
        elif item['probability'] < 50:
            prob_category = 'Low/Medium'
        elif item['probability'] < 75:
            prob_category = 'Medium'
        else:
            prob_category = 'High'

        heatmap_counts[item['business_impact_analysis_code']][prob_category] += 1

    heatmap_data = []
    for likelihood in likelihoods:
        for probability in probabilities:
            heatmap_data.append({
                'likelihood': likelihood,
                'probability': probability,
                'count': heatmap_counts[likelihood][probability]
            })

    return render(request, 'risk_register.html', {
        'data': data,
        'bia_data_with_id': bia_data_with_id,
        'heatmap_data': heatmap_data,
        'sle_sum': sle_sum['sle__sum'],
        'sle_low_sum': sle_low_sum['sle_low__sum'],
        'sle_high_sum': sle_high_sum['sle_high__sum'], })


@login_required()
def save_risk_data(request):
    if request.method == 'POST':
        # Get the existing record
        scenario_id = request.POST.get('scenario_id')
        scenario = tblCyberPHAScenario.objects.get(ID=scenario_id)

        risk_owner = request.POST.get('risk_owner')
        risk_priority = request.POST.get('risk_priority')
        risk_response = request.POST.get('risk_response')
        risk_status = request.POST.get('risk_status')

        # Check for risk_open_date
        risk_open_date = request.POST.get('risk_open_date')
        if not risk_open_date:
            risk_open_date = scenario.risk_open_date  # Use the existing value if not provided

        # Logic for risk_status and risk_close_date
        if risk_status == "Closed":
            if scenario.risk_status != "Closed":
                scenario.risk_status = "Closed"
                risk_close_date = request.POST.get('risk_close_date')
                if not risk_close_date:
                    risk_close_date = date.today()  # Set to current date if not provided
                scenario.risk_close_date = risk_close_date
        else:
            scenario.risk_status = risk_status

        # Update the record
        scenario.risk_owner = risk_owner
        scenario.risk_priority = risk_priority
        scenario.risk_response = risk_response
        scenario.risk_open_date = risk_open_date

        scenario.save()

        return JsonResponse({'status': 'success'})
    return JsonResponse({'status': 'error'})


def get_weightings_from_openai(facility_type, industry):
    """
    Query the OpenAI API to get recommended weightings based on facility type and industry.

    Args:
    - facility_type (str): The type of the facility.
    - industry (str): The industry in which the facility operates.

    Returns:
    - dict: A dictionary of recommended weightings.
    """
    prompt = f"Given a facility type of '{facility_type}' in the '{industry}' industry, how should the following impact factors be weighted: impactSafety, impactDanger, impactProduction, impactFinance, impactReputation, impactEnvironment, impactRegulation, impactData, impactSupply?"

    response = openai.Completion.create(engine="davinci", prompt=prompt, max_tokens=150)

    # TODO: Parse the response to extract the recommended weightings
    # This will depend on the format of the response from OpenAI.
    # For simplicity, let's assume the response is a comma-separated list of weightings.
    weightings_list = response.choices[0].text.strip().split(',')
    weightings = {
        'impactSafety': float(weightings_list[0]),
        'impactDanger': float(weightings_list[1]),
        'impactProduction': float(weightings_list[2]),
        'impactFinance': float(weightings_list[3]),
        'impactReputation': float(weightings_list[4]),
        'impactEnvironment': float(weightings_list[5]),
        'impactRegulation': float(weightings_list[6]),
        'impactData': float(weightings_list[7]),
        'impactSupply': float(weightings_list[8])
    }

    return weightings


@login_required
def delete_snapshot(request, snapshot_id, scenario_id):
    if request.method == 'POST':
        snapshot = get_object_or_404(CyberPHAScenario_snapshot, ID=snapshot_id)
        snapshot.delete()

        # Redirect to view_snapshots after deletion
        return redirect('OTRisk:view_snapshots', scenario=scenario_id)
    else:
        return HttpResponse(status=405)  # Method Not Allowed


@login_required()
def view_snapshots(request, scenario):
    # Retrieve the single record from tblCyberPHAScenario where ID = scenario
    scenario_record = tblCyberPHAScenario.objects.get(ID=scenario)

    # Using the ForeignKey relationship to retrieve the associated tblCyberPHAHeader record
    header_record = scenario_record.CyberPHA

    # Retrieve all the records from CyberPHAScenario_snapshot where ScenarioID = scenario
    snapshots = CyberPHAScenario_snapshot.objects.filter(ScenarioID=scenario)

    # Pass the datasets to the risk_snapshots template
    context = {
        'scenario_record': scenario_record,
        'snapshots': snapshots,
        'header_record': header_record
    }
    return render(request, 'risk_snapshots.html', context)


@login_required()
def manage_organization(request):
    org_to_edit = None

    if request.method == "POST":
        org_id = request.POST.get('organization_id', None)
        if org_id:
            org_to_edit = Organization.objects.get(id=org_id)

        form = OrganizationAdmin(request.POST, instance=org_to_edit)

        if form.is_valid():
            form.save()
            return redirect('OTRisk:manage_organization')
    else:
        form = OrganizationAdmin()

    organizations = Organization.objects.all()
    context = {
        'organizations': organizations,
        'form': form,
        'org_to_edit': org_to_edit
    }
    return render(request, 'OTRisk/manage_organization.html', context)


@login_required()
def get_organization_details(request, org_id):
    org = Organization.objects.get(id=org_id)
    data = {
        'name': org.name,
        'address': org.address,
        'address2': org.address2,
        'city': org.city,
        'state': org.state,
        'zip': org.zip,
        'country': org.country,
        'max_users': org.max_users,
        'subscription_status': org.subscription_status,
        'subscription_start': org.subscription_start,
        'subscription_end': org.subscription_end
    }
    return JsonResponse(data)


@login_required()
def write_audit_record(user, organization_id, ip_address, session_id, user_action, record_type, record_id=None):
    audit_record = Audit(
        user=user,
        organization_id=organization_id,
        ip_address=ip_address,
        session_id=session_id,
        user_action=user_action,
        record_type=record_type,
        record_id=record_id
    )
    audit_record.save()


@login_required
def read_audit_records(user):
    return Audit.objects.filter(organization_id=user.userprofile.organization_id)


def get_cve_details(request):
    if request.method == 'POST':
        cve_number = request.POST['cve_number']

        # Ensure that the input is in the correct CVE format (e.g., CVE-2023-123456)
        if not re.match(r'^CVE-\d{4}-\d+$', cve_number):
            return JsonResponse({"error": "Invalid CVE format"})

        # Fetch details from NIST NVD API
        url = f"https://services.nvd.nist.gov/rest/json/cve/1.0/{cve_number}"
        response = requests.get(url)
        data = response.json()

        # Ensure the request was successful and the CVE exists
        if data.get('result') and data['result'].get('CVE_data_type') == 'CVE':
            cve_item = data['result']['CVE_Items'][0]
            # Extract relevant details or modify this based on your needs
            description = cve_item['cve']['description']['description_data'][0]['value']
            published_date = cve_item['publishedDate']
            last_modified_date = cve_item['lastModifiedDate']

            return JsonResponse({
                "description": description,
                "published_date": published_date,
                "last_modified_date": last_modified_date
            })

        return JsonResponse({"error": "CVE not found or an error occurred"})

    return JsonResponse({"error": "Invalid request method"})


def scenario_sim(request):  # Changed the function name
    scenario_form = CyberSecurityScenarioForm(request.POST)
    industries = tblIndustry.objects.all().order_by('Industry')
    facilities = FacilityType.objects.all().order_by('FacilityType')
    threatsources = tblThreatSources.objects.all().order_by('ThreatSource')
    attack_vectors = tblThreatActions.objects.all().order_by('ThreatAction')
    return render(request, 'OTRisk/scenario_sim.html',
                  {'scenario_form': scenario_form, 'industries': industries, 'facilities': facilities,
                   'threats': threatsources, 'attack_vectors': attack_vectors})


def get_api_key(service_name):
    try:
        key_record = APIKey.objects.get(service_name=service_name)
        return key_record.key
    except ObjectDoesNotExist:
        # Handle the case where the key is not found
        return None


@login_required
def update_user_phone_number(request):
    if request.method == 'POST':
        user_id = request.POST.get('userId')
        new_phone_number = request.POST.get('newPhoneNumber')

        # Update the user profile
        user_profile = UserProfile.objects.get(user_id=user_id)
        user_profile.phone_number = new_phone_number
        user_profile.save()

        return JsonResponse({'status': 'success'})
    else:
        return JsonResponse({'status': 'failed'}, status=400)


def generate_scenario_description(request):
    if request.method == 'POST':
        # Extracting form data
        attacker = request.POST.get('attacker', '').strip()
        attack_vector = request.POST.get('attackVector', '').strip()
        target_component = request.POST.get('targetComponent', '').strip()
        attack_effect = request.POST.get('attackEffect', '').strip()
        target_system = request.POST.get('targetSystem', '').strip()
        impact = request.POST.get('impact', '').strip()
        motivation = request.POST.get('motivation', '').strip()
        country = request.POST.get('country', '').strip()
        industry = request.POST.get('industry', '').strip()
        facility_type = request.POST.get('facility_type', '').strip()
        severity = request.POST.get('severity', '').strip()
        detection_response = request.POST.get('detectionResponse', '').strip()
        preventive_measures = request.POST.get('preventiveMeasures', '').strip()

        prompt = (
            "You are an Data scientist specialising in OT cybersecurity writing scenarios for a cybersecurity insurance underwriter. Using only the following inputs, you are to construct and generate in natural language a brief, concise, and realistic scenario. Consider that an attack tree will be created from the scenario. You output MUST be less than 150 words with no additional narrative or commentary.  \n\n"
            f"- Attacker: {attacker}\n"
            f"- Attack Vector: {attack_vector}\n"
            f"- Target Component: {target_component}\n"
            f"- Effect of Attack: {attack_effect}\n"
            f"- Target System/Network: {target_system}\n"
            f"- Potential Impact: {impact}\n"
            f"- Attacker's Motivation: {motivation}\n\n"
            f"- Facility type: {facility_type}\n\n"
            f"- Industry sector: {industry}\n\n"
        )
        print(prompt)
        # Setting OpenAI API key
        openai.api_key = get_api_key('openai')

        # Querying the OpenAI API
        response = openai.ChatCompletion.create(
            model="gpt-4",
            messages=[
                {"role": "system", "content": prompt}
            ],
            max_tokens=150,
            temperature=0.5
        )
        # Extracting the generated scenario
        # The response structure is different for chat completions, so adjust accordingly
        if response.choices and response.choices[0].message:
            scenario_description = response.choices[0].message['content'].strip()
        else:
            scenario_description = "No scenario generated."

        return JsonResponse({'scenario_description': scenario_description})
    else:
        return JsonResponse({'error': 'Invalid request'}, status=400)


def save_scenario_builder(request):
    if request.method == 'POST':
        user = request.user
        data = request.POST

        # Reconstruct tableData from individual key-value pairs
        tableData = []
        for i in range(9):  # Assuming there are 9 factors
            factor_key = f'tableData[{i}][factor]'
            score_key = f'tableData[{i}][score]'
            narrative_key = f'tableData[{i}][narrative]'
            if factor_key in data and score_key in data and narrative_key in data:
                tableData.append({
                    'factor': data[factor_key],
                    'score': data[score_key],
                    'narrative': data[narrative_key]
                })

        scenario = ScenarioBuilder(
            user=user,
            scenario_name=data.get('name'),
            scenario_data=json.dumps({
                'scenario': data.get('scenario'),
                'attackTree': data.get('attackTree'),
                'consequences': data.get('consequences'),
                'tableData': tableData,  # Updated line
                'cost_projection': data.get('cost_projection'),
                'investment_projection': data.get('investment_projection'),
                'costs': {
                    'bestCase': data.get('bestCaseCost'),
                    'mostLikelyCase': data.get('mostLikelyCaseCost'),
                    'worstCase': data.get('worstCaseCost')
                }
            })
        )
        scenario.save()
        return JsonResponse({'status': 'success'})
    else:
        return JsonResponse({'error': 'Invalid request'}, status=400)


# Django view to fetch saved scenarios
def get_saved_scenario_builders(request):
    if request.method == 'GET':
        current_user = request.user

        try:
            # Get the current user's organization ID directly from their UserProfile
            current_user_organization_id = UserProfile.objects.get(user=current_user).organization_id

            # Get IDs of all users in the same organization as the current user
            users_in_same_organization_ids = UserProfile.objects.filter(
                organization_id=current_user_organization_id
            ).values_list('user_id', flat=True)

            # Filter scenarios by users in the same organization and not deleted
            scenarios = ScenarioBuilder.objects.filter(
                user_id__in=users_in_same_organization_ids,
                is_deleted=False
            ).values('id', 'scenario_name', 'created_at')

            return JsonResponse(list(scenarios), safe=False)
        except UserProfile.DoesNotExist:
            # Handle the case where the current user does not have a UserProfile
            return JsonResponse({'error': 'UserProfile for the current user does not exist'}, status=400)

    return JsonResponse({'error': 'Invalid request'}, status=400)


@login_required
def list_scenario_builders(request):
    if request.method == 'GET':
        current_user = request.user
        try:
            # Get the current user's organization ID directly from their UserProfile
            current_user_organization_id = UserProfile.objects.get(user=current_user).organization_id

            # Get IDs of all users in the same organization as the current user
            users_in_same_organization_ids = UserProfile.objects.filter(
                organization_id=current_user_organization_id
            ).values_list('user_id', flat=True)

            # Filter scenarios by users in the same organization and not deleted
            scenarios = ScenarioBuilder.objects.filter(
                user_id__in=users_in_same_organization_ids,
                is_deleted=False
            ).values('id', 'scenario_name', 'created_at')

            return JsonResponse({'scenarios': list(scenarios)})

        except UserProfile.DoesNotExist:
            # Handle the case where the current user does not have a UserProfile
            return JsonResponse({'error': 'UserProfile for the current user does not exist'}, status=400)



@login_required
def get_scenario_builder_details(request, scenario_id):
    try:
        scenario = ScenarioBuilder.objects.get(id=scenario_id, user=request.user, is_deleted=False)

        return JsonResponse({'scenario_data': scenario.scenario_data})
    except ScenarioBuilder.DoesNotExist:
        return JsonResponse({'error': 'Scenario not found'}, status=404)
