import hashlib
import json
from urllib.parse import urljoin

from django.contrib import messages
import requests
import logging

from django.db import transaction
from google.oauth2 import service_account
from ibm_watson import NaturalLanguageUnderstandingV1
from ibm_watson.natural_language_understanding_v1 import Features, KeywordsOptions, SummarizationOptions, \
    CategoriesOptions, ConceptsOptions, EntitiesOptions, SentimentOptions, RelationsOptions
from ibm_cloud_sdk_core.authenticators import IAMAuthenticator
from django.db.models import CharField
from google.cloud import language_v1
from django.db.models.functions import Coalesce
from django.forms import model_to_dict, CharField
from django.utils import timezone
from django.utils.dateparse import parse_datetime, parse_date
from django.core.serializers import serialize
from django.views.decorators.http import require_POST, require_http_methods

from OTRisk.models.Model_CyberPHA import tblIndustry, tblCyberPHAHeader, tblZones, tblStandards, \
    tblCyberPHAScenario, vulnerability_analysis, tblAssetType, tblMitigationMeasures, MitreControlAssessment, \
    cyberpha_safety, SECURITY_LEVELS, ScenarioConsequences, user_scenario_audit, auditlog, CyberPHAModerators, \
    WorkflowStatus, APIKey, CyberPHA_Group, ScenarioBuilder, PHA_Safeguard, CyberSecurityInvestment, UserScenarioHash, \
    CyberPHARiskTolerance, CyberPHACybersecurityDefaults, PHA_Observations
from OTRisk.models.raw import SecurityControls
from OTRisk.models.raw import MitreICSMitigations, RAActions
from OTRisk.models.questionnairemodel import FacilityType
from OTRisk.models.model_assessment import SelfAssessment, AssessmentFramework, AssessmentAnswer, AssessmentQuestion
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, get_object_or_404, redirect
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from datetime import date, time, datetime
from django.views import View
from django.http import JsonResponse
from django.core.exceptions import ObjectDoesNotExist
import openai
import re
from django.db.models import Avg, Sum, F, Count, Subquery, OuterRef, Case, When, Value, IntegerField, Q
import concurrent.futures
import os
import math
from decimal import Decimal, InvalidOperation

from ProjectAlpha import settings
from ProjectAlpha.settings import BASE_DIR
from accounts.models import UserProfile, Organization
from accounts.views import get_client_ip
from .dashboard_views import get_user_organization_id, get_organization_users
from django.contrib.auth.models import User
from concurrent.futures import ThreadPoolExecutor, as_completed
from .forms import VulnerabilityAnalysisForm
import aiohttp
import asyncio
import tempfile
import time
import uuid
from django.core import serializers
from django.http import FileResponse
from pptx import Presentation
from pptx.util import Inches, Pt


def get_api_key(service_name):
    try:
        key_record = APIKey.objects.get(service_name=service_name)
        return key_record.key
    except ObjectDoesNotExist:
        # Handle the case where the key is not found
        return None


def validate_and_format_date(date_str, default_date='2001-01-01', date_format='%Y-%m-%d'):
    """
    Validates and formats a date string into a timezone-aware datetime object.

    :param date_str: The date string to validate and format.
    :param default_date: The default date to return if date_str is invalid or empty.
    :param date_format: The format to which the date string should be formatted.
    :return: A timezone-aware datetime object representing the validated and formatted date.
    """
    if date_str:
        try:
            # Attempt to parse the date string using the specified format
            valid_date = datetime.strptime(date_str, date_format)
            # Make the datetime object timezone-aware
            timezone_aware_date = timezone.make_aware(valid_date, timezone.get_default_timezone())
            return timezone_aware_date
        except ValueError:
            # If parsing fails, return the default date as a timezone-aware datetime object
            default_datetime = datetime.strptime(default_date, date_format)
            return timezone.make_aware(default_datetime, timezone.get_default_timezone())
    else:
        # If the date string is empty, return the default date as a timezone-aware datetime object
        default_datetime = datetime.strptime(default_date, date_format)
        return timezone.make_aware(default_datetime, timezone.get_default_timezone())


@login_required
def iotaphamanager(request, record_id=None):
    pha_header = None
    new_record_id = None  # Initialize new_record_id to None
    annual_revenue_str = "$0"
    coho_str = "$0"

    if request.method == 'POST':
        is_new_record = False  # Initialize flag
        title = request.POST.get('txtTitle')
        facility_name = request.POST.get('txtFacility')
        # Check for duplicate record

        pha_id = request.POST.get('txtHdnCyberPHAID')
        if pha_id and int(pha_id) > 0:
            # Update existing record
            pha_header, created = tblCyberPHAHeader.objects.get_or_create(ID=pha_id)
        else:
            duplicate_record = tblCyberPHAHeader.objects.filter(title=title, FacilityName=facility_name).exists()
            if duplicate_record:
                return redirect('OTRisk:iotaphamanager')
            # Create a new record
            is_new_record = True
            pha_header = tblCyberPHAHeader()

        PHATitle = request.POST.get('txtTitle')
        pha_header.title = PHATitle if PHATitle else "Not Given"
        PHALeaderName = request.POST.get('txtLeader')
        pha_header.PHALeader = PHALeaderName if PHALeaderName else "Not Given"
        PHALeaderEmail = request.POST.get('txtLeaderEmail')
        pha_header.PHALeaderEmail = PHALeaderEmail if PHALeaderEmail else "Not Given"
        pha_header.FacilityName = request.POST.get('txtFacility')
        pha_header.Industry = request.POST.get('selIndustry')
        pha_header.FacilityType = request.POST.get('selFacilityType')

        pha_header.AssessmentUnit = request.POST.get('txtUnit')

        selZone_value = request.POST.get('selZone')
        pha_header.AssessmentZone = selZone_value if selZone_value else "None"

        start_date_str = request.POST.get('txtStartDate')
        pha_header.AssessmentStartDate = validate_and_format_date(start_date_str)

        # Validate and format AssessmentEndDate
        end_date_str = request.POST.get('txtEndDate')
        pha_header.AssessmentEndDate = validate_and_format_date(end_date_str)

        pha_header.facilityAddress = request.POST.get('txtAddress')

        if is_new_record:
            risk_profile_data = facility_risk_profile_newrecord(request.user.id,
                                                                request.POST.get('selIndustry'),
                                                                request.POST.get('selFacilityType'),
                                                                request.POST.get('txtAddress'),
                                                                request.POST.get('countrySelector'),
                                                                request.POST.get('txtFacility'),
                                                                int(request.POST.get('txtEmployees') or 0),
                                                                request.POST.get('shift_model'),
                                                                int(request.POST.get('assessment_id') or 0),
                                                                int(request.POST.get('sl') or 0),
                                                                request.POST.get('ir_plan'),
                                                                request.POST.get('ir_plan_ut'),
                                                                request.POST.get('ir_plan_date')
                                                                )
            pha_header.safetySummary = risk_profile_data['safety_summary']
            pha_header.chemicalSummary = risk_profile_data['chemical_summary']
            pha_header.physicalSummary = risk_profile_data['physical_security_summary']
            pha_header.otherSummary = risk_profile_data['other_summary']
            pha_header.threatSummary = risk_profile_data['threatSummary']
            pha_header.insightSummary = risk_profile_data['insightSummary']
            pha_header.strategySummary = risk_profile_data['strategySummary']
            pha_header.complianceSummary = risk_profile_data['compliance_summary']
            pha_header.pha_score = risk_profile_data['pha_score']

        else:
            pha_header.safetySummary = request.POST.get('txtSafetySummary')
            pha_header.chemicalSummary = request.POST.get('txtChemical')
            pha_header.physicalSummary = request.POST.get('txtPhysical')
            pha_header.otherSummary = request.POST.get('txtOther')
            pha_header.threatSummary = request.POST.get('threatSummary')
            pha_header.insightSummary = request.POST.get('insightSummary')
            pha_header.strategySummary = request.POST.get('strategySummary')
            pha_header.complianceSummary = request.POST.get('txtCompliance')
            try:
                # Attempt to convert the POST value to an integer.
                pha_header.pha_score = int(request.POST.get('hdn_pha_score', 0))
            except ValueError:
                # If conversion fails, set pha_score to 0.
                pha_header.pha_score = 0

        pha_header.country = request.POST.get('countrySelector')
        pha_header.Date = validate_and_format_date(start_date_str)
        pha_header.EmployeesOnSite = int(request.POST.get('txtEmployees') or 0)
        pha_header.facilityAQI = request.POST.get('txthdnAQI')
        pha_header.facilityCity = request.POST.get('txtCity')
        pha_header.facilityCode = request.POST.get('zipCode')
        pha_header.facilityLat = request.POST.get('txthdnLat')

        pha_header.facilityLong = request.POST.get('txthdnLong')
        pha_header.facilityState = request.POST.get('txtState')
        pha_header.shift_model = request.POST.get('shift_model')
        try:
            assessment_id = int(request.POST.get('assessment_id')) if request.POST.get('assessment_id') else None
        except ValueError:
            assessment_id = None
        pha_header.assessment = assessment_id
        pha_header.last_assessment_score = int(request.POST.get('last_assessment_score') or 0)

        pha_header.last_assessment_summary = request.POST.get('last_assessment_summary') or ''
        pha_header.npm = int(request.POST.get('npm') or 0)

        # Continue with the rest of the processing

        pha_header.sl_t = request.POST.get('selSL')
        pha_header.FacilityID = 0
        pha_header.Deleted = 0

        annual_revenue_str = request.POST.get('annual_revenue', '')
        coho_str = request.POST.get('coho', '')
        # Strip out $ and , characters
        cleaned_annual_revenue_str = ''.join(filter(str.isdigit, annual_revenue_str))
        cleaned_coho_str = ''.join(filter(str.isdigit, coho_str))

        # Convert the cleaned string to an integer
        try:
            annual_revenue_int = int(cleaned_annual_revenue_str)
        except ValueError:  # Handle cases where the input might still not be a valid integer
            annual_revenue_int = 0  # Or handle this situation differently if needed
        try:
            coho_int = int(cleaned_coho_str)
        except ValueError:  # Handle cases where the input might still not be a valid integer
            coho_int = 0  # Or handle this situation differently if needed
        # Save to your model
        pha_header.annual_revenue = annual_revenue_int
        pha_header.coho = coho_int

        cyber_insurance_value = request.POST.get('cyber_insurance')
        pha_header.cyber_insurance = False if cyber_insurance_value is None else bool(cyber_insurance_value)
        pha_header.is_default = request.POST.get('defaultFacility') == 'on'
        has_ir_plan = request.POST.get('ir_plan') == 'on'  # Checkbox 'on' if checked
        ir_plan_date_str = request.POST.get('ir_plan_date')
        ir_plan_never_tested = request.POST.get('ir_plan_ut') == 'on'

        # Convert ir_plan_date from string to date object, handle empty string
        if ir_plan_date_str:
            ir_plan_date = timezone.datetime.strptime(ir_plan_date_str, '%Y-%m-%d').date()
            pha_header.plan_last_tested_date = ir_plan_date
            pha_header.plan_never_tested = False  # If a date is provided, plan has been tested
        else:
            # If no date provided and plan exists, consider if it's marked as never tested
            if has_ir_plan:
                pha_header.plan_never_tested = ir_plan_never_tested
            else:
                # If no IR plan, reset related fields
                pha_header.plan_last_tested_date = None
                pha_header.plan_never_tested = True

        pha_header.has_incident_response_plan = has_ir_plan
        pha_header.UserID = request.user.id
        pha_header.save()

        saved_record_id = pha_header.ID
        if is_new_record:
            user_action = f"Created a new CyberPHA titled {pha_header.title}"
        else:
            user_action = f"Amended CyberPHA titled {pha_header.title}"

        cyber_pha_instance = tblCyberPHAHeader.objects.get(ID=saved_record_id)
        write_to_audit(
            user_id=request.user,
            user_action=user_action,
            user_ip=get_client_ip(request),
            cyberPHAID=cyber_pha_instance,
            cyberPHAScenario=None,
            qraw=None
        )

        #### Save investment information

        if pha_id and int(pha_id) > 0:
            CyberSecurityInvestment.objects.filter(cyber_pha_header=pha_header).delete()

        # Extract and process investment information from POST data
        investment_types = request.POST.getlist('investment_type[]')
        vendor_names = request.POST.getlist('vendor_name[]')
        product_names = request.POST.getlist('product_name[]')
        costs = request.POST.getlist('cost[]')
        dates = request.POST.getlist('date[]')

        for i_type, vendor, product, cost, date_str in zip(investment_types, vendor_names, product_names, costs, dates):
            # Ensure empty strings are saved for text fields if no data is entered
            i_type = i_type if i_type else ""
            vendor = vendor if vendor else ""
            product = product if product else ""

            # Handle cost, ensuring a default of 0 if no cost is entered
            cost = cost if cost else "0"

            # Convert date string to a date object, making it timezone-aware if necessary
            if not date_str:
                investment_date = timezone.now().date()  # Get the current date
            else:
                investment_date = parse_datetime(date_str + " 00:00")
                if investment_date and timezone.is_naive(investment_date):
                    investment_date = timezone.make_aware(investment_date, timezone.get_default_timezone()).date()

            CyberSecurityInvestment.objects.create(
                cyber_pha_header=pha_header,
                investment_type=i_type,
                vendor_name=vendor,
                product_name=product,
                cost=cost,
                date=investment_date
            )

        #### End save investments

        ##### save risk tolerance data
        risk_tolerance_data = {
            'negligible_low': request.POST.get('negligible_low'),
            'negligible_high': request.POST.get('negligible_high'),
            'minor_low': request.POST.get('minor_low'),
            'minor_high': request.POST.get('minor_high'),
            'moderate_low': request.POST.get('moderate_low'),
            'moderate_high': request.POST.get('moderate_high'),
            'significant_low': request.POST.get('significant_low'),
            'significant_high': request.POST.get('significant_high'),
            'severe_low': request.POST.get('severe_low'),
            'severe_high': request.POST.get('severe_high'),
        }

        # Convert string values to Decimal, handling empty strings
        for key, value in risk_tolerance_data.items():
            risk_tolerance_data[key] = Decimal(value) if value else Decimal('0.00')

        # Check if a CyberPHARiskTolerance record already exists for this header
        risk_tolerance, created = CyberPHARiskTolerance.objects.update_or_create(
            cyber_pha_header=pha_header,
            defaults=risk_tolerance_data
        )

        #### End save risk tolerance data
        # After saving pha_header, handle CyberPHACybersecurityDefaults
        if request.method == 'POST':
            # Assuming pha_header is the instance of tblCyberPHAHeader you've just created or updated
            defaults_data = {
                'overall_aggregate_limit': request.POST.get('overall_aggregate_limit'),
                'per_claim_limit': request.POST.get('per_claim_limit'),
                'deductible_amount': request.POST.get('deductible_amount'),
                'first_party_coverage': request.POST.get('first_party_coverage') == 'on',
                'third_party_coverage': request.POST.get('third_party_coverage') == 'on',
                'security_event_liability': request.POST.get('security_event_liability') == 'on',
                'privacy_regulatory_actions': request.POST.get('privacy_regulatory_actions') == 'on',
                'cyber_extortion_coverage': request.POST.get('cyber_extortion_coverage') == 'on',
                'data_breach_response_coverage': request.POST.get('data_breach_response_coverage') == 'on',
                'business_interruption_coverage': request.POST.get('business_interruption_coverage') == 'on',
                'dependent_business_coverage': request.POST.get('dependent_business_coverage') == 'on',
                'data_recovery': request.POST.get('data_recovery') == 'on',
                'hardware_replacement': request.POST.get('hardware_replacement') == 'on',
                'reputation_harm': request.POST.get('reputation_harm') == 'on',
                'media_liability': request.POST.get('media_liability') == 'on',
                'pci_dss': request.POST.get('pci_dss') == 'on',
                'premium_base': request.POST.get('premium_base'),
                'notification_period_days': request.POST.get('notification_period_days'),
                'cancellation_terms_days': request.POST.get('cancellation_terms_days'),
            }

            # Convert string values to appropriate types
            for key in ['overall_aggregate_limit', 'per_claim_limit', 'deductible_amount', 'premium_base']:
                defaults_data[key] = float(defaults_data[key]) if defaults_data[key] else 0.0
            for key in ['notification_period_days', 'cancellation_terms_days']:
                defaults_data[key] = int(defaults_data[key]) if defaults_data[key] else 0

            # Update or create CyberPHACybersecurityDefaults instance
            defaults_instance, created = CyberPHACybersecurityDefaults.objects.update_or_create(
                cyber_pha=pha_header,
                defaults=defaults_data
            )

        if is_new_record:
            pha_header.set_workflow_status('Started')
        # Save Workflow Status
        selected_workflow_status = request.POST.get('workflow_selector')
        if selected_workflow_status:
            pha_header.set_workflow_status(selected_workflow_status)
        # First, remove existing moderators for this PHA record
        CyberPHAModerators.objects.filter(pha_header=pha_header).delete()
        # Get the list of selected moderator IDs from the form

        selected_moderators_ids = request.POST.getlist('moderator')
        # Get the target date from the form

        target_date_str = request.POST.get('targetDate', None)
        if target_date_str:
            try:
                # Create a naive datetime object from the string
                naive_datetime = datetime.strptime(target_date_str, '%m/%d/%Y')
                # Make it timezone aware
                target_date = timezone.make_aware(naive_datetime, timezone.get_default_timezone())
            except ValueError:
                target_date = None
        else:
            target_date = None

        # Create new associations
        for moderator_id in selected_moderators_ids:
            moderator = User.objects.get(id=moderator_id)
            CyberPHAModerators.objects.create(pha_header=pha_header, moderator=moderator, target_date=target_date)

        new_record_id = pha_header.ID

    organization_id_from_session = request.session.get('user_organization')

    users_in_organization = User.objects.filter(userprofile__organization__id=organization_id_from_session)

    ra_actions_subquery = RAActions.objects.filter(phaID=OuterRef('ID')).values('phaID').annotate(
        action_count=Count('ID')).values('action_count')

    # Subquery to get the latest workflow status for each tblCyberPHAHeader record
    latest_status_subquery = WorkflowStatus.objects.filter(
        cyber_pha_header=OuterRef('pk')
    ).order_by('-timestamp').values('status')[:1]

    # Annotate the pha_header_records queryset with the latest workflow status
    pha_header_records = tblCyberPHAHeader.objects.filter(
        UserID__in=users_in_organization,
        Deleted=0
    ).annotate(
        scenario_count=Count('tblcyberphascenario'),
        ra_action_count=Coalesce(Subquery(ra_actions_subquery, output_field=IntegerField()), Value(0)),
        latest_workflow_status=Subquery(latest_status_subquery)
    )

    if record_id is not None:
        first_record_id = record_id
    else:
        first_record = pha_header_records.first()
        first_record_id = first_record.ID if first_record else 0
    # get the list of assessments
    # 0 means a global assessment that's built in for all customer
    # any other value is a customer specific assessment so should only be visible for the customer where their id matches
    current_user_profile = UserProfile.objects.get(user=request.user)
    user_organization_id = request.session.get('user_organization', 0)  # Default to 0 if not in session
    assessments = SelfAssessment.objects.filter(
        Q(organization_id=user_organization_id)
    )

    walkdowns = SelfAssessment.objects.filter(
        organization_id=user_organization_id,
        framework__name__icontains='Walkdown'
    )

    industries = tblIndustry.objects.all().order_by('Industry')
    facilities = FacilityType.objects.all().order_by('FacilityType')
    zones = tblZones.objects.all().order_by('PlantZone')
    standardslist = tblStandards.objects.all().order_by('standard')
    mitigations = MitreICSMitigations.objects.all()
    anychart_key = get_api_key('anychart')
    moderators_in_organization = UserProfile.objects.filter(
        organization_id=user_organization_id,
        role_moderator=True
    )

    # Retrieve current workflow status for the pha_header
    current_workflow_status = "Started"  # Default status

    if pha_header:
        latest_status = pha_header.workflow_statuses.last()
        if latest_status:
            current_workflow_status = latest_status.status

    return render(request, 'iotaphamanager.html', {
        'pha_header_records': pha_header_records,
        'industries': industries,
        'facilities': facilities,
        'zones': zones,
        'standardslist': standardslist,
        'current_pha_header': pha_header,
        'new_record_id': new_record_id,
        'mitigations': mitigations,
        'SHIFT_MODELS': tblCyberPHAHeader.SHIFT_MODELS,
        'annual_revenue_str': annual_revenue_str,
        'coho_str': coho_str,
        'selected_record_id': first_record_id,
        'SECURITY_LEVELS': SECURITY_LEVELS,
        'assessments': assessments,
        'walkdowns': walkdowns,
        'moderators': moderators_in_organization,
        'current_workflow_status': current_workflow_status,
        'workflow_status_choices': WorkflowStatus.STATUS_CHOICES,
        'anychart_key': anychart_key,
        'group_types': CyberPHA_Group.GROUP_TYPES,
        'saved_record_id': new_record_id
    })


def get_headerrecord(request):
    record_id = request.GET.get('record_id')
    headerrecord = get_object_or_404(tblCyberPHAHeader, ID=record_id)
    # Retrieve the latest workflow status for this header record
    latest_status = headerrecord.workflow_statuses.last()
    current_workflow_status = latest_status.status if latest_status else "Started"
    # Get current group assignments
    current_groups = headerrecord.groups.all()
    current_groups_data = serialize('json', current_groups)

    # Serialize all_groups
    all_groups = CyberPHA_Group.objects.all()
    all_groups_data = serialize('json', all_groups)
    # Retrieve the CyberPHARiskTolerance record associated with this header record

    # create a dictionary with the record data
    headerrecord_data = {
        'title': headerrecord.title,
        'facility': headerrecord.FacilityName,
        'leader': headerrecord.PHALeader,
        'leaderemail': headerrecord.PHALeaderEmail,
        'Industry': headerrecord.Industry,
        'facilitytype': headerrecord.FacilityType,
        'unit': headerrecord.AssessmentUnit,
        'zone': headerrecord.AssessmentZone,
        'startdate': headerrecord.AssessmentStartDate.strftime('%Y-%m-%d'),
        'enddate': headerrecord.AssessmentEndDate.strftime('%Y-%m-%d'),
        'address': headerrecord.facilityAddress,
        'safetysummary': headerrecord.safetySummary,
        'chemicalsummary': headerrecord.chemicalSummary,
        'physicalsummary': headerrecord.physicalSummary,
        'othersummary': headerrecord.otherSummary,
        'compliancesummary': headerrecord.complianceSummary,
        'threatSummary': headerrecord.threatSummary,
        'insightSummary': headerrecord.insightSummary,
        'strategySummary': headerrecord.strategySummary,
        'country': headerrecord.country,
        'shift_model': headerrecord.shift_model,
        'EmployeesOnSite': headerrecord.EmployeesOnSite,
        'cyber_insurance': headerrecord.cyber_insurance,
        'annual_revenue': headerrecord.annual_revenue,
        'pha_score': headerrecord.pha_score,
        'sl_t': headerrecord.sl_t,
        'assessment_id': headerrecord.assessment,
        'last_assessment_score': headerrecord.last_assessment_score,
        'last_assessment_summary': headerrecord.last_assessment_summary,
        'coho': headerrecord.coho,
        'npm': headerrecord.npm,
        'current_workflow_status': current_workflow_status,
        'current_groups': current_groups_data,
        'all_groups': all_groups_data,
        'group_types': CyberPHA_Group.GROUP_TYPES,
        'facilityAQI': headerrecord.facilityAQI,
        'facilityCity': headerrecord.facilityCity,
        'facilityCode': headerrecord.facilityCode,
        'facilityLat': headerrecord.facilityLat,
        'facilityLong': headerrecord.facilityLong,
        'facilityState': headerrecord.facilityState,
        'has_incident_response_plan': headerrecord.has_incident_response_plan,
        'plan_last_tested_date': headerrecord.plan_last_tested_date.strftime(
            '%Y-%m-%d') if headerrecord.plan_last_tested_date else None,
        'plan_never_tested': headerrecord.plan_never_tested,
        'is_default': headerrecord.is_default
    }

    # Query for moderators associated with this header record
    moderators = CyberPHAModerators.objects.filter(pha_header=headerrecord)
    moderator_ids = [moderator.moderator.id for moderator in moderators]

    moderators_data = [
        {'id': moderator.moderator.id, 'name': f"{moderator.moderator.first_name} {moderator.moderator.last_name}"}
        for moderator in moderators
    ]

    # Retrieve all users from the current organization who are moderators
    organization_moderators = User.objects.filter(
        userprofile__organization_id=get_user_organization_id(request),
        userprofile__role_moderator=True
    )
    organization_moderators_data = [
        {'id': user.id, 'name': f"{user.first_name} {user.last_name}"}
        for user in organization_moderators
    ]
    cyber_pha_instance = tblCyberPHAHeader.objects.get(ID=record_id)
    # Log the user activity
    write_to_audit(
        user_id=request.user,
        user_action=f'Viewed cyberPHA: {headerrecord.title}',
        user_ip=get_client_ip(request),
        cyberPHAID=cyber_pha_instance
    )

    control_assessments = MitreControlAssessment.objects.filter(cyberPHA=headerrecord)
    # control_effectiveness = math.ceil(calculate_effectiveness(record_id))
    try:
        control_effectiveness = SelfAssessment.objects.get(id=headerrecord.assessment).score_effective
        # assessment_summary_result = assessment_summary(headerrecord.assessment)
    except SelfAssessment.DoesNotExist:
        control_effectiveness = 0
    # Create a list of dictionaries for control assessments
    control_assessments_data = []
    for assessment in control_assessments:
        assessment_data = {
            'mitigation_id': assessment.control.id,  # Assuming control has an ID field
            'effectiveness_percentage': assessment.effectiveness_percentage,
            'weighting': assessment.weighting,
            # Add other fields if needed
        }
        control_assessments_data.append(assessment_data)

    investments = CyberSecurityInvestment.objects.filter(cyber_pha_header=headerrecord).values(
        'id', 'investment_type', 'vendor_name', 'product_name', 'cost', 'date'
    )
    investments_data = list(investments)
    try:
        risk_tolerance = CyberPHARiskTolerance.objects.get(cyber_pha_header=headerrecord)
        risk_tolerance_data = {
            'negligible_low': risk_tolerance.negligible_low,
            'negligible_high': risk_tolerance.negligible_high,
            'minor_low': risk_tolerance.minor_low,
            'minor_high': risk_tolerance.minor_high,
            'moderate_low': risk_tolerance.moderate_low,
            'moderate_high': risk_tolerance.moderate_high,
            'significant_low': risk_tolerance.significant_low,
            'significant_high': risk_tolerance.significant_high,
            'severe_low': risk_tolerance.severe_low,
            'severe_high': risk_tolerance.severe_high,
        }
    except CyberPHARiskTolerance.DoesNotExist:
        risk_tolerance_data = {}

    try:
        # Retrieve the related CyberPHACybersecurityDefaults instance
        cyber_defaults = CyberPHACybersecurityDefaults.objects.get(cyber_pha=headerrecord)
        # Serialize the CyberPHACybersecurityDefaults data
        cyber_defaults_data = {
            'overall_aggregate_limit': str(cyber_defaults.overall_aggregate_limit),
            'per_claim_limit': str(cyber_defaults.per_claim_limit),
            'deductible_amount': str(cyber_defaults.deductible_amount),
            'first_party_coverage': cyber_defaults.first_party_coverage,
            'third_party_coverage': cyber_defaults.third_party_coverage,
            'security_event_liability': cyber_defaults.security_event_liability,
            'privacy_regulatory_actions': cyber_defaults.privacy_regulatory_actions,
            'cyber_extortion_coverage': cyber_defaults.cyber_extortion_coverage,
            'data_breach_response_coverage': cyber_defaults.data_breach_response_coverage,
            'business_interruption_coverage': cyber_defaults.business_interruption_coverage,
            'dependent_business_coverage': cyber_defaults.dependent_business_coverage,
            'data_recovery': cyber_defaults.data_recovery,
            'hardware_replacement': cyber_defaults.hardware_replacement,
            'reputation_harm': cyber_defaults.reputation_harm,
            'media_liability': cyber_defaults.media_liability,
            'pci_dss': cyber_defaults.pci_dss,
            'premium_base': str(cyber_defaults.premium_base),
            'notification_period_days': cyber_defaults.notification_period_days,
            'cancellation_terms_days': cyber_defaults.cancellation_terms_days,
        }
    except CyberPHACybersecurityDefaults.DoesNotExist:
        cyber_defaults_data = {}

    response_data = {
        'headerrecord': headerrecord_data,
        'control_assessments': control_assessments_data,
        'control_effectiveness': control_effectiveness,
        'organization_moderators': organization_moderators_data,  # All moderators in the organization
        'current_moderators': moderators_data,  # Moderators for the specific header record
        'moderator_ids': moderator_ids,  # IDs of Moderators for the specific header record
        'investments': investments_data,
        'risk_tolerance': risk_tolerance_data,
        'cyber_defaults': cyber_defaults_data
    }

    return JsonResponse(response_data)


def extract_section(text, title):
    """
    Extracts a section from the provided text using the given title.
    """
    start = text.find(title)
    if start == -1:
        return ''
    start += len(title)
    end = text.find('**', start)
    return text[start:end].strip() if end != -1 else text[start:].strip()


def process_section(section_text):
    # this version of process section works for gpt-4-turbo
    """
    Processes the extracted section text to handle detailed structure,
    including sub-points and bolded text.
    """
    # Initialize an empty list to hold the processed points
    processed_points = []
    current_point_lines = []  # Temporary storage for accumulating lines of the current point

    # Split the section text into lines for processing
    lines = section_text.split('\n')

    for line in lines:
        # Check if the line starts a new main point (e.g., "1. ")
        if line.strip().startswith("1. ") or line.strip().startswith("2. ") or line.strip().startswith(
                "3. ") or line.strip().startswith("4. ") or line.strip().startswith("5. ") or line.strip().startswith(
            "6. ") or line.strip().startswith("7. ") or line.strip().startswith("8. ") or line.strip().startswith(
            "9. ") or line.strip().startswith("10. "):
            # If there's content in current_point_lines, it means the previous point is complete
            if current_point_lines:
                # Join the accumulated lines into a single string and add to the list
                processed_points.append('\n'.join(current_point_lines).strip())
                current_point_lines = [line]  # Start a new point
            else:
                # If current_point_lines is empty, this is the first point
                current_point_lines.append(line)
        else:
            # If the line does not start a new main point, it's a continuation or sub-point
            current_point_lines.append(line)

    # After the loop, add the last accumulated point to the list
    if current_point_lines:
        processed_points.append('\n'.join(current_point_lines).strip())

    # Join the processed points into a single string with double line breaks between points
    return '\n\n'.join(processed_points)


def process_section_gpt4(section_text):
    # this version of process section works for GPT4
    bullet_points = section_text.split('\n')

    # Add a line space between each bullet point
    processed_text = '\n\n'.join(bullet_point.strip() for bullet_point in bullet_points if bullet_point.strip())

    return processed_text


def make_request_with_backoff(openai_function, *args, **kwargs):
    max_attempts = 5
    base_delay = 1.0  # Base delay in seconds
    for attempt in range(max_attempts):
        try:
            return openai_function(*args, **kwargs)
        except openai.error.ServiceUnavailableError:
            sleep_time = base_delay * (2 ** attempt)

            time.sleep(sleep_time)
    raise Exception("Failed to make request after several attempts.")


def facility_threat_profile(security_level, facility, facility_type, country, industry, safety_summary,
                            chemical_summary,
                            physical_security_summary, other_summary, compliance_summary, investment_statement,
                            has_ir_plan_str, ir_plan_never_tested_str, ir_plan_date_str):
    openai_api_key = get_api_key('openai')
    openai_api_key = get_api_key('openai')
    ai_model = get_api_key('OpenAI_Model')

    # Constructing the detailed context
    context = f"""
        Analyze the cybersecurity posture of {facility}, a {facility_type} in {country}, focusing on OT cybersecurity risk mitigation. This facility is notable in the {industry} industry and has specific challenges and assets:
        Safety Hazards: {safety_summary}
        Chemical Hazards: {chemical_summary}
        Physical Security Challenges: {physical_security_summary}
        OT Devices: {other_summary}
        Compliance Requirements: {compliance_summary}
        Incident Response Plan: {has_ir_plan_str} (Last tested: {ir_plan_date_str})
        Cybersecurity Investments: {investment_statement}
        Target Security Level (SL-T) as per IEC62443-3-2: {security_level}.
        """

    prompt = f"""
        {context}
     Based on the facility's profile and investments, provide an executive-level cybersecurity analysis specifically for OT/ICS environments. The analysis should be divided into three sections:
        
        1. Cybersecurity Threats: Make an estimate of the main cybersecurity threats and the actors likely to target this facility, considering the operational technology used, country, and industry specifics. EXTRA INSTRUCTION append a probability (as a percentage) of each threat occurring in the next 12 months..
        2. Predictive Insights: Offer insights on potential future cybersecurity events based on current data and trends.
        3. Proactive Defense Strategies: Suggest strategies to improve the facility's cybersecurity posture and achieve the target security level.
        
        INSTRUCTION: Utilize relevant and credible sources of information and industry reports such as from Dragos, Gartner, Deloitte.
        
        Example Format:
        Section 1: Threats.
        1. Example threat.
        2. Another example threat.
        
        Section 2: Insights
        1. Example insight.
        2. Another example insight.
        
        Section 3: Strategies
        1. Example strategy.
        2. Another example strategy.
        
        Please follow this format for your response, without using '###', '**', or any other special formatting characters.
        """

    # API call using chat model endpoint with the correct 'messages' property
    response = make_request_with_backoff(
        openai.ChatCompletion.create,
        model=ai_model,  # Ensure to use GPT-4 model
        messages=[
            {"role": "system",
             "content": "You are a model trained to provide concise and informative responses in a specific format."},
            {"role": "user", "content": prompt}
        ],
        temperature=0.4,
        max_tokens=2500,
    )

    full_response = response['choices'][0]['message']['content']
    # Function to extract sections from the full_response
    def extract_section1(full_response1, section_title):
        start_index = full_response1.find(section_title)
        if start_index == -1:
            return ""
        start_index += len(section_title)
        end_index = full_response1.find("Section", start_index)
        section_text = full_response1[start_index:end_index].strip()
        return section_text

    # Extracting each section based on titles
    threat_summary = extract_section1(full_response, "Threats")
    insight_summary = extract_section1(full_response, "Insights")
    strategy_summary = extract_section1(full_response, "Strategies")

    return threat_summary, insight_summary, strategy_summary


@login_required()
def facility_risk_profile(request):
    if request.method == 'GET':
        # Gather the necessary data for the risk assessment (impact scores and scenario information)
        Industry = request.GET.get('industry')
        facility_type = request.GET.get('facility_type')
        address = request.GET.get('address')
        country = request.GET.get('country')
        facility = request.GET.get('facility')
        employees = request.GET.get('employees')
        shift_model = request.GET.get('shift_model')
        assessment_id = request.GET.get('assessment_id')
        investments_data = request.GET.get('investments')
        has_ir_plan = request.GET.get('has_ir_plan', 'false') == 'true'
        ir_plan_never_tested = request.GET.get('ir_plan_never_tested', 'false') == 'true'
        ir_plan_date_str = request.GET.get('ir_plan_date')

        aqi = request.GET.get('aqi')
        sl = request.GET.get('sl')
        if investments_data:
            investments = json.loads(investments_data)
        else:
            investments = []

        has_ir_plan_str = 'True' if has_ir_plan else 'False'
        ir_plan_never_tested_str = 'True' if ir_plan_never_tested else 'False'

        # Generate the text statement for investments
        investment_statement = "Investments have been made in:\n"
        for idx, investment in enumerate(investments, start=1):
            investment_statement += f"{idx}: Investment Type:{investment['type']}, Vendor:{investment['vendor_name']}, Product:{investment['product_name']}, Investment date:{investment['date']}.\n"

        language = request.session.get('organization_defaults', {}).get('language', 'en')  # 'en' is the default value

        # Log the user activity
        write_to_audit(
            user_id=request.user,
            user_action=f'Generated a cyberPHA risk profile for: {facility}',
            user_ip=get_client_ip(request)
        )
        # Check if Industry or facility_type are empty or None
        if not Industry or not facility_type:
            error_msg = "Missing industry or facility type. Complete all fields to get an accurate assessment"
            return JsonResponse({
                'safety_summary': error_msg,
                'chemical_summary': error_msg,
                'physical_security_summary': error_msg,
                'other_summary': error_msg
            })

        openai_api_key = get_api_key('openai')
        openai_model = get_api_key('OpenAI_Model')
        # openai_api_key = os.environ.get('OPENAI_API_KEY')
        openai.api_key = openai_api_key
        context = f"You are an industrial safety and hazard expert. For the {facility} {facility_type} at {address}, {country} in the {Industry} industry, with {employees} employees working a {shift_model} shift model. The local Air Quality Index is {aqi}.  "

        prompts = [
            f"{context} List safety hazards, max 100 words. - Specific to facility - mechanical or chemical or electrical or heat or cold or crush or height - Space between bullets. \n\nExample Format:\n 1. Specific safety hazard.\n 2. Another specific safety hazard.",
            f"{context} List expected chemicals, max 100 words. - Specific to facility - Chemical names only - raw materials and by-products and stored chemicals - Space between bullets. \n\nExample Format:\n 1. Chemical name (raw material or by-product).\n- 2. Another chemical name (raw material or by-product).",
            f"{context}, List physical security requirements for the given facility and location - access control - surveillance - consideration of local crime statistics - blind spots - proximity to other infrastructure . Max of 100 words .\n\nExample Format:\n 1. Physical security challenge.\n 2. Another physical security challenge.",
            f"{context}, list of specialized OT and IoT devices and equipment expected to be at the facility. Max of 150 words .\n\nExample Format:\n 1. OT or IoT device (purpose of device).\n 2. Another OT or IoT device (purpose of device).",
            f"{context}, list of national and international regulatory compliance containing cybersecurity requirements relevant to the {Industry} industry that applies to {facility_type} facilities in {country} . Includes laws and standards. Max of 150 words .\n\nExample Format:\n 1. Compliance name (name of issuing authority).\n 2. Another compliance name (name of issuing authority).",
            f"{context}: You are a safety inspector. For a {facility_type} in {country}, estimate a detailed and nuanced safety and hazard risk score. Use a scale from 0 to 100, where 0 indicates an absence of safety hazards and 100 signifies the presence of extreme and imminent fatal hazards. Provide a score reflecting the unique risk factors associated with the facility type and its operational context in {country}. Scores should reflect increments of 10, with each decile corresponding to escalating levels of hazard severity and likelihood of occurrence given the expected attention to safety at the facility. Base your score on a typical {facility_type} in {country}, adhering to expected standard safety protocols, equipment conditions, and operational practices. Provide the score as a single, precise number without additional commentary."
        ]

        responses = []

        # Loop through the prompts and make an API call for each one
        def fetch_response(prompt):
            return openai.ChatCompletion.create(
                # model="gpt-4",
                model=openai_model,
                messages=[
                    {"role": "system",
                     "content": "You are a model trained to provide concise responses. Please provide a concise numbered bullet-point list based on the given statement."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1,
                max_tokens=600

            )

            # Use ThreadPoolExecutor to parallelize the API calls

        with concurrent.futures.ThreadPoolExecutor() as executor:
            responses = list(executor.map(fetch_response, prompts))

            # Extract the individual responses
        safety_summary = responses[0]['choices'][0]['message']['content'].strip()
        chemical_summary = responses[1]['choices'][0]['message']['content'].strip()
        physical_security_summary = responses[2]['choices'][0]['message']['content'].strip()
        other_summary = responses[3]['choices'][0]['message']['content'].strip()
        compliance_summary = responses[4]['choices'][0]['message']['content'].strip()
        pha_score = responses[5]['choices'][0]['message']['content'].strip()

        # Call to facility_threat_profile
        threatSummary, insightSummary, strategySummary = facility_threat_profile(sl, facility, facility_type, country,
                                                                                 Industry, safety_summary,
                                                                                 chemical_summary,
                                                                                 physical_security_summary,
                                                                                 other_summary,
                                                                                 compliance_summary,
                                                                                 investment_statement, has_ir_plan_str,
                                                                                 ir_plan_never_tested_str,
                                                                                 ir_plan_date_str)

        # Return the individual parts as variables in JsonResponse
        return JsonResponse({
            'safety_summary': safety_summary,
            'chemical_summary': chemical_summary,
            'physical_security_summary': physical_security_summary,
            'other_summary': other_summary,
            'compliance_summary': compliance_summary,
            'pha_score': pha_score,
            'threatSummary': threatSummary,
            'insightSummary': insightSummary,
            'strategySummary': strategySummary
        })


@login_required()
def pha_report(request, cyberpha_id):
    organization_id_from_session = request.session.get('user_organization')

    users_in_organization = User.objects.filter(userprofile__organization__id=organization_id_from_session)

    cyberPHAHeader = tblCyberPHAHeader.objects.get(ID=cyberpha_id)
    cyberScenarios = tblCyberPHAScenario.objects.filter(CyberPHA=cyberpha_id, Deleted=0)
    average_impact_safety = cyberScenarios.aggregate(Avg('impactSafety'))['impactSafety__avg']
    average_impact_danger = cyberScenarios.aggregate(Avg('impactDanger'))['impactDanger__avg']
    average_impact_environment = cyberScenarios.aggregate(Avg('impactEnvironment'))['impactEnvironment__avg']
    average_impact_production = cyberScenarios.aggregate(Avg('impactProduction'))['impactProduction__avg']
    average_impact_finance = cyberScenarios.aggregate(Avg('impactFinance'))['impactFinance__avg']
    average_impact_data = cyberScenarios.aggregate(Avg('impactData'))['impactData__avg']
    average_impact_reputation = cyberScenarios.aggregate(Avg('impactReputation'))['impactReputation__avg']
    average_impact_regulation = cyberScenarios.aggregate(Avg('impactRegulation'))['impactRegulation__avg']
    average_impact_supply = cyberScenarios.aggregate(Avg('impactSupply'))['impactSupply__avg']
    total_cost_impact = cyberScenarios.aggregate(Sum('sle'))['sle__sum']
    total_cost_impact_low = cyberScenarios.aggregate(Sum('sle_low'))['sle_low__sum']
    total_cost_impact_high = cyberScenarios.aggregate(Sum('sle_high'))['sle_high__sum']

    control_effectiveness = math.ceil(get_overall_control_effectiveness_score(cyberpha_id))
    # Retrieve the top 5 most effective controls
    top_5_controls = MitreControlAssessment.objects.filter(cyberPHA=cyberpha_id).order_by('-effectiveness_percentage')[
                     :5]

    # Retrieve the bottom 5 least effective controls
    bottom_5_controls = MitreControlAssessment.objects.filter(cyberPHA=cyberpha_id).order_by(
        'effectiveness_percentage')[:5]

    overall_probability = math.ceil(calculate_overall_probability(cyberpha_id))

    return JsonResponse({'cyberPHAHeader': model_to_dict(cyberPHAHeader),
                         'scenarios': list(cyberScenarios.values()),
                         'average_impact_safety': average_impact_safety,
                         'average_impact_danger': average_impact_danger,
                         'average_impact_environment': average_impact_environment,
                         'average_impact_production': average_impact_production,
                         'average_impact_finance': average_impact_finance,
                         'average_impact_data': average_impact_data,
                         'average_impact_reputation': average_impact_reputation,
                         'average_impact_regulation': average_impact_regulation,
                         'average_impact_supply': average_impact_supply,
                         'control_effectiveness': control_effectiveness,
                         'top_5_controls': list(
                             top_5_controls.values('control__name', 'effectiveness_percentage', 'weighting')),
                         'bottom_5_controls': list(
                             bottom_5_controls.values('control__name', 'effectiveness_percentage', 'weighting')),
                         'overall_probability': overall_probability,
                         'total_cost_impact': total_cost_impact,
                         'total_cost_impact_low': total_cost_impact_low,
                         'total_cost_impact_high': total_cost_impact_high
                         })


def get_overall_control_effectiveness_score(cyberPHA_ID):
    """
    Calculate the Overall Control Effectiveness Score for a given cyberPHA_ID.

    Args:
        cyberPHA_ID (int): The ID of the cyberPHA security assessment.

    Returns:
        float: The Overall Control Effectiveness Score.
    """

    # Filter the assessments based on the given cyberPHA_ID
    assessments = MitreControlAssessment.objects.filter(cyberPHA=cyberPHA_ID)

    # Calculate the weighted sum of effectiveness percentages
    weighted_sum = assessments.aggregate(
        total=Sum(F('effectiveness_percentage') * F('weighting'))
    )['total'] or 0

    # Calculate the total weight
    total_weight = assessments.aggregate(total=Sum('weighting'))['total'] or 1

    # Calculate the Overall Control Effectiveness Score
    overall_score = weighted_sum / total_weight

    return overall_score


def calculate_overall_probability(cyberpha_id):
    # Retrieve all scenarios related to the given assessment
    cyberScenarios = tblCyberPHAScenario.objects.filter(CyberPHA=cyberpha_id, Deleted=0)

    # Start with the probability that none of the scenarios occur
    probability_none_occur = 1.0

    # Iterate over each scenario and update the probability
    for scenario in cyberScenarios:
        probability_value = int(scenario.probability.strip('%'))
        probability_none_occur *= (1 - probability_value / 100.0)

    # Calculate the overall probability that at least one scenario occurs
    overall_probability = 1 - probability_none_occur

    return overall_probability * 100  # Return as a percentage


@login_required()
def phascenarioreport(request):
    cyberPHAID = request.POST.get('cyberPHAID')
    cyberPHAHeader = tblCyberPHAHeader.objects.get(ID=cyberPHAID)
    cyberScenarios = tblCyberPHAScenario.objects.filter(CyberPHA=cyberPHAID, Deleted=0)

    average_impact_safety = cyberScenarios.aggregate(Avg('impactSafety'))['impactSafety__avg']
    average_impact_danger = cyberScenarios.aggregate(Avg('impactDanger'))['impactDanger__avg']
    average_impact_environment = cyberScenarios.aggregate(Avg('impactEnvironment'))['impactEnvironment__avg']
    average_impact_production = cyberScenarios.aggregate(Avg('impactProduction'))['impactProduction__avg']
    average_impact_finance = cyberScenarios.aggregate(Avg('impactFinance'))['impactFinance__avg']
    average_impact_data = cyberScenarios.aggregate(Avg('impactData'))['impactData__avg']
    average_impact_reputation = cyberScenarios.aggregate(Avg('impactReputation'))['impactReputation__avg']
    average_impact_regulation = cyberScenarios.aggregate(Avg('impactRegulation'))['impactRegulation__avg']

    return render(request, 'phascenarioreport.html', {
        'cyberPHAHeader': cyberPHAHeader,
        'cyberScenarios': cyberScenarios,
        'average_impact_safety': average_impact_safety,
        'average_impact_danger': average_impact_danger,
        'average_impact_environment': average_impact_environment,
        'average_impact_production': average_impact_production,
        'average_impact_finance': average_impact_finance,
        'average_impact_data': average_impact_data,
        'average_impact_reputation': average_impact_reputation,
        'average_impact_regulation': average_impact_regulation
    })


@login_required()
def getSingleScenario(request):
    # Get the ID from the GET parameters
    scenario_id = request.GET.get('id')
    current_user = request.user

    # Try to retrieve the scenario with the given ID
    try:
        scenario = tblCyberPHAScenario.objects.get(ID=scenario_id)
    except ObjectDoesNotExist:
        return JsonResponse({'error': 'Scenario not found'}, status=404)
        # Check if the current user is the owner, moderator, read-only, or has full access

    current_user_profile = UserProfile.objects.get(user=current_user)
    scenario_user_profile = UserProfile.objects.get(user=scenario.userID)

    if scenario.userID == current_user:
        user_role = 'Scenario Owner'
    else:
        try:
            user_profile = UserProfile.objects.get(user=current_user)
            if user_profile.role_moderator:
                user_role = 'Scenario Moderator'
            elif user_profile.role_readonly:
                user_role = 'Read Only'
            elif current_user_profile.organization_id == scenario_user_profile.organization_id:
                user_role = 'Scenario Editor'
            else:
                return JsonResponse({'error': 'Access denied'}, status=403)
        except UserProfile.DoesNotExist:
            return JsonResponse({'error': 'User profile not found'}, status=404)

    # Convert the scenario to a dictionary
    scenario_dict = {
        'ID': scenario.ID,
        'CyberPHA': scenario.CyberPHA.ID,
        'Scenario': scenario.Scenario,
        'ThreatClass': scenario.ThreatClass,
        'ThreatAgent': scenario.ThreatAgent,
        'ThreatAction': scenario.ThreatAction,
        'Countermeasures': scenario.Countermeasures,
        'RiskCategory': scenario.RiskCategory,
        'Consequence': scenario.Consequence,
        'impactSafety': scenario.impactSafety,
        'impactDanger': scenario.impactDanger,
        'impactProduction': scenario.impactProduction,
        'impactFinance': scenario.impactFinance,
        'impactReputation': scenario.impactReputation,
        'impactEnvironment': scenario.impactEnvironment,
        'impactRegulation': scenario.impactRegulation,
        'impactData': scenario.impactData,
        'impactSupply': scenario.impactSupply,
        'justifySafety': scenario.justifySafety,
        'justifyLife': scenario.justifyLife,
        'justifyProduction': scenario.justifyProduction,
        'justifyFinancial': scenario.justifyFinancial,
        'justifyReputation': scenario.justifyReputation,
        'justifyEnvironment': scenario.justifyEnvironment,
        'env_contaminant': scenario.env_contaminant,
        'env_ecosystem': scenario.env_ecosystem,
        'env_contamination': scenario.env_contamination,
        'env_population': scenario.env_population,
        'env_wildlife': scenario.env_wildlife,
        'justifyRegulation': scenario.justifyRegulation,
        'justifyData': scenario.justifyData,
        'UEL': scenario.UEL,
        'uel_threat': scenario.uel_threat,
        'uel_vuln': scenario.uel_vuln,
        'uel_exposure': scenario.uel_exposure,
        'RRU': scenario.RRU,
        'SM': scenario.SM,
        'MEL': scenario.MEL,
        'RRM': scenario.RRM,
        'SA': scenario.SA,
        'MELA': scenario.MELA,
        'RRa': scenario.RRa,
        'recommendations': scenario.recommendations,
        'Deleted': scenario.Deleted,
        'timestamp': scenario.timestamp,
        'aro': scenario.aro,
        'sle': scenario.sle,
        'sle_low': scenario.sle_low,
        'sle_high': scenario.sle_high,
        'ale_median': scenario.ale_median,
        'ale_low': scenario.ale_low,
        'ale_high': scenario.ale_high,
        'ale': scenario.ale,
        'countermeasureCosts': scenario.countermeasureCosts,
        'control_recommendations': scenario.control_recommendations,
        'probability': scenario.probability,
        'risk_register': scenario.risk_register,
        'safety_hazard': scenario.safety_hazard,
        'sis_compromise': scenario.sis_compromise,
        'sis_outage': scenario.sis_outage,
        'risk_priority': scenario.risk_priority,
        'risk_status': scenario.risk_status,
        'risk_owner': scenario.risk_owner,
        'risk_response': scenario.risk_response,
        'risk_open_date': scenario.risk_open_date,
        'risk_close_date': scenario.risk_close_date,
        'control_effectiveness': scenario.control_effectiveness,
        'likelihood': scenario.likelihood,
        'frequency': scenario.frequency,
        'sl_a': scenario.sl_a,
        'dangerScope': scenario.dangerScope,
        'prodOutage': scenario.outage,
        'prodOutageDuration': scenario.outageDuration,
        'prodOutageCost': scenario.outageCost,
        'ai_bia_score': scenario.ai_bia_score,
        'exposed_system': scenario.exposed_system,
        'weak_credentials': scenario.weak_credentials,
        'compliance_map': scenario.compliance_map,
        'attack_tree_text': scenario.attack_tree_text,
        'scenario_status': scenario.scenario_status,
        'cost_projection': scenario.cost_projection,
        'user_role': user_role,
        'risk_rationale': scenario.risk_rationale,
        'risk_recommendation': scenario.risk_recommendation,
        'cost_justification': scenario.cost_justification
    }
    # Retrieve the related PHAControlList records
    control_list = []
    for control in scenario.controls.all():
        control_dict = {
            'ID': control.ID,
            'control': control.control,
            'reference': control.reference,
            'score': control.score
        }
        control_list.append(control_dict)

    # Add the control list to the scenario dictionary
    scenario_dict['controls'] = control_list
    has_controls = 1 if len(control_list) > 0 else 0

    # Add has_controls to the scenario_dict
    scenario_dict['has_controls'] = has_controls
    # Retrieve related consequences
    consequences = ScenarioConsequences.objects.filter(scenario=scenario)
    consequences_list = [{'consequence_text': consequence.consequence_text, 'is_validated': consequence.is_validated}
                         for consequence in consequences]
    scenario_dict['Consequences'] = consequences_list
    # Retrieve the related PHA_Safeguard records
    safeguards = PHA_Safeguard.objects.filter(scenario=scenario)
    safeguards_list = [
        {
            'id': safeguard.id,
            'safeguard_description': safeguard.safeguard_description,
            'safeguard_type': safeguard.safeguard_type
        } for safeguard in safeguards
    ]

    # Add the safeguards list to the scenario dictionary
    scenario_dict['safeguards'] = safeguards_list

    observations = PHA_Observations.objects.filter(scenario=scenario)
    observations_list = [
        {
            'id': observation.id,
            'observation_description': observation.observation_description,

        } for observation in observations
    ]

    # Add the safeguards list to the scenario dictionary
    scenario_dict['observations'] = observations_list

    scenario_instance = tblCyberPHAScenario.objects.get(ID=scenario_id)
    write_to_audit(
        user_id=request.user,
        user_action=f'Viewed Scenario',
        user_ip=get_client_ip(request),
        cyberPHAScenario=scenario_instance,
    )

    # Return the scenario as a JSON response
    return JsonResponse(scenario_dict)


# function to calculate overall control effectiveness for a given cyberpha
def calculate_effectiveness(cyberPHA_value):
    # Filter assessments by the given cyberPHA value
    assessments = MitreControlAssessment.objects.filter(cyberPHA=cyberPHA_value)

    # If there are no matching records, return 0
    if not assessments.exists():
        return 0

    # Calculate the numerator (sum of effectiveness_percentage multiplied by weighting)
    numerator = assessments.aggregate(
        total_effectiveness=Sum(F('effectiveness_percentage') * F('weighting'))
    )['total_effectiveness']

    # Calculate the denominator (sum of weighting)
    denominator = assessments.aggregate(total_weighting=Sum('weighting'))['total_weighting']

    # Calculate the weighted average
    if denominator:
        overall_effectiveness = numerator / denominator
    else:
        overall_effectiveness = 0

    return overall_effectiveness


def get_response(user_message):
    openai_model = get_api_key("OpenAI_Model")
    message = [
        {
            "role": "system",
            "content": "You are an expert and experienced process and safety engineer conducting a cybersecurity risk analysis for a cyberPHA (where P=Process, H=Hazards, A=Analysis) scenario related to industrial automation and control systems."
        },
        user_message
    ]

    response = openai.ChatCompletion.create(
        model=openai_model,
        messages=message,
        temperature=0.1,
        max_tokens=2600
    )

    return response['choices'][0]['message']['content']


def compliance_map_data(common_content):
    user_message = {
        "role": "user",
        "content": f"{common_content}. Based on the provided information, please map the current OT security posture to a maximum of 10 of the MOST RELEVANT AND IMPORTANT industry regulatory compliance regulations for this organization in the given country. When naming these regulations, use their official titles as recognized by the issuing bodies or as commonly used in official publications. Separate each item with '||' and use '>' to separate parts within an item. Ensure each item's format is concise and can be easily parsed for display in an HTML table. Example format: <Concise Compliance Concern, maximum 30 words> > <Official Compliance Reference> > <Internet URL>. Output only the line items with NO additional text, header, intro, or narrative. Strive for consistency in the naming of compliance regulations to facilitate accurate parsing and display."
    }

    try:
        response = get_response(user_message)

        return response
    except Exception as e:
        return f"Error: {str(e)}"


def generate_recommendation_prompt(likelihood, adjustedRR, costs, probability, frequency, biaScore, cyberphaID):
    # Attempt to fetch the related CyberPHARiskTolerance record
    try:
        risk_tolerance = CyberPHARiskTolerance.objects.get(cyber_pha_header_id=cyberphaID)
        risk_tolerance_str = f"""
        - Risk Tolerance Levels:
            - Negligible: {risk_tolerance.negligible_low} to {risk_tolerance.negligible_high}
            - Minor: {risk_tolerance.minor_low} to {risk_tolerance.minor_high}
            - Moderate: {risk_tolerance.moderate_low} to {risk_tolerance.moderate_high}
            - Significant: {risk_tolerance.significant_low} to {risk_tolerance.significant_high}
            - Severe: {risk_tolerance.severe_low} to {risk_tolerance.severe_high}
        """
    except ObjectDoesNotExist:
        risk_tolerance_str = "\n        - Risk Tolerance Levels: Not specified"

    prompt = f"""
        Given the cybersecurity risk assessment results for a given OT cybersecurity scenario:
        - Likelihood of occurrence: {likelihood}%
        - Adjusted residual risk: {adjustedRR}
        - Estimated costs (low|medium|high): {costs}
        - Probability of a targeted attack being successful: {probability}%
        - Annual loss event frequency (as defined by FAIR): {frequency}
        - Business impact score: {biaScore}{risk_tolerance_str}

        Provide a response structured exactly as follows:

        1. Recommendation: [Insert recommendation here based on the assessment results. For example, Mitigate Risk, Accept Risk, Manage Risk, or another recommendation depending on results]
        2. Rationale: [Insert a concise, executive-level rationale here. Consider the likelihood of occurrence (values under 10 should be considered negligible), adjusted residual risk, business impact score, estimated costs, annual threat event frequency, probability of a targeted attack being successful, and risk tolerance levels. Structure your rationale in clear, bullet-pointed explanations.]
        """
    return prompt


def get_openai_recommendation(prompt):
    openai.api_key = get_api_key("openai")  # Ensure this retrieves your OpenAI API key correctly
    model = get_api_key("OpenAI_Model")

    messages = [
        {"role": "system",
         "content": "You are an expert in OT cybersecurity risk assessment. Provide a recommendation based on the analysis."},
        {"role": "user", "content": prompt}
    ]

    response = openai.ChatCompletion.create(
        model=model,
        messages=messages,
        temperature=0.2,
        max_tokens=600
    )

    if response.choices and len(response.choices) > 0:
        # Assuming the response follows the structured format: "1. Recommendation: ... 2. Rationale: ..."
        text = response.choices[0].message['content'].strip()
        text = text.replace("**", "")
        # Splitting the response into Recommendation and Rationale parts
        parts = text.split("2. Rationale:")
        recommendation = parts[0].replace("1. Recommendation:", "").strip()
        rationale = parts[1].strip() if len(parts) > 1 else ""

        # Structuring the response for JSON
        structured_response = {
            "Recommendation": recommendation,
            "Rationale": rationale
        }

    else:
        structured_response = {"Recommendation": "No recommendation could be generated.", "Rationale": ""}

    return structured_response


@login_required
def scenario_analysis(request):
    # Log the user activity
    user_profile = UserProfile.objects.get(user=request.user)

    # Check if the user has exceeded the maximum scenario analysis count
    if user_profile.current_scenario_count >= user_profile.max_scenario_count:
        return JsonResponse({
            'error': 'User has reached the maximum number of scenario assessments'
        }, status=403)  # 403 Forbidden or another appropriate status code

    if request.method == 'GET':
        industry = request.GET.get('industry')
        facility_type = request.GET.get('facility_type')
        scenario = request.GET.get('scenario')
        threatSource = request.GET.get('threatsource')
        safetyimpact = request.GET.get('safety')
        safety_hazard = request.GET.get('safety_hazard')
        lifeimpact = request.GET.get('life')
        productionimpact = request.GET.get('production')
        production_outage = request.GET.get('production_outage')
        production_outage_length = request.GET.get('production_outage_length')
        reputationimpact = request.GET.get('reputation')
        environmentimpact = request.GET.get('environment')
        regulatoryimpact = request.GET.get('regulatory')
        dataimpact = request.GET.get('data')
        supplyimpact = request.GET.get('supply')
        severitymitigated = request.GET.get('sm')
        mitigatedexposure = request.GET.get('mel')
        residualrisk = request.GET.get('rrm')
        country = request.GET.get('country')
        uel = request.GET.get('uel')
        financial = request.GET.get('financial')
        cyberPHAID = request.GET.get('cpha')
        exposed_system = request.GET.get('exposed_system')
        weak_credentials = request.GET.get('weak_credentials')
        # Retrieve the string of validated consequences
        validated_consequences_str = request.GET.get('validated_consequences', '')
        physical_safeguards_str = request.GET.get('physical_safeguards', '')
        observations = request.GET.get('observations')
        force_resubmit = request.GET.get('force_resubmit', 'false').lower() == 'true'
        safetyJustification = request.GET.get('safetyJustification')
        supplychainJustification = request.GET.get('supplychainJustification')
        environmentJustification = request.GET.get('environmentJustification')
        dangerJustification = request.GET.get('dangerJustification')

        # Concatenate all GET parameters to form a string
        values_str = '|'.join([request.GET.get(param, '') for param in request.GET])
        # Generate SHA-256 hash
        hash_value = hashlib.sha256(values_str.encode()).hexdigest()

        # Attempt to find a matching record
        existing_record = UserScenarioHash.objects.filter(
            user=request.user,
            cyberphaID=request.GET.get('cpha', 0),
            hash_value=hash_value
        ).exists()

        if existing_record and not force_resubmit:
            # If a matching record is found, inform the user and exit
            return JsonResponse({'message': 'Scenario parameters have not changed.'}, status=200)

        if not existing_record:
            UserScenarioHash.objects.create(
                user=request.user,
                cyberphaID=request.GET.get('cpha', ''),
                hash_value=hash_value
            )
        # Split the string into a list, using semicolon as the separator
        validated_consequences_list = validated_consequences_str.split(';')

        cyber_pha_header = tblCyberPHAHeader.objects.get(ID=cyberPHAID)

        has_incident_response_plan = cyber_pha_header.has_incident_response_plan
        plan_last_tested_date = cyber_pha_header.plan_last_tested_date
        plan_never_tested = cyber_pha_header.plan_never_tested

        # Convert plan_last_tested_date to string format if it's not None
        plan_last_tested_date_str = plan_last_tested_date.strftime('%Y-%m-%d') if plan_last_tested_date else None

        ####### Audit Write ########
        write_to_audit(
            request.user,
            f'Executed a scenario analysis for {cyber_pha_header.title} and scenario: {scenario}',
            get_client_ip(request)
        )
        ###########################

        # Get the assessment id from the tblCyberPHAHeader instance
        assessment_id = cyber_pha_header.assessment
        last_assessment_score = cyber_pha_header.last_assessment_score
        last_assessment_summary = cyber_pha_header.last_assessment_summary

        investments = CyberSecurityInvestment.objects.filter(cyber_pha_header=cyber_pha_header).values(
            'investment_type', 'vendor_name', 'product_name', 'cost', 'date'
        )

        if investments.exists():
            # Generate the text statement for investments
            investment_statement = "OT Cybersecurity Investments listed here:\n"
            for idx, investment in enumerate(investments, start=1):
                investment_date = investment['date'].strftime('%Y-%m-%d') if investment['date'] else 'N/A'
                investment_statement += f"{idx}: Investment Type: {investment['investment_type']}, Vendor: {investment['vendor_name']}, Product: {investment['product_name']}, Cost: {investment['cost']}, Investment date: {investment_date}.\n"
        else:
            # Return an empty string if there are no investment records
            investment_statement = ""

        employees_on_site = cyber_pha_header.EmployeesOnSite
        # get the compliance summary for the cyberpha
        compliance = cyber_pha_header.complianceSummary
        net_profit_margin = cyber_pha_header.npm
        cost_op_hour = cyber_pha_header.coho
        annual_revenue = cyber_pha_header.annual_revenue

        openai.api_key = get_api_key('openai')
        # Define the common part of the user message
        common_content = f"""
        
        Act as both an Insurance Actuary and an OT Cybersecurity HAZOPS Risk Expert. You're tasked with analyzing a specific scenario for a facility in the industry sector, located in a particular country. Your analysis should cover various risk outcomes based on the detailed context provided.

        Scenario Details:

        Facility Type & Industry: A facility in the {industry} industry, located in {country}.
        Scenario Overview: {scenario}.
        Critical System Exposures:
        Internet Exposure: Systems with public IP addresses: {exposed_system}.
        Credential Security: Systems with weak/default credentials: {weak_credentials}.
        OT Cybersecurity Incident Response:
        Presence of an Incident Response Plan: {has_incident_response_plan}.
        Last Tested Date: {plan_last_tested_date_str}.
        Estimated Business Impact Scores:
        Safety: {safetyimpact}, Life Danger: {lifeimpact}
        Production: {productionimpact}, Production Outage: {production_outage} (Duration: {production_outage_length} hours)
        Reputation: {reputationimpact}, Environmental: {environmentimpact}
        Regulatory Compliance: {regulatoryimpact}, Supply Chain: {supplyimpact}
        Data & Intellectual Property: {dataimpact}
        Estimated Current OT Cybersecurity Controls:
         OT Cybersecurity Control Effectiveness score: {last_assessment_score}/100.  OT Cybersecurity Control Effectiveness Summary: {last_assessment_summary}.
        Mitigated Severity: {severitymitigated}/10, Risk Exposure: {mitigatedexposure}/10, Residual Risk: {residualrisk}/10
        Estimated Unmitigated likelihood of all identified threats and vulnerabilities: {uel}/10
        Physical Security:
        Physical Safeguards: {physical_safeguards_str} (Assumed effective)
        Vulnerability Observations: {observations}
        Investment Statement: {investment_statement}
        Additional Information if given:
        Explanation of safety score: {safetyJustification}
        Explanation of supply chain score: {supplychainJustification}
        Explanation of environmental score: {environmentJustification}
        Explanation of life danger score: {dangerJustification}
        """

        # Define the refined user messages
        user_messages = [

            {
                "role": "user",
                "content": f" {common_content} .Task: Given the scenario described and publicly reported cybersecurity incidents over the time scale from 5 years ago to the current day , estimate the likelihood (as a whole number percentage) of the given scenario occurring against a {facility_type} in {country}. Answer with a whole number. Do NOT include any other words, sentences, or explanations."
            },
            {
                "role": "user",
                "content": f"{common_content}. The FAIR (Factor Analysis of Information Risk) methodology, which is used to quantify and manage risk, defines residual risk as the amount of risk that remains after controls are applied. Task: Given the scenario described and publicly reported cybersecurity incidents over the time scale from 5 years ago to the current day, assess the cybersecurity residual risk after all recommended controls and physical security controls have been implemented and are assumed to be at least 75% effective. Give an estimated residual risk rating based on the FAIR methodology from the following options: Very Low, Low, Low/Medium, Medium, Medium/High, High, Very High.  Provide ONLY one of the given risk ratings without any additional text or explanations."
            },

            {
                "role": "user",
                "content": f"{common_content}.  Consequences of the scenario are assumed to be as follows: {validated_consequences_list}. TASK: Read and comply with all instructions that follow. Provide an estimate of the DIRECT COSTS of a single loss event (SLE) in US dollars. Provide three cost estimates: best case, worst case, and most likely case. Output these estimates as integers in the specific format: 'low|medium|high', where '|' is the delimiter. Ensure that your estimates are realistic, taking into account recent (no older than 3 years) industry reports about the cost of cybersecurity incidents, and tailored to the scenario, focusing solely on relevant Direct costs such as incident response, remediation, legal fees, notification costs, regulatory fines, compensations, and increased insurance premiums. The financial impact for this scenario is estimated as {financial}/10 in the business impact analysis. (IMPORTANT take into account the  OT Cybersecurity investments that have been made). IMPORTANT: Respond with only three positive integers, representing the low, medium, and high estimates, in the exact order and format specified: 'low|medium|high'. Do not include any additional text, explanations, or commentary."
            },

            {
                "role": "user",
                "content": f"""
                {common_content}
                TASK: Assess the likelihood of a successful targeted attack on the specified facility, given the described scenario and cybersecurity investments. Consider the effectiveness of implemented controls and any vulnerabilities due to the facility's internet exposure or weak/default credentials.
                Provide ONLY the estimated probability of such an attack being successful, expressed as a whole number percentage (e.g., 25%). Do NOT include any additional text, explanations, or commentary.
                """
            },
            # {
            #    "role": "user",
            #    "content": f"{common_content}. Provide an estimate of the annual Threat Event Frequency (TEF) as defined by the Open FAIR Body of Knowledge. TEF is the probable frequency, within a given timeframe, that a threat agent will act against an asset. It reflects the number of attempts by a threat actor to cause harm, regardless of whether these attempts are successful. Your response should reflect an integer or a decimal value representing the estimated number of times per year such a threat event is expected to occur. IMPORTANT: Respond only with the frequency value as an integer or a decimal, without including any additional words, sentences, or explanations. This value should strictly represent the estimated annual occurrence rate of the threat event as per the given scenario."
            #
            # },
            {
                "role": "user",
                "content": f"{common_content}. Provide an estimate of the annual Loss Event Frequency (LEF) as defined by the Open FAIR Body of Knowledge. LOSS Event Frequency is defined by the technical Open FAIR Body of Knowledge as: The probable frequency, within a given timeframe, that a threat agent will SUCCESSFULLY act against an asset. Your response should reflect an integer or a decimal value representing the estimated number of times per year such a threat event is expected to occur. IMPORTANT: Respond only with the frequency value as an integer or a decimal, without including any additional words, sentences, or explanations. This value should strictly represent the estimated annual occurrence rate of the threat event as per the given scenario."

            },
            {
                "role": "user",
                "content": f"{common_content}. TASK: Hypothesize the business impact score from 0 to 100 in the event of a successful attack resulting in the given scenario. Consequences of the scenario are given as follows: {validated_consequences_list}. A score of 1 would mean minimal business impact while a score of 100 would indicate catastrophic business impact without the ability to continue operations. Your answer should be given as an integer. Do NOT include any other words, sentences, or explanations."
            },

            {
                "role": "user",
                "content": f"I am a CISO at a {industry} company with approximately {employees_on_site} employees, operating primarily in {country}. We are assessing our cybersecurity posture and need to estimate the potential costs associated with a {scenario} that has consequences of {validated_consequences_list}."
                           "Your Task: Given the scenario, please provide an estimate of the direct and indirect costs we might incur, including but not limited to:"
                           "1. Immediate Response Costs: Costs associated with the initial response to the incident, such as emergency IT support, forensic analysis, and legal consultations."
                           "2. Remediation Costs: Expenses related to remediating the cybersecurity breach, including software updates, hardware replacements, and strengthening of security measures."
                           "3. Regulatory and Compliance Costs: Potential fines and penalties for non-compliance with relevant data protection and privacy regulations, as well as costs associated with compliance audits and reporting requirements post-incident."
                           "4. Reputation and Brand Impact: Estimated impact on our brand and customer trust, potentially leading to loss of business and decreased revenue."
                           "5. Operational Disruption: Costs associated with operational disruptions or downtime, including loss of productivity and impact on service delivery."
                           "6. Legal and Settlement Costs: Expenses related to legal actions taken against the company and any settlements or compensations paid out to affected parties."
                           "7. Long-term Costs: Any long-term costs such as increased insurance premiums, ongoing monitoring and security measures, and potential loss of intellectual property."
                           "INDUSTRY DATA AND ANALYTICS: Please consider the specifics of our industry, size, and the nature of the assets involved in this scenario to provide a comprehensive cost estimate. Please reference industry-specific data from the latest research and findings relating to the cost of a cybersecurity incident and data breach from Gartner, McKinsey, Dragos, Ponemon Institute, Verizon DBIR, Palo Alto Networks."
                           "OUTPUT INSTRUCTION: First, provide a 12-month direct cost projection for the scenario in the format: COST PROJECTION: Month1value|Month2value|...|Month12value. Each value must be an integer to represent a dollar value wth no other text or narrative included and should reflect a realistic, pragmatic monthly estimate. Then, provide a concise and conservative executive-level explanation summary, in 150 words or less, specific to the given scenario as JUSTIFICATION: <Your justification here>. Ensure the cost projection and justification are clearly separated by these keywords."
            },

            {
                "role": "user",
                "content": f"""{common_content}
                            
                            Based only on the provided scenario and facility details, generate a concise numbered bullet point list of OT/ICS cybersecurity risk mitigation recommendations. Each recommendation should be directly aligned with the latest versions of NIST 800-82 and the NIST CSF. Include the relevant NIST reference in brackets at the end of each recommendation. Include in brackets an estimation of the amount of risk reduction associated with the recommendation as a whole number integer percentage. The output should strictly adhere to the following format:
                            
                            Example Format:
                            1. Example recommendation related to OT cybersecurity. (<estimation of risk reduction %>) [NIST Reference] 
                            2. Another example recommendation focused on OT cybersecurity risk mitigation. (<estimation of risk reduction %>) [NIST Reference] 
                            
                            Following this example format, provide the recommendations in order of priority, specific to the given scenario without any additional narrative, description, advice, or guidance. The recommendations should be clear and easily parsable within an HTML page.
                            """

            },
            {
                "role": "user",
                "content": f"{common_content}. ISA-62443-3-2 describes five Security Levels SL-1, SL-2, SL-3, SL-4, SL-5. As an OT Cybersecurity risk analyst, assess which security level has been achieved and format your response as follows: 'Security Level: [SL Value], Justification: [Concise Justification, no more than 20 words].'"
            }
        ]

        def get_response_safe(user_message):
            try:
                return get_response(user_message)
            except Exception as e:
                return f"Error: {str(e)}"

        # Initialize an empty list to store the responses
        responses = []

        # Use ThreadPoolExecutor to parallelize the first five API calls
        with concurrent.futures.ThreadPoolExecutor() as executor:
            # Submit all the tasks and get a list of futures
            futures = [executor.submit(get_response, msg) for msg in user_messages]
            # Collect the results in the order the futures were submitted
            responses = [future.result() for future in futures]


        # Now handle the compliance mapping separately
        compliance_data = compliance_map_data(common_content)
        responses.append(compliance_data)

        recommendation_prompt = generate_recommendation_prompt(
            likelihood=responses[0],
            adjustedRR=responses[1],
            costs=responses[2],
            probability=responses[3],
            frequency=responses[4],
            biaScore=responses[5],
            cyberphaID=cyberPHAID
        )

        # Get the recommendation from OpenAI
        rationale = get_openai_recommendation(recommendation_prompt)

        user_profile.current_scenario_count += 1
        user_profile.save()
        cost_projection_with_justification = responses[6]

        # Splitting the response to separate the cost projection and the justification
        cost_projection_parts = cost_projection_with_justification.split("COST PROJECTION: ")
        justification_parts = cost_projection_parts[1].split("JUSTIFICATION: ") if len(cost_projection_parts) > 1 else [
            "", "Justification not provided."]

        cost_projection = justification_parts[0].strip()
        cost_projection_justification = justification_parts[1].strip() if len(
            justification_parts) > 1 else "Justification not provided."

        # Return the responses as variables
        return JsonResponse({
            'likelihood': responses[0],
            'adjustedRR': responses[1],
            'costs': responses[2],
            'probability': responses[3],
            'frequency': responses[4],
            'biaScore': responses[5],
            'projection': cost_projection,
            'cost_projection_justification': cost_projection_justification,
            'control_effectiveness': last_assessment_score,
            'recommendations': responses[7],
            'select_level': responses[8],
            'scenario_compliance_data': responses[9],
            'rationale': rationale
        })


def prepare_controls_summary():
    controls = SecurityControls.objects.filter(framework='ISA 62443-2-1')
    summary = ""
    for control in controls:
        summary += f"Control: {control.Control}"
    return summary


def get_recommended_controls(scenario, threat_source):
    # Prepare the summary of controls
    controls_summary = prepare_controls_summary()

    # Construct the prompt for OpenAI
    prompt = f"Given these controls from the ISA 62443-2-1 standard:\n{controls_summary}\nWhat are the top 5 controls that would be most applicable for a scenario involving '{scenario}' with a threat source of '{threat_source}'? "

    # Make a call to OpenAI API
    try:
        response = openai.Completion.create(
            engine="text-davinci-002",  # Or the appropriate engine you are using
            prompt=prompt,
            max_tokens=250,  # Adjust as needed
            temperature=0.7  # Adjust for creativity level
        )
        return response.choices[0].text.strip()
    except Exception as e:
        # Handle exceptions (e.g., API errors)

        return None


def parse_recommendations(recommendations_str):
    # Regular expression to match the format
    pattern = re.compile(r'(\d+)\.\s(.*?)(\([^)]+\))')  # This regex captures any content within brackets

    matches = pattern.findall(recommendations_str)

    # Convert matches to a list of dictionaries
    parsed_data = [{
        'line_number': int(match[0]),
        'control_text': match[1].strip(),
        'reference': match[2]
    } for match in matches]

    return parsed_data


def scenario_vulnerability(request, scenario_id):
    try:
        scenario = tblCyberPHAScenario.objects.get(pk=scenario_id)
        vulnerabilities = vulnerability_analysis.objects.filter(scenario=scenario)
        asset_types = tblAssetType.objects.all()  # Fetch asset types

        if request.method == 'POST':
            form = VulnerabilityAnalysisForm(request.POST)
            if form.is_valid():
                form.save()
                # Redirect to the 'scenario_vulnerability' view with the scenario_id
                return redirect('OTRisk:scenario_vulnerability', scenario_id=scenario_id)
        else:
            form = VulnerabilityAnalysisForm()

        return render(request, 'OTRisk/vulnerability_table.html', {
            'scenario': scenario,
            'vulnerabilities': vulnerabilities,
            'form': form,
            'scenario_id_value': scenario_id,
            'asset_types': asset_types
        })
    except tblCyberPHAScenario.DoesNotExist:
        # Handle the scenario not found error, e.g., return a 404 page
        return render(request, 'no_vulnerabilities.html')


def add_vulnerability(request, scenario_id):
    scenario = get_object_or_404(tblCyberPHAScenario, pk=scenario_id)
    action = request.POST.get('action')
    if request.method == 'POST':
        if action == 'save':  # Check if Save button was clicked
            description = request.POST.get('description')
            asset_type_id = request.POST.get('asset_type')
            asset_name = request.POST.get('asset_name')
            cve = request.POST.get('cve')
            cve_detail = request.POST.get('cve_detail')

            # Create a new vulnerability instance and save it
            vulnerability = vulnerability_analysis(
                description=description,
                asset_name=asset_name,
                asset_type_id=asset_type_id,
                cve=cve,
                scenario=scenario,
                cve_detail=cve_detail
            )
            vulnerability.save()

        elif action == 'edit':  # Check if Update button was clicked
            vulnerability_id = request.POST.get('vulnerability_id')
            description = request.POST.get('description')
            asset_type_id = request.POST.get('asset_type')
            asset_name = request.POST.get('asset_name')
            cve = request.POST.get('cve')
            cve_detail = request.POST.get('cve_detail')

            # Get the existing vulnerability instance
            vulnerability = get_object_or_404(vulnerability_analysis, pk=vulnerability_id)

            # Update the fields and save
            vulnerability.description = description
            vulnerability.asset_type_id = asset_type_id
            vulnerability.asset_name = asset_name
            vulnerability.cve = cve
            vulnerability.cve_detail = cve_detail
            vulnerability.save()

    return redirect('OTRisk:scenario_vulnerability', scenario_id=scenario_id)


def get_asset_types(request):
    asset_types = tblAssetType.objects.all()
    asset_type_list = [{'id': asset_type.id, 'AssetType': asset_type.AssetType} for asset_type in asset_types]
    return JsonResponse({'asset_types': asset_type_list})


def generate_ppt(request):
    if request.method == "POST":

        # Extract data from POST parameters
        safety = request.POST.get('txtSafetySummary', '')
        chemical = request.POST.get('txtChemical', '')
        physical = request.POST.get('txtPhysical', '')
        other = request.POST.get('txtOther', '')
        compliance = request.POST.get('txtCompliance', '')
        facility = request.POST.get('FacilityName', '')
        threatSummary = request.POST.get('threatSummary', '')
        insightSummary = request.POST.get('insightSummary', '')
        strategySummary = request.POST.get('strategySummary', '')

        # Create a new PowerPoint presentation
        prs = Presentation()

        # For each section, add a slide and set its title and content
        sections = [
            (f"{facility} Safety Profile", safety),
            (f"{facility} Chemical Profile", chemical),
            (f"{facility} Physical Security Profile", physical),
            (f"{facility} OT Asset Profile", other),
            (f"{facility} Compliance Profile", compliance),
            (f"{facility} Threat Summary", threatSummary),
            (f"{facility} Security Insights", insightSummary),
            (f"{facility} Suggested Strategy", strategySummary)
        ]

        for title, content in sections:
            slide_layout = prs.slide_layouts[1]  # Using a title and content layout
            slide = prs.slides.add_slide(slide_layout)
            title_shape = slide.shapes.title
            content_shape = slide.placeholders[1]  # Using the primary content placeholder

            title_shape.text = title
            title_shape.text_frame.paragraphs[0].font.name = 'Arial'
            title_shape.text_frame.paragraphs[0].font.size = Pt(18)

            content_shape.text = content
            for paragraph in content_shape.text_frame.paragraphs:
                paragraph.font.name = 'Arial'
                paragraph.font.size = Pt(10)

        # Save to a temporary file
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pptx') as temp_file:
            prs.save(temp_file.name)
            temp_path = temp_file.name

        # Return a response to provide the file for download
        response = FileResponse(open(temp_path, 'rb'),
                                content_type='application/vnd.openxmlformats-officedocument.presentationml.presentation')
        response['Content-Disposition'] = 'attachment; filename=report.pptx'

        # Remove the temporary file after sending it to the client
        os.remove(temp_path)
        filename = f"report_{uuid.uuid4()}.pptx"

        filepath = os.path.join(os.path.join(BASE_DIR, 'static'), filename)

        prs.save(filepath)
        download_url = urljoin(settings.STATIC_URL, filename)

        return JsonResponse({
            'status': 'success',
            'download_url': download_url
        })

    else:
        return JsonResponse({
            'status': 'error',
            'error': 'Invalid request method'
        })


def reformat_attack_tree(data):
    # Recursive function to adjust the format
    def adjust_node_format(node):
        new_node = {'name': node['Node']}
        if 'Children' in node and node['Children']:
            new_node['children'] = [adjust_node_format(child) for child in node['Children']]
        return new_node

    formatted_tree = {'name': data['Attack'], 'children': []}
    for node in data['Nodes']:
        formatted_tree['children'].append(adjust_node_format(node))

    return formatted_tree


@login_required
def analyze_scenario(request):
    openai_api_key = get_api_key('openai')
    openai.api_key = openai_api_key

    if request.method == 'POST':
        scenario = request.POST.get('scenario')
        attack_tree_drawn = request.POST.get('attackTreeDrawn') == 'true'
        attacker = request.POST.get('attacker')
        riskCategory = request.POST.get('riskCategory')
        attack_vector = request.POST.get('attack_vector')
        exposed_system = request.POST.get('exposed_system')
        weak_credentials = request.POST.get('weak_credentials')

        # Fetch the organization_id from the user's profile
        try:
            user_profile = UserProfile.objects.get(user=request.user)
            organization_id = user_profile.organization.id
        except UserProfile.DoesNotExist:
            organization_id = None  # Or handle the lack of a profile as you see fit

        # Create a record in user_scenario_audit
        user_scenario_audit.objects.create(
            scenario_text=scenario,
            user=request.user,
            organization_id=organization_id,
            ip_address=get_client_ip(request),
            session_id=request.session.session_key
        )
        # validate the scenario doesn't contain vulgar terms using the OpenAPI moderator
        if is_inappropriate(scenario):
            consequence_text = 'Scenario contains inappropriate terms'
            return JsonResponse({'consequence_text': consequence_text}, status=400)

        validation_prompt = f"""
        Evaluate if the following text represents a coherent and plausible cybersecurity scenario, or OT incident scenario, or industrial incident scenario: '{scenario}'. Respond yes if valid, no if invalid.
        """

        validation_response = openai.ChatCompletion.create(
            model="gpt-4",
            messages=[
                {"role": "system", "content": validation_prompt}
            ],
            max_tokens=50,
            temperature=0.7
        )

        if "yes" in validation_response['choices'][0]['message']['content'].lower():

            pha_id = request.POST.get('phaID')

            try:
                cyber_pha = tblCyberPHAHeader.objects.get(ID=pha_id)
            except tblCyberPHAHeader.DoesNotExist:
                return JsonResponse({'error': 'PHA record not found'}, status=404)

            facility_type = cyber_pha.FacilityType
            industry = cyber_pha.Industry
            zone = cyber_pha.AssessmentZone
            unit = cyber_pha.AssessmentUnit
            address = cyber_pha.facilityAddress
            country = cyber_pha.country
            devices = cyber_pha.otherSummary

            # Construct a prompt for GPT-4
            system_message = f"""
            TASK: Analyze and consider the following scenario as part of an OT/ICS focused Cyber HAZOPS/Layer of Protection Analysis (LOPA) assessment: {scenario} which occurs at a {facility_type} in the {industry} industry, located at {address} in {country}, specifically in the {zone} zone and the {unit} unit. 
            The attacker is assumed to be: {attacker}. The attack vector is assumed to be {attack_vector}. The risk category is assumed to be {riskCategory}. Vulnerable systems with Internet exposed IP address {exposed_system}. Vulnerable systems with default or weak credentials {weak_credentials}.
            Considering the likely presence of these OT devices: {devices}, concisely describe in 50 words in a list format (separated by semicolons) of a maximum of 5 of the most likely direct consequences of the given scenario. 
            The direct consequences should be specific to the facility and the mentioned details. 
            Assume the role of an expert OT Cybersecurity risk advisor. 
            Additional instruction: output ONLY the list items with no text either before or after the list items.
            """
            user_message = scenario

            # Query OpenAI API
            response = openai.ChatCompletion.create(
                model="gpt-4-0125-preview",
                messages=[
                    {"role": "system", "content": system_message},
                    {"role": "user", "content": user_message}
                ],
                max_tokens=100,
                temperature=0.1
            )

            # Extract and process the text from the response
            consequence_text = response['choices'][0]['message']['content']
            consequence_list = consequence_text.split(';')  # Splitting based on the chosen delimiter

            attack_tree_json = {}

            if not attack_tree_drawn:
                attack_tree_system_message = """
                  Generate a hierarchical structure of a probable attack tree, based on the MITRE ATT@CK framework for Industrial Control Systems (ICS) applied to and specific to the given OT cybersecurity scenario, in a strictly valid JSON format. 
                  Incorporate relevant terminology from ISA 62443-3-2 if applicable. 
                  The structure should use 'name' for node labels and 'children' for nested nodes, where each node represents a step or method in the attack. 
                  The attack tree must have at least two main branches, each potentially containing dozens of branches or sub-branches. 
                  CRITICAL INSTRUCTION: Ensure the output is in JSON format WITH NO additional characters outside of the JSON structure. The JSON structure should be formatted as: {'name': 'Node Name', 'children': [{...}]}.

                  Example of a correctly formatted output:
                  {
                    "name": "Attack Root",
                    "children": [
                      {
                        "name": "Branch 1",
                        "children": [
                          {
                            "name": "Sub-branch 1.1",
                            "children": []
                          },
                          {
                            "name": "Sub-branch 1.2",
                            "children": []
                          }
                        ]
                      },
                      {
                        "name": "Branch 2",
                        "children": [
                          {
                            "name": "Sub-branch 2.1",
                            "children": []
                          },
                          {
                            "name": "Sub-branch 2.2",
                            "children": []
                          }
                        ]
                      }
                    ]
                  }

                  Please generate a similar structure for the provided cybersecurity scenario, adhering STRICTLY to the JSON format and ensuring at least two main branches are present.
                  """

                # Query OpenAI API for the attack tree
                attack_tree_response = openai.ChatCompletion.create(
                    model="gpt-4-0125-preview",
                    messages=[
                        {"role": "system", "content": attack_tree_system_message},
                        {"role": "user", "content": user_message}
                    ],
                    max_tokens=1600,
                    temperature=0.3
                )

                # Process the response for attack tree
                attack_tree_raw = attack_tree_response['choices'][0]['message']['content']
                attack_tree_raw = attack_tree_raw.strip()

                match = re.search(r'\{.*\}', attack_tree_raw, re.DOTALL)
                if match:
                    cleaned_json_str = match.group(0)
                else:
                    cleaned_json_str = "{}"  # Fallback to empty JSON object if no match

                    # Parse the raw JSON string into a Python dictionary
                attack_tree_json = json.loads(cleaned_json_str)
            return JsonResponse({'consequence': consequence_list, 'attack_tree': attack_tree_json})


    else:
        return JsonResponse({'consequence': [], 'attack_tree': {}, 'error': 'Not a valid scenario'}, status=400)

    return JsonResponse({'error': 'Invalid request'}, status=400)


def generate_attack_tree(user_message):
    attack_tree_system_message = f"""
        Generate a hierarchical structure of a potential attack tree for the given cybersecurity scenario in a machine-readable JSON format. The structure should use 'name' for node labels and 'children' for nested nodes. Each node should represent a step or method in the attack, formatted as: {{'name': 'Node Name', 'children': [{{...}}]}}. EXTRA INSTRUCTION: Output MUST be in JSON format with no additional characters outside of the JSON structure.
    """

    # Query OpenAI API for the attack tree
    attack_tree_response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": attack_tree_system_message},
            {"role": "user", "content": user_message}
        ],
        max_tokens=800,
        temperature=0.3
    )

    # Process the response for attack tree
    attack_tree_raw = attack_tree_response['choices'][0]['message']['content']

    try:
        # Parse the raw JSON string into a Python dictionary
        return json.loads(attack_tree_raw)
    except json.JSONDecodeError:
        return {"error": "Invalid JSON format from AI response"}


def is_inappropriate(text):
    openai_api_key = get_api_key('openai')
    openai.api_key = openai_api_key

    try:
        response = openai.Moderation.create(
            input=text,
            model="text-moderation-latest"
        )
        # Check the 'flagged' field in the results
        return any(result['flagged'] for result in response['results'])
    except Exception as e:
        return False  # or handle error appropriately


def write_to_audit(user_id, user_action, user_ip, cyberPHAID=None, cyberPHAScenario=None, qraw=None):
    try:
        user_profile = UserProfile.objects.get(user=user_id)

        audit_log = auditlog(
            user=user_id,
            timestamp=timezone.now(),
            user_action=user_action,
            user_ipaddress=user_ip,
            user_profile=user_profile,
            cyberPHAID=cyberPHAID,
            cyberPHAScenario=cyberPHAScenario,
            qraw=qraw
        )
        audit_log.save()
    except UserProfile.DoesNotExist:
        # Handle the case where UserProfile does not exist for the user
        pass


@csrf_exempt
@require_POST
def assign_cyberpha_to_group(request):
    cyberpha_id = request.POST.get('cyberpha_id')
    existing_group_id = request.POST.get('existing_group_id')
    new_group_name = request.POST.get('new_group_name')
    new_group_type = request.POST.get('new_group_type')
    org_id = get_user_organization_id(request)

    try:
        cyberpha = tblCyberPHAHeader.objects.get(pk=cyberpha_id)

        if existing_group_id:

            group = CyberPHA_Group.objects.get(pk=existing_group_id)
            # Check if the group is already assigned
            if group not in cyberpha.groups.all():
                cyberpha.groups.add(group)
            else:
                return JsonResponse({'status': 'error', 'message': 'CyberPHA is already assigned to this group.'})

            write_to_audit(
                user_id=request.user.id,
                user_ip=get_client_ip(request),
                user_action=f'Add CyberPHA to group: {new_group_name}/{new_group_type}',
                cyberPHAID=cyberpha
            )

        elif new_group_name and new_group_type:
            # Check if group with the same name and type already exists
            organization_instance = Organization.objects.get(id=org_id)
            group, created = CyberPHA_Group.objects.get_or_create(name=new_group_name, group_type=new_group_type,
                                                                  organization=organization_instance)
            if not created:
                return JsonResponse({'status': 'error', 'message': 'Group with this name and type already exists.'})
            cyberpha.groups.add(group)

            write_to_audit(
                user_id=request.user.id,
                user_ip=get_client_ip(request),
                user_action=f'Add CyberPHA to group: {new_group_name}/{new_group_type}',
                cyberPHAID=cyberpha
            )

        return JsonResponse({'status': 'success'})
    except Exception as e:
        return JsonResponse({'status': 'error', 'message': str(e)})


@login_required
def fetch_groups(request):
    # Assuming UserProfile contains the organization_id linked to the user
    try:
        user_profile = UserProfile.objects.get(user=request.user)
        organization_id = user_profile.organization_id
    except UserProfile.DoesNotExist:
        # Handle case where user profile or organization is not found
        return JsonResponse({'error': 'User profile or organization not found'}, status=404)

    # Fetch user IDs for the given organization ID
    organization_users = get_organization_users(organization_id)

    cyberpha_id = request.GET.get('cyberpha_id')
    try:
        cyberpha = tblCyberPHAHeader.objects.get(pk=cyberpha_id, UserID__in=organization_users)
    except tblCyberPHAHeader.DoesNotExist:
        # Handle case where tblCyberPHAHeader does not exist or does not belong to the organization
        return JsonResponse({'error': 'CyberPHA not found or does not belong to the organization'}, status=404)

    # Fetch groups associated with this tblCyberPHAHeader that belong to the organization
    groups = cyberpha.groups.all()

    group_data = [{'name': group.name, 'id': group.id} for group in groups]
    return JsonResponse({'groups': group_data})


@login_required
def fetch_all_groups(request):
    # Assuming UserProfile links users to organizations and contains a reference to the user model
    try:
        user_profile = UserProfile.objects.get(user=request.user)
        organization_id = user_profile.organization_id
    except UserProfile.DoesNotExist:
        # Handle case where user profile or organization is not found
        return JsonResponse({'error': 'User profile or organization not found'}, status=404)

    # Assuming tblCyberPHAHeader.UserID is meant to store user ID, but actually stores organization ID
    # and there's a way to map users to their organization IDs correctly in your application
    # This fetches tblCyberPHAHeader records belonging to the user's organization
    # Note: This approach needs adjustment if UserID does not directly relate to organization_id
    organization_user_ids = UserProfile.objects.filter(organization_id=organization_id).values_list('user_id',
                                                                                                    flat=True)
    cyberphas = tblCyberPHAHeader.objects.filter(UserID__in=organization_user_ids).distinct()

    # Fetch groups associated with these tblCyberPHAHeader records
    groups = CyberPHA_Group.objects.filter(tblcyberphaheader__in=cyberphas).distinct()

    group_data = [{'name': group.name, 'id': group.id} for group in groups]
    return JsonResponse({'groups': group_data})


def retrieve_scenario_builder(request, scenario_id):
    try:
        # Retrieve the scenario from the database
        scenario = ScenarioBuilder.objects.get(id=scenario_id)

        # Parse the stored JSON data
        scenario_data = json.loads(scenario.scenario_data)

        # Extract elements from the scenario data
        attack_tree_data = scenario_data.get('attackTree')
        scenario_description = scenario_data.get('scenario')
        investment_projection = scenario_data.get('investment_projection')

        industry = scenario_data.get('industry')
        facility = scenario_data.get('facility')
        country = scenario_data.get('country')
        org = scenario_data.get('org')
        regs = scenario_data.get('regs')
        attacker = scenario_data.get('attacker')
        vector = scenario_data.get('vector')
        target = scenario_data.get('target')
        effect = scenario_data.get('effect')
        network = scenario_data.get('network')
        impact = scenario_data.get('impact')
        motivation = scenario_data.get('motivation')

        # Correctly process consequences to ensure each starts with a single dash
        raw_consequences = scenario_data.get('consequences', '')
        # Split by any known delimiter and ensure each consequence starts with a dash
        consequences_list = raw_consequences.replace(',', '\n').split('\n')
        consequences = [f"- {line.strip()}" if not line.strip().startswith('-') else line.strip()
                        for line in consequences_list if line.strip()]
        # Join the consequences with a line break between each
        formatted_consequences = '\n'.join(consequences)
        table_data = scenario_data.get('tableData')

        costs = scenario_data.get('costs')
        # Check if cost_projection is None or not present, and set a default value if so
        cost_projection = scenario_data.get('cost_projection', '0|0|0|0|0|0|0|0|0|0|0|0')
        if not cost_projection:
            cost_projection = '0|0|0|0|0|0|0|0|0|0|0|0'

        # Prepare factors data
        factors = {}
        for item in table_data:
            factor = item.get('factor')
            score = int(item.get('score').split('/')[0])  # Extract score as integer
            narrative = item.get('narrative')
            factors[factor] = {'score': score, 'narrative': narrative}

        # Return the extracted data
        return JsonResponse({
            'attack_tree_data': attack_tree_data,
            'scenario_description': scenario_description,
            'consequences': formatted_consequences,
            'factors': factors,
            'costs': costs,
            'cost_projection': cost_projection,
            'investment_projection': investment_projection,
            'industry': industry,
            'facility': facility,
            'country': country,
            'org': org,
            'regs': regs,
            'attacker': attacker,
            'vector': vector,
            'target': target,
            'effect': effect,
            'network': network,
            'impact': impact,
            'motivation': motivation
        })

    except ScenarioBuilder.DoesNotExist:
        return JsonResponse({'error': 'Scenario not found'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


logger = logging.getLogger(__name__)


def get_facilities_by_zip(zip_code):
    url = f"https://ofmpub.epa.gov/frs_public2/frs_rest_services.get_facilities?zip_code={zip_code}&output=JSON"
    try:
        response = requests.get(url, verify=False, timeout=20)
        if response.status_code == 200:
            return response.json()
        else:
            logger.error("HTTP Error %s: %s", response.status_code, response.reason)
            return None
    except requests.RequestException as e:
        logger.error("Request error: %s", e)
        return None
    except ValueError as e:
        logger.error("JSON decoding error: %s", e)
        return None


def facilities(request):
    zip_code = request.GET.get('zip')
    if zip_code:
        facilities = get_facilities_by_zip(zip_code)
        if facilities:
            return JsonResponse({'facilities': facilities}, safe=False)
        else:
            return JsonResponse({'error': 'No facilities found or error in API call'}, status=500)
    else:
        return JsonResponse({'error': 'No ZIP code provided'}, status=400)


def get_coordinates_from_address(address, country, google_maps_api_key):
    geocode_url = f"https://maps.googleapis.com/maps/api/geocode/json?address={address},+{country}&key={google_maps_api_key}"
    response = requests.get(geocode_url)
    data = response.json()
    if data['status'] == 'OK':
        latitude = data['results'][0]['geometry']['location']['lat']
        longitude = data['results'][0]['geometry']['location']['lng']
        return latitude, longitude
    else:
        return None, None


def air_quality_index(request):
    latitude = request.GET.get('lat')
    longitude = request.GET.get('lon')
    address = request.GET.get('address')
    country = request.GET.get('country')

    aqicn_api_key = get_api_key("aqicn")  # Replace with your actual AQICN API key

    # If latitude and longitude are not provided, use address and country to get them
    if not latitude or not longitude:
        if address and country:
            latitude, longitude = get_coordinates_from_address(address, country,
                                                               "AIzaSyBJu4p9r_vFL9g5nzctO4yLbNxjK08q4G0")
            if not latitude or not longitude:
                return JsonResponse({'error': 'Failed to geocode address'}, status=400)

    url = f"https://api.waqi.info/feed/geo:{latitude};{longitude}/?token={aqicn_api_key}"

    try:
        response = requests.get(url)
        data = response.json()
        aqi = data.get('data', {}).get('aqi')
        return JsonResponse({'aqi': aqi})
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


def facility_risk_profile_newrecord(userid, industry, facility_type, address, country, facility, employees,
                                    shift_model, assessment_id, sl, has_ir_plan, ir_plan_never, ir_plan_tested_date):
    language = 'en'

    if has_ir_plan == 'on':
        ir_plan = 'true'
    else:
        ir_plan = 'false'

    if ir_plan_never == 'on':
        ir_plan_never_tested = 'true'
    else:
        ir_plan_never_tested = 'false'

    if not industry or not facility_type:
        error_msg = "Missing industry or facility type. Complete all fields to get an accurate assessment"
        return JsonResponse({
            'safety_summary': error_msg,
            'chemical_summary': error_msg,
            'physical_security_summary': error_msg,
            'other_summary': error_msg
        })

    openai_api_key = get_api_key('openai')
    openai_model = get_api_key('OpenAI_Model')
    # openai_api_key = os.environ.get('OPENAI_API_KEY')
    openai.api_key = openai_api_key
    context = f"You are an industrial safety and hazard expert. For the {facility} {facility_type} at {address}, {country} in the {industry} industry, with {employees} employees working a {shift_model} shift model, (NOTE ALSO - has an OT Cybersecurity Incident Response Plan: {has_ir_plan}. Incident response plan never tested: {ir_plan_never_tested}). "

    prompts = [
        f"{context} List safety hazards, max 100 words. - Specific to facility - mechanical or chemical or electrical or heat or cold or crush or height - Space between bullets. \n\nExample Format:\n 1. Specific safety hazard.\n 2. Another specific safety hazard.",
        f"{context} List expected chemicals, max 100 words. - Specific to facility - Chemical names only - raw materials and by-products and stored chemicals - Space between bullets. \n\nExample Format:\n 1. Chemical name (raw material or by-product).\n- 2. Another chemical name (raw material or by-product).",
        f"{context}, List physical security requirements for the given facility and location - access control - surveillance - consideration of local crime statistics - blind spots - proximity to other infrastructure . Max of 100 words .\n\nExample Format:\n 1. Physical security challenge.\n 2. Another physical security challenge.",
        f"{context}, list of specialized OT and IoT devices and equipment expected to be at the facility. Max of 150 words .\n\nExample Format:\n 1. OT or IoT device (purpose of device).\n 2. Another OT or IoT device (purpose of device).",
        f"{context}, list of national and international regulatory compliance containing cybersecurity requirements relevant to the {industry} industry that applies to {facility_type} facilities in {country} . Includes laws and standards. Max of 150 words .\n\nExample Format:\n 1. Compliance name (name of issuing authority).\n 2. Another compliance name (name of issuing authority).",
        f"{context}: You are a safety inspector. For a {facility_type} in {country}, estimate a detailed and nuanced safety and hazard risk score. Use a scale from 0 to 100, where 0 indicates an absence of safety hazards and 100 signifies the presence of extreme and imminent fatal hazards. Provide a score reflecting the unique risk factors associated with the facility type and its operational context in {country}. Scores should reflect increments of 10, with each decile corresponding to escalating levels of hazard severity and likelihood of occurrence given the expected attention to safety at the facility. Base your score on a typical {facility_type} in {country}, adhering to expected standard safety protocols, equipment conditions, and operational practices. Provide the score as a single, precise number without additional commentary."
    ]

    responses = []

    # Loop through the prompts and make an API call for each one
    def fetch_response(prompt):
        return openai.ChatCompletion.create(
            # model="gpt-4",
            model=openai_model,
            messages=[
                {"role": "system",
                 "content": "You are a model trained to provide concise responses. Please provide a concise numbered bullet-point list based on the given statement."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.1,
            max_tokens=600

        )

        # Use ThreadPoolExecutor to parallelize the API calls

    with concurrent.futures.ThreadPoolExecutor() as executor:
        responses = list(executor.map(fetch_response, prompts))

        # Extract the individual responses
    safety_summary = responses[0]['choices'][0]['message']['content'].strip()
    chemical_summary = responses[1]['choices'][0]['message']['content'].strip()
    physical_security_summary = responses[2]['choices'][0]['message']['content'].strip()
    other_summary = responses[3]['choices'][0]['message']['content'].strip()
    compliance_summary = responses[4]['choices'][0]['message']['content'].strip()
    pha_score = responses[5]['choices'][0]['message']['content'].strip()

    # Call to facility_threat_profile
    threatSummary, insightSummary, strategySummary = facility_threat_profile(sl, facility, facility_type, country,
                                                                             industry, safety_summary,
                                                                             chemical_summary,
                                                                             physical_security_summary,
                                                                             other_summary,
                                                                             compliance_summary, '',
                                                                             has_ir_plan, ir_plan_never_tested,
                                                                             ir_plan_tested_date)

    return {
        'safety_summary': safety_summary,
        'chemical_summary': chemical_summary,
        'physical_security_summary': physical_security_summary,
        'other_summary': other_summary,
        'compliance_summary': compliance_summary,
        'pha_score': pha_score,
        'threatSummary': threatSummary,
        'insightSummary': insightSummary,
        'strategySummary': strategySummary
    }


@csrf_exempt
def delete_pha_record(request):
    if request.method == 'POST':
        record_id = request.POST.get('id')
        try:
            pha_record = tblCyberPHAHeader.objects.get(ID=record_id)
            pha_record.Deleted = 1
            pha_record.save()

            return JsonResponse({'deleted': True})
        except tblCyberPHAHeader.DoesNotExist:
            return JsonResponse({'deleted': False})
    return JsonResponse({'deleted': False})


def assessment_summary(assessment_id, facilityType, industry):
    openai.api_key = get_api_key('openai')  # Ensure the API key is correctly set

    try:
        assessment = SelfAssessment.objects.get(pk=assessment_id)
    except SelfAssessment.DoesNotExist:
        return "Assessment not found."

    # Preparing the chat messages for the conversation with GPT-4
    messages = []

    # System message to set the context for the AI
    messages.append({
        "role": "system",
        "content": f"This is a cybersecurity assessment summary and scoring task in the context of a {facilityType} in the {industry} industry. Analyze the provided responses to the cybersecurity assessment questions and generate a summary and overall control effectiveness score out of 100."
    })

    # Adding questions and answers to the conversation
    framework_questions = AssessmentQuestion.objects.filter(framework=assessment.framework).prefetch_related(
        'assessmentanswer_set')
    answered_questions = assessment.answers.all()

    for question in framework_questions:
        answer = answered_questions.filter(question=question).first()
        if answer:
            response_text = "Yes" if answer.response else "No"
            effectiveness = f"Effectiveness: {answer.effectiveness}%" if answer.response and answer.effectiveness is not None else "Effectiveness not applicable."
            message_content = f"Question: {question.text} Answer: {response_text}. {effectiveness}"
        else:
            message_content = f"Question: {question.text} Answer: Unanswered."
        messages.append({"role": "user", "content": message_content})

    # Final user message prompting for the summary and score
    messages.append({
        "role": "user",
        "content": "Given the above answers, provide a concise summary in under 100 words of the cybersecurity program's state and an overall score of control effectiveness out of 100. Write the output as two variables in a manner that is easily parsed for display <integer score>|<text summary> "
    })

    # Sending the chat completion request to OpenAI
    try:
        response = openai.ChatCompletion.create(
            model=get_api_key('OpenAI_Model'),
            messages=messages,
            temperature=0.3,
            max_tokens=4096,  # Adjusted for comprehensive analysis
        )
        # Extracting and returning the AI's summary and score
        result = response.choices[0].message['content']

        return result
    except Exception as e:
        return f"Failed to generate assessment due to an API error: {str(e)}"


@require_http_methods(["POST"])
@csrf_exempt  # Consider CSRF protection for production
def get_assessment_summary(request):
    assessment_id = request.POST.get('assessment_id')
    facilityType = request.POST.get('facilityType')
    industry = request.POST.get('industry')
    if not assessment_id:
        return JsonResponse({'error': 'Assessment ID is required'}, status=400)

    result = assessment_summary(assessment_id, facilityType, industry)
    if "Failed to generate" in result:
        return JsonResponse({'error': result}, status=500)

    score, summary = result.split('|', 1)  # Splitting based on the expected format
    return JsonResponse({'score': score, 'summary': summary})


from django.utils.timezone import make_aware


def copy_cyber_pha(request, pha_id):
    if request.method == 'POST':
        original_pha = get_object_or_404(tblCyberPHAHeader, ID=pha_id)

        with transaction.atomic():
            # Get a dictionary of the original PHA excluding many-to-many fields
            original_data = model_to_dict(original_pha, exclude=['id'])
            latitude, longitude = get_coordinates_from_address(
                request.POST.get('facilityAddress') + ',' + request.POST.get('facilityCity') + ', ' + request.POST.get(
                    'facilityCode'), request.POST.get('country'),
                "AIzaSyBJu4p9r_vFL9g5nzctO4yLbNxjK08q4G0")
            update_data = {
                'FacilityName': request.POST.get('FacilityName'),
                'facilityAddress': request.POST.get('facilityAddress'),
                'facilityCity': request.POST.get('facilityCity'),
                'facilityState': request.POST.get('facilityState'),
                'facilityCode': request.POST.get('facilityCode'),
                'country': request.POST.get('country'),
                'facilityLat': latitude,
                'facilityLong': longitude
            }

            original_data.update(update_data)
            original_data.pop('ID', None)  # Ensure the ID is not included

            # Exclude many-to-many fields explicitly before creating the new instance
            m2m_fields = {field.name for field in tblCyberPHAHeader._meta.many_to_many}
            for field in m2m_fields:
                original_data.pop(field, None)

            # Create the new PHA header
            new_pha = tblCyberPHAHeader.objects.create(**original_data)

            # Set many-to-many relationships using .set()
            for field_name in m2m_fields:
                m2m_manager = getattr(original_pha, field_name)
                getattr(new_pha, field_name).set(m2m_manager.all())

            # Copy OneToOne and ForeignKey relationships
            # Assume cybersecurity_defaults is a OneToOneField linked to tblCyberPHAHeader
            if hasattr(original_pha, 'cybersecurity_defaults'):
                defaults_data = model_to_dict(original_pha.cybersecurity_defaults, exclude=['id', 'cyber_pha'])
                CyberPHACybersecurityDefaults.objects.create(cyber_pha=new_pha, **defaults_data)

            # Duplicate related scenarios and their nested related objects
            scenarios = tblCyberPHAScenario.objects.filter(CyberPHA=original_pha)
            for scenario in scenarios:
                scenario_data = model_to_dict(scenario, exclude=['ID', 'CyberPHA', 'userID'])
                scenario_data['CyberPHA'] = new_pha
                if scenario.userID:
                    user_instance = User.objects.get(id=scenario.userID.id)  # Ensure you have the correct user instance
                    scenario_data['userID'] = user_instance
                new_scenario = tblCyberPHAScenario.objects.create(**scenario_data)

                # Correctly duplicating related ScenarioConsequences
                consequences = ScenarioConsequences.objects.filter(scenario=scenario)
                for consequence in consequences:
                    consequence_data = model_to_dict(consequence, exclude=['id', 'scenario'])
                    # Now 'scenario' is not duplicated in consequence_data
                    ScenarioConsequences.objects.create(scenario=new_scenario, **consequence_data)

                    # Correctly duplicating related PHA_Safeguard
                    safeguards = PHA_Safeguard.objects.filter(scenario=scenario)
                    for safeguard in safeguards:
                        safeguard_data = model_to_dict(safeguard, exclude=['id',
                                                                           'scenario'])  # Exclude 'scenario' to avoid conflict
                        PHA_Safeguard.objects.create(scenario=new_scenario, **safeguard_data)

                    # Observations
                    observations = PHA_Observations.objects.filter(scenario=scenario)
                    for observation in observations:
                        observation_data = model_to_dict(observation, exclude=['id', 'scenario'])
                        PHA_Observations.objects.create(scenario=new_scenario, **observation_data)

        return redirect('OTRisk:iotaphamanager')  # Redirect after successful duplication

    return render(request, 'OTRisk/iotaphamanager.html')


def parse_ai_response(ai_response):
    """Parse the AI response into a structured dictionary with score."""
    pattern = re.compile(r'^(\d+)\|([^|]+)\|([^|]+)\|(\d+)$', re.MULTILINE)
    gaps = []
    for match in pattern.finditer(ai_response):
        number, heading, description, score = match.groups()
        cleaned_heading = heading.strip().replace('**', '')
        gaps.append({
            'number': number.strip(),
            'heading': cleaned_heading,
            'description': description.strip(),
            'score': int(score.strip())
        })
    return gaps


@csrf_exempt
def assessment_gap_analysis(request):
    # Extract parameters from POST request
    assessment_id = request.POST.get('assessment_id')
    framework_name = request.POST.get('framework_name')

    if not assessment_id or not framework_name:
        return JsonResponse({'error': 'Missing necessary parameters'}, status=400)

    try:
        assessment = SelfAssessment.objects.get(pk=assessment_id)

    except SelfAssessment.DoesNotExist:
        return JsonResponse({'error': 'Assessment not found'}, status=404)

    messages = [
        {
            "role": "system",
            "content": f"Given the results of a cybersecurity self-assessment for an operational technology environment, interpret these results in light of the '{framework_name}' standards. Consider the objectives, scope, and requirements of the '{framework_name}' and identify where the assessment results indicate potential deficiencies. Describe each deficiency in a structured format: 'number|heading|description|score', with a subjective severity score out of 10 where 0 is 100% lack of alignment and 10 is 100% complete alignment"
        }
    ]
    # Include assessment answers; ideally from a detailed perspective
    assessment_answers = assessment.answers.all()
    for answer in assessment_answers:
        response_text = "Yes" if answer.response else "No"
        effectiveness = f"{answer.effectiveness}%" if answer and answer.effectiveness is not None else "Not applicable"
        messages.append({
            "role": "user",
            "content": f"Question: {answer.question.text}, Answer: {response_text}, Effectiveness: {effectiveness}"
        })

    messages.append({
        "role": "user",
        "content": f"Please summarize the principal gaps between the assessment results and the standards of the mentioned framework. INSTRUCTIONS. The principle sections of '{framework_name}' MUST be used as the heading. For example, in NIST 800-53 ACCESS CONTROL is a principle section and AC-1 Policy and Procedures is a sub-section so ACCESS CONTROL will be heading to use. Description must be 20 words. Include a subjective score for the gap relating to each heading. STRICTLY MAINTAIN THE FORMAT number|heading|description|score"
    })
    openai.api_key = get_api_key('openai')

    try:
        response = openai.ChatCompletion.create(
            model=get_api_key('OpenAI_Model'),
            messages=messages,
            temperature=0.2,
            max_tokens=4000
        )
        ai_response = response.choices[0].message['content']
        gaps = parse_ai_response(ai_response)
        prompt_tokens = response.usage['prompt_tokens']
        completion_tokens = response.usage['completion_tokens']
        total_tokens = response.usage['total_tokens']

        return JsonResponse({'gaps': gaps})  # Send structured data
    except Exception as e:
        return JsonResponse({'error': f"API error: {str(e)}"}, status=500)


@login_required
def load_default_facility(request):
    user_organization_id = get_user_organization_id(request)
    organization_users = get_organization_users(user_organization_id)

    try:

        default_facility = tblCyberPHAHeader.objects.filter(
            UserID__in=organization_users,
            is_default=True,  # Assuming is_default is a BooleanField
            Deleted=0
        ).first()

        investments = CyberSecurityInvestment.objects.filter(cyber_pha_header=default_facility).values(
            'id', 'investment_type', 'vendor_name', 'product_name', 'cost', 'date'
        )
        investments_data = list(investments)
        if not default_facility:
            return JsonResponse({'error': 'No default facility found.'}, status=404)

        # Serialize facility data
        facility_data = {
            'title': default_facility.title,
            'leader': default_facility.PHALeader,
            'leaderemail': default_facility.PHALeaderEmail,
            'unit': default_facility.AssessmentUnit,
            'facility': default_facility.FacilityName,
            'facilitytype': default_facility.FacilityType,
            'assessment_id': default_facility.assessment,
            'zone': default_facility.AssessmentZone,
            'sl_t': default_facility.sl_t,
            'startdate': default_facility.AssessmentStartDate.strftime('%Y-%m-%d') if default_facility.AssessmentStartDate else '',
            'enddate': default_facility.AssessmentEndDate.strftime('%Y-%m-%d') if default_facility.AssessmentEndDate else '',
            'safetysummary': default_facility.safetySummary,
            'chemicalsummary': default_facility.chemicalSummary,
            'physicalsummary': default_facility.physicalSummary,
            'othersummary': default_facility.otherSummary,
            'compliancesummary': default_facility.complianceSummary,
            'threatSummary': default_facility.threatSummary,
            'insightSummary': default_facility.insightSummary,
            'strategySummary': default_facility.strategySummary,
            'country': default_facility.country,
            'shift_model': default_facility.shift_model,
            'EmployeesOnSite': default_facility.EmployeesOnSite,
            'annual_revenue': default_facility.annual_revenue,
            'cyber_insurance': default_facility.cyber_insurance,
            'address': default_facility.facilityAddress,
            'facilityLat': default_facility.facilityLat,
            'facilityLong': default_facility.facilityLong,
            'facilityAQI': default_facility.facilityAQI,
            'facilityCity': default_facility.facilityCity,
            'facilityState': default_facility.facilityState,
            'facilityCode': default_facility.facilityCode,
        }

        return JsonResponse({'headerrecord': facility_data,
                             'investments': investments_data,})

    except Exception as e:

        return JsonResponse({'error': str(e)}, status=500)