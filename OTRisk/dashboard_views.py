from django.shortcuts import render
from django.template.loader import render_to_string
from django.utils.html import mark_safe
from OTRisk.models.raw import RAWorksheet, RAWorksheetScenario, RAActions
from django.contrib.auth.decorators import login_required
from OTRisk.models.Model_CyberPHA import tblCyberPHAHeader, tblCyberPHAScenario
from django.db.models import Count, Sum
from django.db.models import Avg
from accounts.models import Organization, UserProfile

import json


def get_user_organization_id(request):
    """Fetch organization ID for the logged-in user."""
    user_profile = UserProfile.objects.get(user=request.user)
    request.session['user_organization'] = user_profile.organization.id
    return user_profile.organization.id


def get_organization_users(organization_id):
    """Fetch users for the given organization ID."""
    return UserProfile.objects.filter(organization_id=organization_id).values_list('user', flat=True)


@login_required()
def dashboardhome(request):

    user_organization_id = get_user_organization_id(request)

    organization_users = get_organization_users(user_organization_id)
    # Set the session variable
    request.session['user_organization'] = user_organization_id

    # Filters added to all model queries to respect the organization of the user
    filters = {'organization_id': user_organization_id}
    records_by_business_unit_type = RAWorksheet.objects.filter(**filters).values('BusinessUnitType').annotate(
        count=Count('ID'))
    records_by_status_flag = RAWorksheet.objects.filter(**filters).values('StatusFlag').annotate(count=Count('ID'))
    records_by_trigger = RAWorksheet.objects.filter(**filters).values('RATrigger').annotate(count=Count('ID'))
    records_by_industry = RAWorksheet.objects.filter(**filters).values('industry').annotate(count=Count('ID'))

    scenarios = RAWorksheetScenario.objects.select_related('RAWorksheetID').filter(
        RAWorksheetID__organization_id=user_organization_id)
    records_by_risk_score = scenarios.values('RiskScore').annotate(count=Count('ID'))
    scenario_risk_status = scenarios.values('RiskStatus').annotate(count=Count('ID'))

    open_raws_count = RAWorksheet.objects.filter(**filters).exclude(StatusFlag="Closed").count()

    total_scenario_cost = scenarios.aggregate(sum_scenarioCost=Sum('scenarioCost'))['sum_scenarioCost']

    try:
        formatted_scenario_cost = "${:,.0f}".format(total_scenario_cost)
    except Exception:
        formatted_scenario_cost = "$--"

    raw_count = RAWorksheet.objects.filter(**filters).count()
    # raw_scenarios = RAWorksheetScenario.objects.all()
    scenarios_count = RAWorksheetScenario.objects.filter(RAWorksheetID__organization=user_organization_id).count()

    cyberpha_count = tblCyberPHAHeader.objects.filter(UserID__in=organization_users).count()
    cyberpha_scenario_count = tblCyberPHAScenario.objects.filter(userID__in=organization_users).count()

    safety_scores_list = list(
        RAWorksheetScenario.objects.filter(RAWorksheetID__organization=user_organization_id).values(
            'SafetyScore').annotate(count=Count('ID')).order_by('SafetyScore'))
    life_scores_list = list(RAWorksheetScenario.objects.filter(RAWorksheetID__organization=user_organization_id).values(
        'lifeScore').annotate(count=Count('ID')).order_by('lifeScore'))

    pha_safety_scores_list = list(
        tblCyberPHAScenario.objects.filter(userID__in=organization_users)
        .values('impactSafety')
        .annotate(count=Count('ID'))
        .order_by('impactSafety')
    )

    pha_danger_scores_list = list(
        tblCyberPHAScenario.objects.filter(userID__in=organization_users)
        .values('impactDanger')
        .annotate(count=Count('ID'))
        .order_by('impactDanger')
    )

    pha_environment_scores_list = list(
        tblCyberPHAScenario.objects.filter(userID__in=organization_users)
        .values('impactEnvironment')
        .annotate(count=Count('ID'))
        .order_by('impactEnvironment')
    )

    pha_threat_class = (
        tblCyberPHAScenario.objects.filter(userID__in=organization_users)
        .values('ThreatClass')
        .annotate(total=Count('ThreatClass'))
    )

    environment_scores_list = list(
        RAWorksheetScenario.objects.filter(RAWorksheetID__organization=user_organization_id).values(
            'environmentScore').annotate(count=Count('ID')).order_by('environmentScore'))
    # risk assessment facilities
    raw_facilities = RAWorksheet.objects.filter(organization=user_organization_id).values_list('ID', 'BusinessUnit',
                                                                                               'BusinessUnitType')

    # cyberPHA facilities
    pha_facilities = tblCyberPHAHeader.objects.filter(UserID__in=organization_users).values_list('ID', 'FacilityName', 'FacilityType')

    total_sle = tblCyberPHAScenario.objects.filter(userID__in=organization_users).aggregate(sum_sle=Sum('sle'))[
        'sum_sle']

    try:
        formatted_sle = "${:,.0f}".format(total_sle)
    except Exception:
        formatted_sle= "$--"

    ra_actions_records_count = RAActions.objects.filter(organizationid=user_organization_id).exclude(
        actionStatus="Closed").count()

    num_records = raw_facilities.count()

    context = {
        'records_by_business_unit_type': list(records_by_business_unit_type),
        'records_by_status_flag': list(records_by_status_flag),
        'records_by_trigger': list(records_by_trigger),
        'records_by_industry': list(records_by_industry),
        'scenario_risk_status': list(scenario_risk_status),
        'records_by_risk_score': records_by_risk_score,
        'raw_count': raw_count,
        'scenarios_count': scenarios_count,
        'cyberpha_count': cyberpha_count,
        'cyberpha_scenario_count': cyberpha_scenario_count,
        'doughnut_data': safety_scores_list,
        'life_scores_list': life_scores_list,
        'raw_facilities': raw_facilities,
        'pha_facilities': pha_facilities,
        'environment_scores_list': environment_scores_list,
        'pha_safety_scores_list': pha_safety_scores_list,
        'pha_danger_scores_list': pha_danger_scores_list,
        'pha_environment_scores_list': pha_environment_scores_list,
        'formatted_sle': formatted_sle,
        'formatted_scenario_cost': formatted_scenario_cost,
        'ra_actions_records_count': ra_actions_records_count,
        'open_raws_count': open_raws_count,
        'pha_threat_class': pha_threat_class
    }

    return render(request, 'dashboard.html', context)
