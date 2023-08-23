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


@login_required()
def dashboardhome(request):
    user_profile = UserProfile.objects.get(user=request.user)
    user_organization = user_profile.organization.id
    # Set the session variable
    request.session['user_organization'] = user_organization

    records_by_business_unit_type = RAWorksheet.objects.values('BusinessUnitType').annotate(count=Count('ID'))
    records_by_status_flag = RAWorksheet.objects.values('StatusFlag').annotate(count=Count('ID'))
    records_by_trigger = RAWorksheet.objects.values('RATrigger').annotate(count=Count('ID'))
    records_by_industry = RAWorksheet.objects.values('industry').annotate(count=Count('ID'))
    records_by_risk_score = RAWorksheetScenario.objects.values('RiskScore').annotate(count=Count('ID'))
    scenario_risk_status = RAWorksheetScenario.objects.values('RiskStatus').annotate(count=Count('ID'))
    open_raws = RAWorksheet.objects.filter(organization=user_organization).exclude(StatusFlag="Closed")
    open_raws_count = open_raws.count()
    total_scenario_cost = RAWorksheetScenario.objects.aggregate(sum_scenarioCost=Sum('scenarioCost'))[
        'sum_scenarioCost']
    formatted_scenario_cost = "${:,.0f}".format(total_scenario_cost)

    raw_count = RAWorksheet.objects.all().count()
    # raw_scenarios = RAWorksheetScenario.objects.all()
    scenarios_count = RAWorksheetScenario.objects.all().count()
    cyberpha_count = tblCyberPHAHeader.objects.all().count()
    cyberpha_scenario_count = tblCyberPHAScenario.objects.all().count()
    safety_scores = RAWorksheetScenario.objects.values('SafetyScore').annotate(count=Count('ID')).order_by(
        'SafetyScore')
    safety_scores_list = list(safety_scores)
    danger_scores = RAWorksheetScenario.objects.values('lifeScore').annotate(count=Count('ID')).order_by('lifeScore')
    life_scores_list = list(danger_scores)

    pha_safety_scores = tblCyberPHAScenario.objects.values('impactSafety').annotate(count=Count('ID')).order_by(
        'impactSafety')
    pha_safety_scores_list = list(pha_safety_scores)
    pha_danger_scores = tblCyberPHAScenario.objects.values('impactDanger').annotate(count=Count('ID')).order_by(
        'impactDanger')
    pha_danger_scores_list = list(pha_danger_scores)
    pha_environment_scores = tblCyberPHAScenario.objects.values('impactEnvironment').annotate(
        count=Count('ID')).order_by('impactEnvironment')
    pha_environment_scores_list = list(pha_environment_scores)
    pha_threat_class = tblCyberPHAScenario.objects.values('ThreatClass').annotate(total=Count('ThreatClass'))
    environment_scores = RAWorksheetScenario.objects.values('environmentScore').annotate(count=Count('ID')).order_by(
        'environmentScore')
    environment_scores_list = list(environment_scores)
    # risk assessment facilities
    raw_facilities = RAWorksheet.objects.values_list('ID', 'BusinessUnit', 'BusinessUnitType')
    # cyberPHA facilities
    pha_facilities = tblCyberPHAHeader.objects.values_list('ID', 'FacilityName', 'FacilityType')

    total_sle = tblCyberPHAScenario.objects.aggregate(sum_sle=Sum('sle'))['sum_sle']
    formatted_sle = "${:,.0f}".format(total_sle)

    ra_actions_records = RAActions.objects.filter(organizationid=user_organization).exclude(actionStatus="Closed")
    ra_actions_records_count = ra_actions_records.count()

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
