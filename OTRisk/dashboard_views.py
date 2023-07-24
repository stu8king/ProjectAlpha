from django.shortcuts import render
from django.template.loader import render_to_string
from django.utils.html import mark_safe
from OTRisk.models.raw import RAWorksheet, RAWorksheetScenario
from OTRisk.models.Model_CyberPHA import tblCyberPHAHeader, tblCyberPHAScenario
from django.db.models import Count
from django.db.models import Avg

import json


def dashboardhome(request):
    records_by_business_unit_type = RAWorksheet.objects.values('BusinessUnitType').annotate(count=Count('ID'))
    records_by_status_flag = RAWorksheet.objects.values('StatusFlag').annotate(count=Count('ID'))
    records_by_trigger = RAWorksheet.objects.values('RATrigger').annotate(count=Count('ID'))
    records_by_industry = RAWorksheet.objects.values('industry').annotate(count=Count('ID'))
    records_by_risk_score = RAWorksheetScenario.objects.values('RiskScore').annotate(count=Count('ID'))
    scenario_risk_status = RAWorksheetScenario.objects.values('RiskStatus').annotate(count=Count('ID'))
    raw_count = RAWorksheet.objects.all().count()
    # raw_scenarios = RAWorksheetScenario.objects.all()
    scenarios_count = RAWorksheetScenario.objects.all().count()
    cyberpha_count = tblCyberPHAHeader.objects.all().count()
    cyberpha_scenario_count = tblCyberPHAScenario.objects.all().count()
    safety_scores = RAWorksheetScenario.objects.values('SafetyScore').annotate(count=Count('ID')).order_by('SafetyScore')
    safety_scores_list = list(safety_scores)
    danger_scores = RAWorksheetScenario.objects.values('lifeScore').annotate(count=Count('ID')).order_by('lifeScore')
    life_scores_list = list(danger_scores)

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
        'life_scores_list': life_scores_list
    }

    return render(request, 'dashboard.html', context)
