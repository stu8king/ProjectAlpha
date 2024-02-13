from collections import defaultdict

from django.shortcuts import render
from django.core.serializers import serialize
from django.template.loader import render_to_string
from django.utils.html import mark_safe
from OTRisk.models.raw import RAWorksheet, RAWorksheetScenario, RAActions
from django.contrib.auth.decorators import login_required
from OTRisk.models.Model_CyberPHA import tblCyberPHAHeader, tblCyberPHAScenario, OrganizationDefaults, auditlog, \
    CyberPHAModerators, CyberPHA_Group
from django.db.models import Count, Sum, Q
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

    try:
        org_defaults = OrganizationDefaults.objects.get(organization_id=user_organization_id)
        # Set organization defaults in the session
        request.session['organization_defaults'] = {
            'industry': org_defaults.industry_id,
            'language': org_defaults.language,
            'annual_revenue': org_defaults.annual_revenue,
            'cyber_insurance': org_defaults.cyber_insurance,
            'insurance_deductible': org_defaults.insurance_deductible,
            'employees': org_defaults.employees,
        }
    except OrganizationDefaults.DoesNotExist:
        # Handle the case where the organization does not have defaults set
        request.session['organization_defaults'] = {}

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
        if total_scenario_cost >= 1000000:
            formatted_scenario_cost = "${:.2f}M".format(total_scenario_cost / 1000000)
        elif total_scenario_cost >= 1000:
            formatted_scenario_cost = "${:.2f}K".format(total_scenario_cost / 1000)
        else:
            formatted_scenario_cost = "${:.2f}".format(total_scenario_cost)
    except Exception:
        formatted_scenario_cost = "$--"

    raw_count = RAWorksheet.objects.filter(**filters).count()

    bia_summary = defaultdict(int)
    raws = RAWorksheet.objects.filter(**filters)
    for raw in raws:
        business_impact_score = calculate_business_impact_score(raw.ID)
        bia_text = map_score_to_text(business_impact_score)
        bia_summary[bia_text] += 1
    bia_summary = json.dumps(dict(bia_summary))

    pha_bia_summary = defaultdict(int)
    phas = tblCyberPHAHeader.objects.filter(UserID__in=organization_users)
    for pha in phas:
        business_impact_score = calculate_pha_business_impact_score(pha.ID)
        bia_text = map_score_to_text(business_impact_score)
        pha_bia_summary[bia_text] += 1
    pha_bia_summary = json.dumps(dict(pha_bia_summary))

    pha_risk_summary = defaultdict(int)
    pha_risks = tblCyberPHAScenario.objects.filter(userID__in=organization_users)
    for pha_risk in pha_risks:
        risk_text = pha_risk.RRa
        pha_risk_summary[risk_text] += 1
    pha_risk_summary = json.dumps(dict(pha_risk_summary))

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

    pha_finance_scores_list = list(
        tblCyberPHAScenario.objects.filter(userID__in=organization_users)
        .values('impactFinance')
        .annotate(count=Count('ID'))
        .order_by('impactFinance')
    )

    pha_production_scores_list = list(
        tblCyberPHAScenario.objects.filter(userID__in=organization_users)
        .values('impactProduction')
        .annotate(count=Count('ID'))
        .order_by('impactProduction')
    )

    pha_reputation_scores_list = list(
        tblCyberPHAScenario.objects.filter(userID__in=organization_users)
        .values('impactReputation')
        .annotate(count=Count('ID'))
        .order_by('impactReputation')
    )

    pha_regulation_scores_list = list(
        tblCyberPHAScenario.objects.filter(userID__in=organization_users)
        .values('impactRegulation')
        .annotate(count=Count('ID'))
        .order_by('impactRegulation')
    )

    pha_data_scores_list = list(
        tblCyberPHAScenario.objects.filter(userID__in=organization_users)
        .values('impactData')
        .annotate(count=Count('ID'))
        .order_by('impactData')
    )

    pha_supply_scores_list = list(
        tblCyberPHAScenario.objects.filter(userID__in=organization_users)
        .values('impactSupply')
        .annotate(count=Count('ID'))
        .order_by('impactSupply')
    )

    pha_threat_class = (
        tblCyberPHAScenario.objects.filter(userID__in=organization_users)
        .values('ThreatClass')
        .annotate(total=Count('ThreatClass'))
    )

    environment_scores_list = list(
        RAWorksheetScenario.objects.filter(RAWorksheetID__organization=user_organization_id).values(
            'environmentScore').annotate(count=Count('ID')).order_by('environmentScore'))

    production_scores_list = list(
        RAWorksheetScenario.objects.filter(RAWorksheetID__organization=user_organization_id).values(
            'productionScore').annotate(count=Count('ID')).order_by('productionScore'))

    regulatory_scores_list = list(
        RAWorksheetScenario.objects.filter(RAWorksheetID__organization=user_organization_id).values(
            'regulatoryScore').annotate(count=Count('ID')).order_by('regulatoryScore'))

    data_scores_list = list(
        RAWorksheetScenario.objects.filter(RAWorksheetID__organization=user_organization_id).values(
            'DataScore').annotate(count=Count('ID')).order_by('DataScore'))

    financial_scores_list = list(
        RAWorksheetScenario.objects.filter(RAWorksheetID__organization=user_organization_id).values(
            'FinancialScore').annotate(count=Count('ID')).order_by('FinancialScore'))

    reputation_scores_list = list(
        RAWorksheetScenario.objects.filter(RAWorksheetID__organization=user_organization_id).values(
            'ReputationScore').annotate(count=Count('ID')).order_by('ReputationScore'))

    supply_scores_list = list(
        RAWorksheetScenario.objects.filter(RAWorksheetID__organization=user_organization_id).values(
            'SupplyChainScore').annotate(count=Count('ID')).order_by('SupplyChainScore'))

    # risk assessment facilities
    raw_facilities = RAWorksheet.objects.filter(organization=user_organization_id).values_list('ID', 'BusinessUnit',
                                                                                               'BusinessUnitType')

    # cyberPHA facilities
    pha_facilities = tblCyberPHAHeader.objects.filter(UserID__in=organization_users).values_list('ID', 'FacilityName',
                                                                                                 'FacilityType')

    total_sle = tblCyberPHAScenario.objects.filter(userID__in=organization_users).aggregate(sum_sle=Sum('sle'))[
        'sum_sle']

    #  try:
    #    formatted_sle = "${:,.0f}".format(total_sle)
    #    formatted_sle= "$--"

    # total_scenario_cost = scenarios.aggregate(sum_scenarioCost=Sum('scenarioCost'))['sum_scenarioCost']

    try:
        if total_sle >= 1000:
            formatted_sle = "${:.2f}M".format(total_sle / 1000000)
        elif total_scenario_cost >= 1000:
            formatted_sle = "${:.2f}K".format(total_sle / 1000)
        else:
            formatted_sle = "${:.2f}".format(total_sle)
    except Exception:
        formatted_sle = "$--"

    ra_actions_records_count = RAActions.objects.filter(organizationid=user_organization_id).exclude(
        actionStatus="Closed").count()

    num_records = raw_facilities.count()
    categories = ["Low", "Low/Medium", "Medium", "Medium/High", "High", "Very High"]

    # Convert the likelihood to one of the required categories
    def get_likelihood_category(likelihood):
        if likelihood < 20:
            return "Low"
        elif likelihood < 40:
            return "Low/Medium"
        elif likelihood < 60:
            return "Medium"
        elif likelihood < 80:
            return "Medium/High"
        elif likelihood <= 95:
            return "High"
        else:
            return "Very High"

    # Create a defaultdict to hold the counts
    heatmap_counts = defaultdict(int)

    scenarios = tblCyberPHAScenario.objects.filter(userID__in=organization_users)
    for scenario in scenarios:
        likelihood_category = get_likelihood_category(scenario.likelihood)
        heatmap_counts[(scenario.RRa, likelihood_category)] += 1

    heatmap_data = {}
    for key, value in heatmap_counts.items():
        if key[0] not in heatmap_data:
            heatmap_data[key[0]] = {}
        heatmap_data[key[0]][key[1]] = value

    sunburst_data = tblCyberPHAHeader.objects.filter(UserID__in=organization_users).values('country', 'Industry',
                                                                                           'FacilityType')
    sunburst_processed_data = process_data(sunburst_data)

    # Query the last 100 audit logs for this organization
    last_100_logs = auditlog.objects.filter(
        user_profile__organization_id=user_organization_id
    ).order_by('-timestamp')[:100]

    # get the moderation tasks for the current user
    moderation_tasks = CyberPHAModerators.objects.filter(moderator=request.user)
    moderation_details = []

    for task in moderation_tasks:
        # Get the related CyberPHAHeader
        pha_header = task.pha_header

        # Count the number of draft scenarios for this CyberPHA
        draft_scenario_count = tblCyberPHAScenario.objects.filter(
            CyberPHA=pha_header, scenario_status='Draft'
        ).count()

        # Add the details to the list
        moderation_details.append({
            'cyberpha_title': pha_header.title,
            'target_date': task.target_date,
            'draft_scenario_count': draft_scenario_count
        })

    groups_with_cyberphas = []
    for group in CyberPHA_Group.objects.all():
        cyberphas = group.tblcyberphaheader_set.filter(UserID__in=organization_users)
        # Only append the group if it has associated tblCyberPHAHeader records within the organization
        if cyberphas.exists():
            groups_with_cyberphas.append({
                'group_name': group.name,
                'cyberphas': [{'facility_name': cyberpha.FacilityName} for cyberpha in cyberphas]
            })
    worksheets_to_approve = RAWorksheet.objects.filter(
        Q(approver=request.user),
        Q(approval_status='Pending') | Q(approval_status='Rejected')
    )

    # Check if there are any worksheets to approve
    if worksheets_to_approve.count != 0:
        worksheets_to_approve_list = list(worksheets_to_approve.values('ID', 'RATitle', 'RADate', 'StatusFlag'))
    else:
        worksheets_to_approve_list = "No approvals for action"

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
        'formatted_sle': formatted_sle,
        'formatted_scenario_cost': formatted_scenario_cost,
        'ra_actions_records_count': ra_actions_records_count,
        'open_raws_count': open_raws_count,
        'pha_threat_class': pha_threat_class,
        'total_sle': total_sle,
        'total_scenario_cost': total_scenario_cost,
        'heatmap_data': json.dumps(heatmap_data),
        'sunburst_processed_data': sunburst_processed_data,
        'bia_summary': bia_summary,
        'pha_bia_summary': pha_bia_summary,
        'pha_risk_summary': pha_risk_summary,
        'scenarios': scenarios,
        'phas': phas,
        'last_100_logs': last_100_logs,
        'moderation_tasks': moderation_details,
        'groups_with_cyberphas':groups_with_cyberphas,
        'worksheets_to_approve': worksheets_to_approve_list
    }

    return render(request, 'dashboard.html', context)


def process_data(data):
    hierarchy = {}

    for entry in data:
        country = entry['country']
        industry = entry['Industry']
        facility = entry['FacilityType']

        if country not in hierarchy:
            hierarchy[country] = {}

        if industry not in hierarchy[country]:
            hierarchy[country][industry] = {}

        if facility not in hierarchy[country][industry]:
            hierarchy[country][industry][facility] = 1
        else:
            hierarchy[country][industry][facility] += 1

    return hierarchy_to_list(hierarchy)


def hierarchy_to_list(hierarchy):
    result = []
    for country, industries in hierarchy.items():
        country_node = {"name": country, "children": []}
        for industry, facilities in industries.items():
            industry_node = {"name": industry, "children": []}
            for facility, count in facilities.items():
                facility_node = {"name": facility, "value": count}
                industry_node["children"].append(facility_node)
            country_node["children"].append(industry_node)
        result.append(country_node)

    return result


def calculate_business_impact_score(ra_worksheet_id):
    # Define the weights for each field
    field_weights = {
        'ReputationScore': 1,
        'SafetyScore': 2,
        'lifeScore': 2,
        'FinancialScore': 1,
        'DataScore': 1,
        'SupplyChainScore': 1,
        'productionScore': 1,
        'environmentScore': 1,
        'regulatoryScore': 1,
    }

    try:
        # Retrieve the RAWorksheet with the given ID
        ra_worksheet = RAWorksheet.objects.get(ID=ra_worksheet_id)

        # Retrieve all associated RAWorksheetScenario instances for this RAWorksheet
        scenarios = RAWorksheetScenario.objects.filter(RAWorksheetID=ra_worksheet)

        # Initialize a total score
        total_score = 0

        # Calculate the total score based on weighted fields for each scenario
        for scenario in scenarios:
            scenario_score = 0
            for field, weight in field_weights.items():
                # Get the value of the field from the scenario
                field_value = getattr(scenario, field)
                # Convert it to a numeric score (assuming it's an integer out of 10)
                numeric_score = int(field_value)
                # Add the weighted score to the scenario score
                scenario_score += numeric_score * weight

            # Add the scenario score to the total score
            total_score += scenario_score

        return total_score

    except RAWorksheet.DoesNotExist:
        return None


def calculate_pha_business_impact_score(pha_id):
    # Define the weights for each field
    field_weights = {
        'impactReputation': 1,
        'impactSafety': 2,
        'impactDanger': 2,
        'impactFinance': 1,
        'impactData': 1,
        'impactSupply': 1,
        'impactProduction': 1,
        'impactEnvironment': 1,
        'impactRegulation': 1,
    }

    # Retrieve the RAWorksheet with the given ID
    pha_header = tblCyberPHAHeader.objects.get(ID=pha_id)

    # Retrieve all associated RAWorksheetScenario instances for this RAWorksheet
    scenarios = tblCyberPHAScenario.objects.filter(CyberPHA=pha_header)

    # Initialize a total score
    total_score = 0

    # Calculate the total score based on weighted fields for each scenario
    for scenario in scenarios:
        scenario_score = 0
        for field, weight in field_weights.items():
            # Get the value of the field from the scenario
            field_value = getattr(scenario, field)
            # Convert it to a numeric score (assuming it's an integer out of 10)
            numeric_score = int(field_value)
            # Add the weighted score to the scenario score
            scenario_score += numeric_score * weight

        # Add the scenario score to the total score
        total_score += scenario_score

    return total_score


def map_score_to_text(score):
    if score < 20:
        return 'Low'
    elif score < 40:
        return 'Low/Medium'
    elif score < 60:
        return 'Medium'
    elif score < 80:
        return 'Medium/High'
    elif score < 95:
        return 'High'
    else:
        return 'Very High'


def get_current_user_organization_id(user):
    try:
        user_profile = UserProfile.objects.get(user=user)
        return user_profile.organization_id
    except UserProfile.DoesNotExist:
        # Return None or handle it as per your application's requirement
        return None
