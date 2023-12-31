from django.conf import settings
from django.urls import path, include
from django.conf.urls.static import static
from django.contrib.auth import views as auth_views
from OTRisk.views import (
    risk_assessment,
    risk_register_data,
    save_or_update_tblRAWorksheet,
    save_raw_scenario,
    save_raw_actions
)
from . import views

app_name = 'OTRisk'

urlpatterns = [
    path('add_walkthrough/', views.add_walkthrough, name='add_walkthrough'),
    path('get_scenarios/', views.get_scenarios, name='get_scenarios'),
    path('get_actions/', views.get_actions, name='get_actions'),
    path('walkthrough/questionnaire/<int:facility_type_id>/<int:questionnaire_id>/',
         views.walkthrough_questionnaire_details, name='walkthrough_questionnaire_details'),
    path('walkthrough/questionnaire/<int:facility_type_id>/', views.walkthrough_questionnaire,
         name='walkthrough_questionnaire'),
    path('workshop/<int:workshop_id>/', views.workshop, name='workshop'),
    path('workshop/', views.workshop, name='workshop_without_id'),
    path('workshopsetup/', views.workshop_setup, name='workshop_setup'),
    path('save_scenario/', views.save_scenario, name='save_scenario'),
    path('save_recommendation/', views.save_recommendation, name='save_recommendation'),
    path('save_threat', views.save_threat, name='save_threat'),
    path('riskassessment/', views.risk_assessment, name='risk_assessment'),
    path('riskassess/', risk_assessment, name='riskassess'),
    path('risk-register-data/', risk_register_data, name='risk_register_data'),
    path('save_or_update_tblRAWorksheet/', save_or_update_tblRAWorksheet, name='save_or_update_tblRAWorksheet'),
    path('api/ra_worksheet/<int:id>/', views.get_ra_worksheet, name='get_ra_worksheet'),
    path('save_raw_scenario/', save_raw_scenario, name='save_raw_scenario'),
    path('save_raw_actions/', save_raw_actions, name='save_raw_actions'),
    path('fill_raw_from_table/<int:id>/', views.fill_raw_from_table, name='fill_raw_from_table'),
    path('logout/', auth_views.LogoutView.as_view(next_page='/accounts/login'), name='logout'),
    path('facility_types/', views.getFacilityTypes, name='facility_types'),
    path('cyber-pha-manager/', views.cyber_pha_manager, name='cyber_pha_manager'),
    path('save-cyberpha/', views.save_cyberpha, name='save_cyberpha'),
    path('assess_cyberpha/', views.assess_cyberpha, name='assess_cyberpha'),
    path('assess_cyberpha/<int:cyberPHAID>/', views.assess_cyberpha, name='cyberpha_id'),
    path('get_mitigation_measures/', views.get_mitigation_measures, name='get_mitigation_measures'),
    path('update_session/', views.update_session, name='update_session'),
    path('set_active_cyberpha/', views.set_active_cyberpha, name='set_active_cyberpha'),
    path('save_or_update_cyberpha/', views.save_or_update_cyberpha, name='save_or_update_cyberpha'),
    path('get_consequences/', views.get_consequences, name='get_consequences'),
    path('scenarioreport/', views.scenarioreport, name='scenarioreport'),
    path('deletecyberpha/<int:cyberpha_id>', views.deletecyberpha, name='deletecyberpha'),
    path('deletescenario/<int:scenarioid>/<int:cyberPHAID>/', views.deletescenario, name='deletescenario'),
    path('PHAeditmode/<int:id>', views.PHAeditmode, name='PHAeditmode'),
    path('openai_assess_risk', views.openai_assess_risk, name='openai_assess_risk'),
    path('qraw', views.qraw, name='qraw'),
    path('raw_action', views.raw_action, name='raw_action'),
    path('get_techniques/', views.GetTechniquesView.as_view(), name='get_techniques'),
    path('dashboardhome', views.dashboardhome, name='dashboardhome'),

    path('iotaphamanager/', views.iotaphamanager, name='iotaphamanager'),
    path('iotaphamanager/<int:record_id>/', views.iotaphamanager, name='iotaphamanager_with_id'),

    path('facility_risk_profile', views.facility_risk_profile, name='facility_risk_profile'),
    path('get_headerrecord', views.get_headerrecord, name='get_headerrecord'),
    path('scenario_analysis',views.scenario_analysis, name='scenario_analysis'),
    path('phascenarioreport',views.phascenarioreport, name='phascenarioreport'),
    path('getSingleScenario/', views.getSingleScenario, name='getSingleScenario'),
    path('check_vulnerabilities/', views.check_vulnerabilities, name='check_vulnerabilities'),
    path('rawreport/<int:raworksheet_id>/', views.rawreport, name='rawreport'),
    path('raw_from_walkdown/', views.raw_from_walkdown, name='raw_from_walkdown'),
    path('save_ra_action', views.save_ra_action, name='save_ra_action'),
    path('get_rawactions/', views.get_rawactions, name='get_rawactions'),

    path('ra_actions_view/', views.ra_actions_view, name='ra_actions_view_default'),
    path('ra_actions_view/pha/<int:pha_id>/', views.ra_actions_view, name='ra_actions_view_pha'),
    path('ra_actions_view/qraw/<int:qraw_id>/', views.ra_actions_view, name='ra_actions_view_qraw'),
    path('ra_actions_view/qraw/<int:qraw_id>/pha/<int:pha_id>/', views.ra_actions_view, name='ra_actions_view_both'),

    path('update_ra_action/', views.UpdateRAAction.as_view(), name='update_ra_action'),
    # For adding and editing scenarios
    path('scenario/add/', views.add_or_update_scenario, name='add_scenario'),
    path('scenario/edit/<int:scenario_id>/', views.add_or_update_scenario, name='edit_scenario'),

    # For deleting scenarios
    path('scenario/delete/<int:scenario_id>/', views.delete_scenario, name='delete_scenario'),
    path('OTRisk/scenario/add/<int:scenario_id>/', views.add_or_update_scenario, name='edit_scenario'),

    # For adding and editing consequences
    path('consequence/add/', views.add_or_update_consequence, name='add_consequence'),
    path('consequence/edit/<int:consequence_id>/', views.add_or_update_consequence, name='edit_consequence'),

    # For deleting consequences
    path('consequence/delete/<int:consequence_id>/', views.delete_consequence, name='delete_consequence'),
    path('OTRisk/consequence/add/<int:consequence_id>/', views.add_or_update_consequence, name='edit_consequence'),
    path('admin_users/', views.admin_users, name='admin_users'),
    path('disable_user/<int:user_id>/', views.disable_user, name='disable_user'),
    path('enable_user/<int:user_id>/', views.enable_user, name='enable_user'),
    path('delete_user/<int:user_id>/', views.delete_user, name='delete_user'),
    path('reports', views.reports, name='reports'),
    path('reports_pha', views.reports_pha, name='reports_pha'),
    path('pha_report/<int:cyberpha_id>/', views.pha_report, name='pha_report'),
    path('user_admin/', views.user_admin, name='user_admin'),
    path('edit_user/<int:user_id>/', views.edit_user, name='edit_user'),
    path('change_password/<int:user_id>/', views.change_password, name='change_password'),
    path('edit_organization/<int:org_id>/', views.edit_organization, name='edit_organization'),
    path('edit_user_profile/<int:user_id>/', views.edit_user_profile, name='edit_user_profile'),
    path('execute_sql/', views.execute_sql, name='execute_sql'),
    path('scenario_vulnerability/<int:scenario_id>/', views.scenario_vulnerability, name='scenario_vulnerability'),
    path('add_vulnerability/<int:scenario_id>/', views.add_vulnerability, name='add_vulnerability'),
    path('get_asset_types/', views.get_asset_types, name='get_asset_types'),
    path('get_mitigations/', views.get_mitigations, name='get_mitigations'),
    path('save_control_assessment/', views.save_control_assessment, name='save_control_assessment'),
    path('risk_register/', views.risk_register, name='risk_register'),
    path('save_risk_data/', views.save_risk_data, name='save_risk_data'),
    path('view_snapshots/<int:scenario>/', views.view_snapshots, name='view_snapshots'),
    path('create_or_update_raw_scenario/', views.create_or_update_raw_scenario, name='create_or_update_raw_scenario'),
    path('generate_ppt/', views.generate_ppt, name='generate_ppt'),
    path('manage_organization/', views.manage_organization, name='manage_organization'),
    path('get_organization_details/<int:org_id>/', views.get_organization_details, name='get_organization_details'),
    path('get_cve_details/', views.get_cve_details, name='get_cve_details'),
    path('pha_reports/<int:cyber_pha_header_id>/', views.pha_reports, name='pha_reports'),
    path('qraw_reports/<int:qraw_id>/', views.qraw_reports, name='qraw_reports'),
    path('get_scenario_report_details/', views.get_scenario_report_details, name='get_scenario_report_details'),
    path('get_qraw_scenario_report_details/', views.get_qraw_scenario_report_details, name='get_qraw_scenario_report_details'),
    path('list_frameworks/', views.list_frameworks, name='list_frameworks'),
    path('frameworks/', views.list_frameworks, name='list_frameworks'),
    path('select_framework/<int:framework_id>/', views.select_framework, name='select_framework'),
    path('start_assessment/<int:framework_id>/', views.start_assessment, name='start_assessment'),
    # To start a new assessment
    path('assessment_questions/<int:framework_id>/', views.assessment_questions, name='assessment_questions'),
    path('fetch-updated-assessments/', views.fetch_updated_assessments, name='fetch_updated_assessments'),

    path('save_assessment/<int:framework_id>/', views.save_assessment, name='save_assessment'),
    path('edit_assessment/<int:assessment_id>/', views.edit_assessment, name='edit_assessment'),
    path('create/', views.setup_org, name='setup_org'),
    path('edit/<int:pk>/', views.edit_org, name='edit_org'),
    path('update_assessment_name/', views.update_assessment_name, name='update_assessment_name'),
    path('upload_questionnaire/', views.upload_questionnaire, name='upload_questionnaire'),
    path('assessment_report_view//<int:assessment_id>/', views.assessment_report_view, name='assessment_report_view'),
    path('analyze_scenario/', views.analyze_scenario, name='analyze_scenario'),
    path('get-organization-defaults/<int:organization_id>/', views.get_organization_defaults, name='get_organization_defaults'),
    path('delete_snapshot/<int:snapshot_id>/<int:scenario_id>/', views.delete_snapshot, name='delete_snapshot'),
    path('organization/form/', views.organization_form_view, name='organization_form'),
    path('scenario_sim/', views.scenario_sim, name='scenario_sim'),
    path('update_user_phone_number/', views.update_user_phone_number, name='update_user_phone_number'),
    path('analyze_raw_scenario/', views.analyze_raw_scenario, name='analyze_raw_scenario'),
    path('analyze_sim_scenario/', views.analyze_sim_scenario, name='analyze_sim_scenario'),
    path('assign_cyberpha_to_group/', views.assign_cyberpha_to_group, name='assign_cyberpha_to_group'),
    path('fetch_groups/', views.fetch_groups, name='fetch_groups'),
    path('fetch_all_groups/', views.fetch_all_groups, name='fetch_all_groups'),
    path('generate_sim_attack_tree/', views.generate_sim_attack_tree, name='generate_sim_attack_tree'),
    path('generate_scenario_description/', views.generate_scenario_description, name='generate_scenario_description'),
    path('analyze_sim_consequences/', views.analyze_sim_consequences, name='analyze_sim_consequences'),
]




if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
