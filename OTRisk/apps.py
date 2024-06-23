from django.apps import AppConfig


class OTRiskConfig(AppConfig):
    name = 'OTRisk'

    def ready(self):
        import OTRisk.templatetags.custom_filters


class OtriskConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'OTRisk'

    def ready(self):
        # Import signal handlers
        import OTRisk.signals
        import OTRisk.templatetags.custom_filters
