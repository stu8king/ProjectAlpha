from django.apps import AppConfig


class OtriskConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'OTRisk'

    def ready(self):
        # Import signal handlers
        import OTRisk.signals
