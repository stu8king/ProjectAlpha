from rest_framework import serializers
from OTRisk.models import ThreatAssessment


class ThreatAssessmentSerializer(serializers.ModelSerializer):
    class Meta:
        model = ThreatAssessment
        fields = '__all__'
