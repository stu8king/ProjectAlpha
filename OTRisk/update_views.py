from django.views.generic import UpdateView
from django.urls import reverse_lazy
from .forms import RiskScenarioForm
from OTRisk.models.RiskScenario import RiskScenario


class ScenarioUpdateView(UpdateView):
    model = RiskScenario
    form_class = RiskScenarioForm
    template_name = 'OTRisk/post/scenario_edit.html'

    def form_valid(self, form):
        scenario = form.save()
        # Optionally, add any additional logic you need
        return super().form_valid(form)

    def get_success_url(self):
        return reverse_lazy('OTRisk:scenario_detail', kwargs={'pk': self.object.pk})

