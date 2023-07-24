function saveScenario() {
  print("Calling save scenario");
  var postId = document.querySelector('button[data-post-id]').getAttribute('data-post-id');
  // Retrieve the user-entered data from the form
  var scenarioDescription = document.getElementById('txtInitiatingEvents').value;
  var consequence = document.getElementById('Consequence').value;
  var threatSource = document.getElementById('threat_source').value;
  var threatAction = document.getElementById('threat_action').value;
  var countermeasures = document.getElementById('countermeasures').value;
  var severity = document.getElementById('severity').value;
  var frequency = document.getElementById('frequency').value;
  var exposure = document.getElementById('exposure').value;
  var resilience = document.getElementById('resilience').value;
  var inputRRu = document.getElementById('Input_RRu').value;
  var unmitigatedLikelihood = document.getElementById('unmitigated-likelihood').value;
  var severityIndex = document.getElementById('severity-index').value;
  var mitigateSeverity = document.getElementById('mitigate-severity').value;
  var mitigatedExposure = document.getElementById('mitigated-exposure').value;
  var residualRiskMitigated = document.getElementById('residual-risk-mitigated').value;
  var afterActionSeverity = document.getElementById('after-action-severity').value;
  var afterActionExposure = document.getElementById('after-action-exposure').value;
  var residualRiskAfterAction = document.getElementById('residual-risk-after-action').value;

  // Prepare the data to be sent to the server
  var data = {
    scenario_description: scenarioDescription,
    consequence_analysis: consequence,
    threat_source: threatSource,
    threat_action: threatAction,
    countermeasures: countermeasures,
    severity: severity,
    frequency: frequency,
    exposure: exposure,
    resilience: resilience,
    input_rru: inputRRu,
    unmitigated_likelihood: unmitigatedLikelihood,
    severity_index: severityIndex,
    mitigate_severity: mitigateSeverity,
    mitigated_exposure: mitigatedExposure,
    residual_risk_mitigated: residualRiskMitigated,
    after_action_severity: afterActionSeverity,
    after_action_exposure: afterActionExposure,
    residual_risk_after_action: residualRiskAfterAction,
    post_id: '{{ post_id }}'
  };

  // Send an AJAX request to the server
  $.ajax({
    url: '/OTRisk/save_scenario/',  // Replace with the actual URL for saving the scenario
    type: 'POST',
    data: data,
    success: function(response) {
      if (response.success) {
        // Scenario saved successfully
        alert('Scenario saved successfully!');
        // Store the scenario ID in a session variable named 'current_scenario'
        sessionStorage.setItem('current_scenario', response.scenario_id);

        // Check if recommendation1 is populated and save it if necessary
        var recommendation1 = document.getElementById('recommendation1').value;
        if (recommendation1) {
          saveRecommendation(recommendation1);
        }

        // Check if recommendation2 is populated and save it if necessary
        var recommendation2 = document.getElementById('recommendation2').value;
        if (recommendation2) {
          saveRecommendation(recommendation2);
        }

        // Check if recommendation3 is populated and save it if necessary
        var recommendation3 = document.getElementById('recommendation3').value;
        if (recommendation3) {
          saveRecommendation(recommendation3);
        }
      } else {
        // Scenario save failed
        alert('Failed to save the scenario.');
      }
    },
    error: function() {
      // Error occurred during the AJAX request
      alert('An error occurred while saving the scenario.');
    }
  });
}

function saveRecommendation(recommendation) {
  // Prepare the data to be sent to the server
  var data = {
    recommendation: recommendation,
    current_scenario_id: sessionStorage.getItem('current_scenario')
  };

  // Send an AJAX request to the server
  $.ajax({
    url: '/OTRisk/save_recommendation/',  // Replace with the actual URL for saving the recommendation
    type: 'POST',
    data: data,
    success: function(response) {
      if (response.success) {
        // Recommendation saved successfully
        alert('Recommendation saved successfully!');
      } else {
        // Recommendation save failed
        alert('Failed to save the recommendation.');
      }
    },
    error: function() {
      // Error occurred during the AJAX request
      alert('An error occurred while saving the recommendation.');
    }
  });
}
