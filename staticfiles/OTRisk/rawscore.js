    function calculateRisk() {


    // Extract scores from the input fields
    const threatScore = parseInt(document.getElementsByName('threatscore')[0].value);
    const vulnerabilityScore = parseInt(document.getElementsByName('vulnerabilityscore')[0].value);
    const financialScore = parseInt(document.getElementsByName('financialscore')[0].value);
    const operationalScore = parseInt(document.getElementsByName('operationalscore')[0].value);
    const safetyScore = parseInt(document.getElementsByName('safetyscore')[0].value);
    const reputationScore = parseInt(document.getElementsByName('reputationscore')[0].value);
    const supplyChainScore = parseInt(document.getElementsByName('supplychainscore')[0].value);
    const dataScore = parseInt(document.getElementsByName('datascore')[0].value);

    // Extract weights from the input fields
    const reputationWeight = parseInt(document.getElementsByName('reputationWeight')[0].value);
    const financialWeight = parseInt(document.getElementsByName('financialWeight')[0].value);
    const operationalWeight = parseInt(document.getElementsByName('operationalWeight')[0].value);
    const safetyWeight = parseInt(document.getElementsByName('safetyWeight')[0].value);
    const supplyChainWeight = parseInt(document.getElementsByName('supplychainWeight')[0].value);
    const dataWeight = parseInt(document.getElementsByName('dataWeight')[0].value);

    // Calculate the sum of weighted scores
    const sumWeightedScores = (threatScore * 1) + (vulnerabilityScore * 1) +
                              (financialScore * financialWeight) +
                              (operationalScore * operationalWeight) +
                              (safetyScore * safetyWeight) +
                              (reputationScore * reputationWeight) +
                              (supplyChainScore * supplyChainWeight) +
                              (dataScore * dataWeight);

    // Calculate the sum of weights
    const sumWeights = 2 + (financialWeight + operationalWeight + safetyWeight +
                            reputationWeight + supplyChainWeight + dataWeight);


    // Calculate the risk score, then round and limit it to the range 1 to 100
    let riskScore = Math.round(sumWeightedScores / sumWeights);
    riskScore = Math.max(1, Math.min(100, riskScore));

    // Determine the risk status
    let riskStatus;
    if (riskScore <= 20) {
        riskStatus = "Low Risk";
    } else if (riskScore <= 40) {
        riskStatus = "Low/Medium Risk";
    } else if (riskScore <= 60) {
        riskStatus = "Medium Risk";
    } else if (riskScore <= 80) {
        riskStatus = "Medium/High Risk";
    } else {
        riskStatus = "High Risk";
    }

    // Output the results
    document.getElementById('riskscore').value = riskScore;
    document.getElementById('riskstatus').value = riskStatus;
}

function calculateSlider(slider,captionID) {
      const value = parseInt(slider.value);
      let riskLevel = "";

      if (value <= 5) {
        riskLevel = "Very Low";
      } else if (value <= 20) {
        riskLevel = "Low";
      } else if (value <= 42) {
        riskLevel = "Low/Medium";
      } else if (value <= 60) {
        riskLevel = "Medium";
      } else if (value <= 82) {
        riskLevel = "Medium/High";
      } else if (value <= 95) {
        riskLevel = "High";
      } else {
        riskLevel = "Very High";
      }

        const caption = document.getElementById(captionID);
        caption.innerText = riskLevel;

        calculateRisk()
    }
