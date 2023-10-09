// save_scenario.js
function getCSRFToken() {
  const csrfCookieName = 'csrftoken';
  const cookieValue = document.cookie
    .split('; ')
    .find((row) => row.startsWith(csrfCookieName))
    .split('=')[1];
  return cookieValue;
}
function saveScenario(event) {
  event.preventDefault();

  let scenarioDescription = document.getElementsByName('scenario1')[0].value;
  let scenarioType = document.getElementsByName('scenarioType')[0].value;
  let threatScore = document.getElementsByName('threatscore')[0].value;
  let vulnerabilityScore = document.getElementsByName('vulnerabilityscore')[0].value;
  let reputationScore = document.getElementsByName('reputationscore')[0].value;
  let operationalScore = document.getElementsByName('operationalscore')[0].value;
  let safetyScore = document.getElementsByName('safetyscore')[0].value;
  let dataScore = document.getElementsByName('datascore')[0].value;
  let supplyChainScore = document.getElementsByName('supplychainscore')[0].value;
  let riskScore = document.getElementsByName('riskscore')[0].value;
  let riskStatus = document.getElementsByName('riskstatus')[0].value;


  let scenarioData = {
    scenario1: scenarioDescription,
    scenarioType: scenarioType,
    threatscore: threatScore,
    vulnerabilityscore: vulnerabilityScore,
    reputationscore: reputationScore,
    operationalscore: operationalScore,
    safetyscore: safetyScore,
    datascore: dataScore,
    supplychainscore: supplyChainScore,
    riskscore: riskScore,
    riskstatus: riskStatus
  };

  fetch('/OTRisk/save_raw_scenario/', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-CSRFToken': getCSRFToken()
    },
    body: JSON.stringify(scenarioData)
  })
    .then(response => {
        if (!response.ok) {
            throw new Error('Network response was not ok');
        }
        return response.json();
    })
    .then(data => {
        // Here you can still access the data from the response if you need it
        updateTable();
    })
    .catch(error => {
        console.error('Error:', error);
    });

}


// Function to update the table with the scenarios
async function updateTable() {
  try {
    // Get the CSRF token
    let csrfToken = document.cookie.split('; ').find(row => row.startsWith('csrftoken')).split('=')[1];

    // Get the table body element
    let tbody = document.getElementById('scenarioTableBody');

    // Clear the table body
    tbody.innerHTML = '';
    console.log("Cleared table body");
    // Make an AJAX request to fetch the scenarios
    const response = await fetch('/OTRisk/get_scenarios/', {
      headers: {
        'X-CSRFToken': csrfToken
      }
    });

    // Check if response is ok
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    const data = await response.json();

    // Add new rows to the table
    data.forEach(scenario => {
      let row = document.createElement('tr');
      row.innerHTML = `
        <td>${scenario.ID}</td>
        <td>${scenario.ScenarioDescription}</td>
        <td>${scenario.ThreatScore}</td>
        <td>${scenario.VulnScore}</td>
        <td>${scenario.RiskScore}</td>
      `;
      tbody.appendChild(row);
    });


  } catch(error) {
    // Display error in console
    console.error('Error:', error);
  }
}

