function getCSRFToken() {
  const csrfCookieName = 'csrftoken';
  const cookieValue = document.cookie
    .split('; ')
    .find((row) => row.startsWith(csrfCookieName))
    .split('=')[1];
  return cookieValue;
}
//Action Items
function saveAction(event) {
  alert("save action");
  event.preventDefault();

  let actionTitle = document.getElementsByName('actionTitle')[0].value;
  let actionDescription = document.getElementsByName('actionDescription')[0].value;
  let actionOwner = document.getElementsByName('actionOwner')[0].value;
  let actionTargetDate = document.getElementsByName('actionTargetDate')[0].value;
  let actionEffort = document.getElementsByName('actionEffort')[0].value;
  let actionCost = document.getElementsByName('actionCost')[0].value;


  let actionItem = {
    actionTitle: actionTitle,
    actionDescription: actionDescription,
    actionOwner: actionOwner,
    actionTargetDate: actionTargetDate,
    actionEffort: actionEffort,
    actionCost: actionCost
  };
  alert("fetch action")
  fetch('/OTRisk/save_raw_actions/', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-CSRFToken': getCSRFToken()
    },
    body: JSON.stringify(actionItem)
  })
    .then(response => {
        if (!response.ok) {
            throw new Error('Network response was not ok');
        }
        return response.json();
    })
    .then(data => {
        // Here you can still access the data from the response if you need it
        updateActionTable();
    })
    .catch(error => {
        console.error('Error:', error);
    });

}


// Function to update the table with the scenarios
async function updateActionTable() {
  try {
    // Get the CSRF token
    let csrfToken = document.cookie.split('; ').find(row => row.startsWith('csrftoken')).split('=')[1];

    // Get the table body element
    let tbody = document.getElementById('tblActionItemLists');

    // Clear the table body
    tbody.innerHTML = '';
    console.log("Cleared table body");
    alert("alert 1");
    // Make an AJAX request to fetch the scenarios
    const response = await fetch('/OTRisk/get_actions/', {
      headers: {
        'X-CSRFToken': csrfToken
      }
    });
    alert("alert 2");
    console.log("Fetch request made");

    // Check if response is ok
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    console.log("Response received and is OK");

    const data = await response.json();
    console.log('Received data:', data);

    // Add new rows to the table
    data.forEach(action => {
      let row = document.createElement('tr');
      row.innerHTML = `
        <td>${action.ID}</td>
        <td>${action.actionTitle}</td>
        <td>${action.actionOwner}</td>
        <td>${action.actionEffort}</td>
        <td>${action.actionCost}</td>
      `;
      tbody.appendChild(row);
    });
    console.log("Table updated with data");

  } catch(error) {
    // Display error in console
    console.error('Error:', error);
  }
}



