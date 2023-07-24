// Generate the Excel file when the Print button is clicked
function generateExcel() {
  // Retrieve the question and response data from the HTML elements
  // and format it into an Excel-compatible data structure

  // Create an array to hold the form field data
  var formData = [];

  // Retrieve the values of the form fields
  var organizationSelect = document.getElementById('OrganizationName');
var organization = organizationSelect.options[organizationSelect.selectedIndex].value;

  var walkdownLeader = document.getElementById('WalkdownLeader').value;
  var orgContact = document.getElementById('OrgContact').value;
  var walkdownDate = document.getElementById('WalkdownDate').value;
  var walkdownStartTime = document.getElementById('WalkdownStartTime').value;
  var walkdownEndTime = document.getElementById('WalkdownEndTime').value;
  var peopleOnSite = document.getElementById('PeopleOnSite').value;
  var safetyBriefingGiven = document.getElementById('SafetyBriefingGiven').value;

  // Add the form field values to the formData array
  formData.push(['Facility:', organization]);
  formData.push(['Walkdown Leader:', walkdownLeader]);
  formData.push(['Organization Contact:', orgContact]);
  formData.push(['Walkdown Date:', walkdownDate]);
  formData.push(['Start Time:', walkdownStartTime]);
  formData.push(['End Time:', walkdownEndTime]);
  formData.push(['Location Headcount:', peopleOnSite]);
  formData.push(['Safety Briefing:', safetyBriefingGiven]);

   formData.push([], []); // Add two empty rows
  // Iterate through the questions and radio buttons
  var questionCards = document.querySelectorAll('.card-body');
  questionCards.forEach(function(card) {
    var question = card.querySelector('.card-title').innerText;
    var responseRadios = card.querySelectorAll('input[type="radio"]');
    var response = '';
    responseRadios.forEach(function(radio) {
      if (radio.checked) {
        response = radio.value;
      }
    });
    formData.push([question, response]);
  });


  // Create the worksheet and workbook
  var ws = XLSX.utils.aoa_to_sheet(formData);
  ws['!cols'] = [{ width: 100 }];
  ws['!cols'][1] = { width: 15 };
  var wb = XLSX.utils.book_new();

  XLSX.utils.book_append_sheet(wb, ws, 'Walkdown Form');

  // Generate the Excel file and trigger the download
  var excelBuffer = XLSX.write(wb, { bookType: 'xlsx', type: 'array' });
  saveAsExcel(excelBuffer, 'walkdown_form_data.xlsx');
}

function generateExcelCategories() {
  // Create a new workbook
  var wb = XLSX.utils.book_new();
  var organizationSelect = document.getElementById('OrganizationName');
  var organization = organizationSelect.options[organizationSelect.selectedIndex].value;

  var walkdownLeader = document.getElementById('WalkdownLeader').value;
  var orgContact = document.getElementById('OrgContact').value;
  var walkdownDate = document.getElementById('WalkdownDate').value;
  var walkdownStartTime = document.getElementById('WalkdownStartTime').value;
  var walkdownEndTime = document.getElementById('WalkdownEndTime').value;
  var peopleOnSite = document.getElementById('PeopleOnSite').value;
  var safetyBriefingGiven = document.getElementById('SafetyBriefingGiven').value;

  // Add the header information worksheet
  var headerWorksheet = XLSX.utils.aoa_to_sheet([
    ['Facility:', organization],
    ['Walkdown Leader:', walkdownLeader],
    ['Organization Contact:', orgContact],
    ['Walkdown Date:', walkdownDate],
    ['Start Time:', walkdownStartTime],
    ['End Time:', walkdownEndTime],
    ['Location Headcount:', peopleOnSite],
    ['Safety Briefing:', safetyBriefingGiven],
    [], // Empty row
    [] // Empty row
  ]);
  XLSX.utils.book_append_sheet(wb, headerWorksheet, "Walkdown Info");

  // Iterate through the question categories
  var categories = document.querySelectorAll('#categoryTabs .nav-link');
  for (var i = 0; i < categories.length; i++) {
    var category = categories[i].getAttribute('id');
    var questions = document.querySelectorAll('#tab-' + category + ' .card-title');

    // Create a new worksheet for each category
    var wsData = [['Question', 'Response']];

    // Iterate through the questions and retrieve the responses
    for (var j = 0; j < questions.length; j++) {
      var question = questions[j];
      var responseElement = question.nextElementSibling.querySelector('input:checked');
      var response = responseElement ? responseElement.value : '';

      // Add the question and response to the worksheet data array
      wsData.push([question.textContent, response]);
    }

    // Convert the worksheet data to worksheet format
    var ws = XLSX.utils.aoa_to_sheet(wsData);
   ws['!cols'] = [{ width: 100 }];
  ws['!cols'][1] = { width: 15 };
    // Set the tab name to the category name
    ws['!name'] = category;

    // Add the worksheet to the workbook
    XLSX.utils.book_append_sheet(wb, ws, category);
  }

  // Export the workbook to Excel file
  XLSX.writeFile(wb, 'output.xlsx');
}






// Function to save the Excel file
function saveAsExcel(buffer, fileName) {
  var data = new Blob([buffer], { type: 'application/octet-stream' });
  var url = window.URL.createObjectURL(data);
  var link = document.createElement('a');
  link.href = url;
  link.setAttribute('download', fileName);
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
}

// Attach the generateExcel function to the button click event
window.addEventListener('DOMContentLoaded', function() {
  var generateExcelBtn = document.getElementById('generateExcelBtn');
  generateExcelBtn.addEventListener('click', generateExcel);
});

