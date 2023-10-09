// assesscyberpha.js

// Add your JavaScript code here
// This file should contain any JavaScript functions or logic required for the assesscyberpha.html page

// Example function to handle form submission




      function filterTable() {
        var input = document.getElementById("scenarioSearch");
        var filter = input.value.toUpperCase();
        var table = document.getElementById("scenarioTable");
        var rows = table.getElementsByTagName("tr");

        for (var i = 0; i < rows.length; i++) {
          var description = rows[i].getElementsByTagName("td")[0]; // Update index to 0
          if (description) {
            var txtValue = description.textContent || description.innerText;
            if (txtValue.toUpperCase().indexOf(filter) > -1) {
              rows[i].style.display = "";
            } else {
              rows[i].style.display = "none";
            }
          }
        }
      }


      function selectScenario(row) {
        const tableRows = document.querySelectorAll("#scenarioTableBody tr");
        tableRows.forEach((row) => row.classList.remove("selected-row"));

        row.classList.add("selected-row");

        const scenario = row.getElementsByTagName("td")[0].textContent;
        const txtScenario = document.getElementById("txtScenario");
        txtScenario.value = scenario;
      }


function filterFunction2() {
                            var input = document.getElementById("consequenceSearch");
                            var filter = input.value.toUpperCase();
                            var table = document.getElementById("consequenceTable");
                            var rows = table.getElementsByTagName("tr");

                            for (var i = 0; i < rows.length; i++) {
                              var consequence = rows[i].getElementsByTagName("td")[0];
                              if (consequence) {
                                var txtValue = consequence.textContent || consequence.innerText;
                                if (txtValue.toUpperCase().indexOf(filter) > -1) {
                                  rows[i].style.display = "";
                                } else {
                                  rows[i].style.display = "none";
                                }
                              }
                            }
                          }


                 function selectConsequence(consequence) {
                    var txtConsequence = document.getElementById("txtConsequence");
                    var existingConsequences = txtConsequence.value.trim();

                    // Split the existing consequences into an array
                    var selectedConsequences = existingConsequences.split("\n");

                    // Check if the maximum limit of 5 records is reached
                    if (selectedConsequences.length >= 5) {
                      alert("You can select up to 5 consequences.");
                      return;
                    }

                    // Check if the selected consequence is already added
                    if (selectedConsequences.includes(consequence)) {
                      alert("This consequence is already selected.");
                      return;
                    }

                    // Add the selected consequence to the array
                    selectedConsequences.push(consequence);

                    // Update the textarea with the selected consequences
                    txtConsequence.value = selectedConsequences.join("\n");

                    // Clear the search input
                    var consequenceSearchInput = document.getElementById("consequenceSearch");
                    if (consequenceSearchInput) {
                      consequenceSearchInput.value = "";
                      consequenceSearchInput.dispatchEvent(new Event("input"));
                    }
                  }



// Function to handle scenario selection
function handleScenarioSelection(event) {
  const selectWrapper = event.target.closest('.select-wrapper');
  const selectDropdown = selectWrapper.querySelector('.select-dropdown');
  const selectedOption = event.target;
  const scenarioSearchInput = selectWrapper.querySelector('.form-control');

  // Set the selected value in the input field
  scenarioSearchInput.value = selectedOption.textContent.trim();

  // Close the dropdown
  selectDropdown.style.visibility = 'hidden';
  selectDropdown.style.opacity = '0';

  // Clear the search input value
  scenarioSearchInput.dispatchEvent(new Event('input'));

  // Reattach event listeners to the dropdown elements
  selectDropdown.removeEventListener('click', handleScenarioSelection);
  selectDropdown.addEventListener('click', handleScenarioSelection);
  const selectOptions = selectDropdown.querySelectorAll('.select-option');
  selectOptions.forEach(option => {
    option.removeEventListener('click', handleScenarioSelection);
    option.addEventListener('click', handleScenarioSelection);
  });
}

// Function to filter scenarios based on search input
function filterScenarios(event) {
  const searchInput = event.target.value.toLowerCase();
  const selectDropdown = event.target.closest('.select-wrapper').querySelector('.select-dropdown');
  const options = selectDropdown.querySelectorAll('.select-option');

  options.forEach(option => {
    const scenarioName = option.textContent.trim().toLowerCase();
    if (scenarioName.includes(searchInput)) {
      option.style.display = 'block';
    } else {
      option.style.display = 'none';
    }
  });
}

