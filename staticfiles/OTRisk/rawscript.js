

function getFormData() {
    var formData = new FormData();
    var table = document.getElementById("riskTable");
    var rowCount = table.rows.length;

    for (var i = 1; i < rowCount; i++) {
        var row = table.rows[i];

        var scenarioInput = row.querySelector("input[name^='scenario']");
        var threatSelect = row.querySelector("select[name^='threat']");
        var vulnerabilitySelect = row.querySelector("select[name^='vulnerability']");
        var reputationSelect = row.querySelector("select[name^='reputation']");
        var financialSelect = row.querySelector("select[name^='financial']");
        var operationalSelect = row.querySelector("select[name^='operational']");
        var safetySelect = row.querySelector("select[name^='safety']");
        var riskInput = row.querySelector("input[name^='risk']");
        var commentsInput = row.querySelector("input[name^='comments']");
        var weightInput = row.querySelector("input[name^='weight']");

        formData.append(scenarioInput.name, scenarioInput.value);
        formData.append(threatSelect.name, threatSelect.value);
        formData.append(vulnerabilitySelect.name, vulnerabilitySelect.value);
        formData.append(reputationSelect.name, reputationSelect.value);
        formData.append(financialSelect.name, financialSelect.value);
        formData.append(operationalSelect.name, operationalSelect.value);
        formData.append(safetySelect.name, safetySelect.value);
        formData.append(riskInput.name, riskInput.value);
        formData.append(commentsInput.name, commentsInput.value);
        formData.append(weightInput.name, weightInput.value);
    }

    return formData;
}

function submitForm() {
    var formData = getFormData();

    var xhr = new XMLHttpRequest();
    xhr.open("POST", "{% url 'OTRisk:risk_assessment' %}", true);
    xhr.setRequestHeader("X-CSRFToken", "{{ csrf_token }}");
    xhr.onreadystatechange = function () {
        if (xhr.readyState === XMLHttpRequest.DONE) {
            if (xhr.status === 200) {
                // Handle successful response
                console.log(xhr.responseText);
            } else {
                // Handle error response
                console.error(xhr.responseText);
            }
        }
    };
    xhr.onerror = function () {
        // Handle request error
        console.error("An error occurred while sending the request.");
    };
    xhr.send(formData);
}

