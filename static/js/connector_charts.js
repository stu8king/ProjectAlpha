function exalens_risk_score_chart(score){
                            $('#risk_score_chart').empty();
                            var gauge = anychart.gauges.circular();

                            // configure the gauge
                            gauge.data([score]);
                            gauge.fill("#5E6266") // Set the fill color to match the inside of the chart
                                .stroke(null)
                                .padding(0)
                                .margin(0)
                                .startAngle(270)
                                .sweepAngle(180);

                            // Set the overall background to match the internal color
                            gauge.background().fill("#5E6266");

                            // configure the gauge axis
                            var axis = gauge.axis();
                            axis.scale()
                                .minimum(0)
                                .maximum(100)
                                .ticks({interval: 10})
                                .minorTicks({interval: 1});
                            axis.fill("#5E6266") // Set the fill color to match the inside of the chart
                                .startAngle(270)
                                .sweepAngle(180)
                                .width(1)
                                .ticks({type: "line", length: 4, position: "outside"})
                                .minorTicks({type: "line", length: 2, position: "outside"})
                                .labels().position("outside").fontColor("white");

                            // configure the gauge pointer
                            gauge.needle()
                                .stroke("2 #FFFFFF") // Set the needle color to white
                                .startRadius("5%")
                                .endRadius("90%")
                                .startWidth("1.4%")
                                .endWidth("0.8%");

                            // add range colors
                            gauge.range(0, {
                                from: 0,
                                to: 33,
                                position: "inside",
                                fill: "green",
                                stroke: "1 #545f69",
                                radius: 100,
                                startSize: 5,
                                endSize: 5
                            });
                            gauge.range(1, {
                                from: 34,
                                to: 66,
                                position: "inside",
                                fill: "yellow",
                                stroke: "1 #545f69",
                                radius: 100,
                                startSize: 5,
                                endSize: 5
                            });
                            gauge.range(2, {
                                from: 67,
                                to: 100,
                                position: "inside",
                                fill: "red",
                                stroke: "1 #545f69",
                                radius: 100,
                                startSize: 5,
                                endSize: 5
                            });

                            var credits = gauge.credits();
                            credits.enabled(false);

                            // set the container id
                            gauge.container('risk_score_chart');

                            // Reduce the overall size by 10%
                            gauge.bounds("5%", "5%", "90%", "90%");

                            // initiate drawing the gauge
                            gauge.draw();
                        }

function darktrace_risk_score_chart(score){
            $('#darktrace_risk_score_chart').empty();
            var gauge = anychart.gauges.circular();

            // configure the gauge
            gauge.data([score]);
            gauge.fill("#5E6266")
                .stroke(null)
                .padding(0)
                .margin(0)
                .startAngle(270)
                .sweepAngle(180);

            gauge.background().fill("#5E6266");

            var axis = gauge.axis();
            axis.scale()
                .minimum(0)
                .maximum(100)
                .ticks({interval: 10})
                .minorTicks({interval: 1});
            axis.fill("#7c868e")
                .startAngle(270)
                .sweepAngle(180)
                .width(1)
                .ticks({type: "line", length: 4, position: "outside"})
                .minorTicks({type: "line", length: 2, position: "outside"})
                .labels().position("outside").fontColor("white");

            // configure the gauge pointer
            gauge.needle()
                .stroke("2 #FFFFFF")
                .startRadius("5%")
                .endRadius("90%")
                .startWidth("1.4%")
                .endWidth("0.8%");

            // add range colors
            gauge.range(0, {
                from: 0,
                to: 33,
                position: "inside",
                fill: "green",
                stroke: "1 #545f69",
                radius: 100,
                startSize: 5,
                endSize: 5
            });
            gauge.range(1, {
                from: 34,
                to: 66,
                position: "inside",
                fill: "yellow",
                stroke: "1 #545f69",
                radius: 100,
                startSize: 5,
                endSize: 5
            });
            gauge.range(2, {
                from: 67,
                to: 100,
                position: "inside",
                fill: "red",
                stroke: "1 #545f69",
                radius: 100,
                startSize: 5,
                endSize: 5
            });
            var credits = gauge.credits();
            credits.enabled(false);

            // set the container id
            gauge.container('darktrace_risk_score_chart');
            gauge.bounds("5%", "5%", "90%", "90%");
            // initiate drawing the gauge
            gauge.draw();

        }

function exalens_createCategoryDistributionChart(categoryData) {
        var colorMapping = {
            "SYSTEM_HEALTH": "#be7126",
            "PHYSICAL": "#3d87b9",
            "CYBER": "#482c1a",

        };

        var chartData = [];
        for (var category in categoryData) {
            chartData.push({ x: category, value: categoryData[category], fill: colorMapping[category] });
        }

        // Create the chart
        anychart.onDocumentReady(function() {
            // Create a pie chart
            var chart = anychart.pie(chartData);

            // Convert pie chart to doughnut chart
            chart.innerRadius("80%");

            // Set the container id for the chart
            chart.container("exalens_category_distribution");

            // Set bounds to ensure the chart fills the container and adjust size
            chart.bounds("0%", "0%", "100%", "100%");

            // Customize the chart labels and title font size
            chart.labels()
                .position("outside")
                .fontSize("8pt") // Set font size for labels
                .fontColor("#ffffff")
                .format("{%x}");

            chart.legend(false); // Disable default legend
            var credits = chart.credits();
            credits.enabled(false);

            // Match the canvas color to the container background
            var containerBackgroundColor = window.getComputedStyle(document.getElementById('exalens_category_distribution')).backgroundColor;
            chart.background().fill(containerBackgroundColor);

            // Add lines from segments to labels
            chart.labels()
                .useHtml(true)
                .position("outside")
                .anchor('center')
                .format(function() {
                    return `<span style="color: ${this.fill};">${this.x}</span>`;
                })
                .connectorStroke({
                    color: "black",
                    thickness: 1,
                    dash: "2 2"
                })
                .hAlign('center') // Horizontally align labels to center
                .vAlign('middle'); // Vertically align labels to middle
            chart.bounds("0%", "0%", "115%", "115%");

            // Draw the chart
            chart.draw();
        });
    }

function exalens_createSeverityDistributionChart(severityData) {
    var colorMapping = {
        "High": "#b42121",       // Red
        "Critical": "#ff9100",   // Orange
        "Medium": "#ffd500",     // Yellow
        "Low": "#008000"         // Green
    };

    var chartData = [];
    for (var severity in severityData) {
        chartData.push({ x: severity, value: severityData[severity], fill: colorMapping[severity] });
    }

                            // Create the chart
                            anychart.onDocumentReady(function() {
                                // Create a pie chart
                                var chart = anychart.pie(chartData);

                                // Convert pie chart to doughnut chart
                                chart.innerRadius("80%");

                                // Set the container id for the chart
                                chart.container("exalens_severity_distribution");

                                // Set bounds to ensure the chart fills the container and adjust size
                                chart.bounds("0%", "0%", "100%", "100%");

                                // Customize the chart labels and title font size
                                chart.labels()
                                    .position("outside")
                                    .fontSize("10pt") // Set font size for labels
                                    .fontColor("#ffffff")
                                    .format("{%x}");


                                chart.legend(false); // Disable default legend
                                var credits = chart.credits();
                                credits.enabled(false);

                                // Match the canvas color to the container background
                                var containerBackgroundColor = window.getComputedStyle(document.getElementById('exalens_severity_distribution')).backgroundColor;
                                chart.background().fill(containerBackgroundColor);

                                // Add lines from segments to labels
                                chart.labels()
                                    .useHtml(true)
                                    .position("outside")
                                    .anchor('center')
                                    .format(function() {
                                        return `<span style="color: ${this.fill};">${this.x}</span>`;
                                    })
                                    .connectorStroke({
                                        color: "black",
                                        thickness: 1,
                                        dash: "2 2"
                                    })
                                    .hAlign('center') // Horizontally align labels to center
                                    .vAlign('middle'); // Vertically align labels to middle
                                chart.bounds("0%", "0%", "115%", "115%");

                                // Draw the chart
                                chart.draw();
                            });
                        }

function darktrace_incident_severity_DistributionChart(categoryData) {
    console.log(categoryData);
    var colorMapping = {
        "high": "#b42121",       // Red
        "critical": "#ff9100",   // Orange
        "medium": "#ffd500",     // Yellow
        "low": "#008000"         // Green
    };
    var chartData = [];
    for (var category in categoryData) {
        chartData.push({ x: category, value: categoryData[category], fill: colorMapping[category] });
    }

    // Ensure the container is ready before drawing the chart
    $(document).ready(function() {
        var container = document.getElementById('darktrace_tactics');
        if (!container) {
            console.error('Container not found!');
            return;
        }

        // Clear previous chart instances
        while (container.firstChild) {
            container.removeChild(container.firstChild);
        }

        anychart.onDocumentReady(function() {
            var chart = anychart.pie(chartData);
            chart.innerRadius("80%");
            chart.container("darktrace_tactics");
            chart.bounds(0, 0, "100%", "100%");

            chart.labels()
                .position("outside")
                .fontSize("8pt")
                .fontColor("#ffffff")
                .format("{%x}");
            chart.legend(false);
            var credits = chart.credits();
            credits.enabled(false);

            var containerBackgroundColor = window.getComputedStyle(container).backgroundColor;
            chart.background().fill(containerBackgroundColor || "transparent");

            chart.labels()
                .useHtml(true)
                .position("outside")
                .anchor('center')
                .format(function() {
                    return `<span style="color: ${this.fill};">${this.x}</span>`;
                })
                .connectorStroke({
                    color: "black",
                    thickness: 1,
                    dash: "2 2"
                })
                .hAlign('center')
                .vAlign('middle');

            chart.draw();

        });
    });
    document.getElementById('hdn_darktrace_tactics').value = JSON.stringify(categoryData);

}


function darktrace_tactics_DistributionChart(categoryData) {
    console.log(categoryData);

    var chartData = [];
    for (var category in categoryData) {
        chartData.push({ x: category, value: categoryData[category] });
    }

    // Ensure the container is ready before drawing the chart
    $(document).ready(function() {
        var container = document.getElementById('darktrace_mitre');
        if (!container) {
            console.error('Container not found!');
            return;
        }

        console.log('Container found:', container);
        console.log('Container dimensions:', container.clientWidth, container.clientHeight);

        // Clear previous chart instances
        while (container.firstChild) {
            container.removeChild(container.firstChild);
        }

        anychart.onDocumentReady(function() {
            var chart = anychart.pie(chartData);
            chart.innerRadius("80%");
            chart.container("darktrace_mitre");
            chart.bounds(0, 0, "100%", "100%");

            chart.labels()
                .position("outside")
                .fontSize("8pt")
                .fontColor("#ffffff")
                .format("{%x}");
            chart.legend(false);
            var credits = chart.credits();
            credits.enabled(false);

            var containerBackgroundColor = window.getComputedStyle(container).backgroundColor;
            chart.background().fill(containerBackgroundColor || "transparent");

            chart.labels()
                .useHtml(true)
                .position("outside")
                .anchor('center')
                .format(function() {
                    return `<span style="color: ${this.fill};">${this.x}</span>`;
                })
                .connectorStroke({
                    color: "black",
                    thickness: 1,
                    dash: "2 2"
                })
                .hAlign('center')
                .vAlign('middle');

            chart.draw();
            console.log('Chart container after draw:', container.innerHTML);
        });
    });
        document.getElementById('hdn_darktrace_mitre').value = JSON.stringify(categoryData);

}



