function drawAttackTree(data) {
    alert("statucfiles");
    var container = document.getElementById('attack_tree');
    var containerWidth = container.clientWidth;
    var svgWidth = containerWidth; // Use full container width
    var margin = { top: 10, right: 60, bottom: 10, left: 140 }; // Adjusted margins
    var width = svgWidth - margin.left - margin.right;
    var height = width / 2; // Height is half of the width

    // Create an off-screen SVG element for D3 to use
    var svgElement = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svgElement.setAttribute("width", svgWidth);
    svgElement.setAttribute("height", height);
    svgElement.setAttribute("viewBox", "0 0 " + svgWidth + " " + height);

    // Render the diagram to the off-screen SVG using D3
    var svg = d3.select(svgElement)
        .append("g")
        .attr("transform", "translate(" + margin.left + "," + margin.top + ")");

    // Define the arrow marker
    svg.append("svg:defs").selectAll("marker")
        .data(["end"])
        .enter().append("svg:marker")
        .attr("id", String)
        .attr("viewBox", "0 -5 10 10")
        .attr("refX", 25)
        .attr("markerWidth", 6)
        .attr("markerHeight", 6)
        .attr("orient", "auto")
        .append("svg:path")
        .attr("d", "M0,-5L10,0L0,5");

    var i = 0;
    var treemap = d3.tree()
        .size([height, width - margin.left - margin.right])
        .separation(function(a, b) { return (a.parent == b.parent ? 1 : 2); });

    var root = d3.hierarchy(data, function(d) { return d.children; });
    root.x0 = height / 2;
    root.y0 = 0;

    // Color-blind-friendly color scale
    var colorScale = d3.scaleOrdinal(["#88CCEE", "#DDCC77", "#CC6677", "#882255", "#44AA99", "#117733", "#999933", "#AA4499"]);

    update(root);

    function update(source) {
        var treeData = treemap(root);

        var nodes = treeData.descendants(),
            links = treeData.descendants().slice(1);

        nodes.forEach(function(d) { d.y = d.depth * 180 });

        var node = svg.selectAll('g.node')
            .data(nodes, function(d) { return d.id || (d.id = ++i); });

        var nodeEnter = node.enter().append('g')
            .attr('class', 'node')
            .attr("transform", function(d) { return "translate(" + d.y + "," + d.x + ")"; });

        nodeEnter.append('circle')
            .attr('r', 5) // Smaller radius
            .style("stroke", "black")
            .style("stroke-width", 1.5)
            .style("fill", function(d) { return colorScale(d.depth); });

        nodeEnter.append('text')
            .style("fill", "darkgray")
            .style("font-size", "10px")
            .style("font-weight", "bold")
            .attr("transform", "rotate(-10)")
            .attr("dy", ".35em")
            .attr("x", function(d) { return d.children ? -13 - this.getComputedTextLength() : 13; })
            .attr("text-anchor", function(d) { return d.children ? "end" : "start"; })
            .text(function(d) { return d.data.name; });

        var link = svg.selectAll('path.link')
            .data(links, function(d) { return d.id; });

        link.enter().insert('path', "g")
            .attr("class", "link")
            .style("stroke", function(d) { return colorScale(d.depth); })
            .style("stroke-width", 2)
            .style("fill", "none")
            .attr("marker-end", "url(#end)") // Add the arrow marker
            .attr('d', function(d) {
                return "M" + d.y + "," + d.x
                    + "C" + (d.y + d.parent.y) / 2 + "," + d.x
                    + " " + (d.y + d.parent.y) / 2 + "," + d.parent.x
                    + " " + d.parent.y + "," + d.parent.x;
            });
    }

     // Ensure the SVG is fully rendered before converting
    setTimeout(function() {
        convertSVGtoPNG(svgElement).then(pngUrl => {
            // Display the PNG in the attack_tree container
            container.innerHTML = '<img src="' + pngUrl + '" style="width: 100%; height: auto;">';
        }).catch(error => {
            console.error("Error converting SVG to PNG:", error);
        });
    }, 0); // Timeout set to 0 to allow the rendering cycle to complet
}

function convertSVGtoPNG(svgElement) {
    return new Promise((resolve, reject) => {
        var svgData = new XMLSerializer().serializeToString(svgElement);
        var canvas = document.createElement('canvas');
        var ctx = canvas.getContext('2d');
        var img = new Image();

        canvas.width = svgElement.getAttribute("width");
        canvas.height = svgElement.getAttribute("height");

        img.onload = function() {
            ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
            var pngUrl = canvas.toDataURL("image/png");
            resolve(pngUrl);
        };

        img.onerror = function() {
            reject(new Error("Error loading SVG data into image"));
        };

        img.src = 'data:image/svg+xml; charset=utf8, ' + encodeURIComponent(svgData);
    });
}



