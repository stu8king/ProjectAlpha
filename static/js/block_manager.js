/**
 * Function to organize visible blocks within their respective grid columns.
 * Resets the CSS properties for proper alignment within the grid.
 */
function organizeVisibleBlocks() {
    var visibleBlocks = $(".info-block:visible");

    // Iterate over visible blocks and append them back to their parent columns
    visibleBlocks.each(function(index, block) {
        var parentCol = $(block).closest('.flex-col');
        $(block).css({
            'position': 'relative',
            'top': 'auto',
            'left': 'auto',
            'width': 'auto',
            'height': 'auto',
            'z-index': 'auto'
        }).appendTo(parentCol);
    });
}

/**
 * Function to adjust the width of the block body content.
 * Ensures the content width is adjusted based on the block's padding and border.
 * @param {object} block - The jQuery object representing the block element.
 */
function adjustContentWidth(block) {
    var blockBodyContent = block.find(".block-body-content");
    var paddingLeft = parseInt(block.css('padding-left'));
    var paddingRight = parseInt(block.css('padding-right'));
    var borderWidth = parseInt(block.css('border-width')) || 0;
    var totalPadding = paddingLeft + paddingRight + (2 * borderWidth);
    blockBodyContent.width(block.width() - totalPadding);
}

// Counter to manage z-index of the blocks
var zIndexCounter = 1000;

$(document).ready(function() {
    // Store the original width, height, and position of each block
    $(".info-block").each(function() {
        var block = $(this);
        block.data("originalWidth", block.width());
        block.data("originalHeight", block.height());
        block.data("originalPosition", block.position());
    });

    // Make info-blocks draggable within the container
    $(".info-block").draggable({
        handle: ".block-header",
        containment: "#block_container", // Constrain the movement within #block_container
        start: function(event, ui) {
            // Bring the dragged element to the front
            $(this).css('z-index', ++zIndexCounter);
        },
        stop: function(event, ui) {
            // Reset the height to auto to adjust to the content
            $(this).css({
                'height': 'auto',
                'max-height': '90vh'
            });
        }
    });

    // Toggle block-body visibility on double-click
$(".block-header").on('dblclick', function() {
    var block = $(this).closest(".info-block");
    var blockBody = block.find(".block-body");
    var blockBodyContent = block.find(".block-body-content");

    blockBody.toggle();
    var isVisible = blockBody.is(":visible");
    $(this).find(".toggle-body").text(isVisible ? "-" : "+");

    if (isVisible) {
        block.css({
            'z-index': ++zIndexCounter,
            'height': 'auto',
            'max-height': '90vh'
        });
        adjustContentWidth(block); // Adjust the content width when the block is opened
        // Check if content exceeds the block-body height
        if (blockBodyContent.prop('scrollHeight') > blockBodyContent.height()) {
            blockBodyContent.css('overflow-y', 'auto');
        } else {
            blockBodyContent.css('overflow-y', 'hidden');
        }
        if (blockBodyContent.prop('scrollWidth') > blockBodyContent.width()) {
            blockBodyContent.css('overflow-x', 'auto');
        } else {
            blockBodyContent.css('overflow-x', 'hidden');
        }
    } else {
        block.css({
            'width': '100%',
            'height': block.data("originalHeight")
        });
        blockBodyContent.css({
            'overflow-y': 'hidden',
            'overflow-x': 'hidden'
        });
        var originalParent = $("#block_container").find("#" + block.attr('id')).parent();
        originalParent.append(block);
    }
});

    // Make info-blocks resizable
    $(".info-block").resizable({
        handles: 'e, w, ne, nw, se, sw',
        stop: function(event, ui) {
            var block = $(this);
            var blockId = block.attr('id');
            adjustContentWidth(block); // Adjust the content width after resizing

            // Adjust the content width for the specific block-body-content
            var blockBodyContent = block.find("#" + blockId + "-content");
            var paddingLeft = parseInt(block.css('padding-left'));
            var paddingRight = parseInt(block.css('padding-right'));
            var borderWidth = parseInt(block.css('border-width')) || 0;
            var totalPadding = paddingLeft + paddingRight + (2 * borderWidth);
            blockBodyContent.width(block.width() - totalPadding);
        }
    });

    // Toggle block-body visibility
    $(".toggle-body").on('click', function() {
        var block = $(this).closest(".info-block");
        var blockBody = block.find(".block-body");
        var blockBodyContent = block.find(".block-body-content");

        blockBody.toggle();
        var isVisible = blockBody.is(":visible");

        $(this).text(isVisible ? "-" : "+");

        if (isVisible) {
            block.css({
                'z-index': ++zIndexCounter,
                'height': 'auto',
                'max-height': '90vh'
            });
            adjustContentWidth(block); // Adjust the content width when the block is opened
            // Check if content exceeds the block-body height
            if (blockBodyContent.prop('scrollHeight') > blockBodyContent.height()) {
                blockBodyContent.css('overflow-y', 'auto');
            } else {
                blockBodyContent.css('overflow-y', 'hidden');
            }
            if (blockBodyContent.prop('scrollWidth') > blockBodyContent.width()) {
                blockBodyContent.css('overflow-x', 'auto');
            } else {
                blockBodyContent.css('overflow-x', 'hidden');
            }
        } else {
            block.css({
                'width': '100%',
                'height': block.data("originalHeight")
            });
            blockBodyContent.css({
                'overflow-y': 'hidden',
                'overflow-x': 'hidden'
            });
            var originalParent = $("#block_container").find("#" + block.attr('id')).parent();
        originalParent.append(block);
        }
    });

    // Ensure the overflow is hidden initially
    $(".block-body-content").css({
        'overflow-y': 'hidden',
        'overflow-x': 'hidden'
    });

    // Restore all blocks to their original sizes and positions
    $("#restoreLink").on('click', function(event) {
        event.preventDefault();
        $(".info-block").each(function() {
            var block = $(this);
            var originalPosition = block.data("originalPosition");
            block.animate({
                width: block.data("originalWidth"),
                height: block.data("originalHeight"),
                top: originalPosition.top,
                left: originalPosition.left
            }, 500); // Duration of the animation in milliseconds
        });
    });

    // Handle block selection
     $("#block_selector input[type=checkbox]").on('change', function() {
        var blockId = $(this).data('block-id');
        var block = $("#" + blockId);
        var isChecked = $(this).is(":checked");

        if (isChecked) {
            // Find the first available container that doesn't already have a visible block with the same ID
            var availableContainer = $(".flex-col:has(.info-block)").filter(function() {
                return !$(this).find(".info-block:visible").length;
            }).first();

            if (availableContainer.length) {
                block.appendTo(availableContainer).show();
                block.find(".block-body").hide();
                block.find(".toggle-body").text("+");
            } else {
                // If no available container, find the first empty container
                availableContainer = $(".flex-col").not(":has(.info-block)").first();
                if (availableContainer.length) {
                    block.appendTo(availableContainer).show();
                    block.find(".block-body").hide();
                    block.find(".toggle-body").text("+");
                } else {
                    alert("No available containers to display the block.");
                }
            }
        } else {
            // Move the block back to its original container and hide it
            block.hide();
        }
    });

    // Organize blocks when the "Organize" button is clicked
    $("#organizeBlocks").on('click', function() {
        organizeVisibleBlocks();
    });
});
