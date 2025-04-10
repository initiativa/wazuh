/**
 * JavaScript functions for Wazuh plugin
 */

document.addEventListener('DOMContentLoaded', function() {
    // Initialize Wazuh plugin JavaScript
    initWazuhPlugin();
});

function wazuhExpandAllTreeNodes(buttonElement, tableId) {
    console.log('--- ' + tableId);
    const table = document.getElementById(tableId);
    table.querySelectorAll('.tree-node').forEach(function (node) {
        node.style.display = '';
    });

    table.querySelectorAll('.tree-toggle').forEach(function (toggler) {
        toggler.classList.remove('fa-caret-right');
        toggler.classList.add('fa-caret-down');
    });
}

function wazuhCollapseAllTreeNodes(buttonElement, tableId) {
    const table = document.getElementById(tableId);
    table.querySelectorAll('.tree-node[data-is-child="true"]').forEach(function (node) {
        node.style.display = 'none';
    });

    table.querySelectorAll('.tree-toggle').forEach(function (toggler) {
        toggler.classList.remove('fa-caret-down');
        toggler.classList.add('fa-caret-right');
    });
}

function wazuhToggleTreeNode(element, tableId) {
    var nodeId = element.getAttribute('data-node-id');
    var children = wazuhTreeFindChildren(nodeId);
    var isExpanded = element.classList.contains('fa-caret-down');

    // Toggle visibility of children
    children.forEach(function (child) {
        if (isExpanded) {
            // Collapse: hide this child and all its children
            child.style.display = 'none';

            // If this child was expanded, make sure to collapse its icon
            if (child.dataset.hasChildren === 'true') {
                var childToggler = child.querySelector('.tree-toggle');
                if (childToggler && childToggler.classList.contains('fa-caret-down')) {
                    childToggler.classList.remove('fa-caret-down');
                    childToggler.classList.add('fa-caret-right');
                }
            }
        } else {
            // Expand: show only direct children
            child.style.display = '';
        }
    });

    // Toggle icon
    if (isExpanded) {
        element.classList.remove('fa-caret-down');
        element.classList.add('fa-caret-right');
    } else {
        element.classList.remove('fa-caret-right');
        element.classList.add('fa-caret-down');
    }
    wazuhTreeUpdateZebraStripes(tableId);
}

function wazuhTreeCheckChanged(element) {
    const row = element.closest('tr');
    if (!row)
        return;

    const rowId = row.dataset.nodeId;
    if (!rowId)
        return;

    if (row.dataset.hasChildren === 'true') {

        const children = wazuhTreeFindAllChildren(rowId);

        const isChecked = element.checked;
        children.forEach(function (child) {
            const childCheckbox = child.querySelector('.massive_action_checkbox');
            if (childCheckbox) {
                childCheckbox.checked = isChecked;
            }
        });
    }

}

function wazuhTreeFindAllChildren(nodeId) {
    nodeId = String(nodeId);

    const directChildren = wazuhTreeFindChildren(nodeId);
    let allChildren = [...directChildren];

    directChildren.forEach(function (child) {
        if (child.dataset.hasChildren === 'true') {
            const childId = child.dataset.nodeId;
            const childrenOfChild = wazuhTreeFindAllChildren(childId);
            allChildren = allChildren.concat(childrenOfChild);
        }
    });

    return allChildren;
}

function wazuhTreeUpdateZebraStripes(tableId) {
    const table = document.getElementById(tableId);
    if (!table)
        return;

    const visibleRows = Array.from(table.querySelectorAll('tbody tr'))
            .filter(row => row.style.display !== 'none');

    table.querySelectorAll('tbody tr').forEach(row => {
        row.classList.remove('odd-row', 'even-row');
    });

    visibleRows.forEach((row, index) => {
        if (index % 2 === 0) {
            row.classList.add('even-row');
        } else {
            row.classList.add('odd-row');
        }
    });
}

function wazuhTreeFindChildren(nodeId) {
    nodeId = String(nodeId);
    const parentRow = document.querySelector('.tree-node[data-node-id="' + nodeId + '"]');
    if (!parentRow)
        return [];

    const children = [];
    let currentNode = parentRow.nextElementSibling;

    while (currentNode &&
            currentNode.classList.contains('tree-node') &&
            currentNode.dataset.isChild === 'true') {
        children.push(currentNode);
        currentNode = currentNode.nextElementSibling;
    }

    return children;
}

function wazuhTreeFindChildren2(nodeId) {
    // Convert nodeId to string for comparison
    nodeId = String(nodeId);

    // Get all tree nodes
    var nodes = document.querySelectorAll('.tree-node');
    var children = [];

    // First find direct parent row
    var parentRow = document.querySelector('.tree-node[data-node-id="' + nodeId + '"]');

    if (!parentRow)
        return [];

    // Get next siblings until we find another node at the same or higher level
    var currentNode = parentRow.nextElementSibling;

    while (currentNode &&
            currentNode.classList.contains('tree-node') &&
            currentNode.dataset.isChild === 'true') {
        children.push(currentNode);
        currentNode = currentNode.nextElementSibling;
    }

    return children;
}




/**
 * Initialize Wazuh plugin JavaScript functions
 */
function initWazuhPlugin() {
    // Add listeners to sync button if it exists
    const syncButton = document.querySelector('.wazuh-sync-button');
    if (syncButton) {
        syncButton.addEventListener('click', confirmSyncAgents);
    }
    
    // Add listeners to status indicators
    updateStatusIndicators();
    
    // Initialize tooltips
    initTooltips();
}

function toggleWazuhPassword(fieldId) {
    var field = document.getElementById(fieldId);
    var button = field.nextElementSibling.querySelector('i');

    if (field.type === 'password') {
        field.type = 'text';
        button.classList.remove('ti-eye');
        button.classList.add('ti-eye-off');
    } else {
        field.type = 'password';
        button.classList.remove('ti-eye-off');
        button.classList.add('ti-eye');
    }
}

/**
 * Update agent status indicators with visual cues
 */
function updateStatusIndicators() {
    const statusCells = document.querySelectorAll('.agent-status');
    
    statusCells.forEach(function(cell) {
        const status = cell.textContent.trim().toLowerCase();
        
        // Remove existing classes
        cell.classList.remove('status-active', 'status-disconnected', 'status-pending', 'status-never-connected');
        
        // Add class based on status
        switch (status) {
            case 'active':
                cell.classList.add('status-active');
                break;
            case 'disconnected':
                cell.classList.add('status-disconnected');
                break;
            case 'pending':
                cell.classList.add('status-pending');
                break;
            case 'never_connected':
            case 'never connected':
                cell.classList.add('status-never-connected');
                break;
        }
    });
}

/**
 * Display confirmation dialog before synchronizing agents
 * @param {Event} event - Click event
 */
function confirmSyncAgents(event) {
    if (!confirm(GLPI_LANG.plugin_wazuh_confirm_sync)) {
        event.preventDefault();
    }
    
    // Show loading indicator
    if (document.getElementById('display-spinner')) {
        document.getElementById('display-spinner').style.display = 'block';
    }
}

/**
 * Initialize tooltips for agent information
 */
function initTooltips() {
    // Check if jQuery UI tooltips are available
    if (typeof $.fn.tooltip !== 'undefined') {
        $('.wazuh-tooltip').tooltip({
            track: true,
            show: {
                delay: 500
            }
        });
    }
}

/**
 * Open agent details in a modal
 * @param {string} agentId - Wazuh agent ID
 */
function openAgentDetails(agentId) {
    glpi_ajax_dialog({
        title: GLPI_LANG.plugin_wazuh_agent_details,
        url: CFG_GLPI.root_doc + '/plugins/wazuh/ajax/get_agent_details.php',
        params: {
            agent_id: agentId
        }
    });
}

/**
 * Test Wazuh API connection
 */
function testWazuhConnection() {
    const serverUrl = document.querySelector('input[name="server_url"]').value;
    const apiPort = document.querySelector('input[name="api_port"]').value;
    const apiUsername = document.querySelector('input[name="api_username"]').value;
    const apiPassword = document.querySelector('input[name="api_password"]').value;
    
    // Show spinner
    const testButton = document.getElementById('test-connection-button');
    testButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i> ' + GLPI_LANG.plugin_wazuh_testing;
    
    // Send AJAX request to test connection
    $.ajax({
        url: CFG_GLPI.root_doc + '/plugins/wazuh/ajax/test_connection.php',
        type: 'POST',
        data: {
            server_url: serverUrl,
            api_port: apiPort,
            api_username: apiUsername,
            api_password: apiPassword
        },
        success: function(response) {
            const result = JSON.parse(response);
            
            if (result.success) {
                // Show success message
                alert(GLPI_LANG.plugin_wazuh_connection_success);
            } else {
                // Show error message
                alert(GLPI_LANG.plugin_wazuh_connection_error + ': ' + result.message);
            }
        },
        error: function() {
            // Show error message
            alert(GLPI_LANG.plugin_wazuh_connection_error);
        },
        complete: function() {
            // Restore button text
            testButton.innerHTML = GLPI_LANG.plugin_wazuh_test_connection;
        }
    });
}

/**
 * Update agent group assignment
 * @param {string} agentId - Wazuh agent ID
 */
function updateAgentGroups(agentId) {
    // Implementation for group management
    // To be expanded based on Wazuh API capabilities
}
