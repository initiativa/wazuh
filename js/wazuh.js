/**
 * JavaScript functions for Wazuh plugin
 */

document.addEventListener('DOMContentLoaded', function() {
    // Initialize Wazuh plugin JavaScript
    initWazuhPlugin();
});

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
