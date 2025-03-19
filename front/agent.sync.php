<?php
/**
 * Agent synchronization for Wazuh plugin
 */

include ('../../../inc/includes.php');

use GlpiPlugin\Wazuh\PluginWazuhConfig;
use GlpiPlugin\Wazuh\PluginWazuhAgent;

// Check if user has access to this page
//Session::checkRight("plugin_wazuh_agent", UPDATE);

// Get configuration
$config = new PluginWazuhConfig();
$config->getFromDB(1);

// Synchronize agents
if (PluginWazuhAgent::syncAgents()) {
    // Update last sync time
    $config->update([
        'id' => 1,
        'last_sync' => date('Y-m-d H:i:s')
    ]);
    
    Session::addMessageAfterRedirect(
        __('Agents synchronized successfully', 'wazuh'),
        true,
        INFO
    );
} else {
    Session::addMessageAfterRedirect(
        __('Error synchronizing agents', 'wazuh'),
        true,
        ERROR
    );
}

// Redirect to agent list
Html::redirect('agent.php');

