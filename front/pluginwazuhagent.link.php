<?php
/**
 * Agent synchronization for Wazuh plugin
 */

include ('../../../inc/includes.php');

use GlpiPlugin\Wazuh\Connection;
use GlpiPlugin\Wazuh\PluginWazuhAgent;

// Check if user has access to this page
//Session::checkRight("plugin_wazuh_agent", UPDATE);

Session::checkLoginUser();
Session::checkRight("plugin_wazuh_agent", UPDATE);

// Get configuration
$config = new Connection();
$config->getFromDB(1);

// Synchronize agents
if (PluginWazuhAgent::linkAgents()) {
    // Update last sync time
    $config->update([
        'id' => 1,
        'last_sync' => date('Y-m-d H:i:s')
    ]);
    
    Session::addMessageAfterRedirect(
        __('Agents linked successfully', 'wazuh'),
        true,
        INFO
    );
} else {
    Session::addMessageAfterRedirect(
        __('Not linked all agents', 'wazuh'),
        true,
        ERROR
    );
}

// Redirect to agent list
Html::redirect('pluginwazuhagent.php');

