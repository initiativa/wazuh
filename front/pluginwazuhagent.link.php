<?php
/**
 * Agent synchronization for Wazuh plugin
 */

include ('../../../inc/includes.php');

use GlpiPlugin\Wazuh\Connection;
use GlpiPlugin\Wazuh\WazuhAgent;

// Check if user has access to this page
//Session::checkRight("plugin_wazuh_agent", UPDATE);

Session::checkLoginUser();
Session::checkRight("plugin_wazuh_agent", UPDATE);

// Get configuration
$config = new Connection();
$config->getFromDB(1);

// Link agents to devices
$result = WazuhAgent::linkAgents();
$not_linked = $result['to_link'] - $result['linked'];

if ($not_linked === 0) {
    // Update last sync time
    $config->update([
        'id' => 1,
        'last_sync' => date('Y-m-d H:i:s')
    ]);
}

if ($result['to_link'] === 0) {
    Session::addMessageAfterRedirect(
        __('All agents are already linked', 'wazuh'),
        true,
        INFO
    );
} elseif ($not_linked === 0) {
    Session::addMessageAfterRedirect(
        sprintf(__('Linked agents: %d', 'wazuh'), $result['linked']),
        true,
        INFO
    );
} else {
    Session::addMessageAfterRedirect(
        sprintf(
            __('Linked %1$d of %2$d agents, %3$d without matching device', 'wazuh'),
            $result['linked'],
            $result['to_link'],
            $not_linked
        ),
        true,
        WARNING
    );
}

// Redirect to agent list
Html::redirect(WazuhAgent::getSearchURL());
