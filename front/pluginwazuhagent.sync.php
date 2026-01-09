<?php
/**
 * Agent synchronization for Wazuh plugin
 */

include ('../../../inc/includes.php');

use Glpi\Exception\RedirectException;
use GlpiPlugin\Wazuh\PluginConfig;
use GlpiPlugin\Wazuh\WazuhAgent;

// Check if user has access to this page
Session::checkLoginUser();
Session::checkRight("plugin_wazuh_agent", UPDATE);

// Synchronize agents
if (WazuhAgent::syncAgents()) {

    Session::addMessageAfterRedirect(
        __('Active agents synchronized successfully', PluginConfig::APP_CODE),
        true,
        INFO
    );
} else {
    Session::addMessageAfterRedirect(
        __('Not synchronizing all agents', PluginConfig::APP_CODE),
        true,
        ERROR
    );
}

// Redirect to agent list
Html::redirect(WazuhAgent::getSearchURL());