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

// The sync changes state (outbound calls, agent writes), so it runs on POST only.
// GLPI's CheckCsrfListener validates the CSRF token of every non-AJAX POST before this script runs.
// Any other method (e.g. the GET from the menu link) only shows a confirmation form.
if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
    Html::header(WazuhAgent::getTypeName(Session::getPluralNumber()), '', 'admin', WazuhAgent::class);
    echo "<div class='card mx-auto mt-3' style='max-width: 40rem;'><div class='card-body'>";
    // explicit target: in GLPI 11 $_SERVER['PHP_SELF'] is the front controller (/index.php)
    global $CFG_GLPI;
    $sync_url = $CFG_GLPI['root_doc'] . '/plugins/wazuh/front/pluginwazuhagent.sync.php';
    echo "<form method='post' action='" . htmlescape($sync_url) . "'>";
    echo "<p>" . htmlescape(__('Fetch agents from all active Wazuh connections of the current entity and update the agent list.', PluginConfig::APP_CODE)) . "</p>";
    echo "<div class='d-flex gap-2 justify-content-end'>";
    echo "<a class='btn btn-outline-secondary' href='" . htmlescape(WazuhAgent::getSearchURL()) . "'>" . htmlescape(__('Cancel')) . "</a>";
    echo "<button type='submit' name='sync_agents' value='1' class='btn btn-primary'><i class='fas fa-shield-alt me-1'></i>"
        . htmlescape(_n('Sync Agent', 'Sync Agents', 2, PluginConfig::APP_CODE)) . "</button>";
    echo "</div>";
    Html::closeForm();
    echo "</div></div>";
    Html::footer();
    return;
}

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