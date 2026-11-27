<?php
/**
 * Agent synchronization for Wazuh plugin
 */

use GlpiPlugin\Wazuh\Connection;
use GlpiPlugin\Wazuh\WazuhAgent;

// Check if user has access to this page
//Session::checkRight("plugin_wazuh_agent", UPDATE);

Session::checkLoginUser();
Session::checkRight("plugin_wazuh_agent", UPDATE);

// Linking changes state (agent links), so it runs on POST only.
// GLPI's CheckCsrfListener validates the CSRF token of every non-AJAX POST before this script runs.
// Any other method (e.g. the GET from the menu link) only shows a confirmation form.
if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
    // explicit target: in GLPI 11 $_SERVER['PHP_SELF'] is the front controller (/index.php)
    global $CFG_GLPI;
    $link_url = $CFG_GLPI['root_doc'] . '/plugins/wazuh/front/pluginwazuhagent.link.php';
    Html::header(WazuhAgent::getTypeName(Session::getPluralNumber()), '', 'admin', WazuhAgent::class);
    echo "<div class='card mx-auto mt-3' style='max-width: 40rem;'><div class='card-body'>";
    echo "<form method='post' action='" . htmlescape($link_url) . "'>";
    echo "<p>" . htmlescape(__('Link not yet linked agents to computers and network equipments with the same name in the same entity.', 'wazuh')) . "</p>";
    echo "<div class='d-flex gap-2 justify-content-end'>";
    echo "<a class='btn btn-outline-secondary' href='" . htmlescape(WazuhAgent::getSearchURL()) . "'>" . htmlescape(__('Cancel')) . "</a>";
    echo "<button type='submit' name='link_agents' value='1' class='btn btn-primary'><i class='fas fa-link me-1'></i>"
        . htmlescape(_n('Link Agent', 'Link Agents', 2, 'wazuh')) . "</button>";
    echo "</div>";
    Html::closeForm();
    echo "</div></div>";
    Html::footer();
    return;
}

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
