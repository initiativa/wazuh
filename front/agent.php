<?php
/**
 * Agent list for Wazuh plugin
 */

include ('../../../inc/includes.php');

// Check if user has access to this page
Session::checkRight("plugin_wazuh_agent", READ);

Html::header(
    __('Wazuh Agents', 'wazuh'),
    $_SERVER['PHP_SELF'],
    'admin',
    '\\GlpiPlugin\\Wazuh\\PluginWazuhMenu',
    'agent'
);

// Add search criteria
$search_params = [
    'criteria' => [
        [
            'field'      => 'view',
            'searchtype' => 'contains',
            'value'      => '',
            'link'       => 'AND'
        ]
    ],
    'sort' => 1,
    'order' => 'DESC'
];

// Add synchronize button
echo "<div class='center'>";
echo "<a class='btn btn-primary' href='agent.sync.php'>" . 
     __('Synchronize from Wazuh', 'wazuh') . "</a>";
echo "</div>";

// Display the list of agents
Search::show('GlpiPlugin\\Wazuh\\PluginWazuhAgent', $search_params);


Html::footer();