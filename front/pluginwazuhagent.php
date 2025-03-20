<?php
/**
 * Agent list for Wazuh plugin
 */

include ('../../../inc/includes.php');

use GlpiPlugin\Wazuh\PluginWazuhAgent;

//echo "<div class='center'>";
//echo "<a class='btn btn-primary' href='pluginwazuhagent.sync.php'>" . 
//     __('Synchronize from Wazuh', 'wazuh') . "</a>";
//echo "</div>";



$common = new PluginWazuhAgent();
include('dbtm.common.php');

echo Html::scriptBlock("
    $(document).ready(function() {
        // Dodaj element do navbara
        var newNavItem = '<li class=\"nav-item\"><a class=\"btn btn-icon btn-sm btn-secondary me-1 pe-2\" href=\"pluginwazuhagent.sync.php\" title=\"Sync agents\"><i class=\"fas fa-shield-alt\"></i><span class=\"d-none d-xxl-block\">Sync Agents</span></a></li>';
        $('.nav.navbar-nav').append(newNavItem);
        
    });
");

