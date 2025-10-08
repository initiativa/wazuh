<?php
/**
 * Agent list for Wazuh plugin
 */

include ('../../../inc/includes.php');

use GlpiPlugin\Wazuh\PluginWazuhAgent;

$common = new PluginWazuhAgent();
include('dbtm.common.php');

