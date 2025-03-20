<?php

require_once ("../../../inc/includes.php");

use GlpiPlugin\Wazuh\PluginConfig;
use GlpiPlugin\Wazuh\PluginWazuhConfig;
use GlpiPlugin\Wazuh\Logger;
use Search;
use Html;

Session::checkLoginUser();
Session::checkRight(PluginWazuhConfig::$rightname, UPDATE);
Plugin::load(PluginConfig::APP_CODE);

Html::header(
    PluginWazuhConfig::getTypeName(2),
    $_SERVER['PHP_SELF'],
    'config',
    '\\GlpiPlugin\\Wazuh\\PluginWazuhMenu',
    'config'
);

Search::show('GlpiPlugin\\Wazuh\\PluginWazuhConfig');

Html::footer();

