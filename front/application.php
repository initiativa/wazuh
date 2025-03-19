<?php

include('../../../inc/includes.php');

Html::header(
        \GlpiPlugin\Wazuh\PluginConfig::APP_CODE,
        $_SERVER['PHP_SELF'],
        "config",
        \GlpiPlugin\Wazuh\ServerConnection::class,
        \GlpiPlugin\Wazuh\PluginConfig::APP_CODE);

if (\GlpiPlugin\Wazuh\ServerConnection::canView()) {
    Search::show(\GlpiPlugin\Wazuh\ServerConnection::class);
    Html::footer();
} else {
    Html::displayRightError();
    Html::helpFooter();
}