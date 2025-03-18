<?php

include('../../../inc/includes.php');

Html::header(
        \src\PluginConfig::APP_CODE,
        $_SERVER['PHP_SELF'],
        "config",
        \GlpiPlugin\Wazuh\ServerConnection::class,
        \src\PluginConfig::APP_CODE);

if (\GlpiPlugin\Wazuh\ServerConnection::canView()) {
    Search::show(\GlpiPlugin\Wazuh\ServerConnection::class);
    Html::footer();
} else {
    Html::displayRightError();
    Html::helpFooter();
}