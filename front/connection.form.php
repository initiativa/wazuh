<?php

include('../../../inc/includes.php');
use GlpiPlugin\Wazuh\Connection;
use GlpiPlugin\Wazuh\PluginConfig;

$dropdown = new Connection();

if (isset($_POST['id']) && isset($_POST['request_authorization'])) {
    $dropdown->check($_POST['id'], UPDATE);
    $dropdown->redirectToAuthorizationUrl();
} else {
    Html::requireJs('clipboard');

    include(GLPI_ROOT . '/front/dropdown.common.form.php');
}

