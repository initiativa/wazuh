<?php

include('../../../inc/includes.php');
use GlpiPlugin\Wazuh\NetworkEqTab;

global $_UPOST;

$item = new NetworkEqTab();

if (isset($_POST['id']) && isset($_POST['request_authorization'])) {
    $item->check($_POST['id'], UPDATE);
    $item->redirectToAuthorizationUrl();
} else {
    Html::requireJs('clipboard');

    if (array_key_exists('api_password', $_POST) && array_key_exists('api_password', $_UPOST)) {
        $_POST['api_password'] = $_UPOST['api_password'];
    }

    include('dbtm.common.form.php');
}

