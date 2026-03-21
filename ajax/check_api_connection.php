<?php
include('../../../inc/includes.php');

use GlpiPlugin\Wazuh\Connection;
use GlpiPlugin\Wazuh\PluginLogger;

Session::checkLoginUser();
Session::checkCSRF($_POST, true);
Session::checkRight(Connection::$rightname, READ);

$connection = Connection::getById($_POST['connid']);
if ($connection) {

    $wazuh_server = $connection->getField('server_url');
    $api_port = $connection->getField('api_port');
    $api_user = $connection->getField('api_username');
    $api_password = (new GLPIKey())->decrypt($connection->getField('api_password'));
    $api_suffix = '/security/user/authenticate';

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, "$wazuh_server:$api_port$api_suffix");
    curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type: application/json'));
    curl_setopt($ch, CURLOPT_USERPWD, "$api_user:$api_password");
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 10);
    curl_setopt($ch, CURLOPT_TIMEOUT, 10);
    curl_setopt($ch, CURLOPT_POSTFIELDS, "{}"); // Empty JSON body

    $response = curl_exec($ch);
    $curl_error = curl_error($ch);
    $status_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
//    curl_close($ch);

    PluginLogger::debug(json_encode($_POST));
    PluginLogger::debug("Authentication attempt to Wazuh API: $status_code, URL: $wazuh_server:$api_port$api_suffix");

    header('Content-Type: application/json');
    if ($curl_error) {
        PluginLogger::debug("cURL Error: $curl_error");
        echo json_encode(['success' => false, 'message' => $curl_error]);
        return;
    }

    if ($status_code != 200) {
        PluginLogger::debug("Auth Response: $response");

        echo json_encode(['success' => false, 'status_code' => $status_code]);
        return;
    }

    echo json_encode([
        'success' => true,
        'status' => 'success',
        'message' => __('Connection completed', 'wazuh')
    ]);
    return;
}

echo json_encode(['success' => false, 'status_code' => 404]);
