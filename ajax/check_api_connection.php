<?php
include('../../../inc/includes.php');

use Glpi\Application\View\TemplateRenderer;
use GlpiPlugin\Wazuh\Logger;

Session::checkLoginUser();

$wazuh_server = $_POST['url'];
$api_port = $_POST['port'];
$api_user = $_POST['username'];
$api_password = $_POST['password'];
$api_suffix = $_POST['suffix'];

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
curl_close($ch);

Logger::addDebug(json_encode($_POST));
Logger::addDebug("Authentication attempt to Wazuh API: $status_code, URL: $wazuh_server:$api_port$api_suffix");

header('Content-Type: application/json');
if ($curl_error) {
    Logger::addDebug("cURL Error: $curl_error");
    echo json_encode(['success' => false, 'message' => $curl_error]);
    return;
}

if ($status_code != 200) {
    Logger::addDebug("Auth Response: $response");

    echo json_encode(['success' => false, 'status_code' => $status_code]);
    return;
}

echo json_encode([
    'success' => true,
    'status' => 'success',
    'message' => __('Connection completed', 'wazuh')
]);