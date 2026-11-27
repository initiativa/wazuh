<?php
include('../../../inc/includes.php');

use Glpi\Application\View\TemplateRenderer;
use GlpiPlugin\Wazuh\PluginLogger;
use GlpiPlugin\Wazuh\Connection;

Session::checkLoginUser();
Session::checkCSRF($_POST, true);
Session::checkRight(Connection::$rightname, READ);

// per-record check (incl. the connection's entity), not only the global right
$connection = new Connection();
if ($connection->can((int) ($_POST['connid'] ?? 0), READ)) {
    $wazuh_server = $connection->getField('indexer_url');
    $api_port = $connection->getField('indexer_port');
    $api_user = $connection->getField('indexer_user');
    $api_password = (new GLPIKey())->decrypt($connection->getField('indexer_password'));
    $api_suffix = '/security/user/authenticate';

    $url = Connection::buildEndpointUrl($wazuh_server, $api_port, '/');

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type: application/json'));
    curl_setopt($ch, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
    curl_setopt($ch, CURLOPT_USERPWD, "$api_user:$api_password");
    curl_setopt_array($ch, $connection->getCurlTlsOptions());
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 10);
    curl_setopt($ch, CURLOPT_TIMEOUT, 10);

    $response = curl_exec($ch);
    $curl_error = curl_error($ch);
    $status_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
//    curl_close($ch);

    PluginLogger::debug(json_encode($_POST));
    PluginLogger::debug("Authentication attempt to Wazuh INDEXER: $status_code, URL: $url");

    // details stay in the log: the browser gets a generic result only (no port/host probing via error text)
    header('Content-Type: application/json');
    if ($curl_error) {
        PluginLogger::error("Wazuh indexer connection test failed, connection #" . $connection->getID() . ", URL: $url, cURL error: $curl_error");
        echo json_encode(['success' => false, 'message' => __('Connection failed', 'wazuh')]);
        return;
    }

    if ($status_code != 200) {
        PluginLogger::error("Wazuh indexer connection test failed, connection #" . $connection->getID() . ", URL: $url, HTTP $status_code");
        PluginLogger::debug("Auth Response: $response");
        echo json_encode(['success' => false, 'message' => __('Authentication failed', 'wazuh')]);
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

