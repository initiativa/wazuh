<?php

use GlpiPlugin\Wazuh\ComputerAlertsTab;
use GlpiPlugin\Wazuh\ComputerTab;
use GlpiPlugin\Wazuh\Logger;
use GlpiPlugin\Wazuh\NetworkEqAlertsTab;
use GlpiPlugin\Wazuh\NetworkEqTab;
use GlpiPlugin\Wazuh\PluginWazuhAgent;

include('../../../inc/includes.php');

// Check user session and rights
Session::checkLoginUser();
Session::checkRight(PluginWazuhAgent::$rightname, READ);

const page_size = 10;

// Get parameters
$itemtype = $_GET['itemtype'] ?? null;
if ($itemtype !== null) {
    $itemtype = rawurldecode($itemtype);
}
$parent_id = isset($_GET['parent_id']) ? intval($_GET['parent_id']) : 0;
$device_id = isset($_GET['device_id']) ? intval($_GET['device_id']) : 0;
$page_no = isset($_GET['page_no']) ? intval($_GET['page_no']) : 1;

if (is_null($itemtype) || $parent_id === 0 || $device_id === 0) {
    throw new \Exception('Illegal Arguments Exception.');
}

if (!($itemtype === ComputerAlertsTab::class || $itemtype === ComputerTab::class || $itemtype === NetworkEqAlertsTab::class || $itemtype === NetworkEqTab::class)) {
    throw new \Exception('Illegal Argument Exception. ' . $itemtype . ' -- ' . ComputerAlertsTab::class);
}

$params['criteria'] = [
    [
        'field' => 7,
        'searchtype' => 'equals',
        'value' => $device_id
    ],
    [
        'field' => 20,
        'searchtype' => 'equals',
        'value' => $parent_id
    ],
];

Logger::addDebug(__FILE__ . " : " . json_encode($params) . " :: " . $itemtype);
$params['list_limit'] = page_size;
$start = ($page_no -1) * page_size;
Logger::addDebug(__FILE__ . " OFFSET: $start , PAGE_NO: $page_no");

$params['start'] = $start;

$data = Search::getDatas($itemtype, $params);

global $DB;
$criteria = [
    'SELECT' => [$itemtype::getForeignKeyField() . ' as parent_id', new QueryExpression('COUNT(*) as total')],
    'FROM' => $itemtype::getTable(),
    'WHERE' => [
        $itemtype::getDeviceForeignKeyField() => $device_id,
        'is_deleted' => 0,
        $itemtype::getForeignKeyField() => ['<>', 0],
    ],
    'GROUPBY' => $itemtype::getForeignKeyField()
];

$has_child_ids = [];
$child_map = [];

$iterator = $DB->request($criteria);
foreach ($iterator as $row) {
    $has_child_ids[] = $row['parent_id'];
    $child_map[$row['parent_id']] = $row['total'];
}

$data['device_id'] = $device_id;
$data['has_child_ids'] = $has_child_ids;
$data['child_map'] = $child_map;

// Send JSON response
header('Content-Type: application/json');
echo json_encode($data);