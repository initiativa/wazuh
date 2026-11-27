<?php
/**
 * Target of the search form embedded in the Wazuh device tabs (trashbin toggle, criteria, sort, paging).
 * Stores the search state for this device and returns to the device page with the same tab open,
 * instead of leaving the device for the plugin's own list page.
 */

use Glpi\Exception\Http\AccessDeniedHttpException;
use Glpi\Exception\Http\BadRequestHttpException;
use GlpiPlugin\Wazuh\ComputerAlertsTab;
use GlpiPlugin\Wazuh\ComputerTab;
use GlpiPlugin\Wazuh\NetworkEqAlertsTab;
use GlpiPlugin\Wazuh\NetworkEqTab;

Session::checkLoginUser();

$itemtype = $_GET['itemtype'] ?? '';
if (!in_array($itemtype, [ComputerTab::class, ComputerAlertsTab::class, NetworkEqTab::class, NetworkEqAlertsTab::class], true)) {
    throw new BadRequestHttpException();
}
Session::checkRight($itemtype::$rightname, READ);

$device_id = (int) ($_GET['device_id'] ?? 0);
$device = $itemtype::newDeviceInstance();
if (!$device->can($device_id, READ)) {
    throw new AccessDeniedHttpException();
}

$params = $_GET;
unset($params['itemtype'], $params['device_id']);

$params = $itemtype::getDeviceSearchParams($device_id, $params);
Search::manageParams($itemtype, $params);
$_SESSION['plugin_wazuh_tabsearch'][$itemtype] = $device_id;

Html::redirect($device::getFormURLWithID($device_id) . '&forcetab=' . rawurlencode($itemtype . '$1'));
