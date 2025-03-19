<?php
require_once ("../../../inc/includes.php");
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

use GlpiPlugin\Wazuh\PluginConfig;
use GlpiPlugin\Wazuh\Logger;
use GlpiPlugin\Wazuh\ServerConnection;
use Search;
use Html;
use Session;

    echo 'ALL RIGHT';

    Logger::addDebug("DISPLAY11111");

Session::checkLoginUser();
Session::checkRight("config", UPDATE);
Plugin::load(PluginConfig::APP_CODE);

    Html::header(ServerConnection::getTypeName(), $_SERVER['PHP_SELF'], "plugins", ServerConnection::class, []);


// Sprawdzenie uprawnień
Session::checkRight("config", READ);
    Logger::addDebug("DISPLAY1");

    
$item = new ServerConnection();

// Obsługa formularza (zapis, usuwanie itp.)
if (isset($_POST["add"])) {
    $item->check(-1, CREATE, $_POST);
    $item->add($_POST);
    Html::back();
} else if (isset($_POST["update"])) {
    $item->check($_POST["id"], UPDATE);
    $item->update($_POST);
    Html::back();
} else if (isset($_POST["delete"])) {
    $item->check($_POST["id"], DELETE);
    $item->delete($_POST);
    $item->redirectToList();
}

Html::header(ServerConnection::getTypeName(), $_SERVER['PHP_SELF'], "config", "pluginwazuhmenu");

if (isset($_GET["id"])) {
    Logger::addDebug("DISPLAY1");
    $item->display(['id' => $_GET["id"]]);
} else {
    Logger::addDebug("DISPLAY2");
    $item->display();
}

Html::footer();
