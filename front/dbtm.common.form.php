<?php

use Glpi\Exception\Http\AccessDeniedHttpException;
use GlpiPlugin\Wazuh\PluginConfig;

if (!Plugin::isPluginActive(PluginConfig::APP_CODE)) {
    Html::displayNotFoundError();
}

if (!($item instanceof \CommonDBTM)) {
    throw new LogicException();
}

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
} else if (isset($_POST["restore"])) {
    $item->check($_POST["id"], PURGE);
    $item->restore($_POST);
    $item->redirectToList();
}

Html::header($item::getTypeName(), $_SERVER['PHP_SELF'], $item::class, $item::class, ['config']);

if (isset($_GET["id"])) {
    $item->check($_GET["id"], READ);
    $options['id'] = $_GET["id"];
    $options['show_nav_header'] = true;
    $item->display($options);
} else {
    $item->check($_GET["id"], READ);
    $item->display();
}

Html::footer();
