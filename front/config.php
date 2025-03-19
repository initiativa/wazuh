<?php


use Glpi\Application\View\TemplateRenderer;

require_once ("../../../inc/includes.php");

use GlpiPlugin\Wazuh\PluginConfig;
use GlpiPlugin\Wazuh\Logger;
use GlpiPlugin\Wazuh\ServerConnection;
use Search;
use Html;

Session::checkLoginUser();
Session::checkRight("config", UPDATE);
Plugin::load(PluginConfig::APP_CODE);


if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['server_name'])) {
//    Session::checkCSRF($_POST);

//    $csrf_valid = Session::validateCSRF($_POST);
//    Logger::addDebug('CSRF validation result: ' . ($csrf_valid ? 'true' : 'false') . ' :POST: ' . $_POST['_glpi_csrf_token']);
//    Logger::addDebug(Logger::implodeWithKeys($_SESSION['glpicsrftokens']));
    $item = ServerConnection::createFromPostData($_POST);

    $item_id = $item->add($item->fields);
    if ($item_id === false) {
        Logger::addError(__FILE__ . " Error while adding data to db: " . Logger::implodeWithKeys($item->fields));
        Session::addMessageAfterRedirect(sprintf(__('server_adding_connection_error', PluginConfig::APP_CODE), $item->name),
                true,
                ERROR);
    } else {
        Logger::addDebug(__FILE__ . " Server connection added to database: " . Logger::implodeWithKeys($item->fields));
        Session::addMessageAfterRedirect(sprintf(__('server_connection_added', PluginConfig::APP_CODE), $item->name),
                true,
                INFO);
    }
    Html::redirect(Plugin::getWebDir(\GlpiPlugin\Wazuh\PluginConfig::APP_CODE) . '/front/config.php');

} else if (isset($_POST['delete'])) {
   Logger::addDebug(__FILE__ . " Deleting: " . $_POST['id']);
   $item = new ServerConnection();
   $item->check($_POST['id'], DELETE);
   $item->delete($_POST);
   $item->redirectToList();
} else {
    Logger::addDebug('Standard config.');
    global $DB;

    $connection = new ServerConnection();
    $connections = $connection->find(['enabled' => 1]);
//    Logger::addDebug(Logger::implodeWithKeys($connections));

    Html::header(
            ServerConnection::getTypeName(Session::getPluralNumber()),
            $_SERVER['PHP_SELF'],
            "config",
            "GlpiPlugin\\Wazuh\Menu"
    );

  if (ServerConnection::canCreate()) {
        echo "<a class='btn btn-primary' href='serverconnection.form.php'>";
        echo "<i class='ti ti-plus me-1'></i>";
        echo __('Add', PluginConfig::APP_CODE);
        echo "</a>";
    }    

    Search::show(ServerConnection::class);
//    $csrf_token = Session::getNewCSRFToken();
//    $twig = TemplateRenderer::getInstance();
//    $twig->display('@wazuh/config.form.twig', [
//        'APP_NAME' => PluginConfig::APP_CODE,
//        'APP_VER' => PluginConfig::loadVersionNumber(),
//        'csrf_token' => $csrf_token,
//        'connections' => $connections
//    ]);

    Html::footer();
}

