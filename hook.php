<?php

/**
 * -------------------------------------------------------------------------
 * Wazuh plugin for GLPI
 * Copyright (C) 2025 by the Wazuh Development Team.
 * -------------------------------------------------------------------------
 *
 * MIT License
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * --------------------------------------------------------------------------
 */

if (!defined('PLUGIN_WAZUH_DIR')) {
    define('PLUGIN_WAZUH_DIR', __DIR__);
}

require_once (PLUGIN_WAZUH_DIR .  "/vendor/autoload.php");

use GlpiPlugin\Wazuh\Logger;
use GlpiPlugin\Wazuh\PluginConfig;
use GlpiPlugin\Wazuh\ServerConnection;

/**
 * Plugin install process
 *
 * @return boolean
 */
function plugin_wazuh_install() {
    Logger::addNotice(__FUNCTION__ . " Installing " . PLUGIN_WAZUH_VERSION);


    $migration = new \Migration(PLUGIN_WAZUH_VERSION);
    $migration->displayMessage("Migrating tables to " . PLUGIN_WAZUH_VERSION);

    \GlpiPlugin\Wazuh\ServerConnection::createTable();

    \GlpiPlugin\Wazuh\PluginWazuhConfig::install($migration);
    \GlpiPlugin\Wazuh\PluginWazuhAgent::install($migration);


    \GlpiPlugin\Wazuh\Profile::initProfile();
    \GlpiPlugin\Wazuh\Profile::createFirstAccess($_SESSION['glpiactiveprofile']['id']);

    $migration->executeMigration();
    return true;
}

function plugin_myplugin_upgrade($old_version) {
    Logger::addNotice(__FUNCTION__ . " Upgrading.");
    
}

/**
 * Plugin uninstall process
 *
 * @return boolean
 */
function plugin_wazuh_uninstall() {
    Logger::addNotice(__FUNCTION__ . " Uninstalling.");
    \GlpiPlugin\Wazuh\Database::dropTables();
    \GlpiPlugin\Wazuh\ServerConnection::dropTable();
    
    $migration = new Migration(PLUGIN_WAZUH_VERSION);
    $migration->displayMessage("UnMigrating tables from " . PLUGIN_WAZUH_VERSION);
    
    \GlpiPlugin\Wazuh\PluginWazuhAgent::uninstall($migration);
    \GlpiPlugin\Wazuh\PluginWazuhConfig::uninstall($migration);

    return true;
}


function plugin_wazuh_getDropdown()
{
    $plugin = new Plugin();

    if ($plugin->isActivated(PluginConfig::APP_CODE)) {
        return [
            'GlpiPlugin\Wazuh\ServerConnection' => ServerConnection::getTypeName(Session::getPluralNumber()),
        ];
    }

    return [];
}

