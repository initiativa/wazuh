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

use src\Logger;
use src\PluginConfig;
use GlpiPlugin\Wazuh\ServerConnection;

/**
 * Plugin install process
 *
 * @return boolean
 */
function plugin_wazuh_install()
{
    Logger::addWarning(__FUNCTION__ . " Installing.");
    \GlpiPlugin\Wazuh\Database::initTables();
    \GlpiPlugin\Wazuh\ServerConnection::createTable();
    
   $migration = new \Migration(2);
   \GlpiPlugin\Wazuh\Profile::initProfile();
   \GlpiPlugin\Wazuh\Profile::createFirstAccess($_SESSION['glpiactiveprofile']['id']);
   $migration->executeMigration();

    return true;
}

function plugin_myplugin_upgrade($old_version) {
    Logger::addWarning(__FUNCTION__ . " Upgrading.");
    
}

/**
 * Plugin uninstall process
 *
 * @return boolean
 */
function plugin_wazuh_uninstall()
{
    Logger::addWarning(__FUNCTION__ . " Uninstalling.");
    \GlpiPlugin\Wazuh\Database::dropTables();
    \GlpiPlugin\Wazuh\ServerConnection::dropTable();
    return true;
}

function get_wazuh_menu()
    {
    return [
        'title' => PluginConfig::APP_NAME,
        'page' => '/plugins/wazuh/front/index.php',
        'icon' => 'ti-shield',
    ];
}

function plugin_wazuh_getDropdown()
{
    $plugin = new Plugin();

    if ($plugin->isActivated('wazuh')) {
        Logger::addWarning(__FUNCTION__ . " Dropdown should exist.");
        return [
            '\GlpiPlugin\Wazuh\ServerConnection' => \GlpiPlugin\Wazuh\ServerConnection::getTypeName(Session::getPluralNumber()),
        ];
    }

    return [];
}

