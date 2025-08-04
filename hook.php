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

//require_once (PLUGIN_WAZUH_DIR .  "/vendor/autoload.php");

use GlpiPlugin\Wazuh\Logger;
use GlpiPlugin\Wazuh\PluginConfig;
use GlpiPlugin\Wazuh\Connection;
use GlpiPlugin\Wazuh\ComputerTab;
use GlpiPlugin\Wazuh\NetworkEqTab;

/**
 * Plugin install process
 *
 * @return boolean
 */
function plugin_wazuh_install() {
    Logger::addNotice(__FUNCTION__ . " Installing " . PLUGIN_WAZUH_VERSION);


    $version = getOldVersion();
    Logger::addDebug(__FUNCTION__ . " Version: " . $version);
    
    $migration = new \Migration(PLUGIN_WAZUH_VERSION);
    $migration->displayMessage("Migrating tables to " . PLUGIN_WAZUH_VERSION);

    \GlpiPlugin\Wazuh\Connection::install($migration, $version);
    \GlpiPlugin\Wazuh\PluginWazuhAgent::install($migration, $version);
    \GlpiPlugin\Wazuh\WazuhAgentAssetsRelation::install($migration);
    \GlpiPlugin\Wazuh\ComputerTab::install($migration, $version);
    \GlpiPlugin\Wazuh\NetworkEqTab::install($migration, $version);
    \GlpiPlugin\Wazuh\ComputerAlertsTab::install($migration, $version);
    \GlpiPlugin\Wazuh\NetworkEqAlertsTab::install($migration, $version);

    \GlpiPlugin\Wazuh\WazuhProfile::initProfile();

    $migration->executeMigration();
    return true;
}

/**
 * Plugin upgrade process
 * @param type $old_version
 * @return bool
 */
function plugin_myplugin_upgrade($old_version) {
    Logger::addNotice(__FUNCTION__ . " ############# Upgrading from $old_version.");

    return true;
}

/**
 * Plugin uninstall process
 *
 * @return boolean
 */
function plugin_wazuh_uninstall() {
    Logger::addNotice(__FUNCTION__ . " Uninstalling.");
    
    $migration = new Migration(PLUGIN_WAZUH_VERSION);
    $migration->displayMessage("Uninstalling tables from " . PLUGIN_WAZUH_VERSION);
    
    \GlpiPlugin\Wazuh\PluginWazuhAgent::uninstall($migration);
    \GlpiPlugin\Wazuh\Connection::uninstall($migration);
    \GlpiPlugin\Wazuh\WazuhAgentAssetsRelation::uninstall($migration);
    \GlpiPlugin\Wazuh\ComputerTab::uninstall($migration);
    \GlpiPlugin\Wazuh\NetworkEqTab::uninstall($migration);
    \GlpiPlugin\Wazuh\ComputerAlertsTab::uninstall($migration);
    \GlpiPlugin\Wazuh\NetworkEqAlertsTab::uninstall($migration);

    return true;
}


function plugin_wazuh_getDropdown()
{
    $plugin = new Plugin();

    if ($plugin->isActivated(PluginConfig::APP_CODE)) {
        return [
            Connection::class => Connection::getTypeName(Session::getPluralNumber()),
            ComputerTab::class => "Computer " . ComputerTab::getTypeName(Session::getPluralNumber()),
            NetworkEqTab::class => "Network Eq " . NetworkEqTab::getTypeName(Session::getPluralNumber()),
        ];
    }

    return [];
}

function getOldVersion(): string | false {
    $plugin = new \Plugin();
    
    if ($plugin->getFromDBbyDir(PluginConfig::APP_CODE)) {
        return $plugin->fields['version'];
    }
    return false;
}
