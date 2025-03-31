<?php

/**
 * -------------------------------------------------------------------------
 * Wazuh plugin for GLPI
 * -------------------------------------------------------------------------
 *
 * LICENSE
 *
 * This file is part of Wazuh GLPI Plugin.
 *
 * Wazuh is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * Wazuh is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Wazuh. If not, see <http://www.gnu.org/licenses/>.
 * -------------------------------------------------------------------------
 * @copyright Copyright (C) 2022 by initiativa s.r.l. - http://www.initiativa.it
 * @license   GPLv3 https://www.gnu.org/licenses/gpl-3.0.html
 * @link      https://github.com/initiativa/Wazug
 * -------------------------------------------------------------------------
 */
if (!defined('PLUGIN_WAZUH_DIR')) {
    define('PLUGIN_WAZUH_DIR', __DIR__);
}

//require_once (PLUGIN_WAZUH_DIR . "/src/PluginConfig.php");
//require_once (PLUGIN_WAZUH_DIR .  "/src/Logger.php");
//require_once (PLUGIN_WAZUH_DIR .  "/src/Menu.php");
//require_once (PLUGIN_WAZUH_DIR .  "/hook.php");

require_once (PLUGIN_WAZUH_DIR . "/vendor/autoload.php");

use GlpiPlugin\Wazuh\PluginConfig;
use GlpiPlugin\Wazuh\Logger;
use GlpiPlugin\Wazuh\ComputerTab;
use GlpiPlugin\Wazuh\WazuhNetworkDeviceTab;
use Glpi\Plugin\Hooks;
use GlpiPlugin\Wazuh\PluginWazuhMenu;
use GlpiPlugin\Wazuh\ServerConnection;

define('PLUGIN_WAZUH_VERSION', PluginConfig::loadVersionNumber());

// Minimal GLPI version, inclusive
define("PLUGIN_WAZUH_MIN_GLPI_VERSION", "10.0.11");
// Maximum GLPI version, exclusive
define("PLUGIN_WAZUH_MAX_GLPI_VERSION", "10.0.99");

/**
 * Init hooks of the plugin.
 * REQUIRED
 *
 * @return void
 */
function plugin_init_wazuh() {
    global $PLUGIN_HOOKS;

    ini_set('display_errors', 1);
    ini_set('display_startup_errors', 1);
    error_reporting(E_ALL);

    $PLUGIN_HOOKS[Hooks::CSRF_COMPLIANT][PluginConfig::APP_CODE] = true;

    if (Plugin::isPluginActive(PluginConfig::APP_CODE)) {

        if (Session::haveRight('config', UPDATE)) {
            $PLUGIN_HOOKS[Hooks::CONFIG_PAGE][PluginConfig::APP_CODE] = 'front/connection.php';
//            Logger::addNotice(__FUNCTION__ . " plugin configuration registered.");

            $PLUGIN_HOOKS[Hooks::USE_MASSIVE_ACTION][PluginConfig::APP_CODE] = true;
        }

        if (Session::getLoginUserID()) {
            plugin_wazuh_registerClasses();
        }

        $PLUGIN_HOOKS['menu_toadd'][PluginConfig::APP_CODE] = [
            'admin' => [
                'GlpiPlugin\Wazuh\PluginWazuhAgent'],
            'config' => [
                'GlpiPlugin\Wazuh\ServerConnection'
            ]
        ];

        $PLUGIN_HOOKS[Hooks::ADD_CSS][PluginConfig::APP_CODE] = ['css/wazuh.css'];
        $PLUGIN_HOOKS[Hooks::ADD_JAVASCRIPT][PluginConfig::APP_CODE] = ['js/wazuh.js'];
    }
}

function plugin_wazuh_registerClasses() {
    Plugin::registerClass(\GlpiPlugin\Wazuh\ComputerTab::class, [
        'addtabon' => ['Computer']
    ]);

    Plugin::registerClass(\GlpiPlugin\Wazuh\NetworkEqTab::class, [
        'addtabon' => ['NetworkEquipment']
    ]);
    Plugin::registerClass('GlpiPlugin\Wazuh\PluginWazuhAgent');
    Plugin::registerClass('GlpiPlugin\Wazuh\Connection');
    Plugin::registerClass('GlpiPlugin\Wazuh\ServerConnection');
//    Plugin::registerClass('GlpiPlugin\Wazuh\WazuhAgentAssetsRelation', [
//        'addtabon' => ['Computer', 'NetworkEquipment']
//    ]);
}

/**
 * Get the name and the version of the plugin
 * REQUIRED
 *
 * @return array
 */
function plugin_version_wazuh() {
    return [
        'name' => PluginConfig::APP_NAME,
        'version' => PluginConfig::loadVersionNumber(),
        'author' => '<a href="http://www.initiativa.it">Initiativa</a>',
        'license' => 'https://github.com/initiativa/Wazuh?tab=GPL-3.0-1-ov-file',
        'homepage' => 'https://github.com/initiativa/Wazuh',
        'requirements' => [
            'glpi' => [
                'min' => PLUGIN_WAZUH_MIN_GLPI_VERSION,
                'max' => PLUGIN_WAZUH_MAX_GLPI_VERSION,
            ]
        ]
    ];
}

/**
 * Check pre-requisites before install
 * OPTIONNAL, but recommanded
 *
 * @return boolean
 */
function plugin_wazuh_check_prerequisites() {
    return true;
}

/**
 * Check configuration process
 *
 * @param boolean $verbose Whether to display message on failure. Defaults to false
 *
 * @return boolean
 */
function plugin_wazuh_check_config($verbose = false) {
    if (true) { // Your configuration check
        return true;
    }

    if ($verbose) {
        echo __('Installed / not configured', PluginConfig::APP_CODE);
    }
    return false;
}
