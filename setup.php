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

require_once (PLUGIN_WAZUH_DIR .  "/vendor/autoload.php");
use src\PluginConfig;
use GlpiPlugin\Wazuh\Computer;
//use GlpiPlugin\Wazuh\PluginConfig;

define('PLUGIN_WAZUH_VERSION', PluginConfig::loadVersionNumber());

// Minimal GLPI version, inclusive
define("PLUGIN_WAZUH_MIN_GLPI_VERSION", "10.0.0");
// Maximum GLPI version, exclusive
define("PLUGIN_WAZUH_MAX_GLPI_VERSION", "10.0.99");


/**
 * Init hooks of the plugin.
 * REQUIRED
 *
 * @return void
 */
function plugin_init_wazuh()
{
    global $PLUGIN_HOOKS;

    $PLUGIN_HOOKS['csrf_compliant'][PluginConfig::APP_NAME] = true;
    
    if (Session::haveRight('config', UPDATE)) {
        $PLUGIN_HOOKS['config_page'][PluginConfig::APP_NAME] = 'front/config.php';
    }
    
    if (Session::getLoginUserID()) {
        \Plugin::registerClass(Computer::class, [
            'addtabon' => ['Computer']
        ]);

        \Plugin::registerClass(\GlpiPlugin\Wazuh\NetworkDevice::class, [
            'addtabon' => ['NetworkEquipment']
        ]);

//        Plugin::registerClass('PluginWazuhComputer', [
//            'addtabon' => ['Computer']
//        ]);
//      Plugin::registerClass('src\Computer', ['addtabon' => ['Computer']]);
//      Plugin::registerClass('src\NetworkDevice', ['addtabon' => ['NetworkDevice']]);

        $PLUGIN_HOOKS['menu_toadd'][PluginConfig::APP_NAME] = [
            'tools' => 'src\\Menu'
        ];
    }
}


/**
 * Get the name and the version of the plugin
 * REQUIRED
 *
 * @return array
 */
function plugin_version_wazuh()
{
    return [
        'name'           => PluginConfig::APP_NAME,
        'version'        => PluginConfig::loadVersionNumber(),
        'author'         => '<a href="http://www.initiativa.it">Initiativa</a>',
        'license'        => '',
        'homepage'       => '',
        'requirements'   => [
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
function plugin_wazuh_check_prerequisites()
{
    return true;
}

/**
 * Check configuration process
 *
 * @param boolean $verbose Whether to display message on failure. Defaults to false
 *
 * @return boolean
 */
function plugin_wazuh_check_config($verbose = false)
{
    if (true) { // Your configuration check
        return true;
    }

    if ($verbose) {
        echo __('Installed / not configured', 'Wazuh');
    }
    return false;
}
