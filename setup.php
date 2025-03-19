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

use GlpiPlugin\Wazuh\PluginConfig;
use GlpiPlugin\Wazuh\Logger;
use GlpiPlugin\Wazuh\Computer;
use GlpiPlugin\Wazuh\NetworkDevice;
use Glpi\Plugin\Hooks;
use GlpiPlugin\Wazuh\PluginWazuhMenu;

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

    $PLUGIN_HOOKS[Hooks::CSRF_COMPLIANT][PluginConfig::APP_CODE] = true;
    
    
    if (Session::haveRight('config', UPDATE)) {
        $PLUGIN_HOOKS[Hooks::CONFIG_PAGE][PluginConfig::APP_CODE] = 'front/config.php';
        Logger::addNotice(__FUNCTION__ . " plugin configuration registered.");

        $PLUGIN_HOOKS[Hooks::USE_MASSIVE_ACTION][PluginConfig::APP_CODE] = true;
        
    }
    
    Plugin::registerClass('GlpiPlugin\\Wazuh\\ServerConnection', [
      'addtabon' => ['Entity'],
      'linkuser_types' => true,
      'linkgroup_types' => true,
      'notificationtemplates_types' => true,
      'document_types' => true,
      'ticket_types' => true,
      'helpdesk_visible_types' => true,
   ]);

//
//   if (Session::haveRight('config', READ)) {
//        Logger::addNotice(__FUNCTION__ . " Rights session OK.");
//      $PLUGIN_HOOKS['menu_toadd']['wazuh'] = ['admin' => 'PluginWazuhMenu'];
      
      
//      $PLUGIN_HOOKS['submenu_entry']['wazuh']['options']['serverconnection'] = [
//         'title' => __('Server Connections', 'wazuh'),
//         'page'  => '/plugins/wazuh/front/serverconnection.php',
//         'links' => [
//            'search' => '/plugins/wazuh/front/serverconnection.php',
//            'add'    => '/plugins/wazuh/front/serverconnection.form.php'
//         ]
//      ];
//   } else {
//        Logger::addWarning(__FUNCTION__ . " Bad session rights.");
//   }
    
    
    if (Session::getLoginUserID()) {
        \Plugin::registerClass(\GlpiPlugin\Wazuh\Computer::class, [
            'addtabon' => ['Computer']
        ]);

        \Plugin::registerClass(\GlpiPlugin\Wazuh\NetworkDevice::class, [
            'addtabon' => ['NetworkEquipment']
        ]);

        $PLUGIN_HOOKS['menu_toadd'][PluginConfig::APP_CODE] = [
            'config' => 'GlpiPlugin\Wazuh\ServerConnection',
        ];
    }
    
    $PLUGIN_HOOKS['menu_toadd'][PluginConfig::APP_CODE] = ['admin' => '\GlpiPlugin\\Wazuh\PluginWazuhMenu'];
    
    
    $PLUGIN_HOOKS[Hooks::ADD_CSS][PluginConfig::APP_CODE] = ['css/wazuh.css'];
    $PLUGIN_HOOKS[Hooks::ADD_JAVASCRIPT][PluginConfig::APP_CODE] = ['js/wazuh.js'];
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
        'license'        => 'https://github.com/initiativa/Wazuh?tab=GPL-3.0-1-ov-file',
        'homepage'       => 'https://github.com/initiativa/Wazuh',
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
        echo __('Installed / not configured', PluginConfig::APP_CODE);
    }
    return false;
}


