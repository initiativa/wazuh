<?php

/*
 * Copyright (C) 2025 w-tomasz
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

namespace GlpiPlugin\Wazuh;

use src\PluginConfig;
use CommonGLPI;
use Session;

/**
 * Description of Menu
 *
 * @author w-tomasz
 */

class Menu extends CommonGLPI {
    static function getMenuName() {
        return __('Wazuh', 'wazuh');
    }

    public static function getMenuContent()
    {
        return [
            'title' => PluginConfig::APP_NAME,
            'page'  => '/plugins/wazuh/front/index.php',
            'icon'  => 'ti-shield',
        ];
    }

//    #[\Override]
//    static function getMenuContent() {
//        $menu = [];
//        if (Session::haveRight('plugin_wazuh', READ)) {
//            $menu['title'] = self::getMenuName();
//            $menu['page'] = '/plugins/wazuh/front/serverconnection.php';
//            $menu['icon'] = 'fas fa-shield-alt';
//
//            // Podmenu
//            $menu['options']['serverconnection'] = [
//                'title' => ServerConnection::getTypeName(Session::getPluralNumber()),
//                'page' => '/plugins/wazuh/front/serverconnection.php',
//                'icon' => 'ti ti-server'
//            ];
//        }
//        return $menu;
//    }
}