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

use CommonGLPI;
use Session;

/**
 * Description of PluginWazuhMenu
 *
 * @author w-tomasz
 */

class PluginWazuhMenu extends CommonGLPI {
   static $rightname = 'plugin_wazuh_agent';
   
   /**
    * Funkcja zwracająca nazwę
    * @param integer $nb
    * @return string
    */
   static function getTypeName($nb = 0) {
      return __('Wazuh', 'wazuh');
   }
   
   /**
    * Funkcja generująca menu
    * @return array
    */
   static function getMenuContent() {
      $menu = [];
      
      $menu['title'] = self::getTypeName();
      $menu['page'] = "/plugins/wazuh/front/agent.php";
      $menu['icon'] = "fas fa-shield-alt";
      
      //Submenus achieved with option swicher. ex: Html::header(...... 'here last swich');
      if (Session::haveRight(PluginWazuhAgent::$rightname, READ)) {
         $menu['options']['agent']['title'] = PluginWazuhAgent::getTypeName(2);
         $menu['options']['agent']['page'] = "/plugins/wazuh/front/agent.php";
         $menu['options']['agent']['icon'] = PluginWazuhAgent::getIcon();
      }
      
      if (Session::haveRight('config', UPDATE)) {
         $menu['options']['config']['title'] = __('Configuration');
         $menu['options']['config']['page'] = "/plugins/wazuh/front/config.form.php?id=1";
         $menu['options']['config']['icon'] = "fas fa-cog";
      }
      
      return $menu;
   }
}