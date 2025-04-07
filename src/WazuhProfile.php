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

if (!defined('GLPI_ROOT')) {
   die("Sorry. You can't access this file directly");
}

/**
 * Description of Profile
 *
 * @author w-tomasz
 */
class WazuhProfile extends \Profile {
    
     #[\Override]
     static function getTypeName($nb = 0) {
      return __('Wazuh Profile', 'wazuh');
   }
   
   static function initProfile() {
      $profileRight = new \ProfileRight();
      
      foreach ($_SESSION['glpiactiveprofile'] as $key => $val) {
         if (strpos($key, 'plugin_wazuh_') !== false) {
            $profileRight->deleteByCriteria(['profiles_id' => $_SESSION['glpiactiveprofile']['id'], 
                                           'name' => $key]);
         }
      }
      
      self::addDefaultProfileInfos($_SESSION['glpiactiveprofile']['id'],
                [
                    PluginWazuhAgent::$rightname => \ALLSTANDARDRIGHT,
                    Connection::$rightname => \ALLSTANDARDRIGHT
                ]
        );
    }
   
   /**
    * Adding default rights to profile
    */
   static function addDefaultProfileInfos($profiles_id, $rights) {
      $profileRight = new \ProfileRight();
      
      foreach ($rights as $right => $value) {
         if (!countElementsInTable('glpi_profilerights', ['profiles_id' => $profiles_id, 'name' => $right])) {
            $profileRight->add(['profiles_id' => $profiles_id, 'name' => $right, 'rights' => $value]);
         }
      }
   }
   
   /**
    */
   static function install(\Migration $migration) {
      self::initProfile();
   }
    
}


