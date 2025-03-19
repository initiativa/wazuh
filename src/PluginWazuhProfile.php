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

/**
 * Description of PluginWazuhProfile
 *
 * @author w-tomasz
 */

class PluginWazuhProfile extends CommonDBTM {
   static $rightname = '';
   
   const RIGHT_NONE = 0;
   const RIGHT_READ = 1;
   const RIGHT_WRITE = 2;
   
   /**
    * Funkcja instalacji tabeli uprawnień
    * @param object $migration
    * @return boolean
    */
   static function install(Migration $migration) {
      global $DB;
      
      $table = self::getTable();
      
      if (!$DB->tableExists($table)) {
         $migration->displayMessage("Installing $table");
         
         $query = "CREATE TABLE IF NOT EXISTS `$table` (
                     `id` int(11) NOT NULL AUTO_INCREMENT,
                     `profiles_id` int(11) NOT NULL DEFAULT '0',
                     `plugin_wazuh_agent` char(1) COLLATE utf8_unicode_ci DEFAULT NULL,
                     PRIMARY KEY (`id`),
                     KEY `profiles_id` (`profiles_id`)
                  ) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci";
         $DB->query($query) or die("Error creating $table table");
      }
      
      self::initProfile();
      
      return true;
   }
   
   /**
    * Funkcja odinstalowania tabeli uprawnień
    * @param object $migration
    * @return boolean
    */
   static function uninstall(Migration $migration) {
      global $DB;
      
      $table = self::getTable();
      
      $migration->displayMessage("Uninstalling $table");
      $migration->dropTable($table);
      
      // Usunięcie uprawnień z profili
      $profileRight = new ProfileRight();
      foreach (self::getAllRights() as $right) {
         $profileRight->deleteByCriteria(['name' => $right['field']]);
      }
      
      return true;
   }
   
   /**
    * Funkcja zwracająca wszystkie uprawnienia
    * @param boolean $all
    * @return array
    */
   static function getAllRights($all = false) {
      $rights = [
         [
            'itemtype' => 'PluginWazuhAgent',
            'label'    => __('Wazuh Agents', 'wazuh'),
            'field'    => 'plugin_wazuh_agent',
            'rights'   => [
               READ  => __('Read'),
               UPDATE => __('Update')
            ]
         ]
      ];
      
      return $rights;
   }
   
   /**
    * Funkcja inicjalizacji profili
    * @param integer $profiles_id
    */
   static function initProfile() {
      global $DB;
      
      $profile = new Profile();
      
      // Dodaj uprawnienia dla super-administratora
      $profile->getFromDB(4); // Super-Admin ID
      
      $rights = self::getAllRights();
      foreach ($rights as $right) {
         self::addDefaultProfileInfos(
            $profile->fields['id'],
            [$right['field'] => ALLSTATUS]
         );
      }
      
      // Dodaj uprawnienia dla innych profili
      foreach ($profile->find() as $prof) {
         self::addDefaultProfileInfos($prof['id'], [], true);
      }
   }
   
   /**
    * @param integer $profiles_id
    * @param array $rights
    * @param boolean $drop_existing
    */
   static function addDefaultProfileInfos($profiles_id, $rights = [], $drop_existing = false) {
      global $DB;
      
      $profileRight = new ProfileRight();
      $dbu = new DbUtils();
      
      foreach (self::getAllRights() as $right) {
         if ($drop_existing) {
            $profileRight->deleteByCriteria([
               'profiles_id' => $profiles_id,
               'name'        => $right['field']
            ]);
         }
         
         if (!$dbu->countElementsInTable(
            'glpi_profilerights',
            [
               'profiles_id' => $profiles_id,
               'name'        => $right['field']
            ]
         )) {
            $right_value = isset($rights[$right['field']]) ? $rights[$right['field']] : 0;
            $profileRight->add([
               'profiles_id' => $profiles_id,
               'name'        => $right['field'],
               'rights'      => $right_value
            ]);
         }
      }
   }
}