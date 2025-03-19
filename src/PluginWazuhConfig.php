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

use CommonDBTM;
use Migration;
/**
 * Description of PluginWazuhConfig
 *
 * @author w-tomasz
 */

class PluginWazuhConfig extends CommonDBTM {
   static $rightname = 'config';
   
   /**
    * @param object $migration
    * @return boolean
    */
   static function install(Migration $migration) {
      global $DB;
      
      $table = self::getTable();
      
      if (!$DB->tableExists($table)) {
         $migration->displayMessage("Installing $table");
         
         $query = "CREATE TABLE IF NOT EXISTS `$table` (
                     `id` int UNSIGNED NOT NULL AUTO_INCREMENT,
                     `server_url` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL,
                     `api_port` varchar(5) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '55000',
                     `api_username` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL,
                     `api_password` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL,
                     `sync_interval` int(11) NOT NULL DEFAULT '86400',
                     `last_sync` timestamp DEFAULT NULL,
                     PRIMARY KEY (`id`)
                  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci";
         $DB->query($query) or die("Error creating $table table");
         
         $DB->insert($table, [
            'id'          => 1,
            'server_url'  => '192.168.0.2',
            'api_port'    => '55000',
            'api_username' => 'wazuh-wui',
            'api_password' => 'MyS3cr37P450r.*-',
            'sync_interval' => 86400
         ]);
      }
      
      return true;
   }
   
   /**
    * @param object $migration
    * @return boolean
    */
   static function uninstall(Migration $migration) {
      global $DB;
      
      $table = self::getTable();
      
      $migration->displayMessage("Uninstalling $table");
      $migration->dropTable($table);
      
      return true;
   }
   
   /**
    * @param integer $ID
    * @param array $options
    * @return boolean
    */
   function showForm($ID, array $options = []) {
      global $CFG_GLPI;
      
      $this->getFromDB($ID);
      $this->showFormHeader($options);
      
      echo "<tr class='tab_bg_1'>";
      echo "<td>" . __('Wazuh Server URL', 'wazuh') . "</td>";
      echo "<td>";
      echo Html::input('server_url', ['value' => $this->fields['server_url'], 'class' => 'form-control']);
      echo "</td>";
      echo "<td>" . __('API Port', 'wazuh') . "</td>";
      echo "<td>";
      echo Html::input('api_port', ['value' => $this->fields['api_port'], 'class' => 'form-control']);
      echo "</td>";
      echo "</tr>";
      
      echo "<tr class='tab_bg_1'>";
      echo "<td>" . __('API Username', 'wazuh') . "</td>";
      echo "<td>";
      echo Html::input('api_username', ['value' => $this->fields['api_username'], 'class' => 'form-control']);
      echo "</td>";
      echo "<td>" . __('API Password', 'wazuh') . "</td>";
      echo "<td>";
      echo Html::input('api_password', ['type' => 'password', 'value' => $this->fields['api_password'], 'class' => 'form-control']);
      echo "</td>";
      echo "</tr>";
      
      echo "<tr class='tab_bg_1'>";
      echo "<td>" . __('Synchronization Interval (seconds)', 'wazuh') . "</td>";
      echo "<td>";
      echo Html::input('sync_interval', ['type' => 'number', 'value' => $this->fields['sync_interval'], 'class' => 'form-control']);
      echo "</td>";
      echo "<td>" . __('Last Synchronization', 'wazuh') . "</td>";
      echo "<td>";
      if (!empty($this->fields['last_sync'])) {
         echo Html::convDateTime($this->fields['last_sync']);
      } else {
         echo __('Never', 'wazuh');
      }
      echo "</td>";
      echo "</tr>";
      
      $this->showFormButtons($options);
      
      echo "<div class='center'>";
      echo "<a class='btn btn-primary' href='" . $CFG_GLPI['root_doc'] . 
         "/plugins/wazuh/front/agent.sync.php'>" . 
         __('Synchronize Now', 'wazuh') . "</a>";
      echo "</div>";
      
      return true;
   }
}