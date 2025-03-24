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

use DBConnection;
use CommonDBRelation;
use CommonGLPI;
use Migration;
/**
 * Relation between WazuhAgent and Glpi Assets
 *
 * @author w-tomasz
 */
class WazuhAgentAssetsRelation extends CommonDBRelation {

    static $itemtype_1 = 'PluginWazuhAgent';
    static $items_id_1 = 'pluginwazuhagent_id'; // Foreign key to your class
    static $table_name = 'glpi_plugin_wazuh_agentassets';

    static function getTypeName($nb = 0) {
        return _n('Agent assets rel', 'Agent assets rel', $nb);
    }

    /**
     * Get the tab name for the item
     * @param CommonGLPI $item
     * @param integer $withtemplate
     * @return string
     */
    #[\Override]
    function getTabNameForItem(CommonGLPI $item, $withtemplate = 0) {
        if ($item->getType() == 'Computer' || $item->getType() == 'NetworkEquipment') {
            return self::getTypeName(2);
        } else if ($item->getType() == 'PluginWazuhAgent') {
            return _n('Associated item', 'Associated items', Session::getPluralNumber());
        }
        return '';
    }

    /**
     * Display content of the tab
     * @param CommonGLPI $item
     * @param integer $tabnum
     * @param integer $withtemplate
     * @return boolean
     */
    #[\Override]
    static function displayTabContentForItem(CommonGLPI $item, $tabnum = 1, $withtemplate = 0) {
        if ($item->getType() == 'Computer' || $item->getType() == 'NetworkEquipment') {
            self::showForItem($item);
        } else if ($item->getType() == 'PluginWazuhAgent') {
            self::showItems($item);
        }
        return true;
    }

    /**
     * Display linked items for a given GLPI asset
     * @param CommonGLPI $item The GLPI asset (Computer or NetworkEquipment)
     * @return bool
     */
    static function showForItem(CommonGLPI $item) {
        global $DB;

        $itemtype = $item->getType();
        $items_id = $item->getID();

        if (!$item->can($items_id, READ)) {
            return false;
        }

        $relation = new self();
        $table = $relation->getTable();

        // Get all your custom items linked to this GLPI asset
        $criteria = [
            'SELECT' => ['glpi_plugin_wazuh_pluginwazuhagents.*'],
            'FROM' => $table,
            'LEFT JOIN' => [
                'glpi_plugin_wazuh_pluginwazuhagents' => [
                    'ON' => [
                        $table => 'pluginwazuhagent_id',
                        'glpi_plugin_wazuh_pluginwazuhagents' => 'id'
                    ]
                ]
            ],
            'WHERE' => [
                $table . '.itemtype' => $itemtype,
                $table . '.items_id' => $items_id
            ],
            'ORDER' => 'glpi_plugin_wazuh_pluginwazuhagents.name'
        ];

        $result = $DB->request($criteria);
        $number = count($result);

        // Display results in a table
        $rand = mt_rand();

        if ($number > 0) {
            $customClass = new PluginWazuhAgent();

            echo "<div class='spaced'>";
            if ($number > 0) {
                Html::openMassiveActionsForm('mass' . __CLASS__ . $rand);
                $massiveactionparams = [
                    'num_displayed' => min($number, $_SESSION['glpilist_limit']),
                    'container' => 'mass' . __CLASS__ . $rand
                ];
                Html::showMassiveActions($massiveactionparams);
            }

            echo "<table class='tab_cadre_fixehov'>";
            echo "<tr class='noHover'><th colspan='" . ($number > 0 ? 3 : 2) . "'>" .
            __('Associated Agents', 'wazuh') . "</th></tr>";

            if ($number > 0) {
                echo "<tr>";
                echo "<th width='10'>" . Html::getCheckAllAsCheckbox('mass' . __CLASS__ . $rand) . "</th>";
                echo "<th>" . __('Name') . "</th>";
                echo "<th>" . __('Status') . "</th>";
                echo "</tr>";

                foreach ($result as $data) {
                    echo "<tr class='tab_bg_1'>";
                    echo "<td width='10'>";
                    Html::showMassiveActionCheckBox(__CLASS__, $data['id']);
                    echo "</td>";
                    echo "<td><a href='" . $customClass->getLinkURL() . "?id=" . $data['id'] . "'>" . $data['name'] . "</a></td>";
                    echo "<td>" . $customClass->getStatus($data['status']) . "</td>";
                    echo "</tr>";
                }
            } else {
                echo "<tr><th colspan='2'>" . __('No associated agents', 'wazuh') . "</th></tr>";
            }
            echo "</table>";

            if ($number > 0) {
                $massiveactionparams['ontop'] = false;
                Html::showMassiveActions($massiveactionparams);
                Html::closeForm();
            }
            echo "</div>";
        }

        return true;
    }

    public static function getTable($classname = null) {
//        if ($classname === null) {
//            $classname = get_called_class();
//        }
//
//        if (!class_exists($classname) || $classname::$notable) {
//            return '';
//        }
//
//        if (!isset(self::$tables_of[$classname]) || empty(self::$tables_of[$classname])) {
//            self::$tables_of[$classname] = (new DbUtils())->getExpectedTableNameForClass($classname);
//        }
//
//        return self::$tables_of[$classname];
        return static::$table_name;
    }

    static function install(Migration $migration) {
        global $DB;
        
        $default_charset   = DBConnection::getDefaultCharset();
        $default_collation = DBConnection::getDefaultCollation();
        $default_key_sign  = DBConnection::getDefaultPrimaryKeySignOption();

        $table = self::$table_name;

        if (!$DB->tableExists($table)) {
            $migration->displayMessage("Installing $table");
            
            $query = "CREATE TABLE `$table` (
                  `id` int $default_key_sign NOT NULL AUTO_INCREMENT,
                  `pluginwazuhagent_id` int $default_key_sign NOT NULL DEFAULT '0',
                  `items_id` int $default_key_sign NOT NULL DEFAULT '0',
                  `itemtype` varchar(100) COLLATE $default_collation NOT NULL,
                  `date_creation` timestamp DEFAULT CURRENT_TIMESTAMP,
                  `date_mod` timestamp DEFAULT CURRENT_TIMESTAMP,
                  PRIMARY KEY (`id`),
                  KEY `pluginwazuhagent_id` (`pluginwazuhagent_id`),
                  KEY `item` (`itemtype`,`items_id`)
                ) ENGINE=InnoDB DEFAULT CHARSET=$default_charset COLLATE=$default_collation";
            $DB->query($query) or die("Error creating relation $table");
        }

        return true;
    }
    
    static function uninstall(Migration $migration) {
      global $DB;
      
      $table = self::getTable();
      
      $migration->displayMessage("Uninstalling $table");
      $migration->dropTable($table);
      
      return true;
   }

    
}
