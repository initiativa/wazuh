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

use Glpi\Application\View\TemplateRenderer;
use CommonGLPI;
use Migration;
use Computer;
use DBConnection;

if (!defined('GLPI_ROOT')) {
   die("No access.");
}

/**
 * Wazuh computer vulenrable tab
 *
 * @author w-tomasz
 */
class WazuhComputerTab extends \CommonDBChild {

    use IndexerRequestsTrait;

    public $dohistory = true;
    public static $itemtype = 'Computer';
    public static $items_id = 'computers_id';

    #[\Override]
    static function getTypeName($nb = 0) {
        return _n('Wazuh Vulnerable', 'Wazuh Vulnerabilities', $nb, PluginConfig::APP_CODE);
    }

    #[\Override]
    function getTabNameForItem(CommonGLPI $item, $withtemplate = 0) {
        if (!$withtemplate && $item instanceof Computer) {
            global $DB;
            $count = $this->countElementsForComputer($item->getID());
            return self::createTabEntry(__(PluginConfig::APP_NAME, PluginConfig::APP_CODE), $count);
        }
        return '';
    }

    private function countElementsForComputer($computers_id) {
        global $DB;

        $count = 0;
        $iterator = $DB->request([
            'COUNT' => 'count',
            'FROM' => $this->getTable(),
            'WHERE' => [Computer::getForeignKeyField() => $computers_id]
        ]);

        if (count($iterator)) {
            $data = $iterator->current();
            $count = $data['count'];
        }

        return $count;
    }

    private static function createItem($result, \Computer $computer) {
        global $DB;
        $key = $result['_id'];
        $item = new self();
        $founded = $item->find(['key' => $key]);
        
        if (count($founded) > 1) {
            throw new \RuntimeException("Founded WazuhComputerTab collection exceeded limit 1.");
        }

        $item_data = [
            'key' => $key,
            Computer::getForeignKeyField() => $computer->getID(),
            'name' => $result['_source']['vulnerability']['id'],
            'v_description' => $DB->escape($result['_source']['vulnerability']['description']),
            'v_severity' => $result['_source']['vulnerability']['severity'],
//            'v_detected' => new \DateTime($result['_source']['vulnerability']['detected_at']),
//            'v_published' => new \DateTime($result['_source']['vulnerability']['published_at']),
            'v_enum' => $result['_source']['vulnerability']['enumeration'],
            'v_category' => $result['_source']['vulnerability']['category'],
            'v_classification' => $result['_source']['vulnerability']['classification'],
            'v_reference' => $result['_source']['vulnerability']['reference'],
        ];

        if (!$founded) {
            $newId = $item->add($item_data);
        } else {
            $item->update($item_data);
        }
        
        return $item;
    }
    
    #[\Override]
    static function displayTabContentForItem(CommonGLPI $item, $tabnum = 1, $withtemplate = 0) {
        Logger::addDebug(__FUNCTION__ . " item type: " . $item->getType());
        if ($item instanceof Computer) {
            Logger::addDebug($item->fields['id']);
            $agent = PluginWazuhAgent::getByDeviceTypeAndId($item->getType(), $item->fields['id']);
            if ($agent) {
                $config = Connection::getById($agent->fields[Connection::getForeignKeyField()]);
                if ($config) {
                    static::initWazuhConnection($config->fields['indexer_url'], $config->fields['indexer_port'], $config->fields['indexer_user'], $config->fields['indexer_password']);
                    $result = static::queryVulnerabilitiesByAgentIds([$agent->fields['agent_id']]);
                    foreach ($result['data']['hits']['hits'] as $res) {
                        Logger::addDebug(json_encode($res['_source']['vulnerability']['severity']) . " -- " . json_encode($res['_id']));
                        self::createItem($res, $item);
                    }
                    $dropdown_options = [
                        'name' => 'plugin_wazuh_agents_id',
                        'value' => $agent->fields['id'],
                        'entity' => $_SESSION['glpiactive_entity'],
                        'rand' => mt_rand(),
                        'disabled' => true,
                        'width' => '30em'
                    ];
//                    PluginWazuhAgent::dropdown($dropdown_options);

                    $params = [
                        'criteria' => [
                            [
                                'field' => 4, // ID pola v_severity
                                'searchtype' => 'all',
                                'value' => ''
                            ]
                        ],
                        'sort' => 4,
                        'order' => 'DESC'
                    ];

                    \Search::show(WazuhComputerTab::class, $params);
                }
            } else {
                $dropdown_options = [
                    'name' => 'plugin_wazuh_agents_id',
                    'value' => null,
                    'entity' => $_SESSION['glpiactive_entity'],
                    'rand' => mt_rand(),
                    'width' => '30em'
                ];
                PluginWazuhAgent::dropdown($dropdown_options);
            }
            
        }
        return true;
    }
    
    #[\Override]
    public function rawSearchOptions() {
        $tab = parent::rawSearchOptions();

        $tab[] = [
            'id' => 3,
            'name' => __('Key', PluginConfig::APP_CODE),
            'table' => self::getTable(),
            'field' => 'key',
            'datatype' => 'text',
            'massiveaction' => false,
        ];

        $tab[] = [
            'id' => 4,
            'name' => __('Severity', PluginConfig::APP_CODE),
            'table' => self::getTable(),
            'field' => 'v_severity',
            'datatype' => 'text',
            'massiveaction' => false,
        ];
        
         $tab[] = [
            'id' => 5,
            'table' => $this->getTable(),
            'field' => 'v_description',
            'name' => __('Description', PluginConfig::APP_CODE),
            'datatype' => 'text',
            'massiveaction' => false,
            'nosearch' => true,
            'nodisplay' => true,
        ];

        $tab[] = [
            'id' => 6,
            'table' => $this->getTable(),
            'field' => 'v_reference',
            'name' => __('Reference', PluginConfig::APP_CODE),
            'datatype' => 'weblink',
            'massiveaction' => false
        ];

        return $tab;
    }

    /**
     * @param object $migration
     * @return boolean
     */
    static function install(Migration $migration) {
        global $DB;

        $default_charset = DBConnection::getDefaultCharset();
        $default_collation = DBConnection::getDefaultCollation();
        $default_key_sign = DBConnection::getDefaultPrimaryKeySignOption();
        $table = self::getTable();
        $agent_fkey = Computer::getForeignKeyField();

        if (!$DB->tableExists($table)) {
            $migration->displayMessage("Installing $table");

        $query = "CREATE TABLE IF NOT EXISTS `$table` (
                     `id` int {$default_key_sign} NOT NULL AUTO_INCREMENT,
                     `name` varchar(255) COLLATE {$default_collation} NOT NULL,
                     `key` varchar(255) COLLATE {$default_collation} NOT NULL,
                     `$agent_fkey` int {$default_key_sign} NOT NULL DEFAULT '0',
                     `v_category` varchar(255) COLLATE {$default_collation} NOT NULL,
                     `v_classification` varchar(255) COLLATE {$default_collation} NOT NULL,
                     `v_description` TEXT COLLATE {$default_collation} DEFAULT NULL,
                     `v_detected` timestamp DEFAULT NULL,
                     `v_published` timestamp DEFAULT NULL,
                     `v_enum` varchar(255) COLLATE {$default_collation} DEFAULT NULL,
                     `v_severity` varchar(255) COLLATE {$default_collation} DEFAULT NULL,
                     `v_reference` TEXT COLLATE {$default_collation} DEFAULT NULL,
                     `v_score` int {$default_key_sign} NOT NULL DEFAULT '0',
                     `date_mod` timestamp DEFAULT CURRENT_TIMESTAMP,
                     `date_creation` timestamp DEFAULT CURRENT_TIMESTAMP,
                     `entities_id` int {$default_key_sign} NOT NULL DEFAULT '0',
                     `is_recursive` tinyint(1) NOT NULL DEFAULT '0',
                     `is_deleted` tinyint(1) NOT NULL DEFAULT '0',
                     PRIMARY KEY (`id`),
                     KEY `$agent_fkey` (`$agent_fkey`),
                     KEY `key` (`key`),
                     KEY `entities_id` (`entities_id`),
                     KEY `date_mod` (`date_mod`),
                     KEY `date_creation` (`date_creation`),
                     KEY `is_recursive` (`is_recursive`),
                     KEY `is_deleted` (`is_deleted`)
                  ) ENGINE=InnoDB DEFAULT CHARSET={$default_charset} COLLATE={$default_collation} ROW_FORMAT=DYNAMIC";
            $DB->query($query) or die("Error creating $table table");

            $migration->updateDisplayPrefs(
                    [
                        'GlpiPlugin\Wazuh\WazuhComputerTab' => [1, 5, 6, 7]
                    ],
            );
        }

        return true;
    }

    static function uninstall(Migration $migration) {
        global $DB;

        $table = self::getTable();
        if ($DB->tableExists($table)) {
            $migration->displayMessage("Uninstalling $table");
            $migration->dropTable($table);
        }

        return true;
    }

    
}
