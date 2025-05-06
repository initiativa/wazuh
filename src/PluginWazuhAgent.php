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
use Session;
use Html;
use Dropdown;
use NetworkEquipment;
use Computer;
use DBConnection;
/**
 * Description of PluginWazuhAgent
 *
 * @author w-tomasz
 */

class PluginWazuhAgent extends CommonDBTM {
   public static $rightname = 'plugin_wazuh_agent';
   public $dohistory = true;
   
//    function showItems() {
//        $relation = new WazuhAgentAssetsRelation();
//        $relation->showItems($this);
//    }
//
    /**
    * Visible tabs definitions
    * @param array $options
    * @return array
    */
   #[\Override]
   function defineTabs($options = []) {
      $ong = [];
      $this->addDefaultFormTab($ong);
      $this->addStandardTab('WazuhAgentAssetsRelation', $ong, $options);
      $this->addStandardTab('Log', $ong, $options);
      
      return $ong;
   }
   
    #[\Override]
    public static function getMenuContent()
    {
        $menu = [];
        if (\Config::canUpdate()) {
            $menu["title"] = self::getMenuName();
            $menu["page"] = "/" . \Plugin::getWebDir(PluginConfig::APP_CODE, false) . "/front/pluginwazuhagent.php";
            $menu["icon"] = self::getIcon();
            
        $menu['options']['tools']['title'] = self::getMenuName() . '2';
        $menu['options']['tools']['page'] = "/" . \Plugin::getWebDir(PluginConfig::APP_CODE, false) . "/front/pluginwazuhagent.php";
        $menu['options']['tools']['icon'] = self::getIcon();

        $menu['tools']['title'] = self::getMenuName() . '3';
        $menu['tools']['page'] = "/" . \Plugin::getWebDir(PluginConfig::APP_CODE, false) . "/front/pluginwazuhagent.php";
        $menu['tools']['icon'] = self::getIcon();

        }
        if (count($menu)) {
            return $menu;
        }

        return false;
    }


    #[\Override]
    public static function getIcon() {
        return "fa-solid fa-user-secret";
    }

    #[\Override]
    public static function getTypeName($nb = 0)
    {
        return _n("Wazuh Agent", "Wazuh Agent's", $nb, "wazuh");
    }

   /**
    * Foreignkeys returning
    * @return string
    */
   static function getForeignKeyField() {
      return 'plugin_wazuh_agents_id';
   }
   
   public static function getByDeviceTypeAndId(string $itemtype, int $item_id): ?PluginWazuhAgent {
        $agent = new self();
        $criteria = [
            'itemtype' => $itemtype,
            'item_id' => $item_id
        ];
        $iterator = $agent->find($criteria);


        $count = count($iterator);

        if ($count === 0) {
            return null;
        }

        if ($count > 1) {
            throw new \RuntimeException("Please check Administration->WazuhAgen't to link only one device per Agent. Itemtype: $itemtype, id: $item_id.");
        }

        $data = reset($iterator);

        if (isset($data['id'])) {
            $agent->getFromDB($data['id']);
            return $agent;
        }
        return null;
   }
   
   /**
    * Funkcja instalacji tabeli agentów
    * @param object $migration
    * @return boolean
    */
   static function install(Migration $migration) {
        global $DB;

        $table = self::getTable();
        $default_charset = DBConnection::getDefaultCharset();
        $default_collation = DBConnection::getDefaultCollation();
        $default_key_sign = DBConnection::getDefaultPrimaryKeySignOption();
        $table = self::getTable();
        $connection_fkey = Connection::getForeignKeyField();

        if (!$DB->tableExists($table)) {
            $migration->displayMessage("Installing $table");

            $query = "CREATE TABLE IF NOT EXISTS `$table` (
                     `id` int {$default_key_sign} NOT NULL AUTO_INCREMENT,
                     `name` varchar(255) COLLATE {$default_collation} DEFAULT NULL,
                     `agent_id` varchar(255) COLLATE {$default_collation} NOT NULL,
                     `$connection_fkey` int {$default_key_sign} NOT NULL DEFAULT '0',
                     `ip` varchar(255) COLLATE {$default_collation} DEFAULT NULL,
                     `version` varchar(50) COLLATE {$default_collation} DEFAULT NULL,
                     `status` varchar(50) COLLATE {$default_collation} DEFAULT NULL,
                     `last_keepalive` timestamp DEFAULT NULL,
                     `os_name` varchar(255) COLLATE {$default_collation} DEFAULT NULL,
                     `os_version` varchar(100) COLLATE {$default_collation} DEFAULT NULL,
                     `groups` text COLLATE {$default_collation} DEFAULT NULL,
                     `date_mod` timestamp DEFAULT CURRENT_TIMESTAMP,
                     `date_creation` timestamp DEFAULT CURRENT_TIMESTAMP,
                     `itemtype` varchar(100) COLLATE {$default_collation} DEFAULT NULL,
                     `item_id` int {$default_key_sign} NOT NULL DEFAULT '0',
                     `entities_id` int {$default_key_sign} NOT NULL DEFAULT '0',
                     `is_recursive` tinyint(1) NOT NULL DEFAULT '0',
                     `is_deleted` tinyint(1) NOT NULL DEFAULT '0',
                     PRIMARY KEY (`id`),
                     KEY `name` (`name`),
                     KEY `status` (`status`),
                     KEY `item_id` (`item_id`),
                     KEY `entities_id` (`entities_id`),
                     KEY `$connection_fkey` (`$connection_fkey`),
                     UNIQUE KEY `connection_aggent_id` (`agent_id`, `$connection_fkey`),
                     KEY `date_mod` (`date_mod`),
                     KEY `date_creation` (`date_creation`),
                     KEY `is_recursive` (`is_recursive`),
                     KEY `is_deleted` (`is_deleted`)
                  ) ENGINE=InnoDB DEFAULT CHARSET={$default_charset} COLLATE={$default_collation}";
            $DB->query($query) or die("Error creating $table table");

            $migration->updateDisplayPrefs(
                    [
                        'GlpiPlugin\Wazuh\PluginWazuhAgent' => [3, 4, 5, 6, 7,8]
                    ],
            );
        }

        return true;
    }

    /**
    * Uninstall db table
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
   
    #[\Override]
    public function rawSearchOptions()
    {
        $tab = parent::rawSearchOptions();

        $tab[] = [
            "id" => 3,
            "name" => __("agent_id", "wazuh"),
            "table" => self::getTable(),
            "field" => "agent_id",
            "searchtype" => "contains",
            "datatype" => "text",
            "massiveaction" => false,
        ];

        $tab[] = [
            "id" => 4,
            "name" => __("IP", "wazuh"),
            "table" => self::getTable(),
            "field" => "ip",
            "searchtype" => "contains",
            "datatype" => "text",
            "massiveaction" => false,
        ];

        $tab[] = [
            "id" => 5,
            "name" => __("Version", "wazuh"),
            "table" => self::getTable(),
            "field" => "version",
            "searchtype" => "contains",
            "datatype" => "text",
            "massiveaction" => false,
        ];

        $tab[] = [
            "id" => 6,
            "name" => __("Os name", "wazuh"),
            "table" => self::getTable(),
            "field" => "os_name",
            "searchtype" => "contains",
            "datatype" => "text",
            "massiveaction" => false,
        ];

        $tab[] = [
            "id" => 7,
            "name" => __("Os version", "wazuh"),
            "table" => self::getTable(),
            "field" => "os_version",
            "searchtype" => "contains",
            "datatype" => "text",
            "massiveaction" => false,
        ];

        $tab[] = [
            "id" => 8,
            "name" => __("Device Type", PluginConfig::APP_CODE),
            "table" => self::getTable(),
            "field" => "itemtype",
            "searchtype" => "contains",
            "datatype" => "text",
            "massiveaction" => false,
        ];


//        $tab[] = [
//            "id" => 9,
//            "name" => __("Device", PluginConfig::APP_CODE),
//            "table" => self::getTable(),
//            "field" => "item_id",
//            "datatype" => "dropdown",
//            "massiveaction" => false,
//            "forcegroupby" => true,
//            "additionalfields" => ['itemtype'],
//            "joinparams" => [
//                'beforejoin' => [
//                    'table' => 'glpi_computers',
//                    'joinparams' => [
//                        'condition' => ["AND" => ["REFTABLE.itemtype" => "Computer"]]
//                    ]
//                ],
//                'beforejoin2' => [
//                    'table' => 'glpi_networkequipments',
//                    'joinparams' => [
//                        'condition' => ["AND" => ["REFTABLE.itemtype" => "NetworkEquipment"]]
//                    ]
//                ]
//            ]
//        ];
        
        $tab[] = [
            "id" => 9,
            "name" => __("Device", PluginConfig::APP_CODE),
            "table" => self::getTable(),
            "field" => "item_id",
            "datatype" => "specific",
            "massiveaction" => false,
            "additionalfields" => ['itemtype'],
        ];
        
        $tab[] = [
            'id' => 10,
            'table' => Connection::getTable(),
            'field' => 'name',
            'name' => __('Wazuh Server Name', PluginConfig::APP_CODE),
            'datatype' => 'dropdown',
            'massiveaction' => true,
            'joinparams' => [
                'jointype' => 'standard',
                'foreignkey' => Connection::getForeignKeyField()
            ]
        ];

        return $tab;
    }

    #[\Override]
    public static function getSpecificValueToDisplay($field, $values, array $options = []) {
        if ($field === 'item_id' && isset($values['itemtype']) && !empty($values['itemtype'])) {
            $itemtype = $values['itemtype'];
            $item_id = $values['item_id'];

            if (class_exists($itemtype) && in_array($itemtype, ['Computer', 'NetworkEquipment'])) {
                $item = new $itemtype();
                if ($item->getFromDB($item_id)) {
                    return $item->getLink();
                }
            }
            return $values['item_id'];
        }
        return parent::getSpecificValueToDisplay($field, $values, $options);
    }


//    #[\Override]
//    public static function canCreate(): bool {
//        return parent::canUpdate();
//    }

    
    public function prepareInputForAdd($input) {
        return $input;
    }

    public function prepareInputForUpdate($input) {
        return $input;
    }

    static function getHistoryChangeWhenUpdateField($field) {
//        switch ($field) {
//            case 'name':
//            case 'content':
//            case 'date':
//                return true;
//            default:
//                return false;
//        }
        return true;
    }

    /**
    * Fetch Wazuh data
    * @return array
    */
   static function fetchAgentsFromWazuh(Connection $config) {

        $wazuh_server = $config->fields['server_url'];
        $api_port = $config->fields['api_port'];
        $api_user = $config->fields['api_username'];
        $api_password = (new \GLPIKey())->decrypt($config->fields['api_password']);

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, "$wazuh_server:$api_port/security/user/authenticate");
        curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type: application/json'));
        curl_setopt($ch, CURLOPT_USERPWD, "$api_user:$api_password");
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, "{}"); // Empty JSON body

        $response = curl_exec($ch);
        $curl_error = curl_error($ch);
        $status_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        Logger::addDebug("Authentication attempt to Wazuh API: $status_code, URL: $wazuh_server:$api_port/security/user/authenticate");

        if ($curl_error) {
            Logger::addDebug("cURL Error: $curl_error");
            Session::addMessageAfterRedirect(
                    __('Connection error to Wazuh API', 'wazuh') . ": " . $curl_error,
                    true,
                    ERROR
            );
            return [];
        }

        if ($status_code != 200) {
            Logger::addDebug("Auth Response: $response");
            Session::addMessageAfterRedirect(
                    __('Error authenticating to Wazuh API', 'wazuh') . ": " . $status_code,
                    true,
                    ERROR
            );
            return [];
        }

        // Parse the token from response
        $auth_data = json_decode($response, true);
        if (!isset($auth_data['data']['token'])) {
            Session::addMessageAfterRedirect(
                    __('Invalid token response from Wazuh API', 'wazuh'),
                    true,
                    ERROR
            );
            return [];
        }

        $token = $auth_data['data']['token'];

        // Now use the token to fetch agents
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, "$wazuh_server:$api_port/agents?pretty=true&limit=500");
        curl_setopt($ch, CURLOPT_HTTPHEADER, array(
            'Content-Type: application/json',
            "Authorization: Bearer $token"
        ));
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

        $response = curl_exec($ch);
        $curl_error = curl_error($ch);
        $status_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        Logger::addDebug("Fetching agents from Wazuh API: $status_code, URL: $wazuh_server:$api_port/agents?pretty=true&limit=500");

        if ($curl_error) {
            Logger::addDebug("cURL Error: $curl_error");
            Session::addMessageAfterRedirect(
                    __('Connection error to Wazuh API', 'wazuh') . ": " . $curl_error,
                    true,
                    ERROR
            );
            return [];
        }

        // Process response
        if ($status_code == 200) {
            $agents_data = json_decode($response, true);
            Logger::addDebug(__FUNCTION__ . ' agents data: ' . $response);
            return $agents_data['data']['affected_items'] ?? [];
        } else {
            Session::addMessageAfterRedirect(
                    __('Error fetching agents from Wazuh API', 'wazuh') . ": " . $status_code,
                    true,
                    ERROR
            );
            return [];
        }
    }

    
    static function syncAgents(): bool {
        $ids = (new Connection())->find(['is_deleted' => 0]);
        foreach ($ids as $id) {
            Logger::addDebug("Syncing agents: " . Logger::implodeWithKeys($id));
            $wazuhConfig = Connection::getById($id['id']);
            if (!self::syncAgent($wazuhConfig)) {
                return false;
            }
        }
        return true;
    }
    
    /**
    * Wazuh agents sync
    * @return boolean
    */
    
   static function syncAgent(Connection $wazuhConfig): bool {
        global $DB;

        $agents = self::fetchAgentsFromWazuh($wazuhConfig);
        if (empty($agents)) {
            Logger::addError(__FUNCTION__ . ' Empty agents.');
            return false;
        }

        Logger::addDebug(__FUNCTION__ . ' Got ' . count($agents) . ' agents from Wazuh');

        $table = self::getTable();
        $currentDate = date('Y-m-d H:i:s');
        $success_count = 0;
        $failure_count = 0;

        foreach ($agents as $agent) {
            // Debug: Sprawdzamy strukturę agenta
            Logger::addDebug("Processing agent: " . $agent['id'] . " - " . $agent['name']);

            // Debug: Wypisz surową wartość lastKeepAlive przed konwersją
            if (isset($agent['lastKeepAlive'])) {
                Logger::addDebug("Raw lastKeepAlive value: " . $agent['lastKeepAlive'] . ", strtotime result: " . strtotime($agent['lastKeepAlive']));
            }

            // Przygotowanie danych agenta
            try {
                // Ustaw bezpieczną wartość dla last_keepalive
                $last_keepalive = $currentDate; // domyślnie bieżąca data

                if (isset($agent['lastKeepAlive'])) {
                    $timestamp = strtotime($agent['lastKeepAlive']);
                    if ($timestamp !== false && $timestamp > 0 && $timestamp < strtotime('2100-01-01')) {
                        $last_keepalive = date('Y-m-d H:i:s', $timestamp);
                    } else {
                        Logger::addDebug("Invalid lastKeepAlive timestamp, using current date instead");
                    }
                }

                $agent_data = [
                    'agent_id' => $agent['id'],
                    'name' => $agent['name'],
                    'ip' => $agent['ip'] ?? '',
                    'version' => $agent['version'] ?? '',
                    'status' => $agent['status'] ?? '',
                    'last_keepalive' => $last_keepalive,
                    'os_name' => $agent['os']['name'] ?? '',
                    'os_version' => $agent['os']['version'] ?? '',
                    'groups' => isset($agent['group']) ? json_encode($agent['group']) : '',
                    'date_mod' => $currentDate,
                    Connection::getForeignKeyField() => $wazuhConfig->fields['id']
                ];
            } catch (Exception $e) {
                Logger::addError("Error preparing agent data for ID " . $agent['id'] . ": " . $e->getMessage());
                Logger::addDebug("Agent data: " . print_r($agent, true));
                $failure_count++;
                continue;
            }

            // Sprawdź, czy agent już istnieje
            $existing_agent = $DB->request([
                        'FROM' => $table,
                        'WHERE' => [
                            'agent_id' => $agent['id'],
                            Connection::getForeignKeyField() => $wazuhConfig->fields['id']
                    ]
                    ])->current();

            // Za każdym razem tworzymy nowy obiekt aby uniknąć potencjalnych problemów
            $agent_obj = new self();

            if ($existing_agent) {
                // Aktualizacja istniejącego agenta
                $agent_data['id'] = $existing_agent['id'];
//                $agent_data['computers_id'] = $computer_id > 0 ? $computer_id : $existing_agent['computers_id'];

                Logger::addDebug("Updating agent ID: " . $existing_agent['id'] . " with data: " . json_encode($agent_data));

                // Próba aktualizacji z obsługą błędów
                if ($agent_obj->update($agent_data)) {
                    $success_count++;
                } else {
                    Logger::addError("Failed to update agent ID: " . $existing_agent['id']);
                    $failure_count++;
                }
            } else {
                // Dodawanie nowego agenta
                $agent_data['date_creation'] = $currentDate;
//                $agent_data['computers_id'] = $computer_id;

                Logger::addDebug("Adding new agent with data: " . json_encode($agent_data));

                // Próba dodania z obsługą błędów
                $new_id = $agent_obj->add($agent_data);
                if ($new_id) {
                    $success_count++;
                    Logger::addDebug("Successfully added agent with new ID: " . $new_id);
                } else {
                    Logger::addError("Failed to add new agent: " . $agent['name']);
                    $failure_count++;
                }
            }
        }

        Logger::addDebug(__FUNCTION__ . " completed. Success: $success_count, Failures: $failure_count");

        if ($failure_count > 0) {
            Session::addMessageAfterRedirect(
                    __('Some agents could not be synchronized.', 'wazuh') . " ($failure_count failures)",
                    true,
                    WARNING
            );
        }

        return $success_count > 0;
    }

    private function collectDevices() {
        $elements = [];

        $elements[''] = Dropdown::EMPTY_VALUE;

        $computer = new Computer();
        $computers = $computer->find([
            'is_deleted' => 0,
            'entities_id' => $_SESSION['glpiactive_entity']
        ]);

        foreach ($computers as $comp) {
            $elements['Computer___' . $comp['id']] = 'Computer > ' . $comp['name'];
        }

        $network = new NetworkEquipment();
        $networks = $network->find([
            'is_deleted' => 0,
            'entities_id' => $_SESSION['glpiactive_entity']
        ]);

        foreach ($networks as $net) {
            $elements['NetworkEquipment___' . $net['id']] = 'NetworkEquipment > ' . $net['name'];
        }
        
        return $elements;
    }
    
    /**
    * @param integer $ID ID agenta
    * @param array $options
    * @return boolean
    */
   function showForm($ID, array $options = []) {
        global $CFG_GLPI;

        $this->initForm($ID, $options);
        $this->showFormHeader($options);

        echo "<tr class='tab_bg_1'>";
        echo "<td>" . __('Name') . "</td>";
        echo "<td>";
        echo Html::input('name', ['value' => $this->fields['name'], 'class' => 'form-control']);
        echo "</td>";
        echo "<td>" . __('Agent ID', 'wazuh') . "</td>";
        echo "<td>";
        echo Html::input('agent_id', ['value' => $this->fields['agent_id'], 'class' => 'form-control', 'readonly' => 'readonly']);
        echo "</td>";
        echo "</tr>";

        echo "<tr class='tab_bg_1'>";
        echo "<td>" . __('IP Address') . "</td>";
        echo "<td>";
        echo Html::input('ip', ['value' => $this->fields['ip'], 'class' => 'form-control']);
        echo "</td>";
        echo "<td>" . __('Status', 'wazuh') . "</td>";
        echo "<td>";
        echo Dropdown::showFromArray('status', [
            'active' => __('Active', 'wazuh'),
            'disconnected' => __('Disconnected', 'wazuh'),
            'pending' => __('Pending', 'wazuh'),
            'never_connected' => __('Never Connected', 'wazuh')
                ], ['value' => $this->fields['status'], 'display' => false]);
        echo "</td>";
        echo "</tr>";

        echo "<tr class='tab_bg_1'>";
        echo "<td>" . __('Version', 'wazuh') . "</td>";
        echo "<td>";
        echo Html::input('version', ['value' => $this->fields['version'], 'class' => 'form-control']);
        echo "</td>";
        echo "<td>" . __('Last Keep Alive', 'wazuh') . "</td>";
        echo "<td>";
        Html::showDateTimeField('last_keepalive', ['value' => $this->fields['last_keepalive']]);
        echo "</td>";
        echo "</tr>";

        echo "<tr class='tab_bg_1'>";
        echo "<td>" . __('OS Name', 'wazuh') . "</td>";
        echo "<td>";
        echo Html::input('os_name', ['value' => $this->fields['os_name'], 'class' => 'form-control']);
        echo "</td>";
        echo "<td>" . __('OS Version', 'wazuh') . "</td>";
        echo "<td>";
        echo Html::input('os_version', ['value' => $this->fields['os_version'], 'class' => 'form-control']);
        echo "</td>";
        echo "</tr>";

        echo "<tr class='tab_bg_1'>";
        echo "<td>" . __('Groups', 'wazuh') . "</td>";
        echo "<td colspan='3'>";
        echo Html::textarea([
            'name' => 'groups',
            'value' => $this->fields['groups'],
            'cols' => 100,
            'rows' => 3
        ]);
        echo "</td>";
        echo "</tr>";

        echo "<tr class='tab_bg_1'>";
        echo "<td>" . __('Device') . "</td>";
        echo "<td>";

        $elements = $this->collectDevices();

        Dropdown::showFromArray('itemtype_item_id', $elements, [
            'value' => (!empty($this->fields['item_id'])) ? $this->fields['itemtype'] . '___' . $this->fields['item_id'] : 0,
            'rand' => mt_rand(),
            'width' => '100%'
        ]);

        echo Html::scriptBlock("
            $(document).ready(function() {
                $('form').submit(function() {
                    var selected = $('select[name=\"itemtype_item_id\"]').val();
                    if (selected) {
                        var parts = selected.split('___');
                        if (parts.length == 2) {
                            $('<input>').attr({
                                type: 'hidden',
                                name: 'itemtype',
                                value: parts[0]
                            }).appendTo('form');

                            $('<input>').attr({
                                type: 'hidden',
                                name: 'item_id',
                                value: parts[1]
                            }).appendTo('form');
                        } else {
                            $('<input>').attr({
                                type: 'hidden',
                                name: 'itemtype',
                                value: ''
                            }).appendTo('form');

                            $('<input>').attr({
                                type: 'hidden',
                                name: 'item_id',
                                value: '0'
                            }).appendTo('form');
                        }
                    } else {
                            $('<input>').attr({
                                type: 'hidden',
                                name: 'itemtype',
                                value: ''
                            }).appendTo('form');

                            $('<input>').attr({
                                type: 'hidden',
                                name: 'item_id',
                                value: '0'
                            }).appendTo('form');
                    }
                    return true;
                });
            });
        ");

        echo "</td>";
        echo "</tr>";

        $this->showFormButtons($options);
       return true;
    }
}
