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

use Cluster;
use CommonDBTM;
use Config;
use Entity;
use Exception;
use Glpi\Application\View\TemplateRenderer;
use GlpiPlugin\Conformitas\User_Item;
use GlpiPlugin\Wazuh\Traits\FieldValidation;
use Migration;
use Session;
use Html;
use Dropdown;
use NetworkEquipment;
use Computer;
use DBConnection;
/**
 * Description of WazuhAgent
 *
 * @author w-tomasz
 */

class WazuhAgent extends CommonDBTM {
    use FieldValidation;

   public static $rightname = 'plugin_wazuh_agent';
   public $dohistory = true;
   
//    function showItems() {
//        $relation = new WazuhAgentAssetsRelation();
//        $relation->showItems($this);
//    }
//

    public static function getSectorizedDetails(): array {
        return ['admin', self::class];
    }

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
    public static function getMenuContent(): false|array {
        $menu = parent::getMenuContent();
        $sync_agents = "<i class='fas fa-shield-alt m-1' title='sync_btn' data-bs-toggle='tooltip'></i>" . _n(' Sync Agent', 'Sync Agents', 2, PluginConfig::APP_CODE);
        $link_agents = "<i class='fas fa-link m-1' title='link_btn'></i>" . _n(' Link Agent', 'Link Agents', 2, PluginConfig::APP_CODE);

        $menu['links'][$sync_agents] = 'plugins/wazuh/front/pluginwazuhagent.sync.php';
        $menu['links'][$link_agents] = 'plugins/wazuh/front/pluginwazuhagent.link.php';

        if (count($menu)) {
            return $menu;
        }

        return false;
    }

    public static function canCreate(): bool {
        return false;
    }


    #[\Override]
    public static function getIcon(): string {
        return "fa-solid fa-user-secret";
    }

    #[\Override]
    public static function getTypeName($nb = 0): string {
        return _n("Wazuh Agent", "Wazuh Agent's", $nb, "wazuh");
    }


   public static function getByDeviceTypeAndId(string $itemtype, int $item_id): ?WazuhAgent {
       $agent = new self();
       global $DB;

       $connection_fkey = Connection::getForeignKeyField();

       $criteria = [
           'SELECT' => [
               static::getTable() . '.*',
               Connection::getTable() . '.id AS CID'
           ],
           'FROM' => self::getTable(),
           'JOIN' => [
               Connection::getTable() => [
                   'ON' => [
                       self::getTable() => $connection_fkey,
                       Connection::getTable() => 'id'
                   ]
               ]
           ],
           'WHERE' => [
               Connection::getTable() . '.is_conn_active' => 1,
               Connection::getTable() . '.is_deleted' => 0,
               'itemtype' => $itemtype,
               'item_id' => $item_id
           ]
       ];

        $iterator = $DB->request($criteria);
        PluginLogger::debug($iterator->getSql());

        $count = count($iterator);

        if ($count === 0) {
            return null;
        }

        if ($count > 1) {
            throw new \RuntimeException("Please check Administration->WazuhAgen't to link only one device per Agent. Itemtype: $itemtype, id: $item_id.");
        }

        $data = $iterator->current();

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
   static function install(Migration $migration, string $version): bool {
        global $DB;

        $table = self::getTable();
        $default_charset = DBConnection::getDefaultCharset();
        $default_collation = DBConnection::getDefaultCollation();
        $default_key_sign = DBConnection::getDefaultPrimaryKeySignOption();
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
                     UNIQUE KEY `connection_aggent_id` (`agent_id`, `$connection_fkey`, `entities_id`),
                     KEY `date_mod` (`date_mod`),
                     KEY `date_creation` (`date_creation`),
                     KEY `is_recursive` (`is_recursive`),
                     KEY `is_deleted` (`is_deleted`)
                  ) ENGINE=InnoDB DEFAULT CHARSET={$default_charset} COLLATE={$default_collation}";
            $DB->doQuery($query) or die("Error creating $table table");

            $migration->updateDisplayPrefs(
                    [
                        self::class => [13, 3, 4, 5, 6, 7, 8, 12]
                    ],
            );
        }

       if (version_compare('0.0.15',
           $version, '<=')) {

           if (self::indexExists($table, 'connection_aggent_id')) {
               $migration->dropKey($table, 'connection_aggent_id');
           }
           if (!self::indexExists($table, 'connection_aggent_entity_id')) {
               $migration->addKey($table, ['agent_id', $connection_fkey, Entity::getForeignKeyField()], 'connection_aggent_entity_id', 'UNIQUE');
           }
       }

       return true;
    }

    static function indexExists($table, $index_name): bool {
        global $DB;

        $iterator = $DB->request([
            'FROM' => 'INFORMATION_SCHEMA.STATISTICS',
            'WHERE' => [
                'table_schema' => $DB->dbdefault,
                'table_name' => $table,
                'index_name' => $index_name
            ]
        ]);

        return count($iterator) > 0;
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
            'datatype' => 'itemlink',
            'massiveaction' => true,
            'joinparams' => [
                'jointype' => 'standard',
                'foreignkey' => Connection::getForeignKeyField()
            ]
        ];

        $tab[] = [
            'id' => 11,
            'table' => Connection::getTable(),
            'field' => 'is_conn_active',
            'name' => __('Active Server', PluginConfig::APP_CODE),
            'datatype' => 'bool',
            'massiveaction' => true,
            'joinparams' => [
                'jointype' => 'standard',
                'foreignkey' => Connection::getForeignKeyField()
            ]
        ];

        $tab[] = [
            "id" => 12,
            "name" => __("Agent Status", PluginConfig::APP_CODE),
            "table" => self::getTable(),
            "field" => "status",
            "searchtype" => "contains",
            "datatype" => "text",
            "massiveaction" => false,
        ];

        $tab[] = [
            "id" => 13,
            "name" => _n("Entity", "Entities", 2, PluginConfig::APP_CODE),
            "table" => Entity::getTable(),
            "linkfield" => "entities_id",
            "field" => "completename",
            "searchtype" => "contains",
            "datatype" => "text",
            "massiveaction" => false,
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

       $config_name = $config->fields['name'];
        $wazuh_server = $config->fields['server_url'];
        $api_port = $config->fields['api_port'];
        $api_user = $config->fields['api_username'];
        $api_password = (new \GLPIKey())->decrypt($config->fields['api_password']);

       $ch = curl_init();
       curl_setopt_array($ch, [
           CURLOPT_URL => "$wazuh_server:$api_port/security/user/authenticate",
           CURLOPT_HTTPHEADER => array('Content-Type: application/json'),
           CURLOPT_USERPWD => "$api_user:$api_password",
           CURLOPT_SSL_VERIFYPEER => false,
           CURLOPT_SSL_VERIFYHOST => false,
           CURLOPT_RETURNTRANSFER => true,
           CURLOPT_POST => true,
           CURLOPT_CONNECTTIMEOUT => 10,
           CURLOPT_TIMEOUT => 10,
           CURLOPT_POSTFIELDS => "{}"
       ]);

        $response = curl_exec($ch);
        $curl_error = curl_error($ch);
        $status_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        PluginLogger::debug("Authentication attempt to Wazuh API: $status_code, URL: $wazuh_server:$api_port/security/user/authenticate");

        if ($curl_error) {
            PluginLogger::debug("cURL Error: $curl_error");
            Session::addMessageAfterRedirect(
                    __('Connection error to Wazuh API', 'wazuh') . ": $curl_error. Server name: $config_name",
                    true,
                    ERROR
            );
            return [];
        }

        if ($status_code != 200) {
            PluginLogger::debug("Auth Response: $response");
            Session::addMessageAfterRedirect(
                    __('Error connectiong to Wazuh API', 'wazuh') . ": " . $status_code,
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

        PluginLogger::debug("Fetching agents from Wazuh API: $status_code, URL: $wazuh_server:$api_port/agents?pretty=true&limit=500");

        if ($curl_error) {
            PluginLogger::debug("cURL Error: $curl_error");
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
            PluginLogger::debug(__FUNCTION__ . ' agents data: ' . $response);
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


    static function linkAgents(): bool {
       global $DB;

       $entities = getSonsOf(Entity::getTable(), $_SESSION['glpiactive_entity']);

        $iterator = $DB->request([
            'FROM' => self::getTable(),
            'WHERE' => [
                Entity::getForeignKeyField() => $entities,
                'item_id' => 0,
                'is_deleted' => 0,
            ]
        ]);

        if ($iterator) {
            $agents = iterator_to_array($iterator);
            foreach ($agents as $agent) {
                if (isset($agent['name'])) {
                    $aname = $agent['name'];
                    $aentity = $agent[Entity::getForeignKeyField()];
                    $idevices = $DB->request(['FROM' => NetworkEquipment::getTable(), 'WHERE' => ['name' => $aname, Entity::getForeignKeyField() => $aentity, 'is_deleted' => false]]);
                    if ($idevices) {
                        $devices = iterator_to_array($idevices);
                        foreach ($devices as $device) { //only last set will be persisted
                            $agent['itemtype'] = NetworkEquipment::class;
                            $agent['item_id'] = $device['id'];
                        }
                        $DB->update(self::getTable(), $agent, ['id' => $agent['id']]);
                    }

                    $icomputers = $DB->request(['FROM' => Computer::getTable(), 'WHERE' => ['name' => $aname, Entity::getForeignKeyField() => $aentity, 'is_deleted' => false]]);
                    if ($icomputers) {
                        $computers = iterator_to_array($icomputers);
                        foreach ($computers as $computer) { //only last set will be persisted
                            $agent['itemtype'] = Computer::class;
                            $agent['item_id'] = $computer['id'];
                        }
                        $DB->update(self::getTable(), $agent, ['id' => $agent['id']]);
                    }
                }
            }
            return true;
        }

        return false;
    }

    static function syncAgents(): bool {
        $entities = array_values(getSonsOf(Entity::getTable(), Session::getActiveEntity()));
        $ids = (new Connection())->find(['is_deleted' => 0, 'is_conn_active' => 1, Entity::getForeignKeyField() => $entities]);
        $allOk = true;
        foreach ($ids as $id) {
            PluginLogger::debug("Syncing agents: " . PluginLogger::implodeWithKeys($id));
            $wazuhConfig = Connection::getById($id['id']);
            if (!self::syncAgent($wazuhConfig)) {
                $allOk = false;
            } else {
                $wazuhConfig->update([
                    'id' => 1,
                    'last_sync' => date('Y-m-d H:i:s')
                ]);
            }
        }
        return $allOk;
    }
    
    /**
    * Wazuh agents sync
    * @return boolean
    */
    
   static function syncAgent(Connection $wazuhConfig): bool {
        global $DB;

       PluginLogger::debug(__FUNCTION__ . json_encode($wazuhConfig));

       $agents = self::fetchAgentsFromWazuh($wazuhConfig);
        if (empty($agents)) {
            PluginLogger::error(__FUNCTION__ . ' Empty agents.');
            return false;
        }

        PluginLogger::debug(__FUNCTION__ . ' Got ' . count($agents) . ' agents from Wazuh');

        $table = self::getTable();
        $currentDate = date('Y-m-d H:i:s');
        $success_count = 0;
        $failure_count = 0;

        foreach ($agents as $agent) {
            PluginLogger::debug("Processing agent: " . $agent['id'] . " - " . $agent['name']);

            if (isset($agent['lastKeepAlive'])) {
                PluginLogger::debug("Raw lastKeepAlive value: " . $agent['lastKeepAlive'] . ", strtotime result: " . strtotime($agent['lastKeepAlive']));
            }

            try {
                $last_keepalive = $currentDate;

                if (isset($agent['lastKeepAlive'])) {
                    $timestamp = strtotime($agent['lastKeepAlive']);
                    if ($timestamp !== false && $timestamp > 0 && $timestamp < strtotime('2100-01-01')) {
                        $last_keepalive = date('Y-m-d H:i:s', $timestamp);
                    } else {
                        PluginLogger::debug("Invalid lastKeepAlive timestamp, using current date instead");
                    }
                }

                $active_entity = $wazuhConfig->fields[Entity::getForeignKeyField()];
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
                    Entity::getForeignKeyField() => $active_entity,
                    Connection::getForeignKeyField() => $wazuhConfig->fields['id']
                ];
            } catch (Exception $e) {
                PluginLogger::error("Error preparing agent data for ID " . $agent['id'] . ": " . $e->getMessage());
                PluginLogger::debug("Agent data: " . print_r($agent, true));
                $failure_count++;
                continue;
            }

            $existing_agent = $DB->request([
                'FROM' => $table,
                'WHERE' => [
                    'agent_id' => $agent['id'],
                    Connection::getForeignKeyField() => $wazuhConfig->fields['id'],
                    Entity::getForeignKeyField() => $active_entity,
                ]
            ])->current();

            $agent_obj = new self();

            if ($existing_agent) {
                $agent_data['id'] = $existing_agent['id'];

                PluginLogger::debug("Updating agent ID: " . $existing_agent['id'] . " with data: " . json_encode($agent_data));

                if ($agent_obj->update($agent_data)) {
                    $success_count++;
                } else {
                    PluginLogger::error("Failed to update agent ID: " . $existing_agent['id']);
                    $failure_count++;
                }
            } else {
                $agent_data['date_creation'] = $currentDate;

                PluginLogger::debug("Adding new agent with data: " . json_encode($agent_data));

                $new_id = $agent_obj->add($agent_data);
                if ($new_id) {
                    $success_count++;
                    PluginLogger::debug("Successfully added agent with new ID: " . $new_id);
                } else {
                    PluginLogger::error("Failed to add new agent: " . $agent['name']);
                    $failure_count++;
                }
            }
        }

        PluginLogger::debug(__FUNCTION__ . " completed. Success: $success_count, Failures: $failure_count");

        if ($failure_count > 0) {
            Session::addMessageAfterRedirect(
                    __('Some agents could not be synchronized.', 'wazuh') . " ($failure_count failures)",
                    true,
                    WARNING
            );
        }

        return $success_count > 0;
    }

    public function showForm($ID, array $options = []): true {
        global $CFG_GLPI;

        $this->initForm($ID, $options);
        $new_item = static::isNewID($ID);
        $in_modal = (bool) ($_GET['_in_modal'] ?? false);
        $cluster = !$new_item && in_array(static::class, $CFG_GLPI['cluster_types'], true)
            ? Cluster::getClusterByItem($this)
            : null;


        echo TemplateRenderer::getInstance()->render('@wazuh/agent.form.html.twig', [
            'item'   => $this,
            'params' => $options,
            'additional_field_options' => self::getAdditionalFieldOptions(),
        ]);

        return true;
    }
}
