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
use Computer;
use Glpi\Application\View\TemplateRenderer;
use CommonGLPI;
use Migration;
use NetworkEquipment;
use Ticket;
use DBConnection;
use Html;
use Entity;
use Search;
use Session;
use ITILFollowup;
use Item_Ticket;

if (!defined('GLPI_ROOT')) {
   die("No access.");
}

/**
 * Wazuh network equipment vulenrable tab
 *
 * @author w-tomasz
 */
class NetworkEqAlertsTab extends DeviceAlertsTab implements Ticketable {
    use TicketableTrait;
    use IndexerRequestsTrait;

    public $dohistory = true;
    public static $itemtype = 'NetworkEquipment';
    public static $items_id = 'networkequipments_id';

    #[\Override]
    static function getTypeName($nb = 0) {
        return _n('Wazuh Alert', 'Wazuh Alerts', $nb, PluginConfig::APP_CODE);
    }

    protected function countElements($device_id) {
        global $DB;

        $count = 0;
        $iterator = $DB->request([
            'COUNT' => 'count',
            'FROM' => $this->getTable(),
            'WHERE' => [
                NetworkEquipment::getForeignKeyField() => $device_id,
                'is_deleted' => 0
                ]
        ]);

        if (count($iterator)) {
            $data = $iterator->current();
            $count = $data['count'];
        }

        return $count;
    }
    
    #[\Override]
    protected static function bindStatement($stmt, $result, \CommonDBTM $device): bool {
        global $DB;

        $d = [
            $result['_id'],
            $device->getID(),
            $result['_id'],
            $DB->escape($result['_source']['agent']['ip'] ?? ''),
            $DB->escape($result['_source']['agent']['name'] ?? ''),
            $DB->escape($result['_source']['agent']['id'] ?? ''),
            json_encode($result['_source']['data'] ?? ''),
            json_encode($result['_source']['rule'] ?? ''),
            $DB->escape($result['_source']['input']['type'] ?? ''),
            (new \DateTime())->format('Y-m-d H:i:s'),
            self::convertIsoToMysqlDatetime(self::array_getvalue($result, ['_source', 'timestamp'])),
            json_encode($result['_source']['syscheck'] ?? '')
        ];
        return $stmt->bind_param('sissssssssss', ...$d);
    }

    #[\Override]
    protected static function getUpsertStatement(): string {
        $table = static::getTable();
        $device_fkey = NetworkEquipment::getForeignKeyField();
        $query = "INSERT INTO `$table` 
          (`key`, `$device_fkey`, `name`, `a_ip`, `a_name`, `a_id`, `data`, `rule`, `input_type`, `date_mod`, `source_timestamp`, `syscheck`) 
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          ON DUPLICATE KEY UPDATE
              `$device_fkey` = VALUES(`$device_fkey`),
              `name` = VALUES(`name`),
              `a_ip` = VALUES(`a_ip`),
              `a_name` = VALUES(`a_name`),
              `a_id` = VALUES(`a_id`),
              `data` = VALUES(`data`),
              `rule` = VALUES(`rule`),
              `input_type` = VALUES(`input_type`),
              `date_mod` = VALUES(`date_mod`),
              `source_timestamp` = VALUES(`source_timestamp`),
              `syscheck` = VALUES(`syscheck`)
          ";
        Logger::addDebug($query, ['device_fkey' => $device_fkey]);
        return $query;
    }

//    private static function createItem($result, NetworkEquipment $device) {
//        global $DB;
//        $key = $result['_id'];
//        $item = new self();
//        $founded = $item->find(['key' => $key]);
//        
//        if (count($founded) > 1) {
//            throw new \RuntimeException("Founded NetworkEqAlertsTab collection exceeded limit 1.");
//        }
//
//        $item_data = [
//            'key' => $key,
//            NetworkEquipment::getForeignKeyField() => $device->getID(),
//            'name' => $result['_source']['vulnerability']['id'],
//            'v_description' => $DB->escape($result['_source']['vulnerability']['description']),
//            'v_severity' => $result['_source']['vulnerability']['severity'],
//            'v_detected' => self::convertIsoToMysqlDatetime($result['_source']['vulnerability']['detected_at']),
//            'v_published' => self::convertIsoToMysqlDatetime($result['_source']['vulnerability']['published_at']),
//            'v_enum' => $result['_source']['vulnerability']['enumeration'],
//            'v_category' => $result['_source']['vulnerability']['category'],
//            'v_classification' => $result['_source']['vulnerability']['classification'],
//            'v_reference' => $result['_source']['vulnerability']['reference'],
//            'p_name' => $result['_source']['package']['name'],
//            'p_version' => $result['_source']['package']['version'],
//            'p_type' => $result['_source']['package']['type'],
//            'p_description' => $DB->escape($result['_source']['package']['description'] ?? ''),
//            'p_installed' => self::convertIsoToMysqlDatetime(self::array_get($result['_source']['package']['installed'] ?? null, $result)),
//        ];
//
//        if (!$founded) {
//            $newId = $item->add($item_data);
//        } else {
//            $item->update($item_data);
//        }
//        
//        return $item;
//    }
    
    #[\Override]
    static function displayTabContentForItem(CommonGLPI $item, $tabnum = 1, $withtemplate = 0): bool {
        Logger::addDebug(__FUNCTION__ . " item type: " . $item->getType());
        self::getAgentAlerts($item);
        $item_type = self::class;
        $params = [
            'sort' => '2',
            'order' => 'DESC',
            'reset' => 'reset',
            'criteria' => [
                [
                    'field' => 7,
                    'searchtype' => 'equals',
                    'value' => $item->getID()
                ]
            ],
        ];
        Search::manageParams($item_type, $params);
        Search::show(NetworkEqAlertsTab::class);
        return true;
    }

    public static function getAgentAlerts(CommonGLPI $device): array | false {
        if ($device instanceof NetworkEquipment) {
            $agent = PluginWazuhAgent::getByDeviceTypeAndId($device->getType(), $device->fields['id']);
            if ($agent) {
                $connection = Connection::getById($agent->fields[Connection::getForeignKeyField()]);
                if ($connection) {
                    static::initWazuhConnection($connection->fields['indexer_url'], $connection->fields['indexer_port'], $connection->fields['indexer_user'], $connection->fields['indexer_password']);
                    $agentId = $agent->fields['agent_id'];
                    return static::queryAlertsByAgentIds([$agentId], $device);
                }
            } else {
                Logger::addError(sprintf("%s %s Can not find agent id = %s type = %s", __CLASS__, __FUNCTION__, $device->fields['id'], $device->getType()));
            }
        } else {
            Logger::addError(sprintf("%s %s Device %s outside of NetworkEquipment or Computer scope.", __CLASS__, __FUNCTION__, $device->getType()));
        }
        return false;
    }

    #[\Override]
    public function rawSearchOptions() {
        $tab = parent::rawSearchOptions();

        $tab[] = [
            'id' => 7,
            'table' => NetworkEquipment::getTable(),
            'field' => 'name',
            'name' => __('Network Eq', PluginConfig::APP_CODE),
            'datatype' => 'dropdown',
            'massiveaction' => true,
            'joinparams' => [
                'jointype' => 'standard',
                'foreignkey' => NetworkEquipment::getForeignKeyField()
            ]
        ];

        return $tab;
    }

    #[\Override]
    protected static function getConnectionId($iids): int {
        global $DB;

        $table = static::getTable();
        $key = array_keys($iids)[0];
        $ids = array_map('intval', array_values($iids[$key]));

        if (empty($ids)) {
            return 0;
        }

        $criteria = [
            'SELECT' => [NetworkEquipment::getForeignKeyField()],
            'FROM' => $table,
            'WHERE' => [
                'id' => $ids[0],
                'is_deleted' => 0,
            ]
        ];

        $iterator = $DB->request($criteria);
        $size = count($iterator);
        if ($size === 0) {
            return 0;
        }

        $device = $iterator->current();
        $device_id = $device[NetworkEquipment::getForeignKeyField()] ?? 0;
        if ($device_id === 0) {
            return 0;
        }

        $agents_table = PluginWazuhAgent::getTable();
        $agents_criteria = [
            'SELECT' => [Connection::getForeignKeyField()],
            'FROM' => $agents_table,
            'WHERE' => [
                'itemtype' => 'Computer',
                'item_id' => $device_id,
                'is_deleted' => 0,
            ]
        ];

        $agents_iterator = $DB->request($agents_criteria);
        $agents_size = count($agents_iterator);
        if ($agents_size === 0) {
            return 0;
        }
        $agent = $agents_iterator->current();
        $connection_id = $agent[Connection::getForeignKeyField()] ?? 0;

        return $connection_id;
    }

    #[\Override]
    public function getSpecificMassiveActions($checkitem = null) {
        $actions = parent::getSpecificMassiveActions($checkitem);

        $actions["GlpiPlugin\Wazuh\NetworkEqAlertsTab:create_ticket"] = __("Create ticket", PluginConfig::APP_CODE);

        return $actions;
    }

    static function processMassiveActionsForOneItemtype(\MassiveAction $ma, \CommonDBTM $item, array $ids) {
        global $DB;

        Logger::addDebug(__FUNCTION__ . " " . $ma->getAction() . " :: " . $item->getType() . " :: " . $item->getID() . " :: " . implode(", ", $ids));
        switch ($ma->getAction()) {
            case "create_ticket":
                $input = $ma->getInput();
                Logger::addDebug(__FUNCTION__ . " " . $ma->getAction() . " :: " . Logger::implodeWithKeys($input));
                
                if (!isset($input['entities_id'])) {
                    Logger::addWarning("Missing entity while ticket creating.");
                    return false;
                }

                if (!isset($input['ticket_title']) || empty($input['ticket_title'])) {
                    Logger::addWarning("Missing ticket title while ticket creating.");
                    return false;
                }
 
                $ticket_id = self::createTicket($ids, $input, $input['entities_id']);
                if ($ticket_id) {
                    $ticketUrl = Ticket::getFormURLWithID($ticket_id);
                    $message = sprintf(
                            __('Ticket created successfully. <a href="%s">View ticket #%s</a>'),
                            $ticketUrl,
                            $ticket_id
                    );
                    Session::addMessageAfterRedirect($message, true, INFO);
                    Html::back();
                }
                return;
        }
        parent::processMassiveActionsForOneItemtype($ma, $item, $ids);
    }

    /**
     * @param object $migration
     * @return boolean
     */
    #[\Override]
    static function install(Migration $migration, string $version): bool {
        global $DB;

        $default_charset = DBConnection::getDefaultCharset();
        $default_collation = DBConnection::getDefaultCollation();
        $default_key_sign = DBConnection::getDefaultPrimaryKeySignOption();
        $table = self::getTable();
        $networkeq_fkey = NetworkEquipment::getForeignKeyField();
        $ticket_fkey = \Ticket::getForeignKeyField();
        $parent_fkey = static::getForeignKeyField();
        $itil_category_fkey = \ITILCategory::getForeignKeyField();

        if (!$DB->tableExists($table)) {
            $migration->displayMessage("Installing $table");

        $query = "CREATE TABLE IF NOT EXISTS `$table` (
                     `id` int {$default_key_sign} NOT NULL AUTO_INCREMENT,
                     `name` varchar(255) COLLATE {$default_collation} NOT NULL,
                     `key` varchar(255) COLLATE {$default_collation} NOT NULL,
                     `$parent_fkey` int {$default_key_sign} NOT NULL DEFAULT '0',
                     `$networkeq_fkey` int {$default_key_sign} NOT NULL DEFAULT '0',
                     `$ticket_fkey` int {$default_key_sign} NOT NULL DEFAULT '0',
                     `$itil_category_fkey` int {$default_key_sign} NOT NULL DEFAULT '0',
                     `a_ip` varchar(255) COLLATE {$default_collation} NOT NULL,
                     `a_name` varchar(255) COLLATE {$default_collation} NOT NULL,
                     `a_id` varchar(255) COLLATE {$default_collation} NOT NULL,
                     `syscheck` JSON COLLATE {$default_collation} DEFAULT NULL,
                     `rule` JSON COLLATE {$default_collation} DEFAULT NULL,
                     `data` JSON COLLATE {$default_collation} DEFAULT NULL,
                     `input_type` varchar(255) COLLATE {$default_collation} DEFAULT NULL,
                     `is_discontinue` tinyint(1) NOT NULL DEFAULT '0',
                     `source_timestamp` timestamp DEFAULT NULL,
                     `date_mod` timestamp DEFAULT CURRENT_TIMESTAMP,
                     `date_creation` timestamp DEFAULT CURRENT_TIMESTAMP,
                     `entities_id` int {$default_key_sign} NOT NULL DEFAULT '0',
                     `is_recursive` tinyint(1) NOT NULL DEFAULT '0',
                     `is_deleted` tinyint(1) NOT NULL DEFAULT '0',
                     PRIMARY KEY (`id`),
                     KEY `$parent_fkey` (`$parent_fkey`),
                     KEY `$networkeq_fkey` (`$networkeq_fkey`),
                     KEY `$ticket_fkey` (`$ticket_fkey`),
                     KEY `$itil_category_fkey` (`$itil_category_fkey`),
                     UNIQUE KEY `key` (`key`),
                     KEY `source_timestamp` (`source_timestamp`),
                     KEY `entities_id` (`entities_id`),
                     KEY `date_mod` (`date_mod`),
                     KEY `date_creation` (`date_creation`),
                     KEY `is_recursive` (`is_recursive`),
                     KEY `is_deleted` (`is_deleted`)
                  ) ENGINE=InnoDB DEFAULT CHARSET={$default_charset} COLLATE={$default_collation} ROW_FORMAT=DYNAMIC";
            $DB->query($query) or die("Error creating $table table");

        }

        $migration->updateDisplayPrefs(
                [
                    self::class => [1, 10, 13, 11, 3, 6, 4, 8, 9, 7]
                ],
        );
        
        return true;
    }

    #[\Override]
    static function uninstall(Migration $migration): bool {
        global $DB;

        $table = self::getTable();
        if ($DB->tableExists($table)) {
            $migration->displayMessage("Uninstalling $table");
            $migration->dropTable($table);
        }

        $itemtype = self::class;
        $migration->displayMessage("Cleaning display preferences for $itemtype.");

        $displayPreference = new \DisplayPreference();
        $displayPreference->deleteByCriteria(['itemtype' => $itemtype]);

        return true;
    }

    static function getDeviceId(Ticketable&CommonDBTM $wazuhTab): int
    {
        return $wazuhTab->fields[NetworkEquipment::getForeignKeyField()];
    }

    static function newDeviceInstance(): Computer|NetworkEquipment
    {
        return new NetworkEquipment();
    }

    static function getWazuhTabHref(int $id): string
    {
        return "../plugins/wazuh/front/networkeqalertstab.form.php?id=$id";
    }

    static function getDeviceHref(int $id): string
    {
        return "networkequipment.form.php?id=$id";
    }

    static function getDefaultTicketTitle(): string {
        return "Wazuh Network Equipment Alert";
    }

    static function generateLinkName(NetworkEqAlertsTab|NetworkEqTab|ComputerAlertsTab|ComputerTab $item): string
    {
        return  $item->fields['name'] . "/" . $item->fields['a_name'];
    }

}
