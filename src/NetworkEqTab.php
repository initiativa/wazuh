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

use Computer;
use Glpi\Application\View\TemplateRenderer;
use CommonGLPI;
use CommonDBTM;
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
class NetworkEqTab extends DeviceTab implements Ticketable {
    use TicketableTrait;
    use IndexerRequestsTrait;

    public $dohistory = true;
    public static $itemtype = 'NetworkEquipment';
    public static $items_id = 'networkequipments_id';

    #[\Override]
    static function getTypeName($nb = 0) {
        return _n('Wazuh Vulnerable', 'Wazuh Vulnerabilities', $nb, PluginConfig::APP_CODE);
    }

    protected function countElements($device_id) {
        $count = countElementsInTableForMyEntities($this->getTable(), [
            NetworkEquipment::getForeignKeyField() => $device_id,
            static::getForeignKeyField() => ['<>', 0],
            'is_deleted' => 0
        ]);

//        global $DB;
//
//        $count = 0;
//        $iterator = $DB->request([
//            'COUNT' => 'count',
//            'FROM' => $this->getTable(),
//            'WHERE' => [
//                NetworkEquipment::getForeignKeyField() => $device_id,
//                static::getForeignKeyField() => ['<>', 0],
//                'is_deleted' => 0
//                ]
//        ]);
//
//        if (count($iterator)) {
//            $data = $iterator->current();
//            $count = $data['count'];
//        }

        return $count;
    }
    
    #[\Override]
    protected static function bindStatement($stmt, $result, \CommonDBTM $device): bool {
        global $DB;

        $d = [
            $result['_id'],
            $device->getID(),
            $result['_source']['vulnerability']['id'],
            $DB->escape($result['_source']['vulnerability']['description'] ?? ''),
            $result['_source']['vulnerability']['severity'] ?? '',
            self::convertIsoToMysqlDatetime($result['_source']['vulnerability']['detected_at']),
            self::convertIsoToMysqlDatetime($result['_source']['vulnerability']['published_at']),
            $result['_source']['vulnerability']['enumeration'],
            $result['_source']['vulnerability']['category'],
            $result['_source']['vulnerability']['classification'],
            $result['_source']['vulnerability']['reference'],
            $result['_source']['package']['name'],
            $result['_source']['package']['version'] ?? '',
            $result['_source']['package']['type'] ?? '',
            $DB->escape($result['_source']['package']['description'] ?? ''),
            self::convertIsoToMysqlDatetime(self::array_getvalue($result, ['_source', 'package', 'installed'])),
            (new \DateTime())->format('Y-m-d H:i:s')
        ];
        return $stmt->bind_param('sisssssssssssssss', ...$d);
    }

    #[\Override]
    protected static function getUpsertStatement(): string {
                $table = static::getTable();
        $device_fkey = NetworkEquipment::getForeignKeyField();
        $query = "INSERT INTO `$table` 
          (`key`, `$device_fkey`, `name`, `v_description`, `v_severity`, `v_detected`, `v_published`, `v_enum`, `v_category`, `v_classification`, `v_reference`, `p_name`, `p_version`, `p_type`, `p_description`, `p_installed`, `date_mod`) 
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          ON DUPLICATE KEY UPDATE
              `$device_fkey` = VALUES(`$device_fkey`),
              `name` = VALUES(`name`),
              `v_description` = VALUES(`v_description`),
              `v_severity` = VALUES(`v_severity`),
              `v_detected` = VALUES(`v_detected`),
              `v_published` = VALUES(`v_published`),
              `v_enum` = VALUES(`v_enum`),
              `v_category` = VALUES(`v_category`),
              `v_classification` = VALUES(`v_classification`),
              `v_reference` = VALUES(`v_reference`),
              `p_name` = VALUES(`p_name`),
              `p_version` = VALUES(`p_version`),
              `p_type` = VALUES(`p_type`),
              `p_description` = VALUES(`p_description`),
              `p_installed` = VALUES(`p_installed`),
              `date_mod` = VALUES(`date_mod`)
          ";
        Logger::addDebug($query, ['computer_fkey' => $device_fkey]);
        return $query;
    }

    protected static function createItem($result, CommonDBTM $device) {
        global $DB;
        $key = $result['_id'];
        $item = new self();
        $founded = $item->find(['key' => $key]);

        if (count($founded) > 1) {
            throw new \RuntimeException("Founded ComputerTab collection exceeded limit 1.");
        }

        $item_data = [
            'key' => $key,
            'is_discontinue' => false,
            \NetworkEquipment::getForeignKeyField() => $device->getID(),
            'name' => $DB->escape($result['_source']['vulnerability']['id']),
            'v_description' => $DB->escape($result['_source']['vulnerability']['description']),
            'v_severity' => $DB->escape($result['_source']['vulnerability']['severity'] ?? ''),
            'v_detected' => static::convertIsoToMysqlDatetime($result['_source']['vulnerability']['detected_at']),
            'v_published' => static::convertIsoToMysqlDatetime($result['_source']['vulnerability']['published_at']),
            'v_enum' => $DB->escape($result['_source']['vulnerability']['enumeration'] ?? ''),
            'v_category' => $DB->escape($result['_source']['vulnerability']['category'] ?? ''),
            'v_classification' => $DB->escape($result['_source']['vulnerability']['classification'] ?? ''),
            'v_reference' => $DB->escape($result['_source']['vulnerability']['reference'] ?? ''),
            'v_score' => floatval($DB->escape($result['_source']['vulnerability']['score']['base'] ?? '')),
            'p_name' => $DB->escape($result['_source']['package']['name'] ?? ''),
            'p_version' => $DB->escape($result['_source']['package']['version'] ?? ''),
            'p_type' => $DB->escape($result['_source']['package']['type'] ?? ''),
            'p_description' => $DB->escape($result['_source']['package']['description'] ?? ''),
            'p_installed' => static::convertIsoToMysqlDatetime(self::array_getvalue($result, ['_source', 'package', 'installed'])),
            'date_mod' => (new \DateTime('now', new \DateTimeZone('UTC')))->format('Y-m-d H:i:s'),
            \Entity::getForeignKeyField() => \Session::getActiveEntity(),
        ];

        $parent_id = self::createParentItem($item_data, new self());
        if ($parent_id) {
            $item_data[self::getForeignKeyField()] = $parent_id;
        }

        if (!$founded) {
            $newId = $item->add($item_data);
            if (!$newId) {
                Logger::addWarning(__FUNCTION__ . ' INSERT ERROR: ' . $DB->error());
            }
        } else {
            $fid = reset($founded)['id'];
            $item_data['id'] = $fid;
            $item->update($item_data);
        }

        return $item;
    }

    #[\Override]
    static function displayTabContentForItem(CommonGLPI $item, $tabnum = 1, $withtemplate = 0) {
        Logger::addDebug(__FUNCTION__ . " item type: " . $item->getType());
        self::getAgentVulnerabilities($item);
        $item_type = self::class;
        $params = [
            'sort' => '2',
            'order' => 'DESC',
            'reset' => 'reset',
            'browse' => 1,
            'criteria' => [
                [
                    'field' => 7,
                    'searchtype' => 'equals',
                    'value' => $item->getID()
                ]
            ],
        ];
        Search::manageParams($item_type, $params);
        Search::show(NetworkEqTab::class);
        return true;
    }

    public static function getAgentVulnerabilities(CommonGLPI $device): array | false {
        if ($device instanceof NetworkEquipment) {
            $agent = PluginWazuhAgent::getByDeviceTypeAndId($device->getType(), $device->fields['id']);
            if ($agent) {
                $connection = Connection::getById($agent->fields[Connection::getForeignKeyField()]);
                if ($connection) {
                    static::initWazuhConnection($connection->fields['indexer_url'], $connection->fields['indexer_port'], $connection->fields['indexer_user'], $connection->fields['indexer_password']);
                    $agentId = $agent->fields['agent_id'];
                    static::queryVulnerabilitiesByAgentIds([$agentId], $device);
                }
            } else {
                $message = sprintf("%s %s Can not find active and not deleted agent id = %s type = %s", __CLASS__, __FUNCTION__, $device->fields['id'], $device->getType());
                Logger::addError($message);
            }
        } else {
            Logger::addError(sprintf("%s %s Device %s outside of NetworkEquipment or Computer scope.", __CLASS__, __FUNCTION__, $device->getType()));
        }
        return false;
    }

    #[\Override]
    public function rawSearchOptions(): array
    {
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

        $actions["GlpiPlugin\Wazuh\NetworkEqTab:create_ticket"] = __("Create ticket", PluginConfig::APP_CODE);

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
     * Ticket creation
     *
     * @param int $entity_id ID encji
     * @param int $device_id
     * @param int $network_id ID
     * @param string $title
     * @return int|boolean ticket ID or false
     */
    private static function createTicketWithDevice($entity_id, array $cves, $input) {
        global $DB;
        $full_cves = [];

        $itil_category_id = $input['ticket_category'] ?? 0;
        $title = $input['ticket_title'] ?? 'Wazuh Vulnerable';
        $comment = $input['ticket_comment'] ?? '';
        $urgency = $input['ticket_urgency'] ?? 3;

        $cve_id = reset($cves);

        $cve = self::getById($cve_id);
        $device_id = $cve->fields[NetworkEquipment::getForeignKeyField()];

        if (!$device_id) {
            return false;
        }

        $content = __('Wazuh auto ticket', PluginConfig::APP_CODE) . "<br>";
        Logger::addDebug(__FUNCTION__ . " Network Eq: $device_id");

        if ($device_id) {
            $device = new \NetworkEquipment();
            if ($device->getFromDB($device_id)) {
                Logger::addDebug(__FUNCTION__ . " Network Eq: $device_id");
                $device_name = $cve->fields['name'] . "/" . $cve->fields['p_name'];
                $content = $comment  . "<br>";
                $content .= sprintf(
                        __('Linked Network Device: %s', PluginConfig::APP_CODE) . "<br>",
                        "<a href='networkequipment.form.php?id=" . $device_id . "'>" . $device_name . "</a>"
                );
                $content .= "Links: ";
                foreach ($cves as $cveid) {
                    $cve = self::getById($cveid);
                    array_push($full_cves, $cve);
                    $name = $cve->fields['name'];
                    $content .= sprintf(
                            " <a href='../plugins/wazuh/front/networkeqtab.form.php?id=$cveid'>$name</a> "
                    );
                }
            }
        }

        $ticket = new Ticket();
        $ticket_input = [
            'name' => $title,
            'content' => \Toolbox::addslashes_deep($content),
            'itilcategories_id' => $itil_category_id,
            'status' => Ticket::INCOMING,
            'priority' => 3,
            'urgency' => $urgency,
            'impact' => 3,
            'entities_id' => $entity_id,
            '_add_items' => [],
        ];

        $ticket_id = $ticket->add($ticket_input);

        if ($ticket_id) {
            //linking cve's to ticket
            foreach ($full_cves as $cve) {
                $cve->fields[Ticket::getForeignKeyField()] = $ticket_id;
                $cve->update($cve->fields);
            }

//            $additional_content = __('More details in Device Wazuh menu.', PluginConfig::APP_CODE);
//            $followup = new ITILFollowup();
//            $followup_input = [
//                'itemtype' => 'Ticket',
//                'items_id' => $ticket_id,
//                'content' => $additional_content,
//                'is_private' => 0,
//            ];
//            $followup->add($followup_input);


            if ($device_id) {
                $ticket_item = new Item_Ticket();
                $ticket_item_input = [
                    'tickets_id' => $ticket_id,
                    'itemtype' => 'NetworkEquipment',
                    'items_id' => $device_id
                ];
                $ticket_item->add($ticket_item_input);
            }
        }

        return $ticket_id;
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

        if (!$DB->tableExists($table)) {
            $migration->displayMessage("Installing $table");

        $query = "CREATE TABLE IF NOT EXISTS `$table` (
                     `id` int {$default_key_sign} NOT NULL AUTO_INCREMENT,
                     `name` varchar(255) COLLATE {$default_collation} NOT NULL,
                     `completename` TEXT COLLATE {$default_collation} DEFAULT NULL,
                     `key` varchar(255) COLLATE {$default_collation} NOT NULL DEFAULT (UUID()),
                     `$parent_fkey` int {$default_key_sign} NOT NULL DEFAULT '0',
                     `$networkeq_fkey` int {$default_key_sign} NOT NULL DEFAULT '0',
                     `$ticket_fkey` int {$default_key_sign} NOT NULL DEFAULT '0',
                     `v_category` varchar(255) COLLATE {$default_collation} DEFAULT NULL,
                     `v_classification` varchar(255) COLLATE {$default_collation} DEFAULT NULL,
                     `v_description` TEXT COLLATE {$default_collation} DEFAULT NULL,
                     `v_detected` timestamp DEFAULT NULL,
                     `v_published` timestamp DEFAULT NULL,
                     `v_enum` varchar(255) COLLATE {$default_collation} DEFAULT NULL,
                     `v_severity` varchar(255) COLLATE {$default_collation} DEFAULT NULL,
                     `v_reference` TEXT COLLATE {$default_collation} DEFAULT NULL,
                     `v_score` decimal(6,2) {$default_key_sign} NOT NULL DEFAULT '0',
                     `p_name` varchar(255) COLLATE {$default_collation} DEFAULT NULL,
                     `p_version` varchar(255) COLLATE {$default_collation} DEFAULT NULL,
                     `p_type` varchar(255) COLLATE {$default_collation} DEFAULT NULL,
                     `p_description` TEXT COLLATE {$default_collation} DEFAULT NULL,
                     `p_installed` TIMESTAMP DEFAULT NULL,
                     `is_discontinue` tinyint(1) NOT NULL DEFAULT false,

                     `level` int NOT NULL DEFAULT '0',
                     `ancestors_cache` longtext DEFAULT NULL,
                     `sons_cache` longtext DEFAULT NULL,

                     `date_mod` timestamp DEFAULT CURRENT_TIMESTAMP,
                     `date_creation` timestamp DEFAULT CURRENT_TIMESTAMP,
                     `entities_id` int {$default_key_sign} NOT NULL DEFAULT '0',
                     `is_recursive` tinyint(1) NOT NULL DEFAULT '0',
                     `is_deleted` tinyint(1) NOT NULL DEFAULT '0',
                     PRIMARY KEY (`id`),
                     KEY `$parent_fkey` (`$parent_fkey`),
                     KEY `$networkeq_fkey` (`$networkeq_fkey`),
                     KEY `$ticket_fkey` (`$ticket_fkey`),
                     UNIQUE KEY `key` (`key`),
                     KEY `v_detected` (`v_detected`),
                     KEY `entities_id` (`entities_id`),
                     KEY `date_mod` (`date_mod`),
                     KEY `date_creation` (`date_creation`),
                     KEY `is_recursive` (`is_recursive`),
                     KEY `is_deleted` (`is_deleted`)
                  ) ENGINE=InnoDB DEFAULT CHARSET={$default_charset} COLLATE={$default_collation} ROW_FORMAT=DYNAMIC";
            $DB->doQuery($query) or die("Error creating $table table");

        }

        $migration->updateDisplayPrefs(
                [
                    self::class => [1, 10, 11, 3, 6, 4, 8, 9, 7]
                ],
        );
        
        if (version_compare('0.0.4', $version, '<=')) {
            $itil_category_fkey = \ITILCategory::getForeignKeyField();
            $migration->addField($table, $itil_category_fkey, "fkey");
            $migration->addKey($table, $itil_category_fkey, $itil_category_fkey);
        }


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
        return $wazuhTab->fields[NetworkEquipment::getForeignKeyField()] ?? 0;
    }

    static function newDeviceInstance(): Computer|NetworkEquipment
    {
        return new NetworkEquipment();
    }

    static function getWazuhTabHref(int $id): string
    {
        return "../plugins/wazuh/front/networkeqtab.form.php?id=$id";
    }

    static function getDeviceHref(int $id): string
    {
        return "networkequipment.form.php?id=$id";
    }

    static function getDefaultTicketTitle(): string {
        return "Wazuh Network Equipment Vulnerable";
    }

    static function generateLinkName(NetworkEqAlertsTab|NetworkEqTab|ComputerAlertsTab|ComputerTab $item): string
    {
        return  $item->fields['name'] . "/" . $item->fields['p_name'];
    }

    static function getDeviceForeignKeyField(): string
    {
        return NetworkEquipment::getForeignKeyField();
    }
}
