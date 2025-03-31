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
 * Wazuh computer vulenrable tab
 *
 * @author w-tomasz
 */
class ComputerTab extends DeviceTab {

    use IndexerRequestsTrait;

    public $dohistory = true;
    public static $itemtype = 'Computer';
    public static $items_id = 'computers_id';


    protected function countElements($computers_id) {
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
            throw new \RuntimeException("Founded ComputerTab collection exceeded limit 1.");
        }

        $item_data = [
            'key' => $key,
            Computer::getForeignKeyField() => $computer->getID(),
            'name' => $result['_source']['vulnerability']['id'],
            'v_description' => $DB->escape($result['_source']['vulnerability']['description']),
            'v_severity' => $result['_source']['vulnerability']['severity'],
            'v_detected' => self::convertIsoToMysqlDatetime($result['_source']['vulnerability']['detected_at']),
            'v_published' => self::convertIsoToMysqlDatetime($result['_source']['vulnerability']['published_at']),
            'v_enum' => $result['_source']['vulnerability']['enumeration'],
            'v_category' => $result['_source']['vulnerability']['category'],
            'v_classification' => $result['_source']['vulnerability']['classification'],
            'v_reference' => $result['_source']['vulnerability']['reference'],
            'p_name' => $result['_source']['package']['name'],
            'p_version' => $result['_source']['package']['version'],
            'p_type' => $result['_source']['package']['type'],
            'p_description' => $DB->escape($result['_source']['package']['description']),
            'p_installed' => self::convertIsoToMysqlDatetime($result['_source']['package']['installed']),
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
            Logger::addDebug($item->fields['name']);
            $agent = PluginWazuhAgent::getByDeviceTypeAndId($item->getType(), $item->fields['id']);
            if ($agent) {
                $config = Connection::getById($agent->fields[Connection::getForeignKeyField()]);
                if ($config) {
                    static::initWazuhConnection($config->fields['indexer_url'], $config->fields['indexer_port'], $config->fields['indexer_user'], $config->fields['indexer_password']);
                    $result = static::queryVulnerabilitiesByAgentIds([$agent->fields['agent_id']]);
                    if (!empty($result)) {
                        foreach ($result['data']['hits']['hits'] as $res) {
//                        Logger::addDebug(json_encode($res['_source']['vulnerability']['severity']) . " -- " . json_encode($res['_id']));
                            self::createItem($res, $item);
                        }
                    }

                    $p = [
                        'addhidden' => [// some hidden inputs added to the criteria form
                            'hidden_input' => 'OK'
                        ],
                        'actionname' => 'preview', //change the submit button name
                        'actionvalue' => __('Preview'), //change the submit button label
                    ];
                    Search::showGenericSearch(ComputerTab::class, $p);

                    $options = [
                        'reset' => true,
                        'criteria' => [
                            [
                                'link' => 'AND',
                                'field' => 7,
                                'searchtype' => 'equals',
                                'value' => $item->getID()
                            ]
                        ],
                        'display_type' => Search::HTML_OUTPUT
                    ];
                    Search::showList(ComputerTab::class, $options);
                    
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
            'id' => 7,
            'table' => Computer::getTable(),
            'field' => 'name',
            'name' => __('Computer', PluginConfig::APP_CODE),
            'datatype' => 'dropdown',
            'massiveaction' => true,
            'joinparams' => [
                'jointype' => 'standard',
                'foreignkey' => Computer::getForeignKeyField()
            ]
        ];

        return $tab;
    }
    
    
    #[\Override]
    public function getSpecificMassiveActions($checkitem = null) {
        $actions = parent::getSpecificMassiveActions($checkitem);

        $actions["GlpiPlugin\Wazuh\ComputerTab:create_ticket"] = __("Create ticket", PluginConfig::APP_CODE);

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
 
                $ticket_id = self::createTicketWithDevice($input['entities_id'], $ids, $input['ticket_title'], $input['ticket_comment']);
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
     * @param int $computer_id 
     * @param int $network_id ID 
     * @param string $title
     * @return int|boolean ticket ID or false
     */
    protected static function createTicketWithDevice($entity_id, array $cves, $title = "Alert Wazuh", $comment = "") {
        global $DB;
        $full_cves = [];

        $cve_id = reset($cves);
        
        $cve = ComputerTab::getById($cve_id);
        $computer_id = $cve->fields[Computer::getForeignKeyField()];
        
        if (!$computer_id) {
            return false;
        }

        $content = __('Wazuh auto ticket', PluginConfig::APP_CODE) . "<br>";
        Logger::addDebug(__FUNCTION__ . " Computer: $computer_id");

        if ($computer_id) {
            $computer = new Computer();
            if ($computer->getFromDB($computer_id)) {
        Logger::addDebug(__FUNCTION__ . " Computer: $computer_id");
                $computer_name = $computer->fields['name'];
                $content = $comment  . "<br>";
                $content .= sprintf(
                        __('Linked Computer: %s', PluginConfig::APP_CODE) . "<br>",
                        "<a href='computer.form.php?id=" . $computer_id . "'>" . $computer_name . "</a>"
                );
                $content .= "Links: ";
                foreach ($cves as $cveid) {
                    $cve = ComputerTab::getById($cveid);
                    array_push($full_cves, $cve);
                    $name = $cve->fields['name'] . "/" . $cve->fields['p_name'];
                    $content .= sprintf(
                            " <a href='../plugins/wazuh/front/computertab.form.php?id=$cveid'>$name</a> "
                    );
                }
            }
        }

        $ticket = new Ticket();
        $ticket_input = [
            'name' => $title,
            'content' => \Toolbox::addslashes_deep($content),
            'status' => Ticket::INCOMING,
            'priority' => 3,
            'urgency' => 3,
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
            
            $additional_content = __('More details in Device Wazuh menu.', PluginConfig::APP_CODE);

            $followup = new ITILFollowup();
            $followup_input = [
                'itemtype' => 'Ticket',
                'items_id' => $ticket_id,
                'content' => $additional_content,
                'is_private' => 0,
            ];

            $followup->add($followup_input);
            
            
            if ($computer_id) {
                $ticket_item = new Item_Ticket();
                $ticket_item_input = [
                    'tickets_id' => $ticket_id,
                    'itemtype' => 'Computer',
                    'items_id' => $computer_id
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
    static function install(Migration $migration) {
        global $DB;

        $default_charset = DBConnection::getDefaultCharset();
        $default_collation = DBConnection::getDefaultCollation();
        $default_key_sign = DBConnection::getDefaultPrimaryKeySignOption();
        $table = self::getTable();
        $computer_fkey = Computer::getForeignKeyField();
        $ticket_fkey = \Ticket::getForeignKeyField();

        if (!$DB->tableExists($table)) {
            $migration->displayMessage("Installing $table");

        $query = "CREATE TABLE IF NOT EXISTS `$table` (
                     `id` int {$default_key_sign} NOT NULL AUTO_INCREMENT,
                     `name` varchar(255) COLLATE {$default_collation} NOT NULL,
                     `key` varchar(255) COLLATE {$default_collation} NOT NULL,
                     `$computer_fkey` int {$default_key_sign} NOT NULL DEFAULT '0',
                     `$ticket_fkey` int {$default_key_sign} NOT NULL DEFAULT '0',
                     `v_category` varchar(255) COLLATE {$default_collation} NOT NULL,
                     `v_classification` varchar(255) COLLATE {$default_collation} NOT NULL,
                     `v_description` TEXT COLLATE {$default_collation} DEFAULT NULL,
                     `v_detected` timestamp DEFAULT NULL,
                     `v_published` timestamp DEFAULT NULL,
                     `v_enum` varchar(255) COLLATE {$default_collation} DEFAULT NULL,
                     `v_severity` varchar(255) COLLATE {$default_collation} DEFAULT NULL,
                     `v_reference` TEXT COLLATE {$default_collation} DEFAULT NULL,
                     `v_score` int {$default_key_sign} NOT NULL DEFAULT '0',
                     `p_name` varchar(255) COLLATE {$default_collation} DEFAULT NULL,
                     `p_version` varchar(255) COLLATE {$default_collation} DEFAULT NULL,
                     `p_type` varchar(255) COLLATE {$default_collation} DEFAULT NULL,
                     `p_description` TEXT COLLATE {$default_collation} DEFAULT NULL,
                     `p_installed` TIMESTAMP DEFAULT NULL,
                     `date_mod` timestamp DEFAULT CURRENT_TIMESTAMP,
                     `date_creation` timestamp DEFAULT CURRENT_TIMESTAMP,
                     `entities_id` int {$default_key_sign} NOT NULL DEFAULT '0',
                     `is_recursive` tinyint(1) NOT NULL DEFAULT '0',
                     `is_deleted` tinyint(1) NOT NULL DEFAULT '0',
                     PRIMARY KEY (`id`),
                     KEY `$computer_fkey` (`$computer_fkey`),
                     KEY `$ticket_fkey` (`$ticket_fkey`),
                     UNIQUE KEY `key` (`key`),
                     KEY `entities_id` (`entities_id`),
                     KEY `date_mod` (`date_mod`),
                     KEY `date_creation` (`date_creation`),
                     KEY `is_recursive` (`is_recursive`),
                     KEY `is_deleted` (`is_deleted`)
                  ) ENGINE=InnoDB DEFAULT CHARSET={$default_charset} COLLATE={$default_collation} ROW_FORMAT=DYNAMIC";
            $DB->query($query) or die("Error creating $table table");

            $migration->updateDisplayPrefs(
                    [
                        'GlpiPlugin\Wazuh\ComputerTab' => [1, 3, 4, 8 ,9, 7]
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
