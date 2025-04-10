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
use CommonDBTM;
use Migration;
use Computer;
use NetworkEquipment;
use Ticket;
use MassiveAction;
use DBConnection;
use Html;
use Entity;
use Search;
use Session;
use ITILFollowup;
use Item_Ticket;
use CommonTreeDropdown;

if (!defined('GLPI_ROOT')) {
   die("No access.");
}

/**
 * Wazuh computer vulenrable tab
 *
 * @author w-tomasz
 */
abstract class DeviceTab extends CommonTreeDropdown implements Upgradeable {
    use IndexerRequestsTrait;

    public $dohistory = true;

    #[\Override]
    function getTabNameForItem(CommonGLPI $item, $withtemplate = 0) {
        if (!$withtemplate && ($item instanceof Computer || $item instanceof NetworkEquipment)) {
            global $DB;
            $count = $this->countElements($item->getID());
            return self::createTabEntry(static::getTypeName($count), $count);
        }
        return '';
    }

    abstract protected function countElements($device_id);
    abstract static protected function getUpsertStatement(): string;
    abstract static protected function bindStatement($stmt, $result, \CommonDBTM $device): bool;

    /**
     * @param integer $ID
     * @param array $options
     * @return boolean
     */
    #[\Override]
    function showForm($ID, array $options = []) {
        global $CFG_GLPI;

        $this->initForm($ID, $options);
        $this->showFormHeader($options);

        $options['formfooter'] = true;
        $options['formactions'] = [
            Html::submit(__('Save'), ['name' => 'update', 'class' => 'btn btn-primary me-2']),
            Html::link(__('Back to list'), 'front/vulnerability.php', ['class' => 'btn btn-outline-secondary'])
        ];

        TemplateRenderer::getInstance()->display('@wazuh/device_tab.html.twig', [
            'item' => $this,
            'params' => $options,
        ]);
        return true;
    }

    static function showBrowseView($itemtype, $params) {
        $item_id = $params['criteria'][0]['value'];
        $params['criteria'] = [
            [
                'field' => 7,
                'searchtype' => 'equals',
                'value' => $item_id
            ],
            [
                'field' => 20,
                'searchtype' => 'equals',
                'value' => 0
            ],
        ];

        Logger::addDebug(__FUNCTION__ . " : " . json_encode($params));

        $data = Search::getDatas($itemtype, $params);
        $raw_data_ids = [];
        $has_parent_ids = [];
        $has_child_ids = [];

        foreach ($data['data']['rows'] as $row) {
            if (isset($row['raw']['id'])) {
                $id = $row['raw']['id'];
                $raw_data_ids[] = $id;
            }
        }

        foreach ($raw_data_ids as $parent_id) {
            $params['criteria'] = [
                [
                    'field' => 7,
                    'searchtype' => 'equals',
                    'value' => $item_id
                ],
                [
                    'field' => 20,
                    'searchtype' => 'equals',
                    'value' => $parent_id
                ],
            ];
            $data1 = Search::getDatas($itemtype, $params);
            $len1 = count($data1['data']['rows']);
            if ($len1 > 0) {
                $has_child_ids[] = $parent_id;
                foreach ($data1['data']['rows'] as $row) {
                    if (isset($row['raw']['id'])) {
                        $id = $row['raw']['id'];
                        $has_parent_ids[] = $id;
                    }
                }
            }
//            $data['data']['rows'] = array_merge_recursive($data['data']['rows'], $data1['data']['rows']);
            $pos = static::findArrayPositionById($data['data']['rows'], $parent_id);
            if ($pos !== false) {
                $data['data']['rows'] = static::arrayInsertAfter($data['data']['rows'], $pos, $data1['data']['rows']);
            }
        }
        $data['has_child_ids'] = $has_child_ids;
        $data['has_parent_ids'] = $has_parent_ids;

        $treeSearch = new TreeSearchOutput();
        unset($data['search']['criteria'][1]);
        $treeSearch->displayData($data, $params);
//        Logger::addDebug(__FUNCTION__ . " " . json_encode($params));
//        Logger::addDebug(__FUNCTION__ . " " . json_encode($data));
    }

    protected static function findArrayPositionById(array $array, int $id): int|false {
        foreach ($array as $i => $row) {
            if (isset($row['raw']['id'])) {
                if ($id == $row['raw']['id']) {
                    return $i;
                }
            }
        }
        
        Logger::addDebug(__FUNCTION__ . " $id not found.");
        return false;
    }

    protected static function arrayInsertAfter($array, $position, $insert_array) {
        Logger::addDebug(__FUNCTION__ . " $position");
        if (empty($insert_array) || $position===false) {
            return $array;
        }
        $first_part = array_slice($array, 0, $position + 1, true);
        $second_part = array_slice($array, $position + 1, null, true);

        return array_merge($first_part, $insert_array, $second_part);
    }

    
    private static function getSeverityValue(string|null $severity): int | null {
        $levels = [
            'very low' => 1,
            'low' => 2,
            'medium' => 3,
            'high' => 4,
            'very high' => 5,
            'critical' => 6
        ];
        if ($severity === null) {
            return 3;
        }
        return $levels[strtolower($severity)] ?? 3;
    }
    
    protected static function createParentItem(array $item_data, CommonDBTM $item): int | false {
        $founded = $item->find([
            'name' => $item_data['name'],
            \Entity::getForeignKeyField() => \Session::getActiveEntity(),
            static::getForeignKeyField() => 0
        ]);
        
        
        if ($founded) {
            return reset($founded)['id'];
        }

        if ($item instanceof ComputerTab) {
            $fkey = \Computer::getForeignKeyField();
        } else {
            $fkey = \NetworkEquipment::getForeignKeyField();
        }
        
        $id = $item->add([
            'name' => $item_data['name'],
            $fkey => $item_data[$fkey]
        ]);

        if (!$id) {
            Logger::addWarning(__FUNCTION__ . " " . $DB->error());
        }

        return $id;
        
    }

    protected static function getAvgUrgencyLevel($iids): int | null {
        global $DB;
        $default = 3;

        $table = static::getTable();
        
        $key = array_keys($iids)[0];
        $ids = array_map('intval', array_values($iids[$key]));

        Logger::addDebug(__FUNCTION__ . " table: " . $table . " :::::: " . json_encode($ids));

         $criteria = [
            'SELECT' => ['v_severity'],
            'FROM' => $table,
             'WHERE' => [
                 'id' => $ids,
                 'is_deleted' => 0,
                 ]
        ];

        $data = [];
        $average = 0;
        $iterator = $DB->request($criteria);
        $size = count($iterator);
        if ($size === 0) {
            return $default;
        }
        foreach ($iterator as $record) {
            $average += self::getSeverityValue($record['v_severity']);
        }

        $result = (int)($average / $size);
        if ($result < 1 || $result > 6) {
            Logger::addError("Average urgency level outof expecting values. Avg=$average, Size=$size, Result=$result");
            throw new \RuntimeException("Average urgency level outof expecting values.");
        }
        
        return $result;

    }
    
    #[\Override]
    static function showMassiveActionsSubForm(\MassiveAction $ma) {
        Logger::addDebug(__FUNCTION__ . " "  . $ma->getAction() . " ----- " . json_encode($ma->getItems()));
        switch ($ma->getAction()) {
            case "create_ticket":
                self::createTicketForm($ma);
                break;
        }
        return parent::showMassiveActionsSubForm($ma);
    }

    protected abstract static function getConnectionId($iids): int;
    
    private static function getConnectionItilCategory(int $connection_id): int {
        if ($connection_id === 0) {
            return 0;
        }
        global $DB;

        $table = Connection::getTable();
        $criteria = [
            'SELECT' => [\ITILCategory::getForeignKeyField()],
            'FROM' => $table,
            'WHERE' => [
                'id' => $connection_id,
                'is_deleted' => 0,
            ]
        ];
        $iterator = $DB->request($criteria);
        $size = count($iterator);
        if ($size === 0 || $size > 1) {
            return 0;
        }
        $connection = $iterator->current();
        $category_id = $connection[\ITILCategory::getForeignKeyField()] ?? 0;
        return $category_id;
    }
    
    
    private static function createTicketForm(MassiveAction $ma) {
        $connection_id = static::getConnectionId($ma->getItems());
        
        echo "<div class='d-flex flex-column align-items-center gap-2 mb-2'>";

        echo "<div class='d-flex gap-2 align-items-baseline'>";
        echo "<label for='ticket_title'>" . __('Title', PluginConfig::APP_CODE) . ":</label>";
        echo Html::input(
                'ticket_title',
                [
                    'id' => 'ticket_title',
                    'value' => 'Wazuh Vulnerable',
                    'class' => 'form-control',
                    'required' => true,
                    'display' => false
                ]
        );

        echo "<label for='ticket_urgency'>" . __('Urgency', PluginConfig::APP_CODE) . ":</label>";
        $uparams = [
            'name' => 'ticket_urgency',
            'value' => static::getAvgUrgencyLevel($ma->getItems()),
            'display' => false
        ];
        echo \Ticket::dropdownUrgency($uparams);


        echo "<label class='no-wrap' for='ticket_category'>" . __('ITIL Category', PluginConfig::APP_CODE) . ":</label>";
        $cparams = [
            'name' => 'ticket_category',
            'entity' => $_SESSION['glpiactive_entity'],
            'value' => self::getConnectionItilCategory($connection_id),
            'display' => false
        ];
        echo \ITILCategory::dropdown($cparams);
        
        echo "</div>";
        echo "<span class='align-self-start'>" . __("Additional ticket comment:", PluginConfig::APP_CODE) . "</span>";
        echo Html::textarea([
            "name" => "ticket_comment",
            "value" => "",
            "cols" => 50,
            "rows" => 4,
            "display" => false
        ]);
        echo Entity::dropdown([
            'name' => 'entities_id',
            'value' => \Session::getActiveEntity(),
            'entity' => $_SESSION['glpiactiveentities'],
            'rand' => mt_rand(),
            'display' => false
        ]);
    }
    
    #[\Override]
    public function rawSearchOptions() {
        $tab = parent::rawSearchOptions();

//        $tab[] = [
//            'id' => 2,
//            'name' => __('Id', PluginConfig::APP_CODE),
//            'table' => static::getTable(),
//            'field' => 'id',
//            'datatype' => 'number',
//            'massiveaction' => false,
//        ];

        $tab[] = [
            'id' => 3,
            'name' => __('Key', PluginConfig::APP_CODE),
            'table' => static::getTable(),
            'field' => 'key',
            'datatype' => 'string',
            'massiveaction' => false,
        ];

        $tab[] = [
            'id' => 4,
            'name' => __('Severity', PluginConfig::APP_CODE),
            'table' => static::getTable(),
            'field' => 'v_severity',
            'datatype' => 'string',
            'massiveaction' => false,
        ];

        $tab[] = [
            'id' => 5,
            'table' => static::getTable(),
            'field' => 'v_description',
            'name' => __('Description', PluginConfig::APP_CODE),
            'datatype' => 'text',
            'massiveaction' => false
        ];

        $tab[] = [
            'id' => 6,
            'table' => static::getTable(),
            'field' => 'v_reference',
            'name' => __('Reference', PluginConfig::APP_CODE),
            'datatype' => 'weblink',
            'massiveaction' => false
        ];

        $tab[] = [
            'id' => 8,
            'table' => Ticket::getTable(),
            'field' => 'id',
            'name' => __('Ticket', PluginConfig::APP_CODE),
            'datatype' => 'itemlink',
            'massiveaction' => true,
            'joinparams' => [
                'jointype' => 'standard',
                'foreignkey' => Ticket::getForeignKeyField()
            ]
        ];

        $tab[] = [
            'id' => 9,
            'table' => Ticket::getTable(),
            'field' => 'status',
            'name' => __('Ticket Status', PluginConfig::APP_CODE),
            'datatype' => 'itemlink',
            'massiveaction' => true,
            'joinparams' => [
                'jointype' => 'standard',
                'foreignkey' => Ticket::getForeignKeyField()
            ]
        ];

        $tab[] = [
            'id' => 10,
            'table' => static::getTable(),
            'field' => 'is_discontinue',
            'name' => __('Discontinued', PluginConfig::APP_CODE),
            'datatype' => 'bool',
            'massiveaction' => false,
        ];

        $tab[] = [
            'id' => 11,
            'table' => static::getTable(),
            'field' => 'v_detected',
            'name' => __('Detected', PluginConfig::APP_CODE),
            'datatype' => 'datetime',
            'massiveaction' => false,
        ];

        $tab[] = [
            'id' => 12,
            'table' => static::getTable(),
            'field' => 'v_published',
            'name' => __('Published', PluginConfig::APP_CODE),
            'datatype' => 'datetime',
            'massiveaction' => false,
        ];
        
        $tab[] = [
            'id' => 20,
            'table' => static::getTable(),
            'field' => static::getForeignKeyField(),
            'name' => __('ParentId', PluginConfig::APP_CODE),
            'datatype' => 'number',
            'massiveaction' => false,
        ];

//        $tab[] = [
//            'id' => 13,
//            'table' => static::getTable(),
//            'field' => 'date_creation',
//            'name' => __('Fetched', PluginConfig::APP_CODE),
//            'datatype' => 'datetime',
//            'massiveaction' => false,
//        ];

        return $tab;
    }

}
