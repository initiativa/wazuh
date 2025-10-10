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
use CommonTreeDropdown;
use Glpi\Application\View\TemplateRenderer;
use CommonGLPI;
use Migration;
use Computer;
use NetworkEquipment;
use QueryExpression;
use Ticket;
use MassiveAction;
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
abstract class DeviceAlertsTab extends CommonTreeDropdown implements Upgradeable, Ticketable {
    use IndexerRequestsTrait;

    public $dohistory = true;

    #[\Override]
    function getTabNameForItem(CommonGLPI $item, $withtemplate = 0): array|string {
        if (!$withtemplate && ($item instanceof Computer || $item instanceof NetworkEquipment)) {
            global $DB;
            $count = $this->countElements($item->getID());
            return self::createTabEntry(static::getTypeName($count), $count);
        }
        return '';
    }

    abstract public static function getAgentAlerts(CommonGLPI $device): array | false;
    abstract protected function countElements($device_id);

    protected static function createParentItem(array $item_data, CommonDBTM $item, int $entity_id): int | false {
//        Logger::addDebug(__FUNCTION__ . json_encode($item_data, JSON_PRETTY_PRINT));

        if ($item_data['name'] === 'syscheck_integrity_changed') {
            $syscheck = json_decode(stripslashes($item_data['syscheck']), true);
            $directoryPath = dirname($syscheck['path']);
            $directories = explode("/", $directoryPath);
//            Logger::addDebug("******************** " . $directories[1] . " -- " . $directories[2]);
        }

        if ($item instanceof ComputerAlertsTab) {
            $fkey = Computer::getForeignKeyField();
        } else {
            $fkey = NetworkEquipment::getForeignKeyField();
        }

        $founded = $item->find([
            'name' => $item_data['name'],
            'is_discontinue' => false,
            $fkey => $item_data[$fkey],
            Entity::getForeignKeyField() => $entity_id,
            static::getForeignKeyField() => 0
        ]);

        if ($founded) {
            $founded_item = reset($founded);
            $founded_item_id = $founded_item['id'];
            if (isset($directories)) {
                return self::subParentItem($item, $item_data, $fkey, $directories, $founded_item_id);
            }
            return $founded_item_id;
        }

        $id = $item->add([
            'name' => $item_data['name'],
            Entity::getForeignKeyField() => $entity_id,
            $fkey => $item_data[$fkey]
        ]);

        if (!$id) {
            global $DB;
            Logger::addWarning(__FUNCTION__ . " " . $DB->error());
            return false;
        }

        if (isset($directories)) {
            return self::subParentItem($item, $item_data, $fkey, $directories, $id);
        }

        return $id;
    }

    private static function subParentItem($item, $item_data, $fkey, $directories, int $parent_id): int | false {
            $dfounded = $item->find([
                'name' => $directories[1],
                Entity::getForeignKeyField() => Session::getActiveEntity(),
                static::getForeignKeyField() => $parent_id
            ]);
            if ($dfounded) {
                return reset($dfounded)['id'];
            }

            $did = $item->add([
                'name' => $directories[1],
                $fkey => $item_data[$fkey],
                static::getForeignKeyField() => $parent_id
            ]);

            if (!$did) {
                global $DB;
                Logger::addWarning(__FUNCTION__ . " " . $DB->error());
            }
            return $did;
    }

    static function showBrowseView($itemtype, $params): void
    {
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

        global $DB;

        $parent_map = [];
        $criteria = [
            'SELECT' => ['id', static::getForeignKeyField() . ' as parent_id'],
            'FROM' => static::getTable(),
            'WHERE' => [
                static::getDeviceForeignKeyField() => $item_id,
                'is_deleted' => 0,
                static::getForeignKeyField() => ['<>', 0],
            ]
        ];

        $iterator = $DB->request($criteria);
        foreach ($iterator as $row) {
            $parent_map[$row['id']] = $row['parent_id'];
        }
        $data['parent_map'] = $parent_map;

        $criteria = [
            'SELECT' => [static::getForeignKeyField() . ' as parent_id', new QueryExpression('COUNT(*) as total')],
            'FROM' => static::getTable(),
            'WHERE' => [
                static::getDeviceForeignKeyField() => $item_id,
                'is_deleted' => 0,
                static::getForeignKeyField() => ['<>', 0],
            ],
            'GROUPBY' => static::getForeignKeyField()
        ];

        $has_child_ids = [];
        $child_map = [];

        $iterator = $DB->request($criteria);
        foreach ($iterator as $row) {
            $has_child_ids[] = $row['parent_id'];
            $child_map[$row['parent_id']] = $row['total'];
        }

        $data['device_id'] = $item_id;
        $data['has_child_ids'] = $has_child_ids;
        $data['child_map'] = $child_map;
        $treeSearch = new TreeSearchOutput();
        unset($data['search']['criteria'][1]);
        $treeSearch->displayData($data, $params);
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

    protected static function arrayInsertAfter($array, $position, $insert_array): array {
        if (empty($insert_array) || $position === false) {
            return $array;
        }
        $first_part = array_slice($array, 0, $position + 1, true);
        $second_part = array_slice($array, $position + 1, null, true);

        return array_merge($first_part, $insert_array, $second_part);
    }

    static function cronInfo($name) {
        switch ($name) {
            case 'fetchalerts' :
                return array('description' => __('Fetch alerts information for linked with Wazuh\'s Agents, Computers and NetworkEquipments.'),
                    'parameter'   => __('None'));
        }
        return [];
    }

    static function cronFetchAlerts($task = null): int
    {
        global $DB;
        $cron_status = 0;
        Logger::addInfo("Executing cron - FetchAlerts.");

        $agents = (new PluginWazuhAgent())->find([
            'itemtype' => 'Computer',
        ]);
        $device_ids = [];
        foreach ($agents as $agent) {
            $device_ids[] = $agent['item_id'];
        }

        if (!empty($device_ids)) {
            if (count($device_ids) === 1) {
                $device_ids = $device_ids[0];
            }
            $devices = (new Computer())->find([
                'id' => $device_ids,
            ]);
            foreach ($devices as $device) {
                ExtApi::fetchLatestAlerts(Computer::getById($device['id']));
            }
        }

        $agents = (new PluginWazuhAgent())->find([
            'itemtype' => 'NetworkEquipment',
        ]);

        $device_ids = [];
        foreach ($agents as $agent) {
            $device_ids[] = $agent['item_id'];
        }

        if (!empty($device_ids)) {
            if (count($device_ids) === 1) {
                $device_ids = $device_ids[0];
            }
            $devices = (new NetworkEquipment())->find([
                'id' => $device_ids,
            ]);
            foreach ($devices as $device) {
                ExtApi::fetchLatestAlerts(NetworkEquipment::getById($device['id']));
            }
        }

        return $cron_status;
    }

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

        $twig = TemplateRenderer::getInstance();
        $twig->display('@wazuh/device_alerts_tab.html.twig', [
            'item' => $this,
            'params' => $options,
            'syscheck_content' => $this->sanitizeOutput($this->formatJsonToHtml($this->fields['syscheck'])),
            'data_content' => $this->sanitizeOutput($this->formatJsonToHtml($this->fields['data'])),
            'rule_content' => $this->sanitizeOutput($this->formatJsonToHtml($this->fields['rule'])),
        ]);
        return true;
    }

    function sanitizeOutput($input) {
        //after json_encode just javascript
        return preg_replace('#</script#i', '<\/script', $input);
    }

    /**
     * Format JSON data to HTML for display in GLPI
     * 
     * @param string|array $json JSON string or already decoded array
     * @return string Formatted HTML
     */
    function formatJsonToHtml($json) {
        // If string provided, decode it first
        if (is_string($json)) {
            $data = json_decode($json, true);
            if (json_last_error() !== JSON_ERROR_NONE) {
                return "<div class='alert alert-warning'>Invalid JSON format</div>";
            }
        } else {
            $data = $json;
        }

        // Start building HTML output
        $html = "<div class='json-viewer'>";

        // Use recursive function to build nested structure
        $html .= $this->formatJsonNodeToHtml($data);

        $html .= "</div>";

        return $html;
    }

    /**
     * Helper function to recursively format JSON nodes
     * 
     * @param mixed $node Current JSON node
     * @param int $level Nesting level
     * @return string HTML representation
     */
    function formatJsonNodeToHtml($node, $level = 0) {
        $html = "";
        if (is_null($node)) {
            $node = '';
        }
        $padding = str_repeat("&nbsp;&nbsp;", $level);

        if (is_array($node)) {
            $html .= "<ul class='json-list'>";
            foreach ($node as $key => $value) {
                $html .= "<li>";
                $html .= "<span class='json-key'>" . htmlspecialchars($key) . "</span>: ";

                if (is_array($value)) {
                    $html .= $this->formatJsonNodeToHtml($value, $level + 1);
                } else {
                    $html .= "<span class='json-value'>" . htmlspecialchars($value) . "</span>";
                }

                $html .= "</li>";
            }
            $html .= "</ul>";
        } else {
            $html .= "<span class='json-value'>" . htmlspecialchars($node) . "</span>";
        }

        return $html;
    }

    private static function getSeverityValue(string $severity): int | null {
        $levels = [
            'very low' => 1,
            'low' => 2,
            'medium' => 3,
            'high' => 4,
            'very high' => 5,
            'critical' => 6
        ];
        
        return $levels[strtolower($severity)] ?? 3;
    }
    
    protected static function getAvgUrgencyLevel($iids): int | null {
        global $DB;
        $default = 3;

        $table = static::getTable();
        
        return $default;

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
                    'value' => static::getDefaultTicketTitle(),
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
    public function rawSearchOptions(): array
    {
        $tab = parent::rawSearchOptions();

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
            'name' => __('Agent IP', PluginConfig::APP_CODE),
            'table' => static::getTable(),
            'field' => 'a_ip',
            'datatype' => 'string',
            'massiveaction' => false,
        ];

        $tab[] = [
            'id' => 5,
            'table' => static::getTable(),
            'field' => 'a_name',
            'name' => __('Agent name', PluginConfig::APP_CODE),
            'datatype' => 'string',
            'massiveaction' => false
        ];

        $tab[] = [
            'id' => 6,
            'table' => static::getTable(),
            'field' => 'a_id',
            'name' => __('Agent id', PluginConfig::APP_CODE),
            'datatype' => 'string',
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
            'field' => 'source_timestamp',
            'name' => __('Detected', PluginConfig::APP_CODE),
            'datatype' => 'datetime',
            'massiveaction' => false,
        ];

        $tab[] = [
            'id' => 12,
            'table' => static::getTable(),
            'field' => 'date_creation',
            'name' => __('Fetched', PluginConfig::APP_CODE),
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

        return $tab;
    }

}
