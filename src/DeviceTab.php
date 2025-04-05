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

if (!defined('GLPI_ROOT')) {
   die("No access.");
}

/**
 * Wazuh computer vulenrable tab
 *
 * @author w-tomasz
 */
abstract class DeviceTab extends \CommonDBChild implements Upgradeable {
    use IndexerRequestsTrait;

    public $dohistory = true;

    #[\Override]
    static function getTypeName($nb = 0) {
        return _n('Wazuh Vulnerable', 'Wazuh Vulnerabilities', $nb, PluginConfig::APP_CODE);
    }

    #[\Override]
    function getTabNameForItem(CommonGLPI $item, $withtemplate = 0) {
        if (!$withtemplate && ($item instanceof Computer || $item instanceof NetworkEquipment)) {
            global $DB;
            $count = $this->countElements($item->getID());
            return self::createTabEntry(__(PluginConfig::APP_NAME, PluginConfig::APP_CODE), $count);
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

        $tab[] = [
            'id' => 2,
            'name' => __('Id', PluginConfig::APP_CODE),
            'table' => static::getTable(),
            'field' => 'id',
            'datatype' => 'number',
            'massiveaction' => false,
        ];

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

        return $tab;
    }

}
