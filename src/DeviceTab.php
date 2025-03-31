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
abstract class DeviceTab extends \CommonDBChild {
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

    
    #[\Override]
    static function showMassiveActionsSubForm(\MassiveAction $ma) {
        Logger::addDebug(__FUNCTION__ . " "  . $ma->getAction());
        switch ($ma->getAction()) {
            case "create_ticket":
                echo "<div class='d-flex flex-column align-items-center gap-2 mb-2'>";

                echo "<div class='d-flex gap-2 align-items-baseline'>";
                echo "<label for='ticket_title'>" . __('Title', PluginConfig::APP_CODE) . ":</label>";
                echo Html::input(
                        'ticket_title',
                        [
                            'id' => 'ticket_title',
                            'value' => 'Wazuh alert',
                            'class' => 'form-control',
                            'required' => true,
                            'display' => false
                        ]
                );
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
                echo "</div>";
                break;
        }
        return parent::showMassiveActionsSubForm($ma);
    }

    /**
     * @param object $migration
     * @return boolean
     */
    abstract static function install(Migration $migration);

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
