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

if (!defined('GLPI_ROOT')) {
   die("Sorry. You can't access this file directly");
}

use CommonGLPI;
use Computer;
use Entity;
use Exception;
use ITILCategory;
use NetworkEquipment;
use Session;
use Ticket;

/**
 * External Api To Call this Plugin functions
 *
 * @author w-tomasz
 */
class ExtApi {

    /**
     * @param CommonGLPI $device device of type Computer or NetworkEquipment with active link of PluginWazuhAgent->device. For example \Computer::getById(1) ...
     * @return array|false
     */
    public static function fetchLatestVulnerabilities(CommonGLPI $device): array | false {
        if ($device instanceof Computer) {
            return ComputerTab::getAgentVulnerabilities($device);
        } else if ($device instanceof NetworkEquipment) {
            return NetworkEqTab::getAgentVulnerabilities($device);
        } else {
            Logger::addError(sprintf("%s %s Device %s outside of NetworkEquipment or Computer scope.", __CLASS__, __FUNCTION__, $device->getType()));
        }
        return false;
    }

    public static function fetchLatestAlerts(CommonGLPI $device): array | false {
        if ($device instanceof Computer) {
            return ComputerAlertsTab::getAgentAlerts($device);
        } else if ($device instanceof NetworkEquipment) {
            return NetworkEqAlertsTab::getAgentAlerts($device);
        } else {
            Logger::addError(sprintf("%s %s Device %s outside of NetworkEquipment or Computer scope.", __CLASS__, __FUNCTION__, $device->getType()));
        }
        return false;
    }

    /**
     * @param CommonGLPI[] $items list of devices for ticket. Every element has to be in the same type (ComputerAlertsTab, ComputerTab, NetworkEqTab or NetworkEqAlertsTab)
     * @param string $title
     * @param string $message
     * @param int $urgency 1-6
     * @param ITILCategory|null $category
     * @param Entity|null $entity
     * @return int|false created Ticket id or false
     * @throws Exception when items of different classes or outside of class scope
     */
    public static function createTicket(array $items, string $title, string $message, ?int $urgency = 3, ?ITILCategory $category = null, ?Entity $entity = null): int | false {
        $item_ids = [];
        $items_class = '';
        foreach ($items as $item) {
            if ($item instanceof ComputerTab) {
                if (!empty($items_class) && $items_class !== ComputerTab::class) {
                    throw new Exception('Items with different class.');
                }
                $items_class = ComputerTab::class;
                $item_ids[] = $item->getID();
            } else if ($item instanceof NetworkEqTab) {
                if (!empty($items_class) && $items_class !== NetworkEqTab::class) {
                    throw new Exception('Items with different class.');
                }
                $items_class = NetworkEqTab::class;
                $item_ids[] = $item->getID();
            } else if ($item instanceof  ComputerAlertsTab) {
                if (!empty($items_class) && $items_class !== ComputerAlertsTab::class) {
                    throw new Exception('Items with different class.');
                }
                $items_class = ComputerAlertsTab::class;
                $item_ids[] = $item->getID();
            } else if ($item instanceof NetworkEqAlertsTab) {
                if (!empty($items_class) && $items_class !== NetworkEqAlertsTab::class) {
                    throw new Exception('Items with different class.');
                }
                $items_class = NetworkEqAlertsTab::class;
                $item_ids[] = $item->getID();
            } else {
                throw new Exception('Items outside of class: ComputerAlertsTab, ComputerTab, NetworkEqTab or NetworkEqAlertsTab');
            }
        }

        $input = [
            'ticket_category' => $category?->getID() ?? 0,
            'ticket_title' => $title,
            'ticket_comment' => $message,
            'ticket_urgency' => $urgency ?? 3,
        ];
        $entity_id = $entity?->getID() ?? Session::getActiveEntity();

        switch ($items_class) {
            case ComputerTab::class:
                return ComputerTab::createTicket($item_ids, $input, $entity_id);
            case NetworkEqTab::class:
                return NetworkEqTab::createTicket($item_ids, $input, $entity_id);
            case ComputerAlertsTab::class:
                return ComputerAlertsTab::createTicket($item_ids, $input, $entity_id);
            case NetworkEqAlertsTab::class:
                return NetworkEqAlertsTab::createTicket($item_ids, $input, $entity_id);
        }
        return false;
    }

    /**
     * Getting ticket object or false of provided item wazuh tab object
     * @param ComputerTab|NetworkEqTab|ComputerAlertsTab|NetworkEqAlertsTab $item
     * @return Ticket|false
     */
    public static function getTicket(ComputerTab|NetworkEqTab|ComputerAlertsTab|NetworkEqAlertsTab $item): Ticket | false {
        $ticket_id = $item->fields[Ticket::getForeignKeyField()];
        return Ticket::getById($ticket_id);
    }

}
