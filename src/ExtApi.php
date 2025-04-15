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
use NetworkEquipment;

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
    public static function getLatestVulnerabilities(CommonGLPI $device): array | false {
        if ($device instanceof Computer) {
            return ComputerTab::getAgentVulnerabilities($device);
        } else if ($device instanceof NetworkEquipment) {
            return NetworkEqTab::getAgentVulnerabilities($device);
        } else {
            Logger::addError(sprintf("%s %s Device %s outside of NetworkEquipment or Computer scope.", __CLASS__, __FUNCTION__, $device->getType()));
        }
        return false;
    }

    public static function getLatestAlerts(CommonGLPI $device): array | false {
        if ($device instanceof Computer) {
            return ComputerAlertsTab::getAgentAlerts($device);
        } else if ($device instanceof NetworkEquipment) {
            return NetworkEqAlertsTab::getAgentAlerts($device);
        } else {
            Logger::addError(sprintf("%s %s Device %s outside of NetworkEquipment or Computer scope.", __CLASS__, __FUNCTION__, $device->getType()));
        }
        return false;
    }

}
