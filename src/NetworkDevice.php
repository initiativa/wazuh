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

namespace src;

if (!defined('GLPI_ROOT')) {
   die("No access.");
}


/**
 * Description of NetworkDevice
 *
 * @author w-tomasz
 */
class NetworkDevice extends \CommonDBTM implements Asset {
    #[\Override]
    static function getTabNameForItem(\CommonGLPI $item, $withtemplate = 0) {
        Logger::addWarning(__FUNCTION__ . " " . $item.getType() . " " . $withtemplate);
        
    }

    #[\Override]
    static function displayTabContentForItem(\CommonGLPI $item, $tabnum = 1, $withtemplate = 0) {
        Logger::addWarning(__FUNCTION__ . " " . $item.getType() . " : " . $tabnum . " : " . $withtemplate);
        
    }
}
