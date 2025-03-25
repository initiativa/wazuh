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

use CommonGLPI;
use Glpi\Application\View\TemplateRenderer;

if (!defined('GLPI_ROOT')) {
   die("No access.");
}

/**
 * Description of NetworkDevice
 *
 * @author w-tomasz
 */
class WazuhNetworkDeviceTab extends \CommonDBTM {
    
   #[\Override]
   static function getTypeName($nb = 0) {
      return PluginConfig::APP_NAME;
   }
   
   #[\Override]
   function getTabNameForItem(CommonGLPI $item, $withtemplate = 0) {
      
      return PluginConfig::APP_NAME;
   }
   
   #[\Override]
   static function displayTabContentForItem(CommonGLPI $item, $tabnum = 1, $withtemplate = 0) {
        $twig = TemplateRenderer::getInstance();
        $twig->display('@wazuh/network_device.vulnerable.view.twig', [
            'APP_NAME' => PluginConfig::APP_CODE,
            'APP_VER' => PluginConfig::loadVersionNumber()
        ]);
      return true;
   }
    
}
