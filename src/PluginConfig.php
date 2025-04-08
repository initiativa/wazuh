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
// namespace GlpiPlugin\Wazuh;

/**
 * Description of Config
 *
 * @author w-tomasz
 */

class PluginConfig
{
    public const APP_NAME = "Wazuh";
    public const APP_CODE = "wazuh";
    public const VQUERY_TIME_SESSION_KEY = "plugin_wazuh_last_vquery_time";
    public const VQUERY_ALERT_TIME_SESSION_KEY = "plugin_wazuh_last_vquery_alert_time";

    public const PLUGIN_ROOT = GLPI_ROOT . "/plugins/" . self::APP_CODE;

    public static function loadVersionNumber(): string
    {
        $xml = simplexml_load_file(static::PLUGIN_ROOT . "/wazuh.xml");
        $versionNumber = (string) $xml->versions->version->num;

        return $versionNumber;
    }
}
