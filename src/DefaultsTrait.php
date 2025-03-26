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
use GLPIKey;
/**
 * Description of DefaultsTrait
 *
 * @author w-tomasz
 */
trait DefaultsTrait {

    protected static function defaultsConfigData($table) {
        global $DB;
        Logger::addDebug(__FUNCTION__ . " ** " . getenv('WPASS2'));
        
        $DB->insert($table, [
            'id' => 1,
            'name' => 'Local Wazuh',
            'server_url' => '192.168.0.2',
            'api_port' => '55000',
            'api_username' => 'wazuh-wui',
            'api_password' => (new GLPIKey())->encrypt(getenv('WPASS1')),
            'sync_interval' => 86400
        ]);
        $DB->insert($table, [
            'id' => 2,
            'name' => 'VPN Wazuh',
            'server_url' => '10.70.0.111',
            'api_port' => '55000',
            'api_username' => 'wazuh',
            'api_password' => (new GLPIKey())->encrypt(getenv('WPASS2')),
            'sync_interval' => 86400
        ]);
    }
}
