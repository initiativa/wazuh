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

namespace GlpiPlugin\Wazuh\Db;

/**
 * Description of Wazuh
 *
 * @author w-tomasz
 */
#[Table(name: "glpi_plugin_wazuh_table")]
class Wazuh extends \CommonDBTM {
    use TableGeneratorTrait;

    public static $rightname = 'glpi_plugin_wazuh_table';
    
    protected static $tableSchema = [
        'id' => ['type' => 'autoincrement', 'not_null' => true],
        'name' => ['type' => 'string', 'length' => 255, 'not_null' => true],
        'description' => ['type' => 'text'],
        'tenant' => ['type' => 'text'],
        'client' => ['type' => 'text'],
        'client_secret' => ['type' => 'text'],
        'enabled' => ['type' => 'integer(1)', 'default' => 1],
        'created' => ['type' => 'timestamp', 'not_null' => true, 'default' => 'CURRENT_TIMESTAMP'],
        'updated' => ['type' => 'timestamp', 'not_null' => true, 'default' => 'CURRENT_TIMESTAMP'],
    ];
    
    public static function createTable() {
        $migration = new \Migration(1);
        $query = self::getTableCreationQuery(static::$rightname, static::$tableSchema);
        \src\Logger::addWarning("*********  " . $query);
    }
    
    #[Column(type: "string", length: 100, nullable: false)]
    private string $name;

    #[Column(type: "string", length: 100, nullable: false)]
    private string $description;
    
    #[Column(type: "boolean")]
    private string $enabled;
}


