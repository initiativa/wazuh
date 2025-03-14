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

if (!defined("GLPI_ROOT")) {
    die("No access.");
}

/**
 * Description of Database
 *
 * @author w-tomasz
 */
class Database
{
    public const pluginTableName = "glpi_plugin_wazuh_table";
    /**
     * @return void
     */
    public static function initTables(): void
    {
        global $DB;

        if (!$DB->tableExists(static::pluginTableName)) {
            $sql = file_get_contents(
                GLPI_ROOT . "/plugins/wazuh/install/db_init.sql"
            );
            $DB->query($sql) or die($DB->error());
        }

        \src\Logger::addWarning("Database installed...");
    }
    /**
     * @return void
     */
    public static function dropTables(): void
    {
        global $DB;
        $sql = file_get_contents(
            GLPI_ROOT . "/plugins/wazuh/install/db_clean.sql"
        );
        $DB->query($sql) or die($DB->error());
        \src\Logger::addWarning("Database uninstalled...");
    }
}
