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

use \ReflectionAttribute;
use \ReflectionProperty;

/**
 * Trait for automatic table schema generation based on annotations in classes
 * extending CommonDBTM in GLPI.
 *
 *  * @author w-tomasz
 */
trait TableGeneratorTrait
{
    /**
     * Generates SQL query to create table based on class annotations
     * @return string SQL query to create the table
     */
    public static function getTableCreationQuery(): string
    {
        $reflection = new \ReflectionClass(static::class);
        $table = static::getTable();
        $columns = [];
        $primaryKey = null;
        $keys = [];
        $foreignKeys = [];
        $definedColumnNames = [];

        foreach ($reflection->getProperties() as $property) {
            // Skip properties from parent classes
            if ($property->getDeclaringClass()->getName() === static::class) {
                $columnDef = self::parsePropertyAttributes($property);

                if (!empty($columnDef)) {
                    $definedColumnNames[] = $columnDef["name"];

                    if (
                        isset($columnDef["isPrimary"]) &&
                        $columnDef["isPrimary"]
                    ) {
                        $primaryKey = $columnDef["name"];
                    }

                    if (isset($columnDef["isKey"]) && $columnDef["isKey"]) {
                        $keys[] = $columnDef["name"];
                    }

                    if (isset($columnDef["foreignKey"])) {
                        $foreignKeys[] = [
                            "column" => $columnDef["name"],
                            "reference" => $columnDef["foreignKey"],
                        ];
                    }

                    $columns[] = self::buildColumnDefinition($columnDef);
                }
            }
        }

        $defaultFields = self::getDefaultCommonFields();
        foreach ($defaultFields as $fieldName => $fieldDef) {
            // Sprawdź, czy kolumna o tej nazwie jest już zdefiniowana
            if (!in_array($fieldName, $definedColumnNames)) {
                $columns[] = $fieldDef;
            }
        }

        $sql = "CREATE TABLE IF NOT EXISTS `$table` (\n";
        $sql .= implode(",\n", $columns);

        if ($primaryKey === null) {
            $sql .= ",\n  PRIMARY KEY (`id`)";
        } else {
            $sql .= ",\n  PRIMARY KEY (`$primaryKey`)";
        }

        foreach ($keys as $key) {
            $sql .= ",\n  KEY `$key` (`$key`)";
        }

        foreach ($foreignKeys as $fk) {
            $sql .= ",\n  FOREIGN KEY (`{$fk["column"]}`) REFERENCES {$fk["reference"]}";
        }

        $sql .=
            "\n) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;";

        return $sql;
    }

    /**
     * Parses property attributes to column definition
     * @param ReflectionProperty $property
     * @return array|null Column definition or null if no attributes
     */
    private static function parsePropertyAttributes(
        ReflectionProperty $property
    ): ?array {
        $result = [
            "name" => $property->getName(),
        ];

        if (PHP_VERSION_ID >= 80000) {
            $attributes = $property->getAttributes();

            foreach ($attributes as $attribute) {
                $attrName = $attribute->getName();
                $attrArgs = $attribute->getArguments();

                switch (basename($attrName)) {
                    case "Column":
                        $result = array_merge($result, $attrArgs);
                        break;
                    case "PrimaryKey":
                        $result["isPrimary"] = true;
                        break;
                    case "Key":
                        $result["isKey"] = true;
                        break;
                    case "ForeignKey":
                        $result["foreignKey"] = $attrArgs["reference"];
                        break;
                    case "Default":
                        $result["default"] = $attrArgs["value"];
                        break;
                }
            }
        }
        // For older PHP versions use PHPDoc comments
        else {
            $docComment = $property->getDocComment();
            if ($docComment === false) {
                return null;
            }

            // Parse column type
            if (
                preg_match(
                    '/@Column\s*\(\s*type\s*=\s*"([^"]+)"/',
                    $docComment,
                    $matches
                )
            ) {
                $result["type"] = $matches[1];
            }

            // Parse length
            if (
                preg_match(
                    "/@Column\s*\([^)]*length\s*=\s*(\d+)/",
                    $docComment,
                    $matches
                )
            ) {
                $result["length"] = (int) $matches[1];
            }

            // Parse NULL/NOT NULL
            if (
                preg_match(
                    "/@Column\s*\([^)]*nullable\s*=\s*(true|false)/",
                    $docComment,
                    $matches
                )
            ) {
                $result["nullable"] = $matches[1] === "true";
            }

            // Parse default value
            if (
                preg_match(
                    '/@Default\s*\(\s*value\s*=\s*"([^"]*)"/',
                    $docComment,
                    $matches
                )
            ) {
                $result["default"] = $matches[1];
            } elseif (
                preg_match(
                    "/@Default\s*\(\s*value\s*=\s*([^\s\)]+)/",
                    $docComment,
                    $matches
                )
            ) {
                // For numeric/boolean default values without quotes
                $result["default"] = $matches[1];
            }

            // Parse primary key
            if (preg_match("/@PrimaryKey/", $docComment)) {
                $result["isPrimary"] = true;
            }

            // Parse index
            if (preg_match("/@Key/", $docComment)) {
                $result["isKey"] = true;
            }

            // Parse foreign key
            if (
                preg_match(
                    '/@ForeignKey\s*\(\s*reference\s*=\s*"([^"]+)"/',
                    $docComment,
                    $matches
                )
            ) {
                $result["foreignKey"] = $matches[1];
            }
        }

        // If type not found, try to determine from type hint
        if (!isset($result["type"]) && PHP_VERSION_ID >= 70400) {
            $type = $property->getType();
            if ($type !== null) {
                $typeName = $type->getName();

                switch ($typeName) {
                    case "int":
                        $result["type"] = "integer";
                        break;
                    case "float":
                        $result["type"] = "float";
                        break;
                    case "string":
                        $result["type"] = "string";
                        if (!isset($result["length"])) {
                            $result["length"] = 255;
                        }
                        break;
                    case "bool":
                        $result["type"] = "boolean";
                        break;
                    case "DateTime":
                        $result["type"] = "datetime";
                        break;
                }

                $result["nullable"] = $type->allowsNull();
            }
        }

        if (!isset($result["type"])) {
            return null;
        }

        return $result;
    }

    /**
     * Builds SQL for column definition
     * @param array $columnDef Column definition
     * @return string SQL for column definition
     */
    private static function buildColumnDefinition(array $columnDef): string
    {
        $name = $columnDef["name"];
        $type = $columnDef["type"];
        $sql = "  `$name` ";

        switch ($type) {
            case "integer":
            case "int":
                $sql .= "INT(11)";
                break;
            case "string":
            case "varchar":
                $length = $columnDef["length"] ?? 255;
                $sql .= "VARCHAR($length)";
                break;
            case "text":
                $sql .= "TEXT";
                break;
            case "boolean":
            case "bool":
                $sql .= "TINYINT(1)";
                break;
            case "float":
            case "decimal":
                $precision = $columnDef["precision"] ?? 10;
                $scale = $columnDef["scale"] ?? 2;
                $sql .= "DECIMAL($precision, $scale)";
                break;
            case "datetime":
                $sql .= "DATETIME";
                break;
            case "date":
                $sql .= "DATE";
                break;
            case "timestamp":
                $sql .= "TIMESTAMP";
                break;
            default:
                $sql .= strtoupper($type);
        }

        // NULL / NOT NULL
        if (isset($columnDef["nullable"])) {
            $sql .= $columnDef["nullable"] ? " NULL" : " NOT NULL";
        } else {
            $sql .= " NOT NULL";
        }

        // Default value
        if (isset($columnDef["default"])) {
            $default = $columnDef["default"];

            // Handle special default values
            if ($default === "CURRENT_TIMESTAMP") {
                $sql .= " DEFAULT CURRENT_TIMESTAMP";
            } elseif (
                is_string($default) &&
                !in_array(strtoupper($default), ["NULL", "TRUE", "FALSE"]) &&
                !is_numeric($default)
            ) {
                $sql .= " DEFAULT '$default'";
            } elseif (
                strtoupper($default) === "NULL" &&
                (isset($columnDef["nullable"]) && $columnDef["nullable"])
            ) {
                $sql .= " DEFAULT NULL";
            } elseif (strtoupper($default) === "TRUE") {
                $sql .= " DEFAULT 1";
            } elseif (strtoupper($default) === "FALSE") {
                $sql .= " DEFAULT 0";
            } else {
                $sql .= " DEFAULT $default";
            }
        }

        // Auto increment
        if (isset($columnDef["autoIncrement"]) && $columnDef["autoIncrement"]) {
            $sql .= " AUTO_INCREMENT";
        }

        return $sql;
    }

    /**
     * Returns standard fields for CommonDBTM classes
     * @return array Definitions of standard fields
     */
    private static function getDefaultCommonFields(): array
    {
        return [
            "id" => "  `id` INT(11) NOT NULL AUTO_INCREMENT",
            "name" =>
                "  `name` VARCHAR(255) COLLATE utf8_unicode_ci DEFAULT NULL",
            "entities_id" => "  `entities_id` INT(11) NOT NULL DEFAULT 0",
            "is_recursive" => "  `is_recursive` TINYINT(1) NOT NULL DEFAULT 0",
            "date_creation" => "  `date_creation` TIMESTAMP NULL DEFAULT NULL",
            "date_mod" => "  `date_mod` TIMESTAMP NULL DEFAULT NULL",
        ];
    }

    public static function getTableDropQuery(): string
    {
        return "DROP TABLE IF EXISTS " . self::getTable();
    }

    /**
     * Get table name from class annotation or fallback to parent's method
     *
     * @param string|null $classname
     * @return string Table name
     */
    public static function getTable($classname = null): string
    {
        if ($classname !== null) {
            return parent::getTable($classname);
        }

        $reflection = new \ReflectionClass(static::class);
        $tableName = null;

        if (PHP_VERSION_ID >= 80000) {
            $tableAttributes = $reflection->getAttributes(
                \GlpiPlugin\Wazuh\Table::class
            );
            $args = $tableAttributes[0]->getArguments();
            if (array_key_exists("name", $args)) {
                return $args["name"];
            }
        }

        if ($tableName === null) {
            $docComment = $reflection->getDocComment();
            if (
                $docComment !== false &&
                preg_match(
                    '/@Table\s*\(\s*name\s*=\s*"([^"]+)"/',
                    $docComment,
                    $matches
                )
            ) {
                $tableName = $matches[1];
            }
        }

        if ($tableName !== null) {
            return $tableName;
        }

        if (method_exists(get_parent_class(static::class), "getTable")) {
            return parent::getTable();
        }

        // Last resort fallback
        return strtolower(str_replace("\\", "_", static::class));
    }

    /**
     * Executes query to create table in database
     * @return bool Whether query was executed successfully
     */
    public static function createTable(): bool
    {
        global $DB;
        $query = self::getTableCreationQuery();
        return $DB->query($query);
    }

    /**
     * Checks if table exists and is up to date
     * If not, creates or updates the table
     * @return bool Whether operation was successful
     */
    public static function ensureTableExists(): bool
    {
        global $DB;
        $table = static::getTable();

        if (!$DB->tableExists($table)) {
            return self::createTable();
        }

        return true;
    }
}
