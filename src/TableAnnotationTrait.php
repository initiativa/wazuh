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

/**
 * Trait DatabaseAnnotationTrait
 * 
 * Trait for generating CREATE TABLE queries based on class annotations.
 * Inspired by Hibernate ORM functionality.
 */
trait TableAnnotationTrait {
    /**
     * Maps data from $_POST to object properties based on @FormId annotations
     * And fills the fields array for CommonDBTM compatibility
     * 
     * @param array $postData Array with form data (typically $_POST)
     * @return object Current instance with mapped properties
     */
    public function mapFromPostData(array $postData): self {
        $reflection = new \ReflectionClass($this);
        
        foreach ($reflection->getProperties() as $property) {
            $docComment = $property->getDocComment();
            if ($docComment === false) {
                continue;
            }
            
            // Check if property has @FormId annotation
            if (preg_match('/@FormId\(name="([^"]+)"(?:,\s*secure=(true|false))?\)/i', $docComment, $matches)) {
                $formFieldName = $matches[1];
                $isSecure = isset($matches[2]) && strtolower($matches[2]) === 'true';
                
                // Check if form field exists in POST data
                if (isset($postData[$formFieldName])) {
                    $property->setAccessible(true);
                    $value = $postData[$formFieldName];
                    
                    // Get PHP type from property type or @var annotation
                    $phpType = self::getPropertyPhpType($property);
                    
                    // Convert value to appropriate PHP type
                    $value = self::convertToPhpType($value, $phpType);
                    
                    // Encrypt value if field is marked as secure
                    if ($isSecure && !empty($value)) {
                        // Use GLPI's encryption function (using shared instance)
                        $GLPIKey = self::getGLPIKeyInstance();
                        $value = $GLPIKey->encrypt($value);
                    }
                    
                    $property->setValue($this, $value);
                    
                    // If this is CommonDBTM, also set the value in the fields array
                    if (is_a($this, 'CommonDBTM')) {
                        // Get the column name from @Column annotation or use property name
                        $columnName = self::getColumnNameFromAnnotation($property);
                        if (!property_exists($this, 'fields') || !is_array($this->fields)) {
                            $this->fields = [];
                        }
                        $this->fields[$columnName] = $value;
                    }
                }
            }
        }
        
        // Fill the fields array with all properties that have @Column annotation
        if (is_a($this, 'CommonDBTM')) {
            $this->fillFieldsFromProperties();
        }
        
        return $this;
    }
    
    /**
     * Check if the object is a CommonDBTM instance and clear its fields array
     * to prevent issues with add() and update() methods
     * 
     * @return void
     */
    private function resetFields(): void {
        if (is_a($this, 'CommonDBTM') && property_exists($this, 'fields') && is_array($this->fields)) {
            $this->fields = [];
        }
    }
    
    /**
     * Fill the fields array with values from properties that have @Column annotation
     * This is needed for CommonDBTM compatibility
     * 
     * @return void
     */
    public function fillFieldsFromProperties(): void {
        if (!is_a($this, 'CommonDBTM') || !property_exists($this, 'fields')) {
            return;
        }
        
        // Start with a clean fields array to avoid duplicate or stale values
        $this->resetFields();
        
        $reflection = new \ReflectionClass($this);
        
        foreach ($reflection->getProperties() as $property) {
            $docComment = $property->getDocComment();
            if ($docComment === false) {
                continue;
            }
            
            // Only process properties with @Column annotation
            if (preg_match('/@Column/i', $docComment)) {
                $property->setAccessible(true);
                
                // Skip properties that are not initialized
                if (method_exists($property, 'isInitialized') && !$property->isInitialized($this)) {
                    continue;
                }
                
                // Property is initialized, safe to get value
                $value = $property->getValue($this);
                
                // Skip null values for non-ID fields
                if ($value === null && !preg_match('/@Id/i', $docComment)) {
                    continue;
                }
                
                // Get the column name from annotation or use property name
                $columnName = self::getColumnNameFromAnnotation($property);
                $this->fields[$columnName] = $value;
            }
        }
    }
    
    /**
     * Get column name from @Column annotation or property name
     * 
     * @param \ReflectionProperty $property The property
     * @return string Column name
     */
    private static function getColumnNameFromAnnotation(\ReflectionProperty $property): string {
        $docComment = $property->getDocComment();
        
        // Look for name parameter in @Column annotation
        if ($docComment && preg_match('/@Column\([^)]*name="([^"]+)"[^)]*\)/i', $docComment, $matches)) {
            return $matches[1];
        }
        
        // If no name specified, use property name
        return $property->getName();
    }
    
    /**
     * Gets the shared GLPIKey instance
     * 
     * @return \GLPIKey
     */
    private static function getGLPIKeyInstance(): \GLPIKey {
        global $GLPIKEY;
        
        // Use global instance if available
        if (isset($GLPIKEY) && $GLPIKEY instanceof \GLPIKey) {
            return $GLPIKEY;
        }
        
        // Create a new instance if not available globally
        return new \GLPIKey();
    }
    
    /**
     * Gets a decrypted value for a field marked as secure
     * 
     * @param string $value The encrypted value
     * @return string The decrypted value
     */
    public static function getDecryptedValue(string $value): string {
        if (empty($value)) {
            return '';
        }
        
        // Use GLPI's decryption function (using shared instance)
        $GLPIKey = self::getGLPIKeyInstance();
        return $GLPIKey->decrypt($value);
    }
    
    /**
     * Creates a new instance from POST data
     * 
     * @param array $postData Array with form data (typically $_POST)
     * @return static New instance with mapped properties
     */
    public static function createFromPostData(array $postData): self {
        $instance = new static();
        
        // Reset fields array for CommonDBTM
        if (is_a($instance, 'CommonDBTM')) {
            $instance->resetFields();
        }
        
        return $instance->mapFromPostData($postData);
    }
    
    /**
     * Gets PHP type from property (using type hint, @var annotation, or default)
     * 
     * @param \ReflectionProperty $property The property to get type for
     * @return string PHP type name
     */
    private static function getPropertyPhpType(\ReflectionProperty $property): string {
        // Check for PHP 7.4+ type hint
        if ($property->hasType()) {
            $type = $property->getType();
            if ($type instanceof \ReflectionNamedType) {
                return $type->getName();
            }
        }
        
        // Check for @var annotation
        $docComment = $property->getDocComment();
        if ($docComment !== false && preg_match('/@var\s+([^\s*]+)/', $docComment, $matches)) {
            return $matches[1];
        }
        
        // Default to string
        return 'string';
    }
    
    /**
     * Converts string value from form to appropriate PHP type
     * 
     * @param mixed $value Value from form
     * @param string $type PHP type name
     * @return mixed Converted value
     */
    private static function convertToPhpType($value, string $type): mixed {
        // Skip conversion if value is null or empty string and not boolean
        if (($value === null || $value === '') && $type !== 'bool' && $type !== 'boolean') {
            return null;
        }
        
        switch (strtolower($type)) {
            case 'int':
            case 'integer':
                return (int)$value;
            
            case 'float':
            case 'double':
                return (float)$value;
            
            case 'bool':
            case 'boolean':
                return !empty($value) && $value !== '0' && strtolower($value) !== 'false';
            
            case 'array':
                return is_array($value) ? $value : [$value];
            
            case 'datetime':
            case '\datetime':
                return $value ? new \DateTime($value) : null;
            
            case 'string':
            default:
                return (string)$value;
        }
    }
    
    /**
     * Generates DROP TABLE query based on class annotations.
     * 
     * @return string SQL DROP TABLE query
     */
    public static function generateDropTableQuery(): string {
        $className = get_called_class();
        $reflection = new \ReflectionClass($className);
        
        // Get table name from class annotation or use class name
        $tableDocComment = $reflection->getDocComment();
        $tableName = self::getTableNameFromDocComment($tableDocComment, $className);
        
        // Create the DROP TABLE query
        return "DROP TABLE IF EXISTS `{$tableName}`;";
    }
    
    /**
     * Generates CREATE TABLE query based on class annotations and property types.
     * 
     * @return string SQL CREATE TABLE query
     */
    public static function generateCreateTableQuery(): string {
        $className = get_called_class();
        $reflection = new \ReflectionClass($className);
        
        // Get table name from class annotation or use class name
        $tableDocComment = $reflection->getDocComment();
        $tableName = self::getTableNameFromDocComment($tableDocComment, $className);
        
        // Collect column definitions based on field annotations and PHP types
        $columns = [];
        $primaryKey = null;
        $indexes = [];
        $foreignKeys = [];
        
        foreach ($reflection->getProperties() as $property) {
            $docComment = $property->getDocComment();
            if ($docComment === false) {
                continue;
            }
            
            // Skip properties without @Column annotation
            if (!preg_match('/@Column/i', $docComment)) {
                continue;
            }
            
            // Get column definition
            $columnDef = self::parseColumnDefinition($docComment, $property);
            
            if (!empty($columnDef)) {
                $columns[] = $columnDef['definition'];
                
                // Check if it's a primary key
                if (isset($columnDef['primary']) && $columnDef['primary']) {
                    $primaryKey = $property->getName();
                }
                
                // Check if the field has an index
                if (isset($columnDef['index']) && $columnDef['index']) {
                    $indexes[] = "INDEX `idx_{$tableName}_{$property->getName()}` (`{$property->getName()}`)";
                }
                
                // Check if the field has a foreign key
                if (isset($columnDef['foreignKey']) && !empty($columnDef['foreignKey'])) {
                    $fkData = $columnDef['foreignKey'];
                    $foreignKeys[] = "CONSTRAINT `fk_{$tableName}_{$property->getName()}` FOREIGN KEY (`{$property->getName()}`) REFERENCES `{$fkData['table']}` (`{$fkData['column']}`) ON DELETE {$fkData['onDelete']} ON UPDATE {$fkData['onUpdate']}";
                }
            }
        }
        
        // Combine column definitions and additional constraints
        $allDefinitions = array_merge($columns, $indexes, $foreignKeys);
        
        // Create the CREATE TABLE query
        $sql = "CREATE TABLE IF NOT EXISTS `{$tableName}` (\n";
        $sql .= "    " . implode(",\n    ", $allDefinitions);
        $sql .= "\n) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;";
        
        return $sql;
    }
    
    /**
     * Parses class annotation to get table name
     * 
     * @param string|false $docComment Class documentation comment
     * @param string $className Class name as fallback
     * @return string Table name
     */
    private static function getTableNameFromDocComment($docComment, $className): string {
        if ($docComment === false) {
            // If no comment, use class name
            $parts = explode('\\', $className);
            return strtolower(preg_replace('/(?<!^)[A-Z]/', '_$0', end($parts)));
        }
        
        if (preg_match('/@Table\(name="([^"]+)"\)/i', $docComment, $matches)) {
            return $matches[1];
        }
        
        // If no @Table annotation, use class name
        $parts = explode('\\', $className);
        return strtolower(preg_replace('/(?<!^)[A-Z]/', '_$0', end($parts)));
    }
    
    /**
     * Parses field annotations to get column definition
     * 
     * @param string $docComment Field documentation comment
     * @param \ReflectionProperty $property The property reflection
     * @return array|null Column definition or null if field is not mapped
     */
    private static function parseColumnDefinition(string $docComment, \ReflectionProperty $property): ?array {
        $propertyName = $property->getName();
        $columnName = $propertyName;
        
        // Get PHP type from property
        $phpType = null;
        if ($property->hasType()) {
            $type = $property->getType();
            if ($type instanceof \ReflectionNamedType) {
                $phpType = $type->getName();
            }
        }
        
        // If no type hint, try to get from @var annotation
        if ($phpType === null && preg_match('/@var\s+([^\s*]+)/', $docComment, $varMatches)) {
            $phpType = $varMatches[1];
        }
        
        // Default to string if no type found
        if ($phpType === null) {
            $phpType = 'string';
        }
        
        // Parse @Column parameters
        $params = [];
        if (preg_match('/@Column\(([^)]+)\)/i', $docComment, $columnMatches)) {
            $paramStr = $columnMatches[1];
            
            // Extract name
            if (preg_match('/name="([^"]+)"/i', $paramStr, $nameMatches)) {
                $columnName = $nameMatches[1];
            }
            
            // Extract length
            if (preg_match('/length=(\d+)/i', $paramStr, $lengthMatches)) {
                $params['length'] = (int)$lengthMatches[1];
            }
            
            // Extract nullable
            if (preg_match('/nullable=(true|false)/i', $paramStr, $nullableMatches)) {
                $params['nullable'] = strtolower($nullableMatches[1]) === 'true';
            } else {
                $params['nullable'] = true; // Default to nullable
            }
            
            // Extract default value
            if (preg_match('/defaultValue="([^"]*)"/i', $paramStr, $defaultMatches)) {
                $params['default'] = $defaultMatches[1];
                $params['hasDefault'] = true;
            } else {
                $params['hasDefault'] = false;
            }
        } else {
            $params['nullable'] = true;
            $params['hasDefault'] = false;
        }
        
        // Determine SQL type from PHP type
        $sqlType = self::mapPhpTypeToSql($phpType, $params);
        
        // Check if field has @Id annotation (primary key)
        $isPrimary = preg_match('/@Id/i', $docComment);
        
        // Check if field has @Index annotation
        $isIndex = preg_match('/@Index/i', $docComment);
        
        // Check if field has @ForeignKey annotation
        $foreignKey = null;
        if (preg_match('/@ForeignKey\(table="([^"]+)",\s*column="([^"]+)"(?:,\s*onDelete="([^"]+)")?(?:,\s*onUpdate="([^"]+)")?\)/i', $docComment, $fkMatches)) {
            $foreignKey = [
                'table' => $fkMatches[1],
                'column' => $fkMatches[2], 
                'onDelete' => isset($fkMatches[3]) ? $fkMatches[3] : 'RESTRICT',
                'onUpdate' => isset($fkMatches[4]) ? $fkMatches[4] : 'RESTRICT'
            ];
        }
        
        // If it's a primary key or foreign key and numeric type, make it unsigned
        if (($isPrimary || isset($foreignKey)) && 
            (strpos(strtoupper($sqlType), 'INT') !== false) && 
            (strpos(strtoupper($sqlType), 'UNSIGNED') === false)) {
            $sqlType .= ' UNSIGNED';
        }
        
        // Create column definition
        $definition = "`{$columnName}` {$sqlType}";
        
        if (!$params['nullable']) {
            $definition .= " NOT NULL";
        } else {
            $definition .= " NULL";
        }
        
        if ($params['hasDefault']) {
            $default = $params['default'];
            if ($default === 'CURRENT_TIMESTAMP') {
                $definition .= " DEFAULT CURRENT_TIMESTAMP";
            } else {
                $definition .= " DEFAULT " . (is_numeric($default) ? $default : "'{$default}'");
            }
        }
        
        if ($isPrimary) {
            $definition .= " PRIMARY KEY" . (strpos(strtoupper($sqlType), 'INT') !== false ? " AUTO_INCREMENT" : "");
        }
        
        return [
            'definition' => $definition,
            'primary' => $isPrimary,
            'index' => $isIndex,
            'foreignKey' => $foreignKey
        ];
    }
    
    /**
     * Maps PHP types to SQL types
     * 
     * @param string $phpType PHP type
     * @param array $params Additional parameters (length, etc.)
     * @return string SQL type
     */
    private static function mapPhpTypeToSql(string $phpType, array $params = []): string {
        // Clean the type (remove namespace, handle arrays, etc.)
        $cleanType = strtolower(trim($phpType, '\\'));
        
        // Handle arrays (e.g., array<string>)
        if (strpos($cleanType, 'array') === 0) {
            return 'TEXT';
        }
        
        // Map PHP types to SQL types
        switch ($cleanType) {
            case 'int':
            case 'integer':
                return 'INT';
            
            case 'float':
                return 'FLOAT';
            
            case 'double':
                return 'DOUBLE';
            
            case 'bool':
            case 'boolean':
                return 'TINYINT(1)';
            
            case 'string':
                $length = $params['length'] ?? 255;
                return "VARCHAR({$length})";
            
            case 'datetime':
                return 'DATETIME';
            
            case 'datetimeimmutable':
                return 'DATETIME';
            
            case 'dateinterval':
                return 'VARCHAR(255)';
            
            case 'resource':
                return 'BLOB';
            
            default:
                // Handle custom or unknown types
                return 'VARCHAR(255)';
        }
    }
}