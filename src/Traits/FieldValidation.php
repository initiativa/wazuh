<?php

namespace GlpiPlugin\Wazuh\Traits;

use DateTime;
use Entity;
use Exception;
use GlpiPlugin\Wazuh\Logger;
use GlpiPlugin\Wazuh\PluginConfig;
use Session;

trait FieldValidation {

    public const DATETIME_OR_EMPTY = 'dateTimeOrEmpty';
    public const DATE_OR_EMPTY = 'dateOrEmpty';
    public const NOT_BLANK = 'notBlank';
    public const INT_IN_ARRAY = 'intInArray';
    public const CONTAINS_ONLY = 'containsOnly';
    public const STRING_IN_ARRAY = 'stringInArray';
    public const STRING_LENGTH = 'stringLength';
    public const STRING_MIN_MAX = 'stringMinMax';
    public const ID_IN_TABLE = 'idInTable';
    public const IDS_IN_TABLE = 'idsInTable';
    public const PATTERN_MATCH = 'patternMatch';
    public const MAX_NOTE_LENGTH = 5000;

    protected function getAdditionalFieldOptions(): array {
        $additional_options = [];

        Logger::debug(static::class);
        if (isset($_SESSION['conformitas_validation_errors'][static::class])) {
            $validation_errors = $_SESSION['conformitas_validation_errors'][static::class];
            foreach ($validation_errors as $field => $error_message) {
                $additional_options[$field] = [
                    'add_label_class' => 'text-danger',
                    'add_field_class' => 'is-invalid',
                    'add_field_html' => '<div class="invalid-feedback d-block">' . $error_message . '</div>'
                ];
            }
            unset($_SESSION['conformitas_validation_errors'][static::class]);
        }
        return $additional_options;

    }

    protected function setAdditionalFieldOptions(array $validation_errors): bool {
        if (!empty($validation_errors)) {
            $_SESSION['conformitas_validation_errors'][static::class] = $validation_errors;
            $message = '';
            foreach ($validation_errors as $field => $error) {
                $message .= $field . ': ' . $error . '<br>';
            }
            Session::addMessageAfterRedirect($message, false, ERROR, true);
            return false;
        }
        return true;
    }

    protected static function DEFAULT_CRITERIA(array $crit = []): array {
        return array_merge(self::ENTITY_CRITERIA(self::ACTIVE_CRITERIA()), $crit);
    }

    protected static function ENTITY_CRITERIA(array $crit = []): array {
        return array_merge([
            Entity::getForeignKeyField() => Session::getActiveEntities()
        ], $crit);
    }

    protected static function ACTIVE_CRITERIA(array $crit = []): array {
        return array_merge([
            'is_deleted' => 0,
        ], $crit);
    }

    protected static function ensure_array($value): array {
        if (is_array($value)) {
            return $value;
        }
        if ($value === null) return [];
        if ($value === '') return [];
        return [];
    }

    /**
     * @throws Exception
     */
    public static function validate(string $name, array &$validation_errors, callable $validator, ...$args): bool {
        $validation_result = $validator(...$args);
        if ($validation_result->isValid()) {
            return true;
        } else {
            $validation_errors[$name] = $validation_result->getErrorMessage();
            return false;
        }
    }

    public static function dateTimeOrEmpty(?string $value, string $format = 'Y-m-d H:i:s', ?callable $error = null): ValidationResult {
        if ($value === null || trim($value) === '') {
            return ValidationResult::ok($value);
        }

        $dt = DateTime::createFromFormat($format, $value);
        if ($dt && $dt->format($format) === $value) {
            return ValidationResult::ok($value);
        }
        if ($error === null) {
            $error = [self::class, 'defaultNotDateTimeError'];
        }
        return ValidationResult::error($error($value));
    }

    public static function dateOrEmpty(?string $value, string $format = 'Y-m-d', ?callable $error = null): ValidationResult {
        if ($value === null || trim($value) === '') {
            return ValidationResult::ok($value);
        }

        $dt = DateTime::createFromFormat($format, $value);
        if ($dt && $dt->format($format) === $value) {
            return ValidationResult::ok($value);
        }
        if ($error === null) {
            $error = [self::class, 'defaultNotDateTimeError'];
        }
        return ValidationResult::error($error($value));
    }



    public static function notBlank(?string $value, ?callable $error = null): ValidationResult {
        if ($error === null) {
            $error = [self::class, 'defaultNotBlankError'];
        }

        if ($value === null || trim($value) === '' || $value === '0') {
            return ValidationResult::error($error());
        }

        return ValidationResult::ok($value);
    }

    public static function idInTable(string|int $value, string $table, array $criterria, bool $with_zero = true, ?callable $error = null): ValidationResult {
        global $DB;
        $ids = $DB->request([
                'SELECT' => ['id'],
                'FROM' => $table,
                'WHERE' => $criterria
            ]);
        if (!$ids) {
            trigger_error($DB->error(), E_CORE_ERROR);
        }

        $ids = array_column(iterator_to_array($ids, false), 'id');
        if ($with_zero) {
            $ids[] = 0;
        }

        if (in_array((int) $value, $ids)) {
            return ValidationResult::ok($value);
        }
        if ($error === null) {
            $error = [self::class, 'defaultNotInTableError'];
        }
        return ValidationResult::error($error((int)$value, $table));
    }

    public static function idsInTable(array $values, string $table, array $criterria, bool $with_zero = true, ?callable $error = null): ValidationResult {
        global $DB;
        $ids = $DB->request([
            'SELECT' => ['id'],
            'FROM' => $table,
            'WHERE' => $criterria
        ]);
        if (!$ids) {
            trigger_error($DB->error(), E_CORE_ERROR);
        }

        $ids = array_column(iterator_to_array($ids, false), 'id');
        if ($with_zero) {
            $ids[] = 0;
        }

        foreach ($values as $value) {
            if (!in_array($value, $ids)) {
                if ($error === null) {
                    $error = [self::class, 'defaultNotInTableError'];
                }
                return ValidationResult::error($error((int)$value, $table));
            }
        }
        return ValidationResult::ok($values);
    }

    public static function intInArray(int $value, array $values = [], ?callable $error = null): ValidationResult {
        if (in_array($value, $values)) {
            return ValidationResult::ok($value);
        }
        if ($error === null) {
            $error = [self::class, 'defaultNotInArrayError'];
        }
        return ValidationResult::error($error($value, $values));
    }

    public static function containsOnly(array|string $value, array $values = [], ?callable $error = null): ValidationResult {
        if (!is_array($value)) {
            $value = [$value];
        }

        $diff = array_diff($value, $values);

        if (empty($diff)) {
            return ValidationResult::ok($value);
        }
        if ($error === null) {
            $error = [self::class, 'defaultArrayNotInArrayError'];
        }
        return ValidationResult::error($error($diff, $values));
    }

    public static function stringInArray(string $value, array $values = [], ?callable $error = null): ValidationResult {
        if (in_array($value, $values)) {
            return ValidationResult::ok($value);
        }
        if ($error === null) {
            $error = [self::class, 'defaultNotInArrayError'];
        }
        return ValidationResult::error($error($value, $values));
    }

    public static function stringLength(string $value, int $min = 1, int $max = 254, ?callable $error = null): ValidationResult {
        $length = strlen($value);

        if ($length >= $min && $length <= $max) {
            return ValidationResult::ok($length);
        }
        if ($error === null) {
            $error = [self::class, 'defaultLengthError'];
        }

        return ValidationResult::error($error($min, $max));
    }

    public static function stringMinMax(string $value, int $min = 1, int $max = 254, ?callable $error = null): ValidationResult {
        if ($value >= $min && $value <= $max) {
            return ValidationResult::ok($value);
        }
        if ($error === null) {
            $error = [self::class, 'defaultMinMaxError'];
        }

        return ValidationResult::error($error($value, $min, $max));
    }

    public static function patternMatch(string $value, string $pattern, ?callable $error = null): ValidationResult {
        if (preg_match($pattern, $value) === 1) {
            return ValidationResult::ok($value);
        }
        if ($error === null) {
            $error = [self::class, 'defaultPatternError'];
        }

        return ValidationResult::error($error($value, $pattern));
    }


    private static function defaultLengthError(int $min, int $max): string {
        return sprintf(__('Value length must be between %d and %d characters', PluginConfig::APP_CODE), $min, $max);
    }

    private static function defaultMinMaxError(string $value, int $min, int $max): string {
        return sprintf(__('Value %s exceeds %d, %d', PluginConfig::APP_CODE), $value, $min, $max);
    }

    private static function defaultNotInArrayError(string|int $value, array $values): string {
        return sprintf(__('Value %s not in %s.', PluginConfig::APP_CODE), $value, json_encode($values));
    }

    private static function defaultNotInTableError(int $id, string $table): string {
        return sprintf(__('Value %d outside table scope.', PluginConfig::APP_CODE), $id, $table);
    }

    private static function defaultArrayNotInArrayError(array $value, array $values): string {
        return sprintf(__('Values %s not in %s.', PluginConfig::APP_CODE), json_encode($value), json_encode($values));
    }

    private static function defaultNotDateTimeError(string $value): string {
        return sprintf(__('Value %s is not look like date time.', PluginConfig::APP_CODE), $value);
    }

    private static function defaultNotBlankError(): string {
        return __('Value can not be blank.', PluginConfig::APP_CODE);
    }

    private static function defaultPatternError(string $value, string $pattern): string {
        return sprintf(__('Value %s is not look like %s.', PluginConfig::APP_CODE), $value, $pattern);
    }

}