<?php

namespace GlpiPlugin\Wazuh\Traits;

use DateTime;
use Entity;
use Exception;
use GlpiPlugin\Wazuh\PluginConfig;
use GlpiPlugin\Wazuh\PluginLogger;
use Session;

trait FieldValidation {

    public const DATETIME_OR_EMPTY = 'dateTimeOrEmpty';
    public const DATE_OR_EMPTY = 'dateOrEmpty';
    public const NOT_BLANK = 'notBlank';
    public const INT_IN_ARRAY = 'intInArray';
    public const INT_MIN_MAX = 'intMinMax';
    public const CONTAINS_ONLY = 'containsOnly';
    public const CONTAINS_OR_EMPTY = 'containsOrEmpty';
    public const STRING_IN_ARRAY = 'stringInArray';
    public const STRING_LENGTH = 'stringLength';
    public const STRING_MIN_MAX = 'stringMinMax';
    public const ID_IN_TABLE = 'idInTable';
    public const IDS_IN_TABLE = 'idsInTable';
    public const PATTERN_MATCH = 'patternMatch';
    public const URL = 'url';
    public const MAX_NOTE_LENGTH = 5000;

    protected function getAdditionalFieldOptions(): array {
        $additional_options = [];

        PluginLogger::debug(static::class);
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

    protected static function validateSet(array $input, array &$validation_errors, string $key): void {
        if (!isset($input[$key])) {
            $validation_errors[$key] = "$key value is required.";
        }
    }

    protected static function validateArray(array $input, array &$validation_errors, string $key, array $allowed_values, bool $multiselect = false): void {
        if ($multiselect === true) {
            if (isset($input[$key])) {
                $value = $input[$key];
                self::validate($key, $validation_errors, [self::class, self::CONTAINS_OR_EMPTY], $value, $allowed_values);
            }
        } else {
            if (isset($input[$key])) {
                $value = $input[$key];
                self::validate($key, $validation_errors, [self::class, self::STRING_IN_ARRAY], $value, $allowed_values);
            }
        }
    }

    protected static function validateTextLength(array $input, array &$validation_errors, string $key, int $min = 0, int $max = 254): void {
        if (isset($input[$key])) {
            $value = $input[$key];
            self::validate($key, $validation_errors, [self::class, self::STRING_LENGTH], $value, $min, $max);
        }
    }

    protected static function validateIntMinMax(array $input, array &$validation_errors, string $key, int $min = 0, int $max = 65535): void {
        if (isset($input[$key])) {
            $value = $input[$key];
            self::validate($key, $validation_errors, [self::class, self::INT_MIN_MAX], $value, $min, $max);
        }
    }

    protected static function validateUrl(array $input, array &$validation_errors, string $key): void {
        if (isset($input[$key])) {
            $value = $input[$key];
            self::validate($key, $validation_errors, [self::class, self::URL], $value);
        }
    }

    protected static function validateYesNo(array $input, array &$validation_errors, string $key): void {
        if (isset($input[$key])) {
            $value = $input[$key];
            self::validate($key, $validation_errors, [self::class, self::CONTAINS_ONLY], $value, ['0', '1']);
        }
    }

    protected static function validateDropdown(array $input, array &$validation_errors, string $key, mixed $table_type, ?array $criteria = null, bool $multiselect = false): void {
        $criteria ??= static::DEFAULT_CRITERIA();
        if ($multiselect === true) {
            if (isset($input[$key])) {
                $value = self::ensure_array($input[$key]);
                self::validate($key, $validation_errors, [self::class, self::IDS_IN_TABLE], $value, $table_type, $criteria);
            }
        } else {
            if (isset($input[$key])) {
                $value = $input[$key];
                self::validate($key, $validation_errors, [self::class, self::ID_IN_TABLE], $value, $table_type, $criteria);
            }
        }
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

    public static function intMinMax(int|string $value, int $min, int $max, ?callable $error = null): ValidationResult {
        if (is_string($value)) {
            $value = filter_var($value, FILTER_VALIDATE_INT);
        }

        if ($value === false) {
            $error = [self::class, 'defaultNotIntError'];
            return ValidationResult::error($error($value));
        }

        if ($value < $min || $value > $max) {
            if ($error === null) {
                $error = [self::class, 'defaultIntMinMaxError'];
            }
            return ValidationResult::error($error($value, $min, $max));
        }
        return ValidationResult::ok($value);
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

    public static function containsOrEmpty(array|string $value, array $values = [], ?callable $error = null): ValidationResult {
        if (empty($value)) {
            return ValidationResult::ok($value);
        }

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

    public static function url(string $url): ValidationResult {
        $ALLOWED_SCHEMES = ['http', 'https'];

        $length = strlen($url);
        if ($length >= 254) {
            return ValidationResult::error(__('URL too long', PluginConfig::APP_CODE));
        }

        if (preg_match('/[\x00-\x1F\x7F]/', $url)) {
            return ValidationResult::error(__('URL must not contain control characters', PluginConfig::APP_CODE));
        }

        $parsed = parse_url($url);
        if ($parsed === false || empty($parsed['host']) || empty($parsed['scheme'])) {
            return ValidationResult::error(__('URL must contain a valid scheme and host (e.g. https://example.com)', PluginConfig::APP_CODE));
        }

        if (!in_array(strtolower($parsed['scheme']), $ALLOWED_SCHEMES, true)) {
            return ValidationResult::error(__('URL scheme must be http or https', PluginConfig::APP_CODE));
        }

        if (isset($parsed['user']) || isset($parsed['pass'])) {
            return ValidationResult::error(__('URL must not contain user credentials', PluginConfig::APP_CODE));
        }

        if (!filter_var($url, FILTER_VALIDATE_URL)) {
            return ValidationResult::error(__('URL format is not valid', PluginConfig::APP_CODE));
        }

        return ValidationResult::ok($url);
    }

    private static function defaultLengthError(int $min, int $max): string {
        return sprintf(__('Value length must be between %d and %d characters', PluginConfig::APP_CODE), $min, $max);
    }

    private static function defaultMinMaxError(string $value, int $min, int $max): string {
        return sprintf(__('Value %s exceeds %d, %d', PluginConfig::APP_CODE), $value, $min, $max);
    }

    private static function defaultIntMinMaxError(int $value, int $min, int $max): string {
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

    private static function defaultNotIntError(string $value): string {
        return sprintf(__('Value %s is not an integer.', PluginConfig::APP_CODE), $value);
    }

    private static function defaultNotBlankError(): string {
        return sprintf(__('Value can not be blank.', PluginConfig::APP_CODE));
    }

    private static function defaultPatternError(string $value, string $pattern): string {
        return sprintf(__('Value %s is not look like %s.', PluginConfig::APP_CODE), $value, $pattern);
    }

}