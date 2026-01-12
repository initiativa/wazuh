<?php

namespace GlpiPlugin\Wazuh;

use Monolog\Level;
use Session;
use Toolbox;
use Monolog\Logger;

if (!defined('GLPI_ROOT')) {
    die("Sorry. You can't access this file directly");
}

/**
 * Simple static logger class for GLPI plugins
 *
 * This class provides static logging methods that log directly to GLPI's log system
 */
class PluginLogger{
    use LoggerArrayTrait;
    // Log levels
    public const DEV = 50;
    public const DEBUG = 100;
    public const INFO = 200;
    public const NOTICE = 250;
    public const WARNING = 300;
    public const ERROR = 400;
    public const CRITICAL = 500;

    /** @var string Plugin name */
    private static string $plugin = PluginConfig::APP_NAME;

    /**
     * Initialize logger with plugin name
     *
     * @param string $pluginName Name of the plugin
     *
     * @return void
     */
    public static function init(string $pluginName): void
    {
        self::$plugin = $pluginName;
    }

    /**
     * Log a debug message to GLPI log
     *
     * @param string $message Message to log
     * @param array $context Optional context data
     *
     * @return void
     */
    public static function debug(string|null $message, array $context = []): void
    {
        self::logToGlpi($message, self::DEBUG, $context);
    }

    public static function dev(string|null $message, array $context = []): void
    {
        self::logToGlpi($message, self::DEV, $context);
    }

    /**
     * Log an info message to GLPI log
     *
     * @param string $message Message to log
     * @param array $context Optional context data
     *
     * @return void
     */
    public static function info(string|null $message, array $context = []): void
    {
        $trace = debug_backtrace();
        $context['Function'] = $trace[1]['function'];
        self::logToGlpi($message, self::INFO, $context);
    }

    /**
     * Log a notice message to GLPI log
     *
     * @param string $message Message to log
     * @param array $context Optional context data
     *
     * @return void
     */
    public static function notice(string|null $message, array $context = []): void
    {
        $trace = debug_backtrace();
        $context['Function'] = $trace[1]['function'];
        self::logToGlpi($message, self::NOTICE, $context);
    }

    /**
     * Log a warning message to GLPI log
     *
     * @param string $message Message to log
     * @param array $context Optional context data
     *
     * @return void
     */
    public static function warning(string|null $message, array $context = []): void
    {
        $trace = debug_backtrace();
        $context['Function'] = $trace[1]['function'];
        self::logToGlpi($message, self::WARNING, $context);
    }

    /**
     * Log an error message to GLPI log
     *
     * @param string $message Message to log
     * @param array $context Optional context data
     *
     * @return void
     */
    public static function error(string|null $message, array $context = []): void
    {
        $trace = debug_backtrace();
        $context['Function'] = $trace[1]['function'];
        self::logToGlpi($message, self::ERROR, $context);
    }

    /**
     * Log a critical message to GLPI log
     *
     * @param string $message Message to log
     * @param array $context Optional context data
     *
     * @return void
     */
    public static function critical(string|null $message, array $context = []): void
    {
        $trace = debug_backtrace();
        $context['Function'] = $trace[1]['function'];
        self::logToGlpi($message, self::CRITICAL, $context);
    }

    /**
     * Internal method to log to GLPI
     *
     * @param string $message Message to log
     * @param int $level Log level
     * @param array $context Context data
     *
     * @return void
     */
    protected static function logToGlpi(string|null $message, int $level, array $context = []): void
    {
        global $PHPLOGGER;
        if ($_SESSION['glpi_use_mode'] === Session::DEBUG_MODE) {
            $trace = debug_backtrace();

            $call = $trace[2] ?? [];
            $file = $call['file'] ?? null;
            $line = $call['line'] ?? '0';
            $function = $call['function'] ?? null;
            $class = $call['class'] ?? null;
            $shortClass = null;
            if ($class != null) {
                $parts = explode('\\', $class);
                $shortClass = end($parts);
            }
            $type = $call['type'] ?? null;

            $msg = $message;
            if (!empty($context)) {
                $msg .= "\n" . json_encode($context);
            }

            $formattedMessage = "[" . self::$plugin . "/$shortClass/$function/$line/" . Session::getLoginUserID() . "/" . self::getLevelName($level) . "]: " . $msg . "\n";
            Toolbox::logInFile('php-all', $formattedMessage);
            if ($level === self::DEV) {
                ob_start();
                debug_print_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS);
                Toolbox::logInFile('php-dev', ob_get_clean());
                Toolbox::logInFile('php-dev', $formattedMessage);
            }
        }

        if ($level === self::DEV) {
            $level = self::DEBUG;
        }

        $glpiLevel = Logger::toMonologLevel($level);
        $message = $message == null ? 'NULL' : $message;

        $PHPLOGGER->log($glpiLevel, $message, $context);

    }

    /**
     * Map our log levels to GLPI/Monolog levels
     *
     * @param int $level Our log level
     *
     * @return int GLPI/Monolog log level
     */
    protected static function mapLevelToGlpi(int $level): Level
    {
        // Map our log levels to Monolog levels used by GLPI
        if ($level >= self::ERROR) {
            return Level::Error;
        } elseif ($level >= self::WARNING) {
            return Level::Warning;
        } elseif ($level >= self::INFO) {
            return Level::Info;
        } else {
            return Level::Debug;
        }
    }

    private static function getLevelName(int $level): string {
        return match ($level) {
            self::DEV => 'DEV',
            self::DEBUG => 'DEBUG',
            self::NOTICE => 'NOTICE',
            self::ERROR => 'ERROR',
            self::WARNING => 'WARNING',
            self::INFO => 'INFO',
            self::CRITICAL => 'CRITICAL',
            default => 'UNKNOWN',
        };
    }
}