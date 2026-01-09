<?php

/**
 * -------------------------------------------------------------------------
 * RoundRobin plugin for GLPI
 * -------------------------------------------------------------------------
 *
 * LICENSE
 *
 * This file is part of RoundRobin GLPI Plugin.
 *
 * RoundRobin is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * RoundRobin is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with RoundRobin. If not, see <http://www.gnu.org/licenses/>.
 * -------------------------------------------------------------------------
 * @copyright Copyright (C) 2022 by initiativa s.r.l. - http://www.initiativa.it
 * @license   GPLv3 https://www.gnu.org/licenses/gpl-3.0.html
 * @link      https://github.com/initiativa/roundrobin
 * -------------------------------------------------------------------------
 */

namespace GlpiPlugin\Wazuh;

use Monolog\Level;
use Session;

class Logger {
    use LoggerArrayTrait;

    private static string $plugin = PluginConfig::APP_CODE;

    protected static $DEBUG = 100;
    protected static $INFO = 200;
    protected static $NOTICE = 250;
    protected static $WARNING = 300;
    protected static $ERROR = 400;
    protected static $CRITICAL = 500;
    protected static $ALERT = 550;
    protected static $EMERGENCY = 600;

    /**
     *
     * @param int $type
     * @param string $message
     * @param array $details
     *@global Logger $PHPLOGGER
     */
    protected static function add(int $type, string $message, array $details = []): void {
        global $PHPLOGGER;
        $recordType = match ($type) {
            self::$DEBUG => Level::Debug,
            self::$NOTICE => Level::Notice,
            self::$WARNING => Level::Warning,
            self::$ERROR => Level::Error,
            self::$CRITICAL => Level::Critical,
            default => Level::Info,
        };
        $PHPLOGGER->addRecord($recordType, $message, $details);
    }

    public static function addDebug($message, $details = []): void {
        $message = self::format($message);
        self::add(self::$DEBUG, $message, $details);
    }

    public static function addInfo($message, $details = []): void {
        $message = self::format($message);
        self::add(self::$INFO, $message, $details);
    }

    public static function addNotice($message, $details = []): void {
        $message = self::format($message);
        self::add(self::$NOTICE, $message, $details);
    }

    public static function addWarning($message, $details = []): void {
        $message = self::format($message);
        self::add(self::$WARNING, $message, $details);
    }

    public static function addError($message, $details = []): void {
        $message = self::format($message);
        self::add(self::$ERROR, $message, $details);
    }

    public static function addCritical($message, $details = []): void {
        $message = self::format($message);
        self::add(self::$CRITICAL, $message, $details);
    }

    private static function format($message): string {
        if ($_SESSION['glpi_use_mode'] === Session::DEBUG_MODE) {
            $trace = debug_backtrace();

            $call = $trace[2] ?? [];
            $file = $call['file'] ?? null;
            $line = $call['line'] ?? '0';
            $function = $call['function'] ?? null;
            $class = $call['class'] ?? $trace[3]['class'] ?? null;
            $shortClass = null;
            if ($class != null) {
                $parts = explode('\\', $class);
                $shortClass = end($parts);
            }
            $type = $call['type'] ?? null;

            return "[" . self::$plugin . "/$shortClass/$function/$line/" . Session::getLoginUserID() . "]: " . $message . "\n";
        }

        return __NAMESPACE__ . ":: " . $message;
    }

    public static function debug(string $msg): void {
        self::addDebug($msg);
    }

}
