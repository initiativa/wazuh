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

class Logger {
    use LoggerArrayTrait;

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
     * @global Logger $PHPLOGGER
     * @param int $type
     * @param string $message
     * @param array $details
     */
    protected static function add($type, $message, $details = [])
    {
        global $PHPLOGGER;
        switch ($type) {
            case self::$DEBUG:
                $recordType = \Monolog\Logger::DEBUG;
                break;
            case self::$INFO:
                $recordType = \Monolog\Logger::INFO;
                break;
            case self::$NOTICE:
                $recordType = \Monolog\Logger::NOTICE;
                break;
            case self::$WARNING:
                $recordType = \Monolog\Logger::WARNING;
                break;
            case self::$ERROR:
                $recordType = \Monolog\Logger::ERROR;
                break;
            case self::$CRITICAL:
                $recordType = \Monolog\Logger::CRITICAL;
                break;
            default:
                $recordType = \Monolog\Logger::INFO;
                break;
        }
        $PHPLOGGER->addRecord($recordType, $message, $details);
    }

    public static function addDebug($message, $details = [])
    {
        self::add(self::$DEBUG, $message, $details);
    }

    public static function addInfo($message, $details = [])
    {
        self::add(self::$INFO, $message, $details);
    }

    public static function addNotice($message, $details = [])
    {
        self::add(self::$NOTICE, $message, $details);
    }

    public static function addWarning($message, $details = [])
    {
        self::add(self::$WARNING, $message, $details);
    }

    public static function addError($message, $details = [])
    {
        self::add(self::$ERROR, $message, $details);
    }

    public static function addCritical($message, $details = [])
    {
        self::add(self::$CRITICAL, $message, $details);
    }
}
