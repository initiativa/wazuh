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

use Computer;
use DateTime;
use DateTimeZone;
use Exception;
use NetworkEquipment;
use Session;
use CommonDBTM;
use Html;

/**
 * Request helper
 *
 * @author w-tomasz
 */
trait IndexerRequestsTrait {
    private static $indexerUrl;
    private static $username;
    private static $password;
    private static $isInitialized = false;

    /**
     * Initializes the Wazuh connection parameters
     * 
     * @param string $indexerUrl Wazuh indexer URL
     * @param string $username Authentication username
     * @param string $password Authentication password
     * @return bool Initialization status
     */
    public static function initWazuhConnection($indexerUrl, $indexer_port, $username, $password) {
        self::$indexerUrl = rtrim($indexerUrl . ':' . $indexer_port, '/');
        self::$username = $username;
        self::$password = (new \GLPIKey)->decrypt($password);
        self::$isInitialized = true;

        return true;
    }

    /**
     * Checks if the connection parameters are initialized
     * 
     * @return bool True if initialized, false otherwise
     */
    public static function isConnectionInitialized() {
        return self::$isInitialized;
    }

    private static function checkHostAvailability($host, $timeout = 5) {
        $ch = curl_init($host);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, $timeout);
        curl_setopt($ch, CURLOPT_TIMEOUT, $timeout);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_NOBODY, true);

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error = curl_error($ch);

        curl_close($ch);

        return $response !== false && $httpCode < 400;
    }

    /**
     * Executes a query to Wazuh Indexer
     * 
     * @param array $query Query in JSON/array format
     * @return array Server response
     */
    private static function executeQuery($query, \CommonDBTM $device, $index = '/wazuh-states-vulnerabilities-*/_search') {
        if (!self::$isInitialized) {
            return ['success' => false, 'error' => 'Connection not initialized'];
        }

        $endpoint = self::$indexerUrl . $index;
        Logger::addDebug(__FUNCTION__ . " " . $endpoint . " Query: " . json_encode($query));

        $ch = curl_init($endpoint);
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "POST");
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($query));
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_USERPWD, self::$username . ":" . self::$password);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Content-Type: application/json',
            'Content-Length: ' . strlen(json_encode($query))
        ]);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
        
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 5);
        curl_setopt($ch, CURLOPT_TIMEOUT, 30);

        $response = curl_exec($ch);
        $error = curl_error($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($error) {
            Logger::addError(__FUNCTION__ . " HttpCode: $httpCode. $endpoint. $error");
            Session::addMessageAfterRedirect($error, true, ERROR);
            echo Html::scriptBlock("$(function() { displayAjaxMessageAfterRedirect(); }); ");
            return [
                'success' => false,
                'error' => $error,
                'http_code' => $httpCode
            ];
        }

        return [
            'success' => ($httpCode >= 200 && $httpCode < 300),
            'data' => json_decode($response, true),
            'http_code' => $httpCode
        ];
    }

    protected static function getLatestDeviceAlertDetectionDate(CommonDBTM $device): string {
        $clazz = static::class;
        $item = new $clazz;

        if ($device instanceof \Computer) {
            $records = $item->find(
                    ['computers_id' => $device->getID()],
                    ['source_timestamp DESC'],
                    1
            );
        }

        if ($device instanceof \NetworkEquipment) {
            $records = $item->find(
                    ['networkequipments_id' => $device->getID()],
                    ['source_timestamp DESC'],
                    1
            );
        }

        $latestRecord = reset($records);
        if (isset($latestRecord['source_timestamp'])) {
            $dt = DateTime::createFromFormat('Y-m-d H:i:s', $latestRecord['source_timestamp'], new DateTimeZone('UTC'));
            return $dt->format('Y-m-d\TH:i:s\Z');
        } else {
            return 'now-7d/d';
        }
    }

    protected static function getLatestDeviceVulnerabilityDetectionDate(CommonDBTM $device): string {
        $clazz = static::class;
        $item = new $clazz;
        
        if ($device instanceof Computer) {
            $records = $item->find(
                    ['computers_id' => $device->getID()],
                    ['v_detected DESC'],
                    1
            );
        }

        if ($device instanceof NetworkEquipment) {
            $records = $item->find(
                    ['networkequipments_id' => $device->getID()],
                    ['v_detected DESC'],
                    1
            );
        }

        $latestRecord = reset($records);
        if (isset($latestRecord['v_detected'])) {
            $dt = DateTime::createFromFormat('Y-m-d H:i:s', $latestRecord['v_detected'], new DateTimeZone('UTC'));
            return $dt->format('Y-m-d\TH:i:s\Z');
        } else {
            return '2000-01-01T12:00:00Z';
        }
    }
    
    public static function getTotalSize($query, CommonDBTM $device, $index = '/wazuh-states-vulnerabilities-*/_search'): int | bool {
        $query['size'] = 1;
        $query['from'] = 0;
        $result = self::executeQuery($query, $device, $index);
        if ($result['success']) {
            Logger::addDebug(__FUNCTION__ . " Total query result size: " . count($result['data']['hits']['hits']));
            return $result['data']['hits']['total']['value'];
        } else {
            return false;
        }
    }
    
    /**
     * Prepare API query by agent ids
     * @param type $agentIds
     * @return string query
     */
    public static function getQueryByAgentIds(array $agentIds, CommonDBTM $computer): array {
        $latestDtStr = static::getLatestDeviceVulnerabilityDetectionDate($computer);
        $agentIdsStr = json_encode($agentIds);
        Logger::addDebug("Quering Wazuh Indexer for agent: $agentIdsStr after: $latestDtStr");

        $a = $agentIds;
        if (count($agentIds) == 1) {
            $a = $agentIds[0];
        }

        $query = [
            "sort" => [
                [
                    "_id" => [
                        "order" => "desc"
                    ]
                ]
            ],
            "query" => [
                "bool" => [
                    "must" => [
                        [
                            "term" => [
                                "agent.id" => $a
                            ]
                        ],
                        [
                            "range" => [
                                "vulnerability.detected_at" => [
                                    "gt" => $latestDtStr
                                ]
                            ]
                        ]
                    ]
                ]
            ]
        ];
        return $query;
    }

    
     /**
     * Prepare API query by agent ids
     * @param type $agentIds
     * @return string query
     */
    public static function getAlertsQueryByAgentIds(array $agentIds, CommonDBTM $computer): array {
        $latestDtStr = static::getLatestDeviceAlertDetectionDate($computer);
        $agentIdsStr = json_encode($agentIds);
        Logger::addDebug("Alerts Wazuh Indexer for agent: $agentIdsStr after: $latestDtStr");

        $a = $agentIds;
        if (count($agentIds) == 1) {
            $a = $agentIds[0];
        }

        $query = [
            "sort" => [
                [
                    "_id" => [
                        "order" => "desc"
                    ]
                ]
            ],
            "query" => [
                "bool" => [
                    "must" => [
                        [
                            "term" => [
                                "agent.id" => $a
                            ]
                        ],
                        [
                            "range" => [
                                "timestamp" => [
                                    'gte' => $latestDtStr,
                                    'lte' => 'now'
                                ]
                            ]
                        ]
                    ]
                ]
            ]
        ];
        return $query;
    }

    /**
     * Retrieves vulnerabilities by agent ID
     * 
     * @param string|array $agentIds Agent ID or array of agent IDs
     * @param int $pageSize Maximum number of results
     * @param int $offset Offset for pagination (default 0)
     * @return array Query result
     */
    public static function queryVulnerabilitiesByAgentIds($agentIds, CommonDBTM $device, $pageSize = 500): array | false {
        global $DB;
        if (!self::$isInitialized) {
            return ['success' => false, 'error' => 'Connection not initialized'];
        }

        $currentTime = time();
        $session_key = PluginConfig::VQUERY_TIME_SESSION_KEY . '_' . $agentIds[0] . '_' . Session::getActiveEntity();

        $lastExecutionTime = isset($_SESSION[$session_key]) ? $_SESSION[$session_key] : -1;

        // 5 minutes = 300 seconds
        if ($currentTime - $lastExecutionTime < 300) {
            return ['success' => false, 'error' => 'To early.'];
        }

        $_SESSION[$session_key] = $currentTime;

        $query = self::getQueryByAgentIds($agentIds, $device);
        
        $total = self::getTotalSize($query, $device);
        if (!$total) {
            return false;
        }
        $totalPages = ceil($total / $pageSize);

        Logger::addDebug(__FUNCTION__ . " Total size: " . $total);
        static::discontinue_all($device->getID());

        for ($page = 0; $page < $totalPages; $page++) {
            $from = $page * $pageSize;

            $query['size'] = $pageSize;
            $query['from'] = $from;

            $result = self::executeQuery($query, $device);
            if ($result['success']) {
                foreach ($result['data']['hits']['hits'] as $res) {
                    static::createItem($res, $device);
                }
            } else {
                return false;
            }
            usleep(100000);
        }
        return ['success' => true, 'data' => 'Fetch completed.'];
    }

    public static function getLatestMonitoringTime(array $agentIds, \CommonDBTM $device): string | false {
        $query = [
            "size" => 1,
            "from" => 0,
            "sort" => [
                [
                    "timestamp" => [
                        "order" => "desc"
                    ]
                ]
            ],
            "query" => [
                "bool" => [
                    "must" => [
                        [
                            "term" => [
                                "id" => $agentIds[0]
                            ]
                        ]
                    ]
                ]
            ]
        ];
        
        $result = self::executeQuery($query, $device, '/wazuh-monitoring-*/_search');
        if ($result['success']) {
            $source = $result['data']['hits']['hits'][0]['_source'] ?? false;
            $isoDateTime = $source['timestamp'] ?? false;
            if ($isoDateTime) {
                Logger::addDebug(__FUNCTION__ . " Latest time fetched: $isoDateTime");
                return self::convertIsoToMysqlDatetime($isoDateTime);
            }
        }
        return false;
    }

    /**
     * Retrieves alerts by agent ID
     * 
     * @param string|array $agentIds Agent ID or array of agent IDs
     * @param int $pageSize Maximum number of results
     * @param int $offset Offset for pagination (default 0)
     * @return array Query result
     */
    public static function queryAlertsByAgentIds(array $agentIds, CommonDBTM $device, $pageSize = 500): array | false {
        global $DB;
        if (!self::$isInitialized) {
            return ['success' => false, 'error' => 'Connection not initialized'];
        }

        $currentTime = time();
        $session_key = PluginConfig::VQUERY_ALERT_TIME_SESSION_KEY . '_' . $agentIds[0] . '_' . Session::getActiveEntity();

        $lastExecutionTime = isset($_SESSION[$session_key]) ? $_SESSION[$session_key] : -1;

        // 5 minutes = 300 seconds
        if ($currentTime - $lastExecutionTime < 300) {
            Logger::addDebug("To early: " . $currentTime - $lastExecutionTime);
//            return ['success' => false, 'error' => 'To early.'];
        }

        $_SESSION[$session_key] = $currentTime;

        $query = self::getAlertsQueryByAgentIds($agentIds, $device);
        
        $total = self::getTotalSize($query, $device, '/wazuh-alerts-*/_search');
        if (!$total) {
            return false;
        }
        $totalPages = ceil($total / $pageSize);

        Logger::addDebug(__FUNCTION__ . " Total size: " . $total);

        for ($page = 0; $page < $totalPages; $page++) {
            $from = $page * $pageSize;

            $query['size'] = $pageSize;
            $query['from'] = $from;

            $result = self::executeQuery($query, $device, '/wazuh-alerts-*/_search');
            if ($result['success']) {
                foreach ($result['data']['hits']['hits'] as $res) {
                    static::createItem($res, $device);
                }
            } else {
                return false;
            }
            usleep(100000);
        }
        return ['success' => true, 'error' => 'Fetch completed.'];
    }

    
    protected static function convertIsoToMysqlDatetime($isoDate) {
        if (empty($isoDate) || $isoDate === '0000-00-00T00:00:00Z' || $isoDate === '0000-00-00T00:00:00.000Z' || $isoDate == null) {
            return null;
        }

        try {
            $dateTime = new DateTime($isoDate, new DateTimeZone('UTC'));
//            $dateTime->setTimezone(new DateTimeZone('UTC'));
            $year = (int) $dateTime->format('Y');

            if ($year <= 1) {
                return null;
            }

            return $dateTime->format('Y-m-d H:i:s');
        } catch (Exception $e) {
            return null;
        }
    }
    
    protected static function array_getvalue(array $res, array $path) {
        $current = $res;
        foreach ($path as $key) {
            if (!isset($current[$key])) {
                Logger::addWarning(__FUNCTION__ . " *** No key $key in path " . json_encode($path));
                return null;
            }
            $current = $current[$key];
        }
        return $current;
    }
}
