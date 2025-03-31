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

    /**
     * Executes a query for vulnerabilities for specific hosts
     * 
     * @param array $hostnames Array of host names to filter
     * @param int $size Maximum number of results (default 100)
     * @param int $offset Offset for pagination (default 0)
     * @param string $severity Optional filtering by severity level (High, Medium, Low)
     * @return array Query result
     */
    public static function queryVulnerabilitiesByHosts($hostnames = [], $size = 100, $offset = 0, $severity = null) {
        if (!self::$isInitialized) {
            return ['success' => false, 'error' => 'Connection not initialized'];
        }

        $query = [
            'size' => $size,
            'from' => $offset,
            'query' => [
                'bool' => [
                    'must' => []
                ]
            ]
        ];

        if (!empty($hostnames)) {
            if (count($hostnames) == 1) {
                $query['query']['bool']['must'][] = [
                    'term' => [
                        'agent.name' => $hostnames[0]
                    ]
                ];
            } else {
                $query['query']['bool']['must'][] = [
                    'terms' => [
                        'agent.name' => $hostnames
                    ]
                ];
            }
        }

        if ($severity !== null) {
            $query['query']['bool']['must'][] = [
                'term' => [
                    'data.vulnerability.severity' => $severity
                ]
            ];
        }

        return self::executeQuery($query);
    }

    /**
     * Executes a query to Wazuh Indexer
     * 
     * @param array $query Query in JSON/array format
     * @return array Server response
     */
    private static function executeQuery($query) {
        if (!self::$isInitialized) {
            return ['success' => false, 'error' => 'Connection not initialized'];
        }

        $endpoint = self::$indexerUrl . '/wazuh-states-vulnerabilities-*/_search';
        Logger::addDebug(__FUNCTION__ . $endpoint);

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

        $response = curl_exec($ch);
        $error = curl_error($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($error) {
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

    /**
     * Retrieves vulnerabilities by agent ID
     * 
     * @param string|array $agentIds Agent ID or array of agent IDs
     * @param int $size Maximum number of results
     * @param int $offset Offset for pagination (default 0)
     * @return array Query result
     */
    public static function queryVulnerabilitiesByAgentIds($agentIds, $size = 100, $offset = 0) {
        if (!self::$isInitialized) {
            return ['success' => false, 'error' => 'Connection not initialized'];
        }

        $currentTime = time();
        $session_key = PluginConfig::VQUERY_TIME_SESSION_KEY . $agentIds[0];

        $lastExecutionTime = isset($_SESSION[$session_key]) ? $_SESSION[$session_key] : -1;

        // 5 minutes = 300 seconds
        if ($currentTime - $lastExecutionTime < 300) {
            return [];
        }

        $_SESSION[$session_key] = $currentTime;

        $query = [
            'size' => $size,
            'from' => $offset,
            'query' => [
                'bool' => [
                    'must' => []
                ]
            ]
        ];

        if (is_array($agentIds)) {
            if (count($agentIds) == 1) {
                $query['query']['bool']['must'][] = [
                    'term' => [
                        'agent.id' => $agentIds[0]
                    ]
                ];
            } else {
                $query['query']['bool']['must'][] = [
                    'terms' => [
                        'agent.id' => $agentIds
                    ]
                ];
            }
        } else {
            $query['query']['bool']['must'][] = [
                'term' => [
                    'agent.id' => $agentIds
                ]
            ];
        }

        return self::executeQuery($query);
    }
}
