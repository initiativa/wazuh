<?php

namespace GlpiPlugin\Wazuh\Traits;

use GlpiPlugin\Wazuh\PluginLogger;

trait DeviceHelper {

    /**
     * Format JSON data to HTML for display in GLPI
     *
     * @param array|string $json JSON string or already decoded array
     * @return string Formatted HTML
     */
    function formatJsonToHtml(array|string|null $json): string {
        // If string provided, decode it first
        if (is_string($json)) {
            $data = json_decode($json, true);
            $err = json_last_error();
            if ($err !== JSON_ERROR_NONE) {
                PluginLogger::error("$err: Invalid JSON encoded '$json'.");
                return "<div class='alert alert-warning'>Invalid JSON format. $err</div>";
            }
        } else {
            $data = $json;
        }

        // Start building HTML output
        $html = "<div class='json-viewer'>";

        // Use recursive function to build nested structure
        $html .= $this->formatJsonNodeToHtml($data);

        $html .= "</div>";

        return $html;
    }

    /**
     * Helper function to recursively format JSON nodes
     *
     * @param mixed $node Current JSON node
     * @param int $level Nesting level
     * @return string HTML representation
     */
    function formatJsonNodeToHtml(mixed $node, int $level = 0): string {
        if (is_null($node)) {
            return "<span class='json-value json-null'>null</span>";
        }

        if (is_bool($node)) {
            return "<span class='json-value json-bool'>" . ($node ? 'true' : 'false') . "</span>";
        }

        if (is_numeric($node)) {
            return "<span class='json-value json-number'>" . $node . "</span>";
        }

        if (is_string($node)) {
            return "<span class='json-value'>" . htmlspecialchars($node, ENT_QUOTES, 'UTF-8') . "</span>";
        }

        if (is_array($node)) {
            $html = "<ul class='json-list'>";
            foreach ($node as $key => $value) {
                $html .= "<li>";
                $html .= "<span class='json-key'>" . htmlspecialchars((string)$key, ENT_QUOTES, 'UTF-8') . "</span>: ";
                $html .= $this->formatJsonNodeToHtml($value, $level + 1);
                $html .= "</li>";
            }
            $html .= "</ul>";
            return $html;
        }

        return '';
    }

}