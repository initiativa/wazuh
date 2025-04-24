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

use Search;
use Html;
use CommonTreeDropdown;

class TreeSearch extends Search {
    public static function show($itemtype, $params = [], $forcedisplay = []) {
        $item = new $itemtype();
        if (!($item instanceof CommonTreeDropdown)) {
            return parent::show($itemtype);
        }
        
        // Get data from search engine
        $data = self::getDatas($itemtype, $params, $forcedisplay);
        
        echo "<div class='enhanced-tree-search'>";
        
        // Display standard search header
        self::showHeader(self::HTML_OUTPUT, count($data['data']['rows']), count($data['data']['cols']), true);
        
        if (count($data['data']['rows']) > 0) {
            // Build tree structure
            $foreign_key = $itemtype::getForeignKeyField();
            $items = [];
            
            // First pass - collect all items
            foreach ($data['data']['rows'] as $row) {
                $item_id = $row['id'];
                $parent_id = 0;
                
                // Get parent ID from raw data
                if (isset($row['raw'][$foreign_key])) {
                    $parent_id = (int)$row['raw'][$foreign_key];
                }
                
                $items[$item_id] = [
                    'id' => $item_id,
                    'parent_id' => $parent_id,
                    'row' => $row,
                    'level' => 0
                ];
            }
            
            // Output table
            echo "<table class='tab_cadre_fixehov'>";
            
            // Table header
            echo "<tr class='noHover'>";
            foreach ($data['data']['cols'] as $col_num => $col) {
                if (isset($col['meta']) && $col['meta']) {
                    continue;
                }
                echo "<th>" . $col['name'] . "</th>";
            }
            echo "</tr>";
            
            // Display root items
            foreach ($items as $id => $item) {
                if ($item['parent_id'] == 0) {
                    self::displayItem($id, $items, $data, $itemtype, 0);
                }
            }
            
            echo "</table>";
        } else {
            echo "<div class='center b'>" . __('No item found') . "</div>";
        }
        
        // Standard search footer
        self::showFooter(self::HTML_OUTPUT);
        
        echo "</div>";
        
        // Add JavaScript for tree functionality
        echo Html::scriptBlock("
            $(document).ready(function() {
                $('.tree-toggle').click(function() {
                    var itemId = $(this).data('id');
                    var icon = $(this).find('i');
                    
                    $('.tree-child-' + itemId).toggle();
                    
                    if (icon.hasClass('fa-caret-right')) {
                        icon.removeClass('fa-caret-right').addClass('fa-caret-down');
                    } else {
                        icon.removeClass('fa-caret-down').addClass('fa-caret-right');
                        // Hide all children recursively
                        $('.tree-child-' + itemId + ' .tree-toggle').each(function() {
                            var childId = $(this).data('id');
                            $(this).find('i').removeClass('fa-caret-down').addClass('fa-caret-right');
                            $('.tree-child-' + childId).hide();
                        });
                    }
                    
                    return false;
                });
                
                // Hide all children initially
                $('.tree-child').hide();
            });
        ");
    }
    
    private static function displayItem($item_id, &$items, $data, $itemtype, $level) {
        $item = $items[$item_id];
        
        // Find children
        $children = [];
        foreach ($items as $id => $potential_child) {
            if ($potential_child['parent_id'] == $item_id) {
                $children[$id] = $potential_child;
            }
        }
        
        $has_children = !empty($children);
        $row_class = $level > 0 ? 'tree-child tree-child-' . $item['parent_id'] : '';
        
        echo "<tr class='tab_bg_1 $row_class'>";
        
        // Display cells
        foreach ($data['data']['cols'] as $col_num => $col) {
            if (isset($col['meta']) && $col['meta']) {
                continue;
            }
            
            echo "<td>";
            
            // Add tree controls for first column
            if ($col_num == 0) {
                // Add indentation
                echo str_repeat("&nbsp;&nbsp;&nbsp;&nbsp;", $level);
                
                // Add expand/collapse icon for items with children
                if ($has_children) {
                    echo "<a href='#' class='tree-toggle' data-id='$item_id'>";
                    echo "<i class='fas fa-caret-right'></i></a>&nbsp;";
                } else {
                    echo "<span style='display:inline-block;width:16px;'></span>&nbsp;";
                }
            }
            
            // Add cell content
            $key = $itemtype . '_' . $col['id'];
            if (isset($item['row'][$key]) && isset($item['row'][$key]['displayname'])) {
                echo $item['row'][$key]['displayname'];
            }
            
            echo "</td>";
        }
        
        echo "</tr>";
        
        // Recursively display children
        foreach ($children as $child_id => $child) {
            self::displayItem($child_id, $items, $data, $itemtype, $level + 1);
        }
    }
}

