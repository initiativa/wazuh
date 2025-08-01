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

use Change;
use CommonDBTM;
use Glpi\Application\View\TemplateRenderer;
use Glpi\Dashboard\Grid;
use Glpi\Socket;
use Glpi\Toolbox\URL;
use Plugin;
use Problem;
use SavedSearch;
use Session;
use Ticket;
use Toolbox;


class TreeSearchOutput extends \CommonDBTM {
    
    private array $search_opt_array;
    private static $search_options_cache = [];

    
    #[Override]
    public function canDisplayResultsContainerWithoutExecutingSearch(): bool
    {
        return true;
    }

    public static function showPreSearchDisplay(string $itemtype): void
    {
        if (
            $itemtype === Ticket::class
            && \Session::getCurrentInterface() === 'central'
            && $default = Grid::getDefaultDashboardForMenu('mini_ticket', true)
        ) {
            $dashboard = new Grid($default, 33, 2);
            $dashboard->show(true);
        }
    }

    public function displayData(array $data, array $params = [])
    {
        /** @var array $CFG_GLPI */
        global $CFG_GLPI;

        $search_was_executed = $params['execute_search'] ?? true;
        $search_error = false;

        if (
            $search_was_executed
            && (!isset($data['data']) || !isset($data['data']['totalcount']))
        ) {
            $search_error = true;
        }

        $search     = $data['search'];
        $itemtype   = $data['itemtype'];
        $item       = $data['item'];
        $is_deleted = $search['is_deleted'];

        foreach ($search['criteria'] as $key => $criteria) {
            if (isset($criteria['virtual']) && $criteria['virtual']) {
                unset($search['criteria'][$key]);
            }
        }

        // Construct parameters
        $globallinkto  = Toolbox::append_params([
            'criteria'     => $search['criteria'],
            'metacriteria' => $search['metacriteria'],
        ], '&');

        $parameters = http_build_query([
            'sort'   => $search['sort'],
            'order'  => $search['order']
        ]);

        $parameters .= "&{$globallinkto}";

        if (isset($_GET['_in_modal'])) {
            $parameters .= "&_in_modal=1";
        }

        // For plugin add new parameter if available
        if ($plug = isPluginItemType($data['itemtype'])) {
            $out = Plugin::doOneHook($plug['plugin'], 'addParamFordynamicReport', $data['itemtype']);
            if (is_array($out) && count($out)) {
                $parameters .= Toolbox::append_params($out, '&');
            }
        }

        $search['target'] = URL::sanitizeURL($search['target']);
        $prehref = $search['target'] . (strpos($search['target'], "?") !== false ? "&" : "?");
        $href    = $prehref . $parameters;

        Session::initNavigateListItems($data['itemtype'], '', $href);

        // search if any saved search is active
        $soptions = self::getOptionsForItemtype($itemtype);
        $active_search_name = '';
        $active_savedsearch = false;
        if (isset($_SESSION['glpi_loaded_savedsearch'])) {
            $savedsearch = new SavedSearch();
            $savedsearch->getFromDB($_SESSION['glpi_loaded_savedsearch']);
            if ($itemtype === $savedsearch->fields['itemtype']) {
                $active_search_name = $savedsearch->getName();
                $active_savedsearch = true;
            }
        } else if (count($data['search']['criteria']) > 0) {
            // check if it isn't the default search
            $default = self::getDefaultSearch($itemtype);
            if ($default != $data['search']['criteria']) {
                $used_fields = array_column($data['search']['criteria'], 'field');
                $used_fields = array_unique($used_fields);

                // remove view field
                $is_view_fields = in_array('view', $used_fields);
                if ($is_view_fields) {
                    unset($used_fields[array_search('view', $used_fields)]);
                }

                $used_soptions = array_intersect_key($soptions, array_flip($used_fields));
                $used_soptions_names = array_column($used_soptions, 'name');

                if ($is_view_fields) {
                    $used_soptions_names[] = _n('View', 'Views', 1);
                }

                //FIXME - is it usable ?
                // check also if there is any default filters
//                if ($defaultfilter = self::getSearchCriteria($itemtype)) {
//                    array_unshift($used_soptions_names, $defaultfilter['name']);
//                }

                // remove latitude and longitude if as map is enabled
                $as_map = $data['search']['as_map'] ?? 0;
                if ($as_map == 1) {
                    unset($used_soptions_names[array_search(__('Latitude'), $used_soptions_names)]);
                    unset($used_soptions_names[array_search(__('Longitude'), $used_soptions_names)]);
                }

                $active_search_name = sprintf(__("Filtered by %s"), implode(', ', $used_soptions_names));
            }
        }

        $active_sort_name = "";
        $active_sort = false;
        // should be sorted (0 => 0 : is the default value -> no sort)
        if (count($data['search']['sort']) > 0 && $data['search']['sort'] != [0 => 0]) {
            $used_fields = array_unique($data['search']['sort']);
            $used_fields = array_filter($used_fields, fn($value) => !is_null($value) && $value !== '');

            $used_soptions_names = [];
            foreach ($used_fields as $sopt_id) {
                $used_soptions_names[] = $soptions[$sopt_id]['name'];
            }

            $active_sort_name = sprintf(__("Sorted by %s"), implode(', ', $used_soptions_names));

            $active_sort = true;
        }

        $count = $data['data']['totalcount'] ?? 0;

        $rand = mt_rand();
        TemplateRenderer::getInstance()->display('@wazuh/display_data.html.twig', [
            'search_error'        => $search_error,
            'search_was_executed' => $search_was_executed,
            'data'                => $data,
            'union_search_type'   => $CFG_GLPI["union_search_type"],
            'rand'                => $rand,
            'no_sort'             => $search['no_sort'] ?? false,
            'order'               => $search['order'] ?? [],
            'sort'                => $search['sort'] ?? [],
            'start'               => $search['start'] ?? 0,
            'limit'               => $_SESSION['glpilist_limit'],
            'count'               => $count,
            'item'                => $item,
            'itemtype'            => $itemtype,
            'href'                => $href,
            'prehref'             => $prehref,
            'posthref'            => $globallinkto,
            'push_history'        => $params['push_history'] ?? true,
            'hide_controls'       => $params['hide_controls'] ?? false,
            'hide_search_toggle'  => $params['hide_criteria'] ?? false,
            'showmassiveactions'  => ($params['showmassiveactions'] ?? $search['showmassiveactions'] ?? true)
                && $data['display_type'] != \Search::GLOBAL_SEARCH
                && ($itemtype == \AllAssets::getType()
                    || count(\MassiveAction::getAllMassiveActions($item, $is_deleted))
                ),
            'massiveactionparams' => $data['search']['massiveactionparams'] + [
                'num_displayed' => min($_SESSION['glpilist_limit'], $count),
                'is_deleted'    => $is_deleted,
                'container'     => "massform$itemtype$rand",
            ],
            'can_config'          => \Session::haveRightsOr('search_config', [
                \DisplayPreference::PERSONAL,
                \DisplayPreference::GENERAL
            ]),
            'may_be_deleted'      => $item instanceof \CommonDBTM && $item->maybeDeleted() && !$item->useDeletedToLockIfDynamic(),
            'may_be_located'      => $item instanceof \CommonDBTM && $item->maybeLocated(),
            'may_be_browsed'      => $item !== null && \Toolbox::hasTrait($item, \Glpi\Features\TreeBrowse::class),
            'may_be_unpublished'  => $itemtype == 'KnowbaseItem' && $item->canUpdate(),
            'original_params'     => $params,
            'active_savedsearch'  => $active_savedsearch,
            'active_search_name'  => $active_search_name,
            'active_sort_name'    => $active_sort_name,
            'active_sort'         => $active_sort,
        ] + ($params['extra_twig_params'] ?? []));

        // Add items in item list
        if (isset($data['data']['rows'])) {
            foreach ($data['data']['rows'] as $row) {
                if ($itemtype !== \AllAssets::class) {
                    \Session::addToNavigateListItems($itemtype, $row["id"]);
                } else {
                    // In case of a global search, reset and empty navigation list to ensure navigation in
                    // item header context is not shown. Indeed, this list does not support navigation through
                    // multiple itemtypes, so it should not be displayed in global search context.
                    \Session::initNavigateListItems($row['TYPE'] ?? $data['itemtype']);
                }
            }
        }

        // Clean previous selection
        $_SESSION['glpimassiveactionselected'] = [];
    }

    public static function showNewLine($odd = false, $is_deleted = false): string
    {
        $class = " class='tab_bg_2" . ($is_deleted ? '_2' : '') . "' ";
        if ($odd) {
            $class = " class='tab_bg_1" . ($is_deleted ? '_2' : '') . "' ";
        }
        return "<tr $class>";
    }

    public static function showEndLine(bool $is_header_line): string
    {
        return '</tr>';
    }

    public static function showBeginHeader(): string
    {
        return '<thead>';
    }

    public static function showHeader($rows, $cols, $fixed = 0): string
    {
        if ($fixed) {
            return "<div class='text-center'><table class='table'>";
        }

        return "<div class='text-center'><table class='table card-table table-hover'>";
    }

    public static function showHeaderItem($value, &$num, $linkto = "", $issort = 0, $order = "", $options = ""): string
    {
        $class = "";
        if ($issort) {
            $class = "order_$order";
        }
        $out = "<th $options class='$class'>";
        if (!empty($linkto)) {
            $out .= "<a href=\"$linkto\">";
        }
        $out .= $value;
        if (!empty($linkto)) {
            $out .= "</a>";
        }
        $out .= "</th>\n";
        $num++;
        return $out;
    }

    public static function showEndHeader(): string
    {
        return '</thead>';
    }

    public static function showItem($value, &$num, $row, $extraparam = ''): string
    {
        /** @var array $CFG_GLPI */
        global $CFG_GLPI;
        $out = "<td $extraparam valign='top'>";

        if (!preg_match('/' . \Search::LBHR . '/', $value)) {
            $values = preg_split('/' . \Search::LBBR . '/i', $value);
            $line_delimiter = '<br>';
        } else {
            $values = preg_split('/' . \Search::LBHR . '/i', $value);
            $line_delimiter = '<hr>';
        }

        if (
            count($values) > 1
            && \Toolbox::strlen($value) > $CFG_GLPI['cut']
        ) {
            $value = '';
            foreach ($values as $v) {
                $value .= $v . $line_delimiter;
            }
            $value = preg_replace('/' . \Search::LBBR . '/', '<br>', $value);
            $value = preg_replace('/' . \Search::LBHR . '/', '<hr>', $value);
            $value = '<div class="fup-popup">' . $value . '</div>';
            $valTip = ' ' . \Html::showToolTip(
                $value,
                [
                    'awesome-class'   => 'fa-comments',
                    'display'         => false,
                    'autoclose'       => false,
                    'onclick'         => true
                ]
            );
            $out .= $values[0] . $valTip;
        } else {
            $value = preg_replace('/' . \Search::LBBR . '/', '<br>', $value);
            $value = preg_replace('/' . \Search::LBHR . '/', '<hr>', $value);
            $out .= $value;
        }
        $out .= "</td>\n";
        return $out;
    }

    public static function showFooter($title = "", $count = null): string
    {
        return "</table></div>\n";
    }

    public static function showError($message = ''): string
    {
        return "<div class='center b'>$message</div>\n";
    }
    
        /**
     * Get the SEARCH_OPTION array
     *
     * @param class-string<\CommonDBTM>  $itemtype     Item type
     * @param boolean $withplugins  Get search options from plugins (true by default)
     *
     * @return array The reference to the array of search options for the given item type
     **/
    public static function getOptionsForItemtype($itemtype, $withplugins = true): array
    {
        /** @var array $CFG_GLPI */
        global $CFG_GLPI;
        $item = null;

        $search = [];

        $cache_key = $itemtype . '_' . $withplugins;
        if (isset(self::$search_options_cache[$cache_key])) {
            return self::$search_options_cache[$cache_key];
        }

        $fn_append_options = static function ($new_options) use (&$search, $itemtype) {
            // Check duplicate keys between new options and existing options
            $duplicate_keys = array_intersect(array_keys($search[$itemtype]), array_keys($new_options));
            if (count($duplicate_keys) > 0) {
                trigger_error(
                    sprintf(
                        'Duplicate keys found in search options for item type %s: %s',
                        $itemtype,
                        implode(', ', $duplicate_keys)
                    ),
                    E_USER_WARNING
                );
            }
            $search[$itemtype] += $new_options;
        };

        // standard type first
        switch ($itemtype) {
            case 'Internet':
                $search[$itemtype]['common']            = __('Characteristics');

                $search[$itemtype][1]['table']          = 'networkport_types';
                $search[$itemtype][1]['field']          = 'name';
                $search[$itemtype][1]['name']           = __('Name');
                $search[$itemtype][1]['datatype']       = 'itemlink';
                $search[$itemtype][1]['searchtype']     = 'contains';

                $search[$itemtype][2]['table']          = 'networkport_types';
                $search[$itemtype][2]['field']          = 'id';
                $search[$itemtype][2]['name']           = __('ID');
                $search[$itemtype][2]['searchtype']     = 'contains';

                $search[$itemtype][31]['table']         = 'glpi_states';
                $search[$itemtype][31]['field']         = 'completename';
                $search[$itemtype][31]['name']          = __('Status');

                $fn_append_options(\NetworkPort::getSearchOptionsToAdd('networkport_types'));
                break;

            case \AllAssets::getType():
                $search[$itemtype]['common']            = __('Characteristics');

                $search[$itemtype][1]['table']          = 'asset_types';
                $search[$itemtype][1]['field']          = 'name';
                $search[$itemtype][1]['name']           = __('Name');
                $search[$itemtype][1]['datatype']       = 'itemlink';
                $search[$itemtype][1]['searchtype']     = 'contains';

                $search[$itemtype][2]['table']          = 'asset_types';
                $search[$itemtype][2]['field']          = 'id';
                $search[$itemtype][2]['name']           = __('ID');
                $search[$itemtype][2]['searchtype']     = 'contains';

                $search[$itemtype][31]['table']         = 'glpi_states';
                $search[$itemtype][31]['field']         = 'completename';
                $search[$itemtype][31]['name']          = __('Status');

                $fn_append_options(\Location::getSearchOptionsToAdd());

                $search[$itemtype][5]['table']          = 'asset_types';
                $search[$itemtype][5]['field']          = 'serial';
                $search[$itemtype][5]['name']           = __('Serial number');

                $search[$itemtype][6]['table']          = 'asset_types';
                $search[$itemtype][6]['field']          = 'otherserial';
                $search[$itemtype][6]['name']           = __('Inventory number');

                $search[$itemtype][16]['table']         = 'asset_types';
                $search[$itemtype][16]['field']         = 'comment';
                $search[$itemtype][16]['name']          = __('Comments');
                $search[$itemtype][16]['datatype']      = 'text';

                $search[$itemtype][70]['table']         = 'glpi_users';
                $search[$itemtype][70]['field']         = 'name';
                $search[$itemtype][70]['name']          = \User::getTypeName(1);

                $search[$itemtype][7]['table']          = 'asset_types';
                $search[$itemtype][7]['field']          = 'contact';
                $search[$itemtype][7]['name']           = __('Alternate username');
                $search[$itemtype][7]['datatype']       = 'string';

                $search[$itemtype][8]['table']          = 'asset_types';
                $search[$itemtype][8]['field']          = 'contact_num';
                $search[$itemtype][8]['name']           = __('Alternate username number');
                $search[$itemtype][8]['datatype']       = 'string';

                $search[$itemtype][71]['table']         = 'glpi_groups';
                $search[$itemtype][71]['field']         = 'completename';
                $search[$itemtype][71]['name']          = \Group::getTypeName(1);

                $search[$itemtype][19]['table']         = 'asset_types';
                $search[$itemtype][19]['field']         = 'date_mod';
                $search[$itemtype][19]['name']          = __('Last update');
                $search[$itemtype][19]['datatype']      = 'datetime';
                $search[$itemtype][19]['massiveaction'] = false;

                $search[$itemtype][23]['table']         = 'glpi_manufacturers';
                $search[$itemtype][23]['field']         = 'name';
                $search[$itemtype][23]['name']          = \Manufacturer::getTypeName(1);

                $search[$itemtype][24]['table']         = 'glpi_users';
                $search[$itemtype][24]['field']         = 'name';
                $search[$itemtype][24]['linkfield']     = 'users_id_tech';
                $search[$itemtype][24]['name']          = __('Technician in charge');
                $search[$itemtype][24]['condition']     = ['is_assign' => 1];

                $search[$itemtype][49]['table']          = 'glpi_groups';
                $search[$itemtype][49]['field']          = 'completename';
                $search[$itemtype][49]['linkfield']      = 'groups_id_tech';
                $search[$itemtype][49]['name']           = __('Group in charge');
                $search[$itemtype][49]['condition']      = ['is_assign' => 1];
                $search[$itemtype][49]['datatype']       = 'dropdown';

                $search[$itemtype][80]['table']         = 'glpi_entities';
                $search[$itemtype][80]['field']         = 'completename';
                $search[$itemtype][80]['name']          = \Entity::getTypeName(1);
                break;

            default:
                if ($item = getItemForItemtype($itemtype)) {
                    $search[$itemtype] = $item->searchOptions();
                }
                break;
        }

        if (
            \Session::getLoginUserID()
            && in_array($itemtype, $CFG_GLPI["ticket_types"])
        ) {
            $search[$itemtype]['tracking']          = __('Assistance');

            $fn_append_options(Problem::getSearchOptionsToAdd($itemtype));
            $fn_append_options(Ticket::getSearchOptionsToAdd($itemtype));
            $fn_append_options(Change::getSearchOptionsToAdd($itemtype));
        }

        if (
            in_array($itemtype, $CFG_GLPI["networkport_types"])
            || ($itemtype == \AllAssets::getType())
        ) {
            $fn_append_options(\NetworkPort::getSearchOptionsToAdd($itemtype));
        }

        if (
            in_array($itemtype, $CFG_GLPI["contract_types"])
            || ($itemtype == \AllAssets::getType())
        ) {
            $fn_append_options(\Contract::getSearchOptionsToAdd());
        }

        if (
            \Document::canApplyOn($itemtype)
            || ($itemtype == \AllAssets::getType())
        ) {
            $fn_append_options(\Document::getSearchOptionsToAdd());
        }

        if (
            \Infocom::canApplyOn($itemtype)
            || ($itemtype == \AllAssets::getType())
        ) {
            $fn_append_options(\Infocom::getSearchOptionsToAdd($itemtype));
        }

        if (
            in_array($itemtype, $CFG_GLPI["domain_types"])
            || ($itemtype == \AllAssets::getType())
        ) {
            $fn_append_options(\Domain::getSearchOptionsToAdd($itemtype));
        }

        if (
            in_array($itemtype, $CFG_GLPI["appliance_types"])
            || ($itemtype == \AllAssets::getType())
        ) {
            $fn_append_options(\Appliance::getSearchOptionsToAdd($itemtype));
        }

        if (in_array($itemtype, $CFG_GLPI["link_types"])) {
            $search[$itemtype]['link'] = \Link::getTypeName(\Session::getPluralNumber());
            $fn_append_options(\Link::getSearchOptionsToAdd($itemtype));
            $search[$itemtype]['manuallink'] = \ManualLink::getTypeName(\Session::getPluralNumber());
            $fn_append_options(\ManualLink::getSearchOptionsToAdd($itemtype));
        }

        if (in_array($itemtype, $CFG_GLPI['reservation_types'], true)) {
            $search[$itemtype]['reservationitem'] = \Reservation::getTypeName(\Session::getPluralNumber());
            $fn_append_options(\ReservationItem::getSearchOptionsToAdd($itemtype));
        }

        if (in_array($itemtype, $CFG_GLPI['socket_types'], true)) {
            $search[$itemtype]['socket'] = Socket::getTypeName(\Session::getPluralNumber());
            $fn_append_options(Socket::getSearchOptionsToAdd($itemtype));
        }

        if ($withplugins) {
            // Search options added by plugins
            $plugsearch = \Plugin::getAddSearchOptions($itemtype);
            $plugsearch = $plugsearch + \Plugin::getAddSearchOptionsNew($itemtype);
            if (count($plugsearch)) {
                $search[$itemtype] += ['plugins' => ['name' => _n('Plugin', 'Plugins', \Session::getPluralNumber())]];
                $fn_append_options($plugsearch);
            }
        }

        // Complete linkfield if not define
        if (!is_a($itemtype, CommonDBTM::class, true)) { // Special union type
            $itemtable = $CFG_GLPI['union_search_type'][$itemtype];
        } else {
            $itemtable = $itemtype::getTable();
        }

        foreach ($search[$itemtype] as $key => $val) {
            if (!is_array($val) || count($val) == 1) {
                // skip sub-menu
                continue;
            }
            // Force massive action to false if linkfield is empty :
            if (isset($val['linkfield']) && empty($val['linkfield'])) {
                $search[$itemtype][$key]['massiveaction'] = false;
            }

            // Set default linkfield
            if (!isset($val['linkfield']) || empty($val['linkfield'])) {
                if (
                    (strcmp($itemtable, $val['table']) == 0)
                    && (!isset($val['joinparams']) || (count($val['joinparams']) == 0))
                ) {
                    $search[$itemtype][$key]['linkfield'] = $val['field'];
                } else {
                    $search[$itemtype][$key]['linkfield'] = getForeignKeyFieldForTable($val['table']);
                }
            }
            // Add default joinparams
            if (!isset($val['joinparams'])) {
                $search[$itemtype][$key]['joinparams'] = [];
            }
        }

        self::$search_options_cache[$cache_key] = $search[$itemtype];
        return $search[$itemtype];
    }

        /**
     * Compute the default search criteria to display for an itemtype
     *
     * @param string $itemtype
     *
     * @return array
     */
    public static function getDefaultSearch(string $itemtype): array {
        // Some item may define a getDefaultSearchRequest method
        if (method_exists($itemtype, 'getDefaultSearchRequest')) {
            $default_search_request = $itemtype::getDefaultSearchRequest();

            // Not all search request define search criteria
            if (isset($default_search_request['criteria'])) {
                return $default_search_request['criteria'];
            }
        }

        // Fallback to getDefaultCriteria
        return self::getDefaultCriteria($itemtype);
    }
    
        /**
     * construct the default criteria for an itemtype
     *
     * @param class-string<\CommonDBTM> $itemtype
     *
     * @return array Criteria
     */
    public static function getDefaultCriteria($itemtype = ''): array {
        /** @var array $CFG_GLPI */
        global $CFG_GLPI;

        $field = '';

        if ($CFG_GLPI['allow_search_view'] == 2) {
            $field = 'view';
        } else {
            $options = self::getCleanedOptions($itemtype);
            foreach ($options as $key => $val) {
                if (
                        is_array($val) && isset($val['table'])
                ) {
                    $field = $key;
                    break;
                }
            }
        }

        return [
            [
                'link' => 'AND',
                'field' => $field,
                'searchtype' => 'contains',
                'value' => ''
            ]
        ];
    }
    
    
    /**
     * Clean search options depending on the user active profile
     *
     * @param class-string<\CommonDBTM>  $itemtype     Item type to manage
     * @param integer $action       Action which is used to manipulate searchoption
     *                               (default READ)
     * @param boolean $withplugins  Get plugins options (true by default)
     *
     * @return array Clean $SEARCH_OPTION array
     * */
    public static function getCleanedOptions($itemtype, $action = READ, $withplugins = true): array {
        /** @var array $CFG_GLPI */
        global $CFG_GLPI;

        $options = self::getOptionsForItemtype($itemtype, $withplugins);
        $todel = [];

        if (
                !\Session::haveRight('infocom', $action) && \Infocom::canApplyOn($itemtype)
        ) {
            $itemstodel = \Infocom::getSearchOptionsToAdd($itemtype);
            $todel = array_merge($todel, array_keys($itemstodel));
        }

        if (
                !\Session::haveRight('contract', $action) && in_array($itemtype, $CFG_GLPI["contract_types"])
        ) {
            $itemstodel = \Contract::getSearchOptionsToAdd();
            $todel = array_merge($todel, array_keys($itemstodel));
        }

        if (
                !\Session::haveRight('document', $action) && \Document::canApplyOn($itemtype)
        ) {
            $itemstodel = \Document::getSearchOptionsToAdd();
            $todel = array_merge($todel, array_keys($itemstodel));
        }

        // do not show priority if you don't have right in profile
        if (
                ($itemtype == 'Ticket') && ($action == UPDATE) && !\Session::haveRight('ticket', \Ticket::CHANGEPRIORITY)
        ) {
            $todel[] = 3;
        }

        if ($itemtype == 'Computer') {
            if (!\Session::haveRight('networking', $action)) {
                $itemstodel = \NetworkPort::getSearchOptionsToAdd($itemtype);
                $todel = array_merge($todel, array_keys($itemstodel));
            }
        }
        if (!\Session::haveRight(strtolower($itemtype), READNOTE)) {
            $todel[] = 90;
        }

        if (count($todel)) {
            foreach ($todel as $ID) {
                if (isset($options[$ID])) {
                    unset($options[$ID]);
                }
            }
        }

        return $options;
    }
    
    public static function getSearchCriteria(string $itemtype): ?array
    {
        /** @var \DBmysql $DB */
        global $DB;

        $default_table = self::getTable();
        $filter_table = \Glpi\Search\CriteriaFilter::getTable();

        $criteria = [
            'SELECT' => [
                "$default_table.*",
                "$filter_table.search_criteria",
            ],
            'FROM' => $default_table,
            'JOIN' => [
                $filter_table => [
                    'FKEY'  => [
                        $default_table => 'id',
                        $filter_table => 'items_id',
                    ],
                    'AND'   => [
                        "$filter_table.itemtype" => __CLASS__
                    ]
                ]
            ],
            'WHERE' => [
                "$default_table.itemtype" => $itemtype,
                "NOT" => [
                    "$filter_table.search_criteria" => null
                ]
            ]
        ];

        $iterator = $DB->request($criteria);

        if ($iterator->count() == 1) {
            $item = $iterator->current();

            return [
                'id' => $item['id'],
                'name' => $item['name'],
                'comment' => $item['comment'],
                'search_criteria' => [
                    'link' => 'AND',
                    'criteria' => json_decode($item['search_criteria'], true),
                ]
            ];
        }
        return null;
    }

    /**
     * Return the table used to store this object
     *
     * @param string $classname Force class (to avoid late_binding on inheritance)
     *
     * @return string
     **/
    public static function getTable($classname = null)
    {
        if ($classname === null) {
            $classname = get_called_class();
        }

        if (!class_exists($classname)) {
            return '';
        }

        if (!isset(self::$tables_of[$classname]) || empty(self::$tables_of[$classname])) {
            self::$tables_of[$classname] = self::getExpectedTableNameForClass($classname);
        }

        return self::$tables_of[$classname];
    }

        /**
     * Returns expected table name for a given class.
     * /!\ This method will only compute the expected table name and will not take into account any
     * table name override made by the class itself.
     *
     * @param string $classname
     * @return string
     */
    public static function getExpectedTableNameForClass(string $classname): string
    {
        $dbu = new \DbUtils();

        // Force singular for itemtype : States case
        $singular = $dbu->getSingular($classname);

        $prefix = "glpi_";

        if ($plug = isPluginItemType($singular)) {
            /* PluginFooBar   => glpi_plugin_foos_bars */
            /* GlpiPlugin\Foo\Bar => glpi_plugin_foos_bars */
            $prefix .= "plugin_" . strtolower($plug['plugin']) . "_";
            $table   = strtolower($plug['class']);
        } else {
            $table = strtolower($singular);
            if (substr($singular, 0, \strlen(NS_GLPI)) === NS_GLPI) {
                $table = substr($table, \strlen(NS_GLPI));
            }
        }

        // handle PHPUnit mocks
        if (str_starts_with($table, 'mockobject_')) {
            $table = preg_replace('/^mockobject_(.+)_.+$/', '$1', $table);
        }
        // handle aoutm mocks
        $table = str_replace(['mock\\', '\\'], ['', '_'], $table);

        if (strstr($table, '_')) {
            $split = explode('_', $table);

            foreach ($split as $key => $part) {
                $split[$key] = $dbu->getPlural($part);
            }
            $table = implode('_', $split);
        } else {
            $table = $dbu->getPlural($table);
        }

        return $prefix . $table;
    }

    
}

