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

use Session;
use Html;
use GlpiPlugin\Wazuh\PluginConfig;
use GlpiPlugin\Wazuh\Logger;
use Glpi\Application\View\TemplateRenderer;
use GLPIKey;

/**
 * Description of ServerConnection
 *
 * @author w-tomasz
 */

/**
 * @Table(name="glpi_plugin_wazuh_serverconnections")
 */
class ServerConnection extends \CommonDropdown
{
    use TableAnnotationTrait;

    public static $rightname = "plugin_wazuh_serverconnection";

//    public $usenotifications = true;
//
//    public $usenotepad = true;

    public static function createTable()
    {
        global $DB;
        $query = self::generateCreateTableQuery();
        Logger::addWarning("*********  " . $query);
        $DB->query($query) or die($DB->error());
    }

    public static function dropTable()
    {
        global $DB;
        $query = self::generateDropTableQuery();
        Logger::addWarning("*********  " . $query);
        $DB->query($query) or die($DB->error());
    }

    /**
     * @Id
     * @Column
     * @var int
     */
    public int $id;

    /**
     * @Column(length=100, nullable=false)
     * @FormId(name="server_name")
     * @var string
     */
    public string $name;

    /**
     * @Column(length=100, nullable=false)
     * @FormId(name="server_url")
     * @var string
     */
    public string $url;

    /**
     * @Column(length=100, nullable=false)
     * @FormId(name="server_username")
     * @var string
     */
    public string $user_name;

    /**
     * @Column(length=100, nullable=false)
     * @FormId(name="server_password", secure=true)
     * @var string
     */
    public string $password;

    /**
     * @Column(nullable=false)
     * @FormId(name="server_port")
     * @var int
     */
    public int $port;

    /**
     * @Column(length=1000)
     * @FormId(name="ticket_description")
     * @var string|null
     */
    public ?string $description = null;

    /**
     * @Column(defaultValue="1")
     * @FormId(name="server_enabled")
     * @var bool
     */
    public bool $enabled;

    /**
     * @Column(defaultValue="1")
     * @FormId(name="active")
     * @var bool
     */
    public bool $is_active;

    /**
     * @Column(nullable=false, defaultValue="CURRENT_TIMESTAMP")
     * @FormId(name="modyfied")
     * @var datetime
     */
    public \DateTime $date_mod;

    /**
     * @Column(nullable=false)
     * @FormId(name="created")
     * @var datetime
     */
    public \DateTime $date_creation;

    #[\Override]
    public static function getMenuContent()
    {
        $menu = [];
        $menu["title"] = self::getMenuName();
        $menu["page"] = "/plugins/wazuh/front/serverconnection.php";
        $menu["icon"] = self::getIcon();
        
        $menu['options']['config']['title'] = 'Konfiguracja2';
        $menu['options']['config']['page'] = "/plugins/wazuh/front/serverconnection.php";
        $menu['options']['config']['icon'] = self::getIcon();

        return $menu;
    }

    public static function getIcon()
    {
        return "fas fa-sign-in-alt";
    }

    //    #[\Override]
    //    public function defineTabs($options = []) {
    //        $tabs = parent::defineTabs($options);
    //
    //        $this->addStandardTab(MailCollectorFeature::class, $tabs, $options);
    //        $this->addStandardTab(PluginOauthimapAuthorization::class, $tabs, $options);
    //
    //        return $tabs;
    //    }

    #[\Override]
    public function prepareInputForAdd($input)
    {
        if (!($input = $this->prepareInput($input))) {
            return false;
        }
        return parent::prepareInputForAdd($input);
    }

    public function getFormFields(): array
    {
        $fields = [];

        $additional_fields = ["url", "user_name", "password", "port"];

        return array_merge($fields, $additional_fields);
    }

    #[\Override]
    public function prepareInputForUpdate($input)
    {
        // Unset encrypted fields input if corresponding to current value
        // (encryption produces a different value each time,
        // so GLPI will consider them as updated on each form submit)
        foreach (["password"] as $field_name) {
            if (
                array_key_exists($field_name, $input) &&
                !empty($input[$field_name]) &&
                $input[$field_name] !== "NULL" &&
                $input[$field_name] ===
                    (new GLPIKey())->decrypt($this->fields[$field_name])
            ) {
                unset($input[$field_name]);
            }
        }

        if (!($input = $this->prepareInput($input))) {
            return false;
        }

        return parent::prepareInputForUpdate($input);
    }

    private function prepareInput($input)
    {
        if (array_key_exists("name", $input) && empty(trim($input["name"]))) {
            Session::addMessageAfterRedirect(
                __("Name cannot be empty", "wazuh"),
                false,
                ERROR
            );

            return false;
        }

        foreach (["password"] as $field_name) {
            if (
                array_key_exists($field_name, $input) &&
                !empty($input[$field_name]) &&
                $input[$field_name] !== "NULL"
            ) {
                $input[$field_name] = (new GLPIKey())->encrypt($input[$field_name]);
            }
        }

        return $input;
    }

    #[\Override]
    public function getSpecificMassiveActions($checkitem = null)
    {
        $actions = parent::getSpecificMassiveActions($checkitem);

        $actions["ServerConnection:your_action"] = __(
            "Your action name",
            "wazuh"
        );
        $actions["ServerConnection:another_action"] = __(
            "Another action",
            "wazuh"
        );

        return $actions;
    }

    static function showMassiveActionsSubForm(\MassiveAction $ma)
    {
        switch ($ma->getAction()) {
            case "ServerConnection:your_action":
                // Tutaj wyświetl dodatkowe pola formularza dla tej akcji, jeśli są potrzebne
                echo "<br><br>" . __("Additional options", "wazuh") . "&nbsp;";
                echo Html::input("some_option", [
                    "value" => "",
                    "size" => 50,
                ]);
                echo "&nbsp;" .
                    Html::submit(_x("button", "Post"), [
                        "name" => "massiveaction",
                    ]);
                return true;

            case "ServerConnection:another_action":
                // Podobnie dla innej akcji
                echo Html::submit(_x("button", "Execute"), [
                    "name" => "massiveaction",
                ]);
                return true;
        }
        return parent::showMassiveActionsSubForm($ma);
    }

    static function processMassiveActionsForOneItemtype(
        \MassiveAction $ma,
        \CommonDBTM $item,
        array $ids
    ) {
        global $DB;

        switch ($ma->getAction()) {
            case "DoIt":
                $input = $ma->getInput();

                foreach ($ids as $id) {
                    if ($item->getFromDB($id) && $item->doIt($input)) {
                        $ma->itemDone(
                            $item->getType(),
                            $id,
                            \MassiveAction::ACTION_OK
                        );
                    } else {
                        $ma->itemDone(
                            $item->getType(),
                            $id,
                            \MassiveAction::ACTION_KO
                        );
                        $ma->addMessage(__("Something went wrong"));
                    }
                }
                return;
        }
        parent::processMassiveActionsForOneItemtype($ma, $item, $ids);
    }

    #[\Override]
    public function showForm($ID, array $options = [])
    {
        $this->initForm($ID, $options);

        $this->showFormHeader($options);
        TemplateRenderer::getInstance()->display(
            "@wazuh/server_connection.form.twig",
            [
                "item" => $this,
                "params" => $options,
                "field_order" => $this->getFormFields(),
            ]
        );

        return true;
    }

    #[\Override]
    public static function canView()
    {
        return Session::haveRight(self::$rightname, READ);
        //        return true;
    }

    #[\Override]
    public static function canCreate()
    {
                return true;
//        return Session::haveRight(self::$rightname, CREATE);
    }

    #[\Override]
    public static function canUpdate()
    {
        return Session::haveRight(self::$rightname, UPDATE);
        //        return true;
    }

    #[\Override]
    public static function canDelete()
    {
        return Session::haveRight(self::$rightname, DELETE);
        //        return true;
    }

    #[\Override]
    public static function getTypeName($nb = 0)
    {
        return _n("Server Connection", "Server Connections", $nb, "wazuh");
    }

    #[\Override]
    public function rawSearchOptions()
    {
        $tab = parent::rawSearchOptions();

        $tab[] = [
            "id" => 3,
            "name" => __("URL", "wazuh"),
            "table" => self::getTable(),
            "field" => "url",
            "searchtype" => "contains",
            "datatype" => "text",
            "massiveaction" => false,
        ];

        $tab[] = [
            "id" => 4,
            "name" => __("User Name", "wazuh"),
            "table" => self::getTable(),
            "field" => "user_name",
            "searchtype" => "contains",
            "datatype" => "text",
            "massiveaction" => false,
        ];

        $tab[] = [
            "id" => 5,
            "name" => __("Port", "wazuh"),
            "table" => self::getTable(),
            "field" => "port",
            "searchtype" => "equals",
            "datatype" => "number",
            "massiveaction" => false,
        ];

        return $tab;
    }

    #[\Override]
    public static function getFormURL($full = true)
    {
        //        $url = \Toolbox::getItemTypeFormURL(static::class, $full);
        //        \GlpiPlugin\Wazuh\Logger::addDebug('Form url: ' . $url);
        //        return $url;

        $link = "serverconnection.form.php";

        //        if ($full) {
        //            $link = GLPI_ROOT . "/" . $link;
        //        }

        return $link;
    }

    function plugin_wazuh_getDropdown()
    {
        return [ServerConnection::class => ServerConnection::getTypeName(2)];
    }

    //    #[\Override]
    //    public function showForm($ID, array $params = []) {
    //        $contentFile = '@' . PluginConfig::APP_CODE . "/server_connection.form.twig";
    //        $replacements = [
    //            'name' => self::class
    //        ];
    //        \GlpiPlugin\Wazuh\Logger::addDebug('Show form: ' . $contentFile);
    //        TemplateRenderer::getInstance()->display($contentFile, $replacements);
    //
    //        return true;
    //    }
}


