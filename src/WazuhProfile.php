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

if (!defined('GLPI_ROOT')) {
   die("Sorry. You can't access this file directly");
}

/**
 * Description of Profile
 *
 * @author w-tomasz
 */
class WazuhProfile extends \Profile {
    
     #[\Override]
     static function getTypeName($nb = 0) {
      return __('Wazuh Profile', 'wazuh');
   }
   
   static function initProfile() {
      $profileRight = new \ProfileRight();
      
      foreach ($_SESSION['glpiactiveprofile'] as $key => $val) {
         if (strpos($key, 'plugin_wazuh_') !== false) {
            $profileRight->deleteByCriteria(['profiles_id' => $_SESSION['glpiactiveprofile']['id'], 
                                           'name' => $key]);
         }
      }
      
      self::addDefaultProfileInfos($_SESSION['glpiactiveprofile']['id'],
                [
                    WazuhAgent::$rightname => \ALLSTANDARDRIGHT,
                    Connection::$rightname => \ALLSTANDARDRIGHT,
                    PluginConfig::FINDING_RIGHTNAME => \READ | \DELETE | \PURGE,
                ]
        );
    }

   /**
    * Vulnerability / alert records were governed by core 'dropdown' before; on upgrade, every profile
    * that can read Wazuh agents gets READ on them, plus DELETE / PURGE when it holds those on agents
    * (only if it does not have the right yet, so choices made in the profile tab are kept).
    */
   static function migrateFindingRight(): void {
      global $DB;

      $iterator = $DB->request([
         'SELECT' => ['profiles_id', 'rights'],
         'FROM'   => \ProfileRight::getTable(),
         'WHERE'  => [
            'name' => WazuhAgent::$rightname,
            new \Glpi\DBAL\QueryExpression('(' . $DB->quoteName('rights') . ' & ' . (int) \READ . ') > 0'),
         ],
      ]);
      foreach ($iterator as $row) {
         $rights = \READ | ((int) $row['rights'] & (\DELETE | \PURGE));
         self::addDefaultProfileInfos($row['profiles_id'], [PluginConfig::FINDING_RIGHTNAME => $rights]);
      }
   }
   
   /**
    * Plugin rights shown in the "Wazuh" tab of a profile.
    */
   public static function getAllRights(): array {
      return [
         ['itemtype' => Connection::class, 'label' => Connection::getTypeName(\Session::getPluralNumber()), 'field' => Connection::$rightname],
         ['itemtype' => WazuhAgent::class, 'label' => WazuhAgent::getTypeName(\Session::getPluralNumber()), 'field' => WazuhAgent::$rightname],
         // same labels as core rights, limited to what applies to fetched records
         ['rights' => array_intersect_key((new ComputerTab())->getRights(), [\READ => 1, \DELETE => 1, \PURGE => 1]), 'label' => __('Vulnerabilities and alerts', PluginConfig::APP_CODE), 'field' => PluginConfig::FINDING_RIGHTNAME],
      ];
   }

   #[\Override]
   public function getTabNameForItem(\CommonGLPI $item, $withtemplate = 0) {
      // helpdesk profiles cannot hold these rights (core keeps only helpdesk rights there)
      if ($item instanceof \Profile && ($item->fields['interface'] ?? '') === 'central') {
         return self::createTabEntry(PluginConfig::APP_NAME);
      }
      return '';
   }

   #[\Override]
   public static function displayTabContentForItem(\CommonGLPI $item, $tabnum = 1, $withtemplate = 0) {
      if ($item instanceof \Profile) {
         self::showRightsForm($item->getID());
      }
      return true;
   }

   /**
    * Rights matrix; saved by the core profile form (front/profile.form.php, "update").
    */
   public static function showRightsForm(int $profiles_id): void {
      $profile = new \Profile();
      if (!$profile->getFromDB($profiles_id)) {
         return;
      }
      $canedit = \Session::haveRightsOr(\Profile::$rightname, [\CREATE, \UPDATE, \PURGE]) && $profile->canUpdateItem();

      echo "<div class='firstbloc'>";
      if ($canedit) {
         echo "<form method='post' action='" . htmlescape(\Profile::getFormURL()) . "'>";
      }
      $profile->displayRightsChoiceMatrix(self::getAllRights(), [
         'canedit'       => $canedit,
         'default_class' => 'tab_bg_2',
         'title'         => PluginConfig::APP_NAME,
      ]);
      if ($canedit) {
         echo "<div class='text-center mt-2'>";
         echo \Html::hidden('id', ['value' => $profiles_id]);
         echo \Html::submit(_sx('button', 'Save'), ['name' => 'update', 'class' => 'btn btn-primary']);
         echo "</div>";
         \Html::closeForm();
      }
      echo "</div>";
   }

   /**
    * Adding default rights to profile
    */
   static function addDefaultProfileInfos($profiles_id, $rights) {
      $profileRight = new \ProfileRight();
      
      foreach ($rights as $right => $value) {
         if (!countElementsInTable('glpi_profilerights', ['profiles_id' => $profiles_id, 'name' => $right])) {
            $profileRight->add(['profiles_id' => $profiles_id, 'name' => $right, 'rights' => $value]);
         }
      }
      // GLPI caches the list of known rights; refresh it so the profile matrix sees new plugin rights
      \ProfileRight::cleanAllPossibleRights();
   }
   
   /**
    */
   static function install(\Migration $migration) {
      self::initProfile();
   }
    
}


