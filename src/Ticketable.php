<?php

namespace GlpiPlugin\Wazuh;

use CommonDBTM;
use Computer;
use NetworkEquipment;

interface Ticketable
{
    static function createTicket(array $item_ids, $input, $entity_id): int | false;
    static function getDeviceId(CommonDBTM&Ticketable $wazuhTab): int;
    static function newDeviceInstance(): Computer|NetworkEquipment;

    /**
     * @return string href following to WazuhTab with id
     */
    static function getWazuhTabHref(int $id): string;
    static function getDeviceHref(int $id): string;
    static function getDefaultTicketTitle(): string;
    static function generateLinkName(ComputerTab|NetworkEqTab|ComputerAlertsTab|NetworkEqAlertsTab $item): string;
}