<?php

namespace GlpiPlugin\Wazuh;

use CommonDBTM;
use Computer;
use Item_Ticket;
use Session;
use Ticket;

/**
 * @method static getById(mixed $cve_id)
 * @method static getDeviceId($cve)
 * @method static newDeviceInstance(): Computer|NetworkEquipment
 * @method static getDeviceHref($device_id)
 * @method static getDefaultTicketTitle()
 */
trait TicketableTrait {

    private static function denyTicketCreation(string $reason): false {
        PluginLogger::warning(static::class . "::createTicket denied: $reason");
        Session::addMessageAfterRedirect(__("You don't have permission to perform this action."), true, ERROR);
        return false;
    }

    public static function createTicket(array $item_ids, $input, $entity_id): int | false {
        global $DB;
        $full_items = [];

        // Authorization is enforced here so that every caller (massive actions, ExtApi) inherits it:
        // the caller must be allowed to create a ticket in the target entity...
        $entity_id = (int) $entity_id;
        if (!Session::haveAccessToEntity($entity_id)) {
            return self::denyTicketCreation("no access to entity $entity_id");
        }
        if (!Session::haveRight(Ticket::$rightname, CREATE)) {
            return self::denyTicketCreation('no ticket CREATE right');
        }

        // ...and every linked item must be readable by the caller and belong to the same device.
        $item_ids = array_values(array_unique(array_map('intval', $item_ids)));
        if (empty($item_ids)) {
            return false;
        }
        $device_id = 0;
        foreach ($item_ids as $id) {
            $item = new static();
            if (!$item->can($id, READ)) {
                return self::denyTicketCreation("item $id not readable");
            }
            $item_device_id = (int) static::getDeviceId($item);
            if ($device_id === 0) {
                $device_id = $item_device_id;
            } elseif ($item_device_id !== $device_id) {
                return self::denyTicketCreation("item $id belongs to another device");
            }
            $full_items[] = $item;
        }

        if ($device_id === 0) {
            return false;
        }

        $device = static::newDeviceInstance();
        if (!$device->can($device_id, READ)) {
            return self::denyTicketCreation("device $device_id not readable");
        }

        $itil_category_id = $input['ticket_category'] ?? 0;
        $default_title = static::getDefaultTicketTitle();
        $title = $input['ticket_title'] ?? 'Wazuh Vulnerable';
        $comment = $input['ticket_comment'] ?? '';
        $urgency = $input['ticket_urgency'] ?? 3;

        $content = __('Wazuh auto ticket', PluginConfig::APP_CODE) . "<br>";
        PluginLogger::debug(__FUNCTION__ . " Device: $device_id");

        if ($device->getFromDB($device_id)) {
            $device_name = $device->fields['name'];
            $content = $comment . "<br>";
            $device_href = static::getDeviceHref($device_id);
            $content .= sprintf(
                __('Linked Device: %s', PluginConfig::APP_CODE) . "<br>",
                "<a href='$device_href'>" . $device_name . "</a>"
            );
            $content .= "Links: ";
            foreach ($full_items as $item) {
                $item_href = static::getWazuhTabHref($item->getID());
                $name = static::generateLinkName($item);
                $content .= sprintf(
                    " <a href='$item_href'>$name</a> "
                );
            }
        }

        $ticket = new Ticket();
        $ticket_input = [
            'name' => $title,
            'content' => $content,
            'itilcategories_id' => $itil_category_id,
            'status' => Ticket::INCOMING,
            'priority' => 3,
            'urgency' => $urgency,
            'impact' => 3,
            'entities_id' => $entity_id,
            '_add_items' => [],
        ];

        $ticket_id = $ticket->add($ticket_input);

        if ($ticket_id) {
            //linking cve's to ticket
            foreach ($full_items as $item) {
                $item->fields[Ticket::getForeignKeyField()] = $ticket_id;
                $item->update($item->fields);
            }

            $ticket_item = new Item_Ticket();
            $ticket_item_input = [
                'tickets_id' => $ticket_id,
                'itemtype' => $device::class,
                'items_id' => $device_id
            ];
            $ticket_item->add($ticket_item_input);
            return $ticket_id;
        }

        return false;

    }

}