<?php

namespace GlpiPlugin\Wazuh;

use CommonDBTM;
use Computer;
use Item_Ticket;
use Ticket;

/**
 * @method static getById(mixed $cve_id)
 * @method static getDeviceId($cve)
 * @method static newDeviceInstance(): Computer|NetworkEquipment
 * @method static getDeviceHref($device_id)
 * @method static getDefaultTicketTitle()
 */
trait TicketableTrait {

    public static function createTicket(array $item_ids, $input, $entity_id): int | false {
        global $DB;
        $full_items = [];

        $itil_category_id = $input['ticket_category'] ?? 0;
        $default_title = static::getDefaultTicketTitle();
        $title = $input['ticket_title'] ?? 'Wazuh Vulnerable';
        $comment = $input['ticket_comment'] ?? '';
        $urgency = $input['ticket_urgency'] ?? 3;

        $item_id = reset($item_ids);

        $item = static::getById($item_id);
        $device_id = static::getDeviceId($item);

        if ($device_id === 0) {
            return false;
        }

        $content = __('Wazuh auto ticket', PluginConfig::APP_CODE) . "<br>";
        Logger::addDebug(__FUNCTION__ . " Device: $device_id");

        $device = static::newDeviceInstance();
        if ($device->getFromDB($device_id)) {
            $device_name = $device->fields['name'];
            $content = $comment . "<br>";
            $device_href = static::getDeviceHref($device_id);
            $content .= sprintf(
                __('Linked Device: %s', PluginConfig::APP_CODE) . "<br>",
                "<a href='$device_href'>" . $device_name . "</a>"
            );
            $content .= "Links: ";
            foreach ($item_ids as $item_id) {
                $item = static::getById($item_id);
                array_push($full_items, $item);
                $item_href = static::getDeviceHref($item_id);
                $name = static::generateLinkName($item);
                $content .= sprintf(
                    " <a href='$item_href'>$name</a> "
                );
            }
        }

        $ticket = new Ticket();
        $ticket_input = [
            'name' => $title,
            'content' => \Toolbox::addslashes_deep($content),
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