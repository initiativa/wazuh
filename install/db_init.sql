CREATE TABLE IF NOT EXISTS `glpi_plugin_wazuh_table` (
    `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
    `name` VARCHAR(255) NOT NULL,
    `environment` VARCHAR(32) NOT NULL,
    `is_enabled` INT(1) UNSIGNED NOT NULL DEFAULT 1,
    --
    -- authentication (Bearer Token Authentication)
    --
    `tenant_id` VARCHAR(128) NOT NULL,
    `client_id` VARCHAR(128) NOT NULL,
    `client_secret` VARCHAR(128) NOT NULL,
    `creation_ts` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `update_ts` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    --
    -- indexes
    --
    PRIMARY KEY (`id`)
);
