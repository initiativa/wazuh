<?php

include('../../../inc/includes.php');
use GlpiPlugin\Wazuh\ServerConnection;

$dropdown = new ServerConnection();
include(GLPI_ROOT . '/front/dropdown.common.php');
