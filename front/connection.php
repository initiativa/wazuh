<?php

include('../../../inc/includes.php');
use GlpiPlugin\Wazuh\Connection;

$dropdown = new Connection();
include(GLPI_ROOT . '/front/dropdown.common.php');
