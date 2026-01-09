<?php

namespace GlpiPlugin\Wazuh\Controller;

use Glpi\Controller\AbstractController;
use GlpiPlugin\Wazuh\PluginConfig;
use GlpiPlugin\Wazuh\WazuhAgent;
use Session;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

class WazuhAgentSyncController extends AbstractController {

    #[Route(
        path: 'sync_agents',
        name: 'wazuh_sync_agents',
        methods: ['GET'],
    )]
    public function wazuh_sync_agents(Request $request): Response {

        Session::checkRight("plugin_wazuh_agent", UPDATE);

        if (WazuhAgent::syncAgents()) {
            Session::addMessageAfterRedirect(
                __('Active agents synchronized successfully', PluginConfig::APP_CODE),
                true,
                INFO
            );
        } else {
            Session::addMessageAfterRedirect(
                __('Not synchronizing all agents', PluginConfig::APP_CODE),
                true,
                ERROR
            );
            return new Response('false', Response::HTTP_EXPECTATION_FAILED);
        }

        return new Response('true');
    }

}