# GLPI Wazuh Plugin

This plugin integrates Wazuh server alerts and events into GLPI, allowing automation of ticket creation for selected alerts.

## Features

- Connect to one or more Wazuh servers and indexers
- Synchronize Wazuh agents with GLPI devices
- Fetch alerts and vulnerabilities from Wazuh
- Display events directly on GLPI device views
- Create tickets automatically from selected alerts

## Configuration

1. **Install the plugin** in GLPI.

2. Go to **Setup → Plugins → Wazuh**, and define Wazuh connections:
    - Fill in:
        - Wazuh server address and port
        - Indexer address and port
        - Username and password
    - Mark the connection as **Active**
    - Save the configuration

3. **Synchronize Wazuh agents**:
    - Go to **Administration → Wazuh Agent's**
    - Click the **Sync Agents** button
    - A list of agents from the defined Wazuh servers should appear

4. **Link agents to devices**:
    - Use the **Devices** dropdown to assign each agent to a corresponding GLPI asset
    - It is possible to link all devicess automatically with "Link Agents" button at the top. To this aim agent.name <-> device.name matching system is in use.

5. **Fetching alerts and vulnerabilities**:
    - By default, the plugin fetches data **every hour**
    - You can adjust this in **Setup → Automatic Actions**:
        - `FetchAlerts`
        - `FetchVulnerabilities`

6. **Viewing alerts and creating tickets**:
    - Navigate to **Assets → Computers** or **Network Devices**
    - Open the **"Wazuh ..."** tabs to view related events
    - Select alerts from the list, then choose **Actions → Create ticket** to generate a new ticket from selected items

---

For support or more documentation, please refer to the plugin page or contact the maintainers.
