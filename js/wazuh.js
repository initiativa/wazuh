/**
 * JavaScript functions for Wazuh plugin
 */

document.addEventListener('DOMContentLoaded', function() {
    // Initialize Wazuh plugin JavaScript
    initWazuhPlugin();
});

function wazuhExpandAllTreeNodes(buttonElement, tableId) {
    const table = document.getElementById(tableId);
    table.querySelectorAll('.tree-node').forEach(function (node) {
        node.style.display = '';
    });

    table.querySelectorAll('.tree-toggle').forEach(function (toggler) {
        toggler.classList.remove('fa-caret-right');
        toggler.classList.add('fa-caret-down');
    });
}

function wazuhCollapseAllTreeNodes(buttonElement, tableId) {
    const table = document.getElementById(tableId);
    table.querySelectorAll('.tree-node[data-is-child="true"]').forEach(function (node) {
        node.style.display = 'none';
    });

    table.querySelectorAll('.tree-toggle').forEach(function (toggler) {
        toggler.classList.remove('fa-caret-down');
        toggler.classList.add('fa-caret-right');
    });
}

function wazuhGetPageMax(element) {
    let page_max = Math.ceil(parseInt(element.getAttribute('data-child-count')) / 10);
    return page_max;
}

function wazuhTreePrevPage(iconElement, searchform_id, rootElement) {
    let page_no = parseInt(rootElement.getAttribute('data-page'));
    if (page_no > 1) {
        page_no --;
    }
    rootElement.setAttribute('data-page', page_no);
    wazuhFetchPageableTreeData(rootElement, searchform_id);
    // console.log('Prev page clicked.');
}

function wazuhTreeNextPage(iconElement, searchform_id, rootElement) {
    let page_no = parseInt(rootElement.getAttribute('data-page'));
    const page_max = wazuhGetPageMax(rootElement);
    if (page_no < page_max) {
        page_no ++;
    }
    rootElement.setAttribute('data-page', page_no);
    wazuhFetchPageableTreeData(rootElement, searchform_id);
    // console.log('Next page clicked.');
}

function wazuhSetPageLabel(row_id, page_no, page_max) {
    const page_id = `page_label_${row_id}`;
    $(`#${page_id}`).text(`Page: ${page_no} / ${page_max}`);
}

/**
 * Last child row to manage children pages
 * @param data
 * @param search_id
 * @param element expand/collapse icon of partent element
 * @returns {*|jQuery|HTMLElement} tr row element
 */
function wazuhCreatePageableRow(data, search_id, element) {
    const has_children = false;
    const has_parent = true;
    const row_id = element.getAttribute('data-node-id');
    const page_no = parseInt(element.getAttribute('data-page'));
    const page_max = wazuhGetPageMax(element);
    const col_size = data.data.cols.length;
    let level = parseInt(element.closest('tr').dataset.level);
    level++;

    const tr = $('<tr>', {
        class: `tree-node is-child`,
        name: `pageable_row[${row_id}]`,
        'data-node-id': row_id,
        'data-level': level,
        'data-is-child': has_parent || undefined,
        'data-has-children': has_children || undefined,
        style: ""
    });

    const massTd = $('<td>');
    const td = $(`<td colspan="${col_size}">`);
    const div = $('<div>', {class: 'd-flex justify-content-end align-items-baseline mr-4'});
    const prevButton = $('<button>', {
        class: 'btn btn-sm btn-icon btn-ghost-secondary',
        type: 'button',
    }).click(function () {wazuhTreePrevPage(this, search_id, element);});

    const prevIcon = $('<i>', {
        class: 'fas fa-caret-left tree-toggle me-2 mr-2'
    });
    prevButton.append(prevIcon);

    const pageLabel = $('<span>', {
        class: 'mx-3',
        id: `page_label_${row_id}`,
    }).text(`Page: ${page_no} / ${page_max}`);

    const nextButton = $('<button>', {
        class: 'btn btn-sm btn-icon btn-ghost-secondary',
        type: 'button',
    }).click(function () {wazuhTreeNextPage(this, search_id, element);});

    const nextIcon = $('<i>', {
        class: 'fas fa-caret-right tree-toggle me-2'
    });
    nextButton.append(nextIcon);

    div.append(prevButton, pageLabel, nextButton);
    td.append(div);
    tr.append(massTd, td);
    return tr;
}

function calculateTreeLevel(row_id, current_level = 0) {
    const parent_map = window['tree_parent_map'];
    const parent_id = parent_map[row_id];
    if (parent_id !== undefined) {
        current_level++;
        return calculateTreeLevel(parent_id, current_level);
    }
    return current_level;
}
function wazuhCreateTableRowsFromData(data, searchform_id, element) {
    const parent_id = element.getAttribute('data-node-id') ?? 0;
    const selected = window[searchform_id + '_selected'] ?? [];
    const device_id = data['device_id'];
    const data_itemtype = data['itemtype']; // Assuming this is already the single backslash version
    const itemtype = data['itemtype'];

    const showmassiveactions = true;
    const rows = data['data']['rows'];
    const cols = data['data']['cols'];
    const has_child_ids = data['has_child_ids'] || [];
    // const has_parent_ids = data['has_parent_ids'] || {};
    const child_map = data['child_map'] || {};

    const fragment = $(document.createDocumentFragment());

    for (const rowkey in rows) {
        if (rows.hasOwnProperty(rowkey)) {
            const row = rows[rowkey];
            const row_id = parseInt(row['id']);
            const has_children = has_child_ids.includes(row_id);
            const has_parent = parent_id > 0;

            let level = calculateTreeLevel(row_id, 0);

            let display_style = "";
            let parent_class = "";
            if (has_parent) {
                display_style = "";
                parent_class = `is-child level-${level}`;
            }

            const tr = $('<tr>', {
                class: `tree-node ${parent_class}`,
                'data-node-id': row_id,
                'data-level': level,
                'data-is-child': has_parent || undefined,
                'data-has-children': has_children || undefined,
                style: display_style
            });

            if (showmassiveactions) {
                const td_massive_action = $('<td>');
                const div_massive_action = $('<div>');

                let show_checkbox = true;
                if (itemtype === 'Entity' && !has_access_to_entity(row_id)) {
                    // Do nothing
                } else if (itemtype === 'User' && !can_view_all_entities() && !has_access_to_user_entities(row_id)) {
                    // Do nothing
                } else {
                    const row_itemtype = row['TYPE'] || itemtype;
                    // Assuming 'isMassiveActionAllowed' is a globally available JS function
                    // if (window[row_itemtype + '::isMassiveActionAllowed'] && window[row_itemtype + '::isMassiveActionAllowed']([row_id])) {
                        show_checkbox = true;
                        const checked = selected.has(parseInt(row_id));
                        const checkbox = $('<input>', {
                            class: 'form-check-input massive_action_checkbox',
                            type: 'checkbox',
                            'data-glpicore-ma-tags': 'common',
                            value: '1',
                            name: `item[${row['TYPE'] || itemtype}][${row_id}]`,
                            form: massive_action_form_id,
                            prop: 'checked',
                            checked: checked
                        }).change(function() { wazuhTreeCheckChanged(this, searchform_id, itemtype); });
                        div_massive_action.append(checkbox);
                    // }
                }
                td_massive_action.append(div_massive_action);
                tr.append(td_massive_action);
            }

            for (let i = 0; i < cols.length; i++) {
                const col = cols[i];
                const colkey = col['itemtype'] + '_' + col['id'];
                const td = $('<td>');

                if (i === 0) {
                    // First column
                    const div_first_col = $('<div>', { class: 'd-flex align-items-center' });
                    if (has_children) {
                        const toggleIcon = $('<i>', {
                            class: 'fas fa-caret-right tree-toggle me-2',
                            'data-node-id': row_id,
                            'data-device-id': device_id,
                            'data-child-count': child_map[row_id],
                            'data-page': '0',
                            'data-itemtype': data_itemtype,
                        }).click(function() { wazuhToggleTreeNode(this, searchform_id); });
                        div_first_col.append(toggleIcon);
                    } else {
                        const spacer = $('<span>', { class: 'tree-spacer me-2' });
                        div_first_col.append(spacer);
                    }
                    div_first_col.append(row[colkey]['displayname']);
                    td.append(div_first_col);
                } else {
                    if (col['meta'] !== undefined && col['meta']) {
                        td.append(row[colkey]['displayname']);
                    } else {
                        td.append(row[colkey]['displayname']);
                    }
                }
                tr.append(td);
            }

            fragment.append(tr);
        }
    }
    fragment.append(wazuhCreatePageableRow(data, searchform_id, element));

    return fragment;
}

function wazuhFetchPageableTreeData(element, formId) {
    let page_no = parseInt(element.getAttribute('data-page'));
    if (page_no === 0) {
        page_no ++;
        element.setAttribute('data-page', page_no);
    }
    let nodeId = element.getAttribute('data-node-id');
    $.ajax({
        url: CFG_GLPI.url_base + '/plugins/wazuh/ajax/fetch_tree_elements.php',
        type: 'GET',
        data: {
            itemtype: encodeURIComponent(element.getAttribute('data-itemtype')),
            parent_id: element.getAttribute('data-node-id'),
            device_id: element.getAttribute('data-device-id'),
            page_no: page_no,
        },
        dataType: 'json',
        beforeSend: function() {
            console.debug("Wazuh fetch pageable data: ", this.url);
        },
        success: function(response) {
            let elements = wazuhCreateTableRowsFromData(response, formId, element);
            let children = wazuhTreeFindChildren(nodeId);
            $(children).remove();
            element.parentNode.parentNode.parentNode.after(elements[0]);
        },
        error: function(xhr, status, error) {
            console.error('AJAX error:', error);
        }
    });
}

function wazuhToggleTreeNode(element, tableId) {
    let nodeId = element.getAttribute('data-node-id');
    let page = parseInt(element.getAttribute('data-page'));
    let itemtype2 = element.getAttribute('data-itemtype');
    let children = wazuhTreeFindChildren(nodeId);
    let isExpanded = element.classList.contains('fa-caret-down');

    // Toggle icon
    if (isExpanded) {
        element.classList.remove('fa-caret-down');
        element.classList.add('fa-caret-right');
        children = wazuhTreeFindChildren(nodeId);
        $(children).remove();
    } else {
        element.classList.remove('fa-caret-right');
        element.classList.add('fa-caret-down');
        wazuhFetchPageableTreeData(element, tableId);
    }
    wazuhTreeUpdateZebraStripes(tableId);
}

function wazuhTreeCheckChanged(element, searchform_id, itemtype) {
    let selected = window[searchform_id + '_selected'];
    const rowTr = element.closest('tr');
    if (!rowTr)
        return;

    const rowId = rowTr.dataset.nodeId;
    if (!rowId)
        return;

    const isChecked = element.checked;
    if (isChecked) {
        selected.add(parseInt(rowId));
    } else {
        selected.delete(parseInt(rowId));
    }

    if (rowTr.dataset.hasChildren === 'true') {
        const children = wazuhTreeFindAllChildren(rowId);
        children.forEach(function (child) {
            const childCheckbox = child.querySelector('.massive_action_checkbox');
            if (childCheckbox) {
                childCheckbox.checked = isChecked;
                const subRow = childCheckbox.closest('tr');
                const subRowId = subRow.dataset.nodeId;
                if (isChecked) {
                    selected.add(parseInt(subRowId));
                } else {
                    selected.delete(parseInt(subRowId));
                }
            }
        });
    }
    const data2 = JSON.stringify(Array.from(selected));
    document.getElementById(searchform_id).setAttribute('data-selected-items', data2);
    wazuhCreateHiddenTrSelection($(rowTr).closest('tbody'), searchform_id, itemtype)
}

function wazuhCreateHiddenTrSelection(tbodyElement, searchform_id, itemtype) {
    let selected = window[searchform_id + '_selected'];
    let outofscope = $(tbodyElement).find("outofscope");
    outofscope.remove();
    outofscope = $('<outofscope>', {
        class: 'd-none',
    });
    $(tbodyElement).append(outofscope);
    selected.forEach(function (id) {
        let itemName = `item[${itemtype}][${id}]`;
        let found = $(tbodyElement).find(`input[name="${itemName}"`);
        if (found.length === 0) {
            wazuhAddHiddenOutOfScopeSelection(outofscope, itemtype, id);
        }
    });
}

function wazuhAddHiddenOutOfScopeSelection(outofscopeElement, itemtype, row_id) {
    const checkbox = $('<input>', {
        class: 'form-check-input massive_action_checkbox',
        type: 'checkbox',
        'data-glpicore-ma-tags': 'common',
        value: '1',
        name: `item[${itemtype}][${row_id}]`,
        form: massive_action_form_id,
        prop: 'checked',
        checked: true
    });
    outofscopeElement.append(checkbox);
}

function wazuhTreeFindAllChildren(nodeId) {
    nodeId = String(nodeId);

    const directChildren = wazuhTreeFindChildren(nodeId);
    let allChildren = [...directChildren];

    directChildren.forEach(function (child) {
        if (child.dataset.hasChildren === 'true') {
            const childId = child.dataset.nodeId;
            const childrenOfChild = wazuhTreeFindAllChildren(childId);
            allChildren = allChildren.concat(childrenOfChild);
        }
    });

    return allChildren;
}

function wazuhTreeUpdateZebraStripes(tableId) {
    const table = document.getElementById(tableId);
    if (!table)
        return;

    const visibleRows = Array.from(table.querySelectorAll('tbody tr'))
            .filter(row => row.style.display !== 'none');

    table.querySelectorAll('tbody tr').forEach(row => {
        row.classList.remove('odd-row', 'even-row');
    });

    visibleRows.forEach((row, index) => {
        if (index % 2 === 0) {
            row.classList.add('even-row');
        } else {
            row.classList.add('odd-row');
        }
    });
}

function wazuhTreeFindChildren(nodeId) {
    nodeId = String(nodeId);
    const parentRow = document.querySelector('.tree-node[data-node-id="' + nodeId + '"]');
    if (!parentRow)
        return [];

    const children = [];
    let currentNode = parentRow.nextElementSibling;
    let level = parseInt(parentRow.dataset.level);

    while (currentNode &&
            currentNode.classList.contains('tree-node') &&
            currentNode.dataset.isChild === 'true' &&
            parseInt(currentNode.dataset.level) > level)
    {
        children.push(currentNode);
        currentNode = currentNode.nextElementSibling;
    }

    return children;
}

function wazuhTreeFindChildren2(nodeId) {
    // Convert nodeId to string for comparison
    nodeId = String(nodeId);

    // Get all tree nodes
    var nodes = document.querySelectorAll('.tree-node');
    var children = [];

    // First find direct parent row
    var parentRow = document.querySelector('.tree-node[data-node-id="' + nodeId + '"]');

    if (!parentRow)
        return [];

    // Get next siblings until we find another node at the same or higher level
    var currentNode = parentRow.nextElementSibling;

    while (currentNode &&
            currentNode.classList.contains('tree-node') &&
            currentNode.dataset.isChild === 'true') {
        children.push(currentNode);
        currentNode = currentNode.nextElementSibling;
    }

    return children;
}




/**
 * Initialize Wazuh plugin JavaScript functions
 */
function initWazuhPlugin() {
    // Add listeners to sync button if it exists
    const syncButton = document.querySelector('.wazuh-sync-button');
    if (syncButton) {
        syncButton.addEventListener('click', confirmSyncAgents);
    }
    
    // Add listeners to status indicators
    updateStatusIndicators();
    
    // Initialize tooltips
    initTooltips();
}

function toggleWazuhPassword(fieldId) {
    var field = document.getElementById(fieldId);
    var button = field.nextElementSibling.querySelector('i');

    if (field.type === 'password') {
        field.type = 'text';
        button.classList.remove('ti-eye');
        button.classList.add('ti-eye-off');
    } else {
        field.type = 'password';
        button.classList.remove('ti-eye-off');
        button.classList.add('ti-eye');
    }
}

/**
 * Update agent status indicators with visual cues
 */
function updateStatusIndicators() {
    const statusCells = document.querySelectorAll('.agent-status');
    
    statusCells.forEach(function(cell) {
        const status = cell.textContent.trim().toLowerCase();
        
        // Remove existing classes
        cell.classList.remove('status-active', 'status-disconnected', 'status-pending', 'status-never-connected');
        
        // Add class based on status
        switch (status) {
            case 'active':
                cell.classList.add('status-active');
                break;
            case 'disconnected':
                cell.classList.add('status-disconnected');
                break;
            case 'pending':
                cell.classList.add('status-pending');
                break;
            case 'never_connected':
            case 'never connected':
                cell.classList.add('status-never-connected');
                break;
        }
    });
}

/**
 * Display confirmation dialog before synchronizing agents
 * @param {Event} event - Click event
 */
function confirmSyncAgents(event) {
    if (!confirm(GLPI_LANG.plugin_wazuh_confirm_sync)) {
        event.preventDefault();
    }
    
    // Show loading indicator
    if (document.getElementById('display-spinner')) {
        document.getElementById('display-spinner').style.display = 'block';
    }
}

/**
 * Initialize tooltips for agent information
 */
function initTooltips() {
    // Check if jQuery UI tooltips are available
    if (typeof $.fn.tooltip !== 'undefined') {
        $('.wazuh-tooltip').tooltip({
            track: true,
            show: {
                delay: 500
            }
        });
    }
}

/**
 * Test Wazuh API connection
 */
function wazuhTestApiConnection(testButton, token, rand) {
    const serverUrl = $('#server_url_' + rand).val();
    const apiPort = $('#api_port_' + rand).val();
    const apiUsername = $('#api_username_' + rand).val();
    const apiPassword = $('#api_password' + rand).val();

    let data = {
        url: serverUrl,
        port: apiPort,
        username: apiUsername,
        password: apiPassword,
        csrf_token: token,
        suffix: '/security/user/authenticate'
    };

    wazuhTestConnection(testButton, data, '/plugins/wazuh/ajax/check_api_connection.php');
}

function wazuhTestIndexerConnection(testButton, token, rand) {
    const indexerUrl = $('#indexer_url_' + rand).val();
    const indexerPort = $('#indexer_port_' + rand).val();
    const indexerUsername = $('#indexer_user_' + rand).val();
    const indexerPassword = $('#indexer_password' + rand).val();

    let data = {
        url: indexerUrl,
        port: indexerPort,
        username: indexerUsername,
        password: indexerPassword,
        csrf_token: token,
        suffix: '/security/user/authenticate'
    };

    wazuhTestConnection(testButton, data, '/plugins/wazuh/ajax/check_indexer_connection.php');
}

function wazuhTestConnection(testButton, data, url) {

    $(testButton).prop('disabled', true);
    let spinner = $(testButton).find('i').first();
    $(spinner).removeClass('d-none');

    $.ajax({
        url: CFG_GLPI.url_base + url,
        method: 'POST',
        dataType: 'json',
        data: data,
        timeout: 5000,
        success: function(response) {
            // console.debug(response);
            // let r = JSON.parse(response);
            if (response.success === false) {
                $(testButton).removeClass(['btn-secondary', 'btn-success']);
                $(testButton).addClass('btn-danger');
                showToast(`Connection to ${data.url}:${data.port} failed. ${response.error}`, 'error');
            } else {
                $(testButton).removeClass(['btn-secondary', 'btn-danger']);
                $(testButton).addClass('btn-success');
                showToast(`Authentication to ${data.url}:${data.port} succeed.`);
            }
        },
        error: function(xhr) {
            console.error('Login error:', xhr);
            showToast(`Connection to ${data.url}:${data.port} failed. ${xhr.statusText}`, 'error');
            $(testButton).removeClass(['btn-secondary', 'btn-success']);
            $(testButton).addClass('btn-danger');
        },
        complete: function() {
            $(testButton).prop('disabled', false);
            $(spinner).addClass('d-none');
        }
    });

}

/**
 * Update agent group assignment
 * @param {string} agentId - Wazuh agent ID
 */
function updateAgentGroups(agentId) {
    // Implementation for group management
    // To be expanded based on Wazuh API capabilities
}

function showToast(message, type = 'info') {
    const classMap = {
        'error': 'bg-danger text-white',
        'warning': 'bg-warning text-dark',
        'info': 'bg-info text-white',
        'success': 'bg-success text-white'
    };

    const toast = $(`
        <div class="toast" role="alert" aria-live="assertive" aria-atomic="true">
            <div class="toast-header ${classMap[type] || classMap.info}">
                <strong class="me-auto">${type.toUpperCase()}</strong>
                <button type="button" class="btn-close" data-bs-dismiss="toast" aria-label="Close"></button>
            </div>
            <div class="toast-body">${message}</div>
        </div>
    `);

    const container = $('#messages_after_redirect');
    if (!container.length) {
        $('body').append('<div id="messages_after_redirect" class="toast-container bottom-right p-3"></div>');
    }
    $('#messages_after_redirect').append(toast);
    const bsToast = new bootstrap.Toast(toast[0], { delay: 10000 });
    bsToast.show();
    toast.on('hidden.bs.toast', () => toast.remove());
}
