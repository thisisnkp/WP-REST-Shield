(function($) {
    'use strict';
    
    const WRSAdmin = {
        
        init: function() {
            this.bindEvents();
            this.loadDashboard();
            this.loadLogs();
            this.loadEndpoints();
        },
        
        bindEvents: function() {
            // Rule management
            $(document).on('click', '#add-rule-btn', this.showRuleModal.bind(this, null));
            $(document).on('click', '.edit-rule', this.editRule.bind(this));
            $(document).on('click', '.delete-rule', this.deleteRule.bind(this));
            $(document).on('change', '.rule-toggle', this.toggleRule.bind(this));
            $(document).on('submit', '#rule-form', this.saveRule.bind(this));
            
            // Modal
            $(document).on('click', '.wrs-modal-close', this.closeModal);
            $(document).on('click', '.wrs-modal', function(e) {
                if (e.target === this) {
                    WRSAdmin.closeModal();
                }
            });
            
            // Logs
            $(document).on('submit', '#logs-filter-form', this.filterLogs.bind(this));
            $(document).on('click', '#clear-filters', this.clearFilters.bind(this));
            $(document).on('click', '#export-logs', this.exportLogs.bind(this));
            
            // JWT Secret management
            $(document).on('click', '#toggle-secret', this.toggleSecret);
            $(document).on('click', '#copy-secret', this.copySecret);
            $(document).on('click', '#save-secret', this.saveSecret);
            $(document).on('click', '#generate-secret', function() {
                WRSAdmin.generateSecret();
                $('#jwt-secret-input').attr('readonly', false);
            });
            
            // Copy API URLs
            $(document).on('click', '.wrs-copy-btn', function(e) {
                e.preventDefault();
                const copyId = $(this).data('copy');
                WRSAdmin.copyToClipboard(copyId);
            });
            
            // Other settings
            $(document).on('click', '#refresh-endpoints-btn', this.loadEndpoints.bind(this));
        },
        
        loadDashboard: function() {
            if ($('#stats-24h').length === 0) return;
            
            // Load 24h stats
            this.loadStats('24h', '#stats-24h');
            
            // Load 7d stats
            this.loadStats('7d', '#stats-7d');
            
            // Load chart
            this.loadActivityChart();
        },
        
        loadStats: function(period, container) {
            $.ajax({
                url: wrsData.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'wrs_get_stats',
                    nonce: wrsData.nonce,
                    period: period
                },
                success: function(response) {
                    if (response.success) {
                        const stats = response.data;
                        let html = '';
                        
                        html += '<div class="wrs-stat-item">';
                        html += '<span class="wrs-stat-label">Total Requests</span>';
                        html += '<span class="wrs-stat-value">' + stats.total_requests + '</span>';
                        html += '</div>';
                        
                        html += '<div class="wrs-stat-item">';
                        html += '<span class="wrs-stat-label">Blocked Requests</span>';
                        html += '<span class="wrs-stat-value blocked">' + stats.blocked_requests + '</span>';
                        html += '</div>';
                        
                        html += '<div class="wrs-stat-item">';
                        html += '<span class="wrs-stat-label">Block Rate</span>';
                        const rate = stats.total_requests > 0 ? ((stats.blocked_requests / stats.total_requests) * 100).toFixed(1) : 0;
                        html += '<span class="wrs-stat-value">' + rate + '%</span>';
                        html += '</div>';
                        
                        $(container).html(html);
                        
                        // Update top IPs table
                        if (period === '24h' && stats.top_ips) {
                            WRSAdmin.updateTopIpsTable(stats.top_ips);
                            WRSAdmin.updateTopEndpointsTable(stats.top_endpoints);
                        }
                    }
                }
            });
        },
        
        updateTopIpsTable: function(ips) {
            const tbody = $('#top-ips-table tbody');
            tbody.empty();
            
            if (ips.length === 0) {
                tbody.append('<tr><td colspan="3">No blocked IPs</td></tr>');
                return;
            }
            
            ips.forEach(function(item) {
                tbody.append(
                    '<tr>' +
                    '<td>' + item.ip_address + '</td>' +
                    '<td>' + item.count + '</td>' +
                    '<td><button class="button button-small" onclick="WRSAdmin.blockIp(\'' + item.ip_address + '\')">Block</button></td>' +
                    '</tr>'
                );
            });
        },
        
        updateTopEndpointsTable: function(endpoints) {
            const tbody = $('#top-endpoints-table tbody');
            tbody.empty();
            
            if (endpoints.length === 0) {
                tbody.append('<tr><td colspan="2">No data</td></tr>');
                return;
            }
            
            endpoints.forEach(function(item) {
                tbody.append(
                    '<tr>' +
                    '<td><code>' + item.endpoint + '</code></td>' +
                    '<td>' + item.count + '</td>' +
                    '</tr>'
                );
            });
        },
        
        loadActivityChart: function() {
            if ($('#activity-chart').length === 0) return;
            
            const ctx = document.getElementById('activity-chart').getContext('2d');
            
            new Chart(ctx, {
                type: 'line',
                data: {
                    labels: ['00:00', '04:00', '08:00', '12:00', '16:00', '20:00'],
                    datasets: [{
                        label: 'Allowed',
                        data: [12, 19, 23, 25, 22, 18],
                        borderColor: 'rgb(75, 192, 192)',
                        tension: 0.1
                    }, {
                        label: 'Blocked',
                        data: [5, 8, 12, 15, 10, 7],
                        borderColor: 'rgb(255, 99, 132)',
                        tension: 0.1
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: true,
                    plugins: {
                        legend: {
                            position: 'top',
                        }
                    }
                }
            });
        },
        
        loadLogs: function() {
            if ($('#logs-table-body').length === 0) return;
            
            const filters = this.getLogFilters();
            
            $.ajax({
                url: wrsData.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'wrs_get_logs',
                    nonce: wrsData.nonce,
                    ...filters
                },
                success: function(response) {
                    if (response.success) {
                        WRSAdmin.renderLogs(response.data);
                    }
                }
            });
        },
        
        renderLogs: function(logs) {
            const tbody = $('#logs-table-body');
            tbody.empty();
            
            if (logs.length === 0) {
                tbody.append('<tr><td colspan="6">No logs found</td></tr>');
                return;
            }
            
            logs.forEach(function(log) {
                const status = log.blocked ? '<span class="wrs-badge wrs-badge-block">Blocked</span>' : '<span class="wrs-badge wrs-badge-allow">Allowed</span>';
                
                tbody.append(
                    '<tr>' +
                    '<td>' + log.timestamp + '</td>' +
                    '<td>' + log.ip_address + '</td>' +
                    '<td><code>' + log.endpoint + '</code></td>' +
                    '<td>' + log.method + '</td>' +
                    '<td>' + status + '</td>' +
                    '<td>' + (log.block_reason || '-') + '</td>' +
                    '</tr>'
                );
            });
        },
        
        getLogFilters: function() {
            return {
                date_from: $('#log-date-from').val() || null,
                date_to: $('#log-date-to').val() || null,
                ip: $('#log-ip').val() || null,
                endpoint: $('#log-endpoint').val() || null,
                blocked: $('#log-blocked').val() || null,
                limit: 50,
                offset: 0
            };
        },
        
        filterLogs: function(e) {
            e.preventDefault();
            this.loadLogs();
        },
        
        clearFilters: function() {
            $('#logs-filter-form')[0].reset();
            WRSAdmin.loadLogs();
        },
        
        exportLogs: function() {
            const filters = WRSAdmin.getLogFilters();
            
            const form = $('<form>', {
                method: 'POST',
                action: wrsData.ajaxUrl
            });
            
            form.append($('<input>', { type: 'hidden', name: 'action', value: 'wrs_export_logs' }));
            form.append($('<input>', { type: 'hidden', name: 'nonce', value: wrsData.nonce }));
            
            Object.keys(filters).forEach(function(key) {
                if (filters[key]) {
                    form.append($('<input>', { type: 'hidden', name: key, value: filters[key] }));
                }
            });
            
            form.appendTo('body').submit().remove();
        },
        
        showRuleModal: function(ruleData) {
            if (ruleData) {
                $('#rule-id').val(ruleData.id);
                $('#rule-name').val(ruleData.name);
                $('#rule-endpoint').val(ruleData.endpoint_pattern);
                $('#rule-method').val(ruleData.method);
                $('#rule-action').val(ruleData.action);
                $('#rule-priority').val(ruleData.priority);
                $('#rule-auth-type').val(ruleData.auth_type);
                $('#rule-capability').val(ruleData.required_capability);
                $('#rule-rate-limit').val(ruleData.rate_limit);
                $('#rule-ip-whitelist').val(ruleData.ip_whitelist);
                $('#rule-ip-blacklist').val(ruleData.ip_blacklist);
            } else {
                $('#rule-form')[0].reset();
                $('#rule-id').val('');
            }
            
            $('#rule-modal').fadeIn();
        },
        
        closeModal: function() {
            $('.wrs-modal').fadeOut();
        },
        
        editRule: function(e) {
            const row = $(e.target).closest('tr');
            const ruleId = row.data('rule-id');
            
            const ruleData = {
                id: ruleId,
                name: row.find('td:eq(1)').text(),
                endpoint_pattern: row.find('td:eq(2) code').text(),
                method: row.find('td:eq(3)').text(),
                action: row.find('td:eq(4) .wrs-badge').text().toLowerCase(),
                priority: parseInt(row.find('td:eq(0)').text()),
            };
            
            WRSAdmin.showRuleModal(ruleData);
        },
        
        saveRule: function(e) {
            e.preventDefault();
            
            const formData = $('#rule-form').serializeArray();
            const data = {
                action: 'wrs_save_rule',
                nonce: wrsData.nonce
            };
            
            formData.forEach(function(item) {
                data[item.name] = item.value;
            });
            
            $.ajax({
                url: wrsData.ajaxUrl,
                type: 'POST',
                data: data,
                success: function(response) {
                    if (response.success) {
                        alert(wrsData.strings.success);
                        location.reload();
                    } else {
                        alert(wrsData.strings.error);
                    }
                }
            });
        },
        
        deleteRule: function(e) {
            if (!confirm(wrsData.strings.confirmDelete)) return;
            
            const row = $(e.target).closest('tr');
            const ruleId = row.data('rule-id');
            
            $.ajax({
                url: wrsData.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'wrs_delete_rule',
                    nonce: wrsData.nonce,
                    id: ruleId
                },
                success: function(response) {
                    if (response.success) {
                        row.fadeOut(function() {
                            $(this).remove();
                        });
                    }
                }
            });
        },
        
        toggleRule: function(e) {
            const checkbox = $(e.target);
            const row = checkbox.closest('tr');
            const ruleId = row.data('rule-id');
            const enabled = checkbox.is(':checked') ? 1 : 0;
            
            $.ajax({
                url: wrsData.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'wrs_toggle_rule',
                    nonce: wrsData.nonce,
                    id: ruleId,
                    enabled: enabled
                }
            });
        },
        
        loadEndpoints: function() {
            if ($('#detected-endpoints').length === 0) return;
            
            $('#detected-endpoints').html('<div class="wrs-loading">Loading endpoints...</div>');
            
            $.ajax({
                url: wrsData.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'wrs_get_endpoints',
                    nonce: wrsData.nonce
                },
                success: function(response) {
                    if (response.success) {
                        WRSAdmin.renderEndpoints(response.data);
                    }
                }
            });
        },
        
        renderEndpoints: function(endpoints) {
            const container = $('#detected-endpoints');
            container.empty();
            
            if (endpoints.length === 0) {
                container.html('<p>No endpoints detected</p>');
                return;
            }
            
            const html = $('<div class="wrs-endpoint-list"></div>');
            
            endpoints.forEach(function(endpoint) {
                const methods = endpoint.methods.map(function(method) {
                    return '<span class="wrs-method-badge wrs-method-' + method + '">' + method + '</span>';
                }).join('');
                
                const item = $('<div class="wrs-endpoint-item"></div>');
                item.append('<div><span class="wrs-endpoint-route">' + endpoint.route + '</span><div class="wrs-endpoint-methods">' + methods + '</div></div>');
                item.append('<button class="button button-small">Create Allow Rule</button>');
                
                html.append(item);
            });
            
            container.append(html);
        },
        
        // JWT Secret Management
        toggleSecret: function() {
            const input = $('#jwt-secret-input');
            const icon = $('#toggle-secret .dashicons');
            
            if (input.attr('type') === 'password') {
                input.attr('type', 'text');
                icon.removeClass('dashicons-visibility').addClass('dashicons-hidden');
            } else {
                input.attr('type', 'password');
                icon.removeClass('dashicons-hidden').addClass('dashicons-visibility');
            }
        },
        
        copySecret: function() {
            const input = $('#jwt-secret-input');
            const secret = input.val();
            
            // Create temporary input
            const temp = $('<input>');
            $('body').append(temp);
            temp.val(secret).select();
            document.execCommand('copy');
            temp.remove();
            
            // Show feedback
            const btn = $('#copy-secret');
            const originalHtml = btn.html();
            btn.html('<span class="dashicons dashicons-yes"></span>');
            btn.addClass('copied');
            
            setTimeout(function() {
                btn.html(originalHtml);
                btn.removeClass('copied');
            }, 2000);
        },
        
        saveSecret: function() {
            const secret = $('#jwt-secret-input').val();
            
            if (!secret || secret.length < 32) {
                alert('Secret must be at least 32 characters long');
                return;
            }
            
            $.ajax({
                url: wrsData.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'wrs_save_jwt_secret',
                    nonce: wrsData.nonce,
                    secret: secret
                },
                success: function(response) {
                    if (response.success) {
                        $('#save-secret').hide();
                        $('#jwt-secret-input').attr('readonly', true);
                        
                        // Show success message
                        const msg = $('<span class="wrs-secret-saved">✓ Saved</span>');
                        $('#save-secret').after(msg);
                        setTimeout(function() {
                            msg.fadeOut(function() { $(this).remove(); });
                        }, 3000);
                    } else {
                        alert('Failed to save secret');
                    }
                },
                error: function() {
                    alert('Error saving secret');
                }
            });
        },
        
        generateSecret: function() {
            const secret = WRSAdmin.randomString(64);
            const input = $('#jwt-secret-input');
            input.val(secret);
            input.attr('type', 'text');
            $('#save-secret').show();
        },
        
        randomString: function(length) {
            const chars = '0123456789abcdef';
            let result = '';
            for (let i = 0; i < length; i++) {
                result += chars.charAt(Math.floor(Math.random() * chars.length));
            }
            return result;
        },
        
        copyToClipboard: function(elementId) {
            const element = document.getElementById(elementId);
            const text = element.textContent;
            
            // Create temporary input
            const temp = document.createElement('input');
            temp.value = text;
            document.body.appendChild(temp);
            temp.select();
            document.execCommand('copy');
            document.body.removeChild(temp);
            
            // Show feedback
            const btn = event.target.closest('.wrs-copy-btn');
            const originalHtml = btn.innerHTML;
            btn.innerHTML = '<span class="dashicons dashicons-yes"></span> Copied!';
            btn.classList.add('copied');
            
            setTimeout(function() {
                btn.innerHTML = originalHtml;
                btn.classList.remove('copied');
            }, 2000);
        },
        
        blockIp: function(ip) {
            const currentList = $('textarea[name="wp_rest_shield_ip_blacklist"]').val();
            const newList = currentList ? currentList + '\n' + ip : ip;
            $('textarea[name="wp_rest_shield_ip_blacklist"]').val(newList);
            alert('IP added to blacklist. Please save settings to apply changes.');
        }
    };
    
    // Initialize when document is ready
    $(document).ready(function() {
        WRSAdmin.init();
    });
    
    // Expose to global scope
    window.WRSAdmin = WRSAdmin;
    
})(jQuery);