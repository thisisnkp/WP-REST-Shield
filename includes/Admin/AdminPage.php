<?php
/**
 * Admin Page
 */

namespace WPRestShield\Admin;

use WPRestShield\Core\Logger;
use WPRestShield\Core\Plugin;

class AdminPage {
    
    public function __construct() {
        add_action('admin_menu', [$this, 'add_admin_menu']);
        add_action('admin_enqueue_scripts', [$this, 'enqueue_assets']);
        add_action('admin_init', [$this, 'register_settings']);
        add_filter('plugin_action_links_' . plugin_basename(WP_REST_SHIELD_PLUGIN_FILE), [$this, 'add_action_links']);
        
        // AJAX handlers
        add_action('wp_ajax_wrs_get_stats', [$this, 'ajax_get_stats']);
        add_action('wp_ajax_wrs_get_logs', [$this, 'ajax_get_logs']);
        add_action('wp_ajax_wrs_save_rule', [$this, 'ajax_save_rule']);
        add_action('wp_ajax_wrs_delete_rule', [$this, 'ajax_delete_rule']);
        add_action('wp_ajax_wrs_toggle_rule', [$this, 'ajax_toggle_rule']);
        add_action('wp_ajax_wrs_export_logs', [$this, 'ajax_export_logs']);
        add_action('wp_ajax_wrs_get_endpoints', [$this, 'ajax_get_endpoints']);
        add_action('wp_ajax_wrs_save_jwt_secret', [$this, 'ajax_save_jwt_secret']);
        add_action('wp_ajax_wrs_flush_rewrite', [$this, 'ajax_flush_rewrite']);
    }
    
    public function ajax_save_jwt_secret() {
        check_ajax_referer('wp_rest_shield_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error('Unauthorized');
        }

        $secret = sanitize_text_field($_POST['secret']);

        if (strlen($secret) < 32) {
            wp_send_json_error('Secret must be at least 32 characters');
        }

        update_option('wp_rest_shield_jwt_secret', $secret);

        wp_send_json_success(['message' => 'Secret saved successfully']);
    }

    public function ajax_flush_rewrite() {
        check_ajax_referer('wp_rest_shield_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error('Unauthorized');
        }

        // Flush rewrite rules
        flush_rewrite_rules(true);

        // Get REST server to check if routes are registered
        $server = rest_get_server();
        $routes = $server->get_routes();

        $v1_routes = [];
        $v2_routes = [];

        foreach ($routes as $route => $data) {
            if (strpos($route, '/wp-rest-shield/v1') === 0) {
                $v1_routes[] = $route;
            }
            if (strpos($route, '/wp-rest-shield/v2') === 0) {
                $v2_routes[] = $route;
            }
        }

        wp_send_json_success([
            'message' => 'Rewrite rules flushed successfully',
            'v1_routes' => $v1_routes,
            'v2_routes' => $v2_routes,
            'total_routes' => count($routes)
        ]);
    }
    
    public function add_admin_menu() {
        add_menu_page(
            __('WP REST Shield', 'wp-rest-shield'),
            __('REST Shield', 'wp-rest-shield'),
            'manage_options',
            'wp-rest-shield',
            [$this, 'render_dashboard'],
            'dashicons-shield',
            80
        );

        // WordPress automatically creates a submenu with the parent slug
        // So we just rename it to "Dashboard" instead of duplicating
        add_submenu_page(
            'wp-rest-shield',
            __('Rules', 'wp-rest-shield'),
            __('Rules', 'wp-rest-shield'),
            'manage_options',
            'wp-rest-shield-rules',
            [$this, 'render_rules']
        );

        add_submenu_page(
            'wp-rest-shield',
            __('Logs', 'wp-rest-shield'),
            __('Logs', 'wp-rest-shield'),
            'manage_options',
            'wp-rest-shield-logs',
            [$this, 'render_logs']
        );

        add_submenu_page(
            'wp-rest-shield',
            __('Settings', 'wp-rest-shield'),
            __('Settings', 'wp-rest-shield'),
            'manage_options',
            'wp-rest-shield-settings',
            [$this, 'render_settings']
        );

        // Rename the first submenu item from "REST Shield" to "Dashboard"
        global $submenu;
        if (isset($submenu['wp-rest-shield'][0][0])) {
            $submenu['wp-rest-shield'][0][0] = __('Dashboard', 'wp-rest-shield');
        }
    }
    
    public function add_action_links($links) {
        $settings_link = '<a href="' . admin_url('admin.php?page=wp-rest-shield-settings') . '">' . __('Settings', 'wp-rest-shield') . '</a>';
        array_unshift($links, $settings_link);
        return $links;
    }
    
    public function enqueue_assets($hook) {
        if (strpos($hook, 'wp-rest-shield') === false) {
            return;
        }
        
        wp_enqueue_style(
            'wp-rest-shield-admin',
            WP_REST_SHIELD_PLUGIN_URL . 'assets/css/admin.css',
            [],
            WP_REST_SHIELD_VERSION
        );
        
        wp_enqueue_script(
            'chart-js',
            'https://cdnjs.cloudflare.com/ajax/libs/Chart.js/3.9.1/chart.min.js',
            [],
            '3.9.1',
            true
        );
        
        wp_enqueue_script(
            'wp-rest-shield-admin',
            WP_REST_SHIELD_PLUGIN_URL . 'assets/js/admin.js',
            ['jquery', 'chart-js'],
            WP_REST_SHIELD_VERSION,
            true
        );
        
        wp_localize_script('wp-rest-shield-admin', 'wrsData', [
            'ajaxUrl' => admin_url('admin-ajax.php'),
            'nonce' => wp_create_nonce('wp_rest_shield_nonce'),
            'strings' => [
                'confirmDelete' => __('Are you sure you want to delete this rule?', 'wp-rest-shield'),
                'error' => __('An error occurred', 'wp-rest-shield'),
                'success' => __('Changes saved successfully', 'wp-rest-shield'),
            ],
        ]);
    }
    
    public function register_settings() {
        register_setting('wp_rest_shield_settings', 'wp_rest_shield_enabled', [
            'sanitize_callback' => 'absint',
            'default' => 1
        ]);
        register_setting('wp_rest_shield_settings', 'wp_rest_shield_mode', [
            'sanitize_callback' => 'sanitize_text_field',
            'default' => 'enforce'
        ]);
        register_setting('wp_rest_shield_settings', 'wp_rest_shield_admin_bypass', [
            'sanitize_callback' => 'absint',
            'default' => 1
        ]);
        register_setting('wp_rest_shield_settings', 'wp_rest_shield_jwt_secret', [
            'sanitize_callback' => 'sanitize_text_field'
        ]);
        register_setting('wp_rest_shield_settings', 'wp_rest_shield_jwt_lifetime', [
            'sanitize_callback' => 'absint',
            'default' => 3600
        ]);
        register_setting('wp_rest_shield_settings', 'wp_rest_shield_jwt_refresh_lifetime', [
            'sanitize_callback' => 'absint',
            'default' => 604800
        ]);
        register_setting('wp_rest_shield_settings', 'wp_rest_shield_rotate_refresh_tokens', [
            'sanitize_callback' => 'absint',
            'default' => 0
        ]);
        register_setting('wp_rest_shield_settings', 'wp_rest_shield_jwt_algorithm', [
            'sanitize_callback' => 'sanitize_text_field',
            'default' => 'HS256'
        ]);
        register_setting('wp_rest_shield_settings', 'wp_rest_shield_global_rate_limit', [
            'sanitize_callback' => 'absint',
            'default' => 60
        ]);
        register_setting('wp_rest_shield_settings', 'wp_rest_shield_log_enabled', [
            'sanitize_callback' => 'absint',
            'default' => 1
        ]);
        register_setting('wp_rest_shield_settings', 'wp_rest_shield_log_retention_days', [
            'sanitize_callback' => 'absint',
            'default' => 30
        ]);
        register_setting('wp_rest_shield_settings', 'wp_rest_shield_allowed_origins', [
            'sanitize_callback' => [$this, 'sanitize_textarea_to_array']
        ]);
        register_setting('wp_rest_shield_settings', 'wp_rest_shield_server_secrets', [
            'sanitize_callback' => [$this, 'sanitize_textarea_to_array']
        ]);
        register_setting('wp_rest_shield_settings', 'wp_rest_shield_webhook_url', [
            'sanitize_callback' => 'esc_url_raw'
        ]);
        register_setting('wp_rest_shield_settings', 'wp_rest_shield_alert_threshold', [
            'sanitize_callback' => 'absint',
            'default' => 100
        ]);
        register_setting('wp_rest_shield_settings', 'wp_rest_shield_ip_whitelist', [
            'sanitize_callback' => [$this, 'sanitize_textarea_to_array']
        ]);
        register_setting('wp_rest_shield_settings', 'wp_rest_shield_ip_blacklist', [
            'sanitize_callback' => [$this, 'sanitize_textarea_to_array']
        ]);
    }

    /**
     * Sanitize textarea input and convert to array
     */
    public function sanitize_textarea_to_array($input) {
        if (is_array($input)) {
            return $input;
        }

        if (empty($input)) {
            return [];
        }

        // Split by newlines and filter empty values
        $lines = array_filter(array_map('trim', explode("\n", $input)));
        return array_values($lines);
    }
    
    public function render_dashboard() {
        ?>
        <div class="wrap wrs-admin">
            <h1><?php _e('WP REST Shield Dashboard', 'wp-rest-shield'); ?></h1>
            
            <div class="wrs-dashboard">
                <div class="wrs-stats-cards">
                    <div class="wrs-card">
                        <div class="wrs-card-header">
                            <h3><?php _e('24 Hour Stats', 'wp-rest-shield'); ?></h3>
                        </div>
                        <div class="wrs-card-body" id="stats-24h">
                            <div class="wrs-loading"><?php _e('Loading...', 'wp-rest-shield'); ?></div>
                        </div>
                    </div>
                    
                    <div class="wrs-card">
                        <div class="wrs-card-header">
                            <h3><?php _e('7 Day Stats', 'wp-rest-shield'); ?></h3>
                        </div>
                        <div class="wrs-card-body" id="stats-7d">
                            <div class="wrs-loading"><?php _e('Loading...', 'wp-rest-shield'); ?></div>
                        </div>
                    </div>
                </div>
                
                <div class="wrs-charts">
                    <div class="wrs-card">
                        <div class="wrs-card-header">
                            <h3><?php _e('Request Activity', 'wp-rest-shield'); ?></h3>
                        </div>
                        <div class="wrs-card-body">
                            <canvas id="activity-chart"></canvas>
                        </div>
                    </div>
                </div>
                
                <div class="wrs-tables">
                    <div class="wrs-card">
                        <div class="wrs-card-header">
                            <h3><?php _e('Top Blocked IPs', 'wp-rest-shield'); ?></h3>
                        </div>
                        <div class="wrs-card-body">
                            <table class="wp-list-table widefat" id="top-ips-table">
                                <thead>
                                    <tr>
                                        <th><?php _e('IP Address', 'wp-rest-shield'); ?></th>
                                        <th><?php _e('Requests', 'wp-rest-shield'); ?></th>
                                        <th><?php _e('Actions', 'wp-rest-shield'); ?></th>
                                    </tr>
                                </thead>
                                <tbody></tbody>
                            </table>
                        </div>
                    </div>
                    
                    <div class="wrs-card">
                        <div class="wrs-card-header">
                            <h3><?php _e('Top Endpoints', 'wp-rest-shield'); ?></h3>
                        </div>
                        <div class="wrs-card-body">
                            <table class="wp-list-table widefat" id="top-endpoints-table">
                                <thead>
                                    <tr>
                                        <th><?php _e('Endpoint', 'wp-rest-shield'); ?></th>
                                        <th><?php _e('Requests', 'wp-rest-shield'); ?></th>
                                    </tr>
                                </thead>
                                <tbody></tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        <?php
    }
    
    public function render_rules() {
        global $wpdb;
        $table = $wpdb->prefix . 'rest_shield_rules';
        $rules = $wpdb->get_results($wpdb->prepare("SELECT * FROM {$table} ORDER BY priority ASC"), ARRAY_A);
        ?>
        <div class="wrap wrs-admin">
            <h1><?php _e('Access Rules', 'wp-rest-shield'); ?></h1>
            
            <div class="wrs-rules">
                <div class="wrs-card">
                    <div class="wrs-card-header">
                        <h3><?php _e('Rules Configuration', 'wp-rest-shield'); ?></h3>
                        <button class="button button-primary" id="add-rule-btn"><?php _e('Add New Rule', 'wp-rest-shield'); ?></button>
                    </div>
                    <div class="wrs-card-body">
                        <table class="wp-list-table widefat striped">
                            <thead>
                                <tr>
                                    <th><?php _e('Priority', 'wp-rest-shield'); ?></th>
                                    <th><?php _e('Name', 'wp-rest-shield'); ?></th>
                                    <th><?php _e('Endpoint Pattern', 'wp-rest-shield'); ?></th>
                                    <th><?php _e('Method', 'wp-rest-shield'); ?></th>
                                    <th><?php _e('Action', 'wp-rest-shield'); ?></th>
                                    <th><?php _e('Status', 'wp-rest-shield'); ?></th>
                                    <th><?php _e('Actions', 'wp-rest-shield'); ?></th>
                                </tr>
                            </thead>
                            <tbody id="rules-table-body">
                                <?php foreach ($rules as $rule): ?>
                                <tr data-rule-id="<?php echo esc_attr($rule['id']); ?>">
                                    <td><?php echo esc_html($rule['priority']); ?></td>
                                    <td><?php echo esc_html($rule['name']); ?></td>
                                    <td><code><?php echo esc_html($rule['endpoint_pattern']); ?></code></td>
                                    <td><?php echo esc_html($rule['method']); ?></td>
                                    <td>
                                        <span class="wrs-badge wrs-badge-<?php echo $rule['action']; ?>">
                                            <?php echo esc_html(ucfirst($rule['action'])); ?>
                                        </span>
                                    </td>
                                    <td>
                                        <label class="wrs-toggle">
                                            <input type="checkbox" class="rule-toggle" <?php checked($rule['enabled'], 1); ?>>
                                            <span class="wrs-toggle-slider"></span>
                                        </label>
                                    </td>
                                    <td>
                                        <button class="button button-small edit-rule"><?php _e('Edit', 'wp-rest-shield'); ?></button>
                                        <button class="button button-small button-link-delete delete-rule"><?php _e('Delete', 'wp-rest-shield'); ?></button>
                                    </td>
                                </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                </div>
                
                <div class="wrs-card">
                    <div class="wrs-card-header">
                        <h3><?php _e('Detected Endpoints', 'wp-rest-shield'); ?></h3>
                        <button class="button" id="refresh-endpoints-btn"><?php _e('Refresh', 'wp-rest-shield'); ?></button>
                    </div>
                    <div class="wrs-card-body">
                        <div id="detected-endpoints"></div>
                    </div>
                </div>
            </div>
            
            <!-- Rule Editor Modal -->
            <div id="rule-modal" class="wrs-modal" style="display:none;">
                <div class="wrs-modal-content">
                    <span class="wrs-modal-close">&times;</span>
                    <h2><?php _e('Edit Rule', 'wp-rest-shield'); ?></h2>
                    <form id="rule-form">
                        <input type="hidden" id="rule-id" name="id">
                        
                        <div class="wrs-form-group">
                            <label><?php _e('Rule Name', 'wp-rest-shield'); ?></label>
                            <input type="text" name="name" id="rule-name" class="regular-text" required>
                        </div>
                        
                        <div class="wrs-form-group">
                            <label><?php _e('Endpoint Pattern (regex)', 'wp-rest-shield'); ?></label>
                            <input type="text" name="endpoint_pattern" id="rule-endpoint" class="regular-text" required>
                            <p class="description"><?php _e('Example: /wp/v2/posts or /wp/v2/.* for all wp/v2 endpoints', 'wp-rest-shield'); ?></p>
                        </div>
                        
                        <div class="wrs-form-group">
                            <label><?php _e('HTTP Method', 'wp-rest-shield'); ?></label>
                            <select name="method" id="rule-method">
                                <option value="*">All Methods</option>
                                <option value="GET">GET</option>
                                <option value="POST">POST</option>
                                <option value="PUT">PUT</option>
                                <option value="DELETE">DELETE</option>
                                <option value="PATCH">PATCH</option>
                            </select>
                        </div>
                        
                        <div class="wrs-form-group">
                            <label><?php _e('Action', 'wp-rest-shield'); ?></label>
                            <select name="action" id="rule-action">
                                <option value="allow">Allow</option>
                                <option value="block">Block</option>
                            </select>
                        </div>
                        
                        <div class="wrs-form-group">
                            <label><?php _e('Priority', 'wp-rest-shield'); ?></label>
                            <input type="number" name="priority" id="rule-priority" value="10" min="1" max="999">
                            <p class="description"><?php _e('Lower numbers = higher priority', 'wp-rest-shield'); ?></p>
                        </div>
                        
                        <div class="wrs-form-group">
                            <label><?php _e('Auth Type', 'wp-rest-shield'); ?></label>
                            <select name="auth_type" id="rule-auth-type">
                                <option value="any">Any</option>
                                <option value="anonymous">Anonymous Only</option>
                                <option value="logged_in">Logged In Users</option>
                                <option value="jwt">JWT Token</option>
                                <option value="server_token">Server Token</option>
                            </select>
                        </div>
                        
                        <div class="wrs-form-group">
                            <label><?php _e('Required Capability', 'wp-rest-shield'); ?></label>
                            <input type="text" name="required_capability" id="rule-capability" class="regular-text">
                            <p class="description"><?php _e('Optional: e.g., edit_posts, manage_options', 'wp-rest-shield'); ?></p>
                        </div>
                        
                        <div class="wrs-form-group">
                            <label><?php _e('Rate Limit (requests/minute)', 'wp-rest-shield'); ?></label>
                            <input type="number" name="rate_limit" id="rule-rate-limit" min="0">
                            <p class="description"><?php _e('0 = no limit', 'wp-rest-shield'); ?></p>
                        </div>
                        
                        <div class="wrs-form-group">
                            <label><?php _e('IP Whitelist (one per line)', 'wp-rest-shield'); ?></label>
                            <textarea name="ip_whitelist" id="rule-ip-whitelist" rows="4"></textarea>
                        </div>
                        
                        <div class="wrs-form-group">
                            <label><?php _e('IP Blacklist (one per line)', 'wp-rest-shield'); ?></label>
                            <textarea name="ip_blacklist" id="rule-ip-blacklist" rows="4"></textarea>
                        </div>
                        
                        <div class="wrs-form-actions">
                            <button type="submit" class="button button-primary"><?php _e('Save Rule', 'wp-rest-shield'); ?></button>
                            <button type="button" class="button wrs-modal-close"><?php _e('Cancel', 'wp-rest-shield'); ?></button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
        <?php
    }
    
    public function render_logs() {
        ?>
        <div class="wrap wrs-admin">
            <h1><?php _e('Access Logs', 'wp-rest-shield'); ?></h1>
            
            <div class="wrs-logs">
                <div class="wrs-card">
                    <div class="wrs-card-header">
                        <h3><?php _e('Filter Logs', 'wp-rest-shield'); ?></h3>
                    </div>
                    <div class="wrs-card-body">
                        <form id="logs-filter-form" class="wrs-filter-form">
                            <div class="wrs-filter-row">
                                <div class="wrs-filter-field">
                                    <label><?php _e('Date From', 'wp-rest-shield'); ?></label>
                                    <input type="date" name="date_from" id="log-date-from">
                                </div>
                                <div class="wrs-filter-field">
                                    <label><?php _e('Date To', 'wp-rest-shield'); ?></label>
                                    <input type="date" name="date_to" id="log-date-to">
                                </div>
                                <div class="wrs-filter-field">
                                    <label><?php _e('IP Address', 'wp-rest-shield'); ?></label>
                                    <input type="text" name="ip" id="log-ip" placeholder="e.g., 192.168.1.1">
                                </div>
                                <div class="wrs-filter-field">
                                    <label><?php _e('Endpoint', 'wp-rest-shield'); ?></label>
                                    <input type="text" name="endpoint" id="log-endpoint" placeholder="e.g., /wp/v2/posts">
                                </div>
                                <div class="wrs-filter-field">
                                    <label><?php _e('Status', 'wp-rest-shield'); ?></label>
                                    <select name="blocked" id="log-blocked">
                                        <option value="">All</option>
                                        <option value="1">Blocked Only</option>
                                        <option value="0">Allowed Only</option>
                                    </select>
                                </div>
                            </div>
                            <div class="wrs-filter-actions">
                                <button type="submit" class="button button-primary"><?php _e('Apply Filters', 'wp-rest-shield'); ?></button>
                                <button type="button" class="button" id="clear-filters"><?php _e('Clear', 'wp-rest-shield'); ?></button>
                                <button type="button" class="button" id="export-logs"><?php _e('Export CSV', 'wp-rest-shield'); ?></button>
                            </div>
                        </form>
                    </div>
                </div>
                
                <div class="wrs-card">
                    <div class="wrs-card-header">
                        <h3><?php _e('Recent Requests', 'wp-rest-shield'); ?></h3>
                    </div>
                    <div class="wrs-card-body">
                        <table class="wp-list-table widefat striped">
                            <thead>
                                <tr>
                                    <th><?php _e('Timestamp', 'wp-rest-shield'); ?></th>
                                    <th><?php _e('IP', 'wp-rest-shield'); ?></th>
                                    <th><?php _e('Endpoint', 'wp-rest-shield'); ?></th>
                                    <th><?php _e('Method', 'wp-rest-shield'); ?></th>
                                    <th><?php _e('Status', 'wp-rest-shield'); ?></th>
                                    <th><?php _e('Reason', 'wp-rest-shield'); ?></th>
                                </tr>
                            </thead>
                            <tbody id="logs-table-body">
                                <tr><td colspan="6" class="wrs-loading"><?php _e('Loading logs...', 'wp-rest-shield'); ?></td></tr>
                            </tbody>
                        </table>
                        <div class="wrs-pagination" id="logs-pagination"></div>
                    </div>
                </div>
            </div>
        </div>
        <?php
    }
    
    public function render_settings() {
        ?>
        <div class="wrap wrs-admin">
            <h1><?php _e('WP REST Shield Settings', 'wp-rest-shield'); ?></h1>
            
            <form method="post" action="options.php">
                <?php settings_fields('wp_rest_shield_settings'); ?>
                
                <div class="wrs-settings">
                    <!-- General Settings -->
                    <div class="wrs-card">
                        <div class="wrs-card-header">
                            <h3><?php _e('General Settings', 'wp-rest-shield'); ?></h3>
                        </div>
                        <div class="wrs-card-body">
                            <table class="form-table">
                                <tr>
                                    <th><?php _e('Enable Plugin', 'wp-rest-shield'); ?></th>
                                    <td>
                                        <label class="wrs-toggle">
                                            <input type="checkbox" name="wp_rest_shield_enabled" value="1" <?php checked(get_option('wp_rest_shield_enabled'), 1); ?>>
                                            <span class="wrs-toggle-slider"></span>
                                        </label>
                                        <p class="description"><?php _e('Master switch to enable/disable all protection', 'wp-rest-shield'); ?></p>
                                    </td>
                                </tr>
                                <tr>
                                    <th><?php _e('Mode', 'wp-rest-shield'); ?></th>
                                    <td>
                                        <select name="wp_rest_shield_mode">
                                            <option value="enforce" <?php selected(get_option('wp_rest_shield_mode'), 'enforce'); ?>><?php _e('Enforce (Block)', 'wp-rest-shield'); ?></option>
                                            <option value="monitor" <?php selected(get_option('wp_rest_shield_mode'), 'monitor'); ?>><?php _e('Monitor Only (Log but allow)', 'wp-rest-shield'); ?></option>
                                        </select>
                                        <p class="description"><?php _e('In monitor mode, requests are logged but not blocked', 'wp-rest-shield'); ?></p>
                                    </td>
                                </tr>
                                <tr>
                                    <th><?php _e('Admin Bypass', 'wp-rest-shield'); ?></th>
                                    <td>
                                        <label>
                                            <input type="checkbox" name="wp_rest_shield_admin_bypass" value="1" <?php checked(get_option('wp_rest_shield_admin_bypass'), 1); ?>>
                                            <?php _e('Allow administrators to bypass all restrictions', 'wp-rest-shield'); ?>
                                        </label>
                                    </td>
                                </tr>
                            </table>
                        </div>
                    </div>
                    
                    <!-- JWT Settings -->
                    <div class="wrs-card">
                        <div class="wrs-card-header">
                            <h3><?php _e('JWT Settings', 'wp-rest-shield'); ?></h3>
                        </div>
                        <div class="wrs-card-body">
                            <table class="form-table">
                                <tr>
                                    <th><?php _e('JWT Secret', 'wp-rest-shield'); ?></th>
                                    <td>
                                        <div class="wrs-secret-input-wrapper" style="display: flex; gap: 8px; align-items: center; margin-bottom: 10px;">
                                            <input 
                                                type="password" 
                                                name="wp_rest_shield_jwt_secret" 
                                                id="jwt-secret-input" 
                                                value="<?php echo esc_attr(get_option('wp_rest_shield_jwt_secret')); ?>" 
                                                class="regular-text" 
                                                style="max-width: 400px;"
                                            >
                                            <button 
                                                type="button" 
                                                class="button" 
                                                id="toggle-secret" 
                                                title="<?php _e('Show/Hide Secret', 'wp-rest-shield'); ?>"
                                                style="min-width: auto; padding: 5px 10px;"
                                            >
                                                <span class="dashicons dashicons-visibility" style="margin-top: 3px;"></span>
                                            </button>
                                            <button 
                                                type="button" 
                                                class="button" 
                                                id="copy-secret" 
                                                title="<?php _e('Copy Secret', 'wp-rest-shield'); ?>"
                                                style="min-width: auto; padding: 5px 10px;"
                                            >
                                                <span class="dashicons dashicons-clipboard" style="margin-top: 3px;"></span>
                                            </button>
                                            <button 
                                                type="button" 
                                                class="button" 
                                                id="generate-secret-btn"
                                            >
                                                <?php _e('Generate New', 'wp-rest-shield'); ?>
                                            </button>
                                            <button 
                                                type="button" 
                                                class="button button-primary" 
                                                id="save-secret-btn" 
                                                style="display: none;"
                                            >
                                                <?php _e('Save Secret', 'wp-rest-shield'); ?>
                                            </button>
                                        </div>
                                        <p class="description"><?php _e('Secret key for signing JWT tokens. Store in wp-config.php as WP_REST_SHIELD_JWT_SECRET for better security', 'wp-rest-shield'); ?></p>
                                        <div id="secret-status" style="margin-top: 10px; font-weight: 500;"></div>
                                    </td>
                                </tr>
                                <tr>
                                    <th><?php _e('Access Token Lifetime', 'wp-rest-shield'); ?></th>
                                    <td>
                                        <input type="number" name="wp_rest_shield_jwt_lifetime" value="<?php echo esc_attr(get_option('wp_rest_shield_jwt_lifetime', 3600)); ?>" min="60">
                                        <?php _e('seconds', 'wp-rest-shield'); ?>
                                        <p class="description"><?php _e('How long access tokens remain valid (default: 3600 = 1 hour)', 'wp-rest-shield'); ?></p>
                                    </td>
                                </tr>
                                <tr>
                                    <th><?php _e('Refresh Token Lifetime', 'wp-rest-shield'); ?></th>
                                    <td>
                                        <input type="number" name="wp_rest_shield_jwt_refresh_lifetime" value="<?php echo esc_attr(get_option('wp_rest_shield_jwt_refresh_lifetime', 604800)); ?>" min="3600">
                                        <?php _e('seconds', 'wp-rest-shield'); ?>
                                        <p class="description"><?php _e('How long refresh tokens remain valid (default: 604800 = 7 days)', 'wp-rest-shield'); ?></p>
                                    </td>
                                </tr>
                                <tr>
                                    <th><?php _e('Rotate Refresh Tokens', 'wp-rest-shield'); ?></th>
                                    <td>
                                        <label>
                                            <input type="checkbox" name="wp_rest_shield_rotate_refresh_tokens" value="1" <?php checked(get_option('wp_rest_shield_rotate_refresh_tokens'), 1); ?>>
                                            <?php _e('Issue new refresh token on each refresh (more secure)', 'wp-rest-shield'); ?>
                                        </label>
                                        <p class="description"><?php _e('When enabled, a new refresh token is issued each time an access token is refreshed', 'wp-rest-shield'); ?></p>
                                    </td>
                                </tr>
                                <tr>
                                    <th><?php _e('Algorithm', 'wp-rest-shield'); ?></th>
                                    <td>
                                        <select name="wp_rest_shield_jwt_algorithm">
                                            <option value="HS256" <?php selected(get_option('wp_rest_shield_jwt_algorithm'), 'HS256'); ?>>HS256</option>
                                            <option value="HS384" <?php selected(get_option('wp_rest_shield_jwt_algorithm'), 'HS384'); ?>>HS384</option>
                                            <option value="HS512" <?php selected(get_option('wp_rest_shield_jwt_algorithm'), 'HS512'); ?>>HS512</option>
                                        </select>
                                    </td>
                                </tr>
                            </table>
                        </div>
                    </div>
                    
                    <!-- Rate Limiting -->
                    <div class="wrs-card">
                        <div class="wrs-card-header">
                            <h3><?php _e('Rate Limiting', 'wp-rest-shield'); ?></h3>
                        </div>
                        <div class="wrs-card-body">
                            <table class="form-table">
                                <tr>
                                    <th><?php _e('Global Rate Limit', 'wp-rest-shield'); ?></th>
                                    <td>
                                        <input type="number" name="wp_rest_shield_global_rate_limit" value="<?php echo esc_attr(get_option('wp_rest_shield_global_rate_limit', 60)); ?>" min="0">
                                        <?php _e('requests per minute per IP', 'wp-rest-shield'); ?>
                                        <p class="description"><?php _e('0 = no limit', 'wp-rest-shield'); ?></p>
                                    </td>
                                </tr>
                            </table>
                        </div>
                    </div>
                    
                    <!-- Server Secrets -->
                    <div class="wrs-card">
                        <div class="wrs-card-header">
                            <h3><?php _e('Server-to-Server Authentication', 'wp-rest-shield'); ?></h3>
                        </div>
                        <div class="wrs-card-body">
                            <table class="form-table">
                                <tr>
                                    <th><?php _e('Server Secrets', 'wp-rest-shield'); ?></th>
                                    <td>
                                        <textarea name="wp_rest_shield_server_secrets" rows="5" class="large-text"><?php echo esc_textarea(implode("\n", (array)get_option('wp_rest_shield_server_secrets', []))); ?></textarea>
                                        <p class="description"><?php _e('One secret per line. Backend servers must send these in X-Server-Secret header', 'wp-rest-shield'); ?></p>
                                    </td>
                                </tr>
                            </table>
                        </div>
                    </div>
                    
                    <!-- Logging -->
                    <div class="wrs-card">
                        <div class="wrs-card-header">
                            <h3><?php _e('Logging & Retention', 'wp-rest-shield'); ?></h3>
                        </div>
                        <div class="wrs-card-body">
                            <table class="form-table">
                                <tr>
                                    <th><?php _e('Enable Logging', 'wp-rest-shield'); ?></th>
                                    <td>
                                        <label>
                                            <input type="checkbox" name="wp_rest_shield_log_enabled" value="1" <?php checked(get_option('wp_rest_shield_log_enabled'), 1); ?>>
                                            <?php _e('Log all REST API requests', 'wp-rest-shield'); ?>
                                        </label>
                                    </td>
                                </tr>
                                <tr>
                                    <th><?php _e('Log Retention', 'wp-rest-shield'); ?></th>
                                    <td>
                                        <input type="number" name="wp_rest_shield_log_retention_days" value="<?php echo esc_attr(get_option('wp_rest_shield_log_retention_days', 30)); ?>" min="1">
                                        <?php _e('days', 'wp-rest-shield'); ?>
                                    </td>
                                </tr>
                            </table>
                        </div>
                    </div>
                    
                    <!-- Alerts -->
                    <div class="wrs-card">
                        <div class="wrs-card-header">
                            <h3><?php _e('Alerts & Notifications', 'wp-rest-shield'); ?></h3>
                        </div>
                        <div class="wrs-card-body">
                            <table class="form-table">
                                <tr>
                                    <th><?php _e('Webhook URL', 'wp-rest-shield'); ?></th>
                                    <td>
                                        <input type="url" name="wp_rest_shield_webhook_url" value="<?php echo esc_attr(get_option('wp_rest_shield_webhook_url')); ?>" class="regular-text">
                                        <p class="description"><?php _e('Receive alerts when thresholds are exceeded', 'wp-rest-shield'); ?></p>
                                    </td>
                                </tr>
                                <tr>
                                    <th><?php _e('Alert Threshold', 'wp-rest-shield'); ?></th>
                                    <td>
                                        <input type="number" name="wp_rest_shield_alert_threshold" value="<?php echo esc_attr(get_option('wp_rest_shield_alert_threshold', 100)); ?>" min="1">
                                        <?php _e('blocked requests per hour', 'wp-rest-shield'); ?>
                                    </td>
                                </tr>
                            </table>
                        </div>
                    </div>
                    
                    <!-- IP Lists -->
                    <div class="wrs-card">
                        <div class="wrs-card-header">
                            <h3><?php _e('Global IP Lists', 'wp-rest-shield'); ?></h3>
                        </div>
                        <div class="wrs-card-body">
                            <table class="form-table">
                                <tr>
                                    <th><?php _e('IP Whitelist', 'wp-rest-shield'); ?></th>
                                    <td>
                                        <textarea name="wp_rest_shield_ip_whitelist" rows="5" class="large-text"><?php echo esc_textarea(implode("\n", (array)get_option('wp_rest_shield_ip_whitelist', []))); ?></textarea>
                                        <p class="description"><?php _e('IPs or CIDR ranges (one per line) that always have access', 'wp-rest-shield'); ?></p>
                                    </td>
                                </tr>
                                <tr>
                                    <th><?php _e('IP Blacklist', 'wp-rest-shield'); ?></th>
                                    <td>
                                        <textarea name="wp_rest_shield_ip_blacklist" rows="5" class="large-text"><?php echo esc_textarea(implode("\n", (array)get_option('wp_rest_shield_ip_blacklist', []))); ?></textarea>
                                        <p class="description"><?php _e('IPs or CIDR ranges (one per line) that are always blocked', 'wp-rest-shield'); ?></p>
                                    </td>
                                </tr>
                            </table>
                        </div>
                    </div>
                    
                    <!-- API Documentation -->
                    <div class="wrs-card wrs-api-docs">
                        <div class="wrs-card-header">
                            <h3><?php _e('📚 API Documentation & Endpoints', 'wp-rest-shield'); ?></h3>
                            <button type="button" class="button" id="flush-rewrite-btn" style="margin-left: auto;">
                                <span class="dashicons dashicons-update"></span> <?php _e('Flush Rewrite Rules', 'wp-rest-shield'); ?>
                            </button>
                        </div>
                        <div class="wrs-card-body">
                            <div id="flush-rewrite-message" style="display: none; margin-bottom: 15px;"></div>
                            <div class="wrs-doc-section">
                                <h4><?php _e('Base URL', 'wp-rest-shield'); ?></h4>
                                <div class="wrs-code-block">
                                    <code id="base-url"><?php echo esc_url(rest_url()); ?></code>
                                    <button class="button button-small wrs-copy-btn" data-copy="base-url">
                                        <span class="dashicons dashicons-clipboard"></span> <?php _e('Copy', 'wp-rest-shield'); ?>
                                    </button>
                                </div>
                            </div>
                            
                            <div class="wrs-doc-section">
                                <h4><?php _e('🔑 Authentication Endpoints', 'wp-rest-shield'); ?></h4>
                                <p>
                                    <strong><?php _e('Available Versions:', 'wp-rest-shield'); ?></strong>
                                    <span class="wrs-badge wrs-badge-allow">v1</span>
                                    <span class="wrs-badge wrs-badge-allow">v2 (Enhanced)</span>
                                </p>
                                <p class="description"><?php _e('v2 includes improved error handling, validation, pagination, and new endpoints like /me, /introspect, and /revoke-all', 'wp-rest-shield'); ?></p>

                                <div class="wrs-endpoint">
                                    <div class="wrs-endpoint-header">
                                        <span class="wrs-method wrs-method-post">POST</span>
                                        <strong><?php _e('Generate Token', 'wp-rest-shield'); ?></strong>
                                    </div>
                                    <div class="wrs-code-block">
                                        <code id="token-url-v1"><?php echo esc_url(rest_url('wp-rest-shield/v1/token')); ?></code>
                                        <button class="button button-small wrs-copy-btn" data-copy="token-url-v1">
                                            <span class="dashicons dashicons-clipboard"></span> <?php _e('Copy v1', 'wp-rest-shield'); ?>
                                        </button>
                                    </div>
                                    <div class="wrs-code-block">
                                        <code id="token-url-v2"><?php echo esc_url(rest_url('wp-rest-shield/v2/token')); ?></code>
                                        <button class="button button-small wrs-copy-btn" data-copy="token-url-v2">
                                            <span class="dashicons dashicons-clipboard"></span> <?php _e('Copy v2', 'wp-rest-shield'); ?>
                                        </button>
                                    </div>
                                    <div class="wrs-endpoint-details">
                                        <p><strong><?php _e('Request Body:', 'wp-rest-shield'); ?></strong></p>
                                        <pre class="wrs-code-example">{
  "username": "your-username",
  "password": "your-password"
}</pre>
                                        <p><strong><?php _e('Response:', 'wp-rest-shield'); ?></strong></p>
                                        <pre class="wrs-code-example">{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_expires_in": 604800,
  "user_id": 1
}</pre>
                                        <p><strong><?php _e('cURL Example:', 'wp-rest-shield'); ?></strong></p>
                                        <pre class="wrs-code-example">curl -X POST <?php echo esc_url(rest_url('wp-rest-shield/v1/token')); ?> \
  -H "Content-Type: application/json" \
  -d '{"username":"your-username","password":"your-password"}'</pre>
                                    </div>
                                </div>
                                
                                <div class="wrs-endpoint">
                                    <div class="wrs-endpoint-header">
                                        <span class="wrs-method wrs-method-post">POST</span>
                                        <strong><?php _e('Validate Token', 'wp-rest-shield'); ?></strong>
                                    </div>
                                    <div class="wrs-code-block">
                                        <code id="validate-url"><?php echo esc_url(rest_url('wp-rest-shield/v1/validate')); ?></code>
                                        <button class="button button-small wrs-copy-btn" data-copy="validate-url">
                                            <span class="dashicons dashicons-clipboard"></span> <?php _e('Copy', 'wp-rest-shield'); ?>
                                        </button>
                                    </div>
                                    <div class="wrs-endpoint-details">
                                        <p><strong><?php _e('Headers:', 'wp-rest-shield'); ?></strong></p>
                                        <pre class="wrs-code-example">Authorization: Bearer YOUR_TOKEN_HERE</pre>
                                        <p><strong><?php _e('cURL Example:', 'wp-rest-shield'); ?></strong></p>
                                        <pre class="wrs-code-example">curl -X POST <?php echo esc_url(rest_url('wp-rest-shield/v1/validate')); ?> \
  -H "Authorization: Bearer YOUR_TOKEN"</pre>
                                    </div>
                                </div>
                                
                                <div class="wrs-endpoint">
                                    <div class="wrs-endpoint-header">
                                        <span class="wrs-method wrs-method-post">POST</span>
                                        <strong><?php _e('Refresh Token', 'wp-rest-shield'); ?></strong>
                                    </div>
                                    <div class="wrs-code-block">
                                        <code id="refresh-url"><?php echo esc_url(rest_url('wp-rest-shield/v1/refresh')); ?></code>
                                        <button class="button button-small wrs-copy-btn" data-copy="refresh-url">
                                            <span class="dashicons dashicons-clipboard"></span> <?php _e('Copy', 'wp-rest-shield'); ?>
                                        </button>
                                    </div>
                                    <div class="wrs-endpoint-details">
                                        <p><strong><?php _e('Request Body:', 'wp-rest-shield'); ?></strong></p>
                                        <pre class="wrs-code-example">{"refresh_token": "your-refresh-token"}</pre>
                                        <p><strong><?php _e('Response:', 'wp-rest-shield'); ?></strong></p>
                                        <pre class="wrs-code-example">{
  "access_token": "new-access-token",
  "refresh_token": "refresh-token-or-new-one",
  "token_type": "Bearer",
  "expires_in": 3600
}</pre>
                                    </div>
                                </div>
                                
                                <div class="wrs-endpoint">
                                    <div class="wrs-endpoint-header">
                                        <span class="wrs-method wrs-method-post">POST</span>
                                        <strong><?php _e('Revoke Token', 'wp-rest-shield'); ?></strong>
                                    </div>
                                    <div class="wrs-code-block">
                                        <code id="revoke-url"><?php echo esc_url(rest_url('wp-rest-shield/v1/revoke')); ?></code>
                                        <button class="button button-small wrs-copy-btn" data-copy="revoke-url">
                                            <span class="dashicons dashicons-clipboard"></span> <?php _e('Copy', 'wp-rest-shield'); ?>
                                        </button>
                                    </div>
                                    <div class="wrs-endpoint-details">
                                        <p><strong><?php _e('Request Body:', 'wp-rest-shield'); ?></strong></p>
                                        <pre class="wrs-code-example">{"token_id": "your-token-id"}</pre>
                                    </div>
                                </div>
                                
                                <div class="wrs-endpoint">
                                    <div class="wrs-endpoint-header">
                                        <span class="wrs-method wrs-method-get">GET</span>
                                        <strong><?php _e('List Active Tokens', 'wp-rest-shield'); ?></strong>
                                    </div>
                                    <div class="wrs-code-block">
                                        <code id="tokens-url"><?php echo esc_url(rest_url('wp-rest-shield/v1/tokens')); ?></code>
                                        <button class="button button-small wrs-copy-btn" data-copy="tokens-url">
                                            <span class="dashicons dashicons-clipboard"></span> <?php _e('Copy', 'wp-rest-shield'); ?>
                                        </button>
                                    </div>
                                    <div class="wrs-endpoint-details">
                                        <p><strong><?php _e('Auth Required:', 'wp-rest-shield'); ?></strong> Admin only</p>
                                    </div>
                                </div>
                                
                                <div class="wrs-endpoint">
                                    <div class="wrs-endpoint-header">
                                        <span class="wrs-method wrs-method-get">GET</span>
                                        <strong><?php _e('Health Check', 'wp-rest-shield'); ?></strong>
                                    </div>
                                    <div class="wrs-code-block">
                                        <code id="health-url-v1"><?php echo esc_url(rest_url('wp-rest-shield/v1/health')); ?></code>
                                        <button class="button button-small wrs-copy-btn" data-copy="health-url-v1">
                                            <span class="dashicons dashicons-clipboard"></span> <?php _e('Copy v1', 'wp-rest-shield'); ?>
                                        </button>
                                    </div>
                                    <div class="wrs-code-block">
                                        <code id="health-url-v2"><?php echo esc_url(rest_url('wp-rest-shield/v2/health')); ?></code>
                                        <button class="button button-small wrs-copy-btn" data-copy="health-url-v2">
                                            <span class="dashicons dashicons-clipboard"></span> <?php _e('Copy v2 (detailed)', 'wp-rest-shield'); ?>
                                        </button>
                                    </div>
                                </div>
                            </div>

                            <div class="wrs-doc-section">
                                <h4><?php _e('🆕 V2 Only Endpoints', 'wp-rest-shield'); ?></h4>

                                <div class="wrs-endpoint">
                                    <div class="wrs-endpoint-header">
                                        <span class="wrs-method wrs-method-get">GET</span>
                                        <strong><?php _e('Get Current User (Me)', 'wp-rest-shield'); ?></strong>
                                        <span class="wrs-badge" style="background: #00a32a; color: white;">New in v2</span>
                                    </div>
                                    <div class="wrs-code-block">
                                        <code id="me-url"><?php echo esc_url(rest_url('wp-rest-shield/v2/me')); ?></code>
                                        <button class="button button-small wrs-copy-btn" data-copy="me-url">
                                            <span class="dashicons dashicons-clipboard"></span> <?php _e('Copy', 'wp-rest-shield'); ?>
                                        </button>
                                    </div>
                                    <div class="wrs-endpoint-details">
                                        <p><strong><?php _e('Auth Required:', 'wp-rest-shield'); ?></strong> Yes (JWT Token)</p>
                                        <p><strong><?php _e('Description:', 'wp-rest-shield'); ?></strong> <?php _e('Get detailed information about the currently authenticated user', 'wp-rest-shield'); ?></p>
                                    </div>
                                </div>

                                <div class="wrs-endpoint">
                                    <div class="wrs-endpoint-header">
                                        <span class="wrs-method wrs-method-post">POST</span>
                                        <strong><?php _e('Token Introspection (RFC 7662)', 'wp-rest-shield'); ?></strong>
                                        <span class="wrs-badge" style="background: #00a32a; color: white;">New in v2</span>
                                    </div>
                                    <div class="wrs-code-block">
                                        <code id="introspect-url"><?php echo esc_url(rest_url('wp-rest-shield/v2/introspect')); ?></code>
                                        <button class="button button-small wrs-copy-btn" data-copy="introspect-url">
                                            <span class="dashicons dashicons-clipboard"></span> <?php _e('Copy', 'wp-rest-shield'); ?>
                                        </button>
                                    </div>
                                    <div class="wrs-endpoint-details">
                                        <p><strong><?php _e('Auth Required:', 'wp-rest-shield'); ?></strong> Admin only</p>
                                        <p><strong><?php _e('Request Body:', 'wp-rest-shield'); ?></strong></p>
                                        <pre class="wrs-code-example">{"token": "JWT_TOKEN_TO_INTROSPECT"}</pre>
                                    </div>
                                </div>

                                <div class="wrs-endpoint">
                                    <div class="wrs-endpoint-header">
                                        <span class="wrs-method wrs-method-post">POST</span>
                                        <strong><?php _e('Revoke All User Tokens', 'wp-rest-shield'); ?></strong>
                                        <span class="wrs-badge" style="background: #00a32a; color: white;">New in v2</span>
                                    </div>
                                    <div class="wrs-code-block">
                                        <code id="revoke-all-url"><?php echo esc_url(rest_url('wp-rest-shield/v2/revoke-all')); ?></code>
                                        <button class="button button-small wrs-copy-btn" data-copy="revoke-all-url">
                                            <span class="dashicons dashicons-clipboard"></span> <?php _e('Copy', 'wp-rest-shield'); ?>
                                        </button>
                                    </div>
                                    <div class="wrs-endpoint-details">
                                        <p><strong><?php _e('Auth Required:', 'wp-rest-shield'); ?></strong> Yes</p>
                                        <p><strong><?php _e('Request Body:', 'wp-rest-shield'); ?></strong></p>
                                        <pre class="wrs-code-example">{
  "user_id": 1,
  "token_type": "access"  // or "refresh", optional
}</pre>
                                    </div>
                                </div>

                                <div class="wrs-endpoint">
                                    <div class="wrs-endpoint-header">
                                        <span class="wrs-method wrs-method-get">GET</span>
                                        <strong><?php _e('API Documentation', 'wp-rest-shield'); ?></strong>
                                        <span class="wrs-badge" style="background: #00a32a; color: white;">New in v2</span>
                                    </div>
                                    <div class="wrs-code-block">
                                        <code id="docs-url"><?php echo esc_url(rest_url('wp-rest-shield/v2/docs')); ?></code>
                                        <button class="button button-small wrs-copy-btn" data-copy="docs-url">
                                            <span class="dashicons dashicons-clipboard"></span> <?php _e('Copy', 'wp-rest-shield'); ?>
                                        </button>
                                    </div>
                                    <div class="wrs-endpoint-details">
                                        <p><strong><?php _e('Description:', 'wp-rest-shield'); ?></strong> <?php _e('Get complete API documentation in JSON format', 'wp-rest-shield'); ?></p>
                                    </div>
                                </div>
                            </div>
                            
                            <div class="wrs-doc-section">
                                <h4><?php _e('🔐 Using JWT Tokens in Requests', 'wp-rest-shield'); ?></h4>
                                
                                <div class="wrs-usage-example">
                                    <h5><?php _e('JavaScript / Fetch API', 'wp-rest-shield'); ?></h5>
                                    <pre class="wrs-code-example">// Get tokens
const response = await fetch('<?php echo esc_url(rest_url('wp-rest-shield/v1/token')); ?>', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ username: 'user', password: 'pass' })
});
const { access_token, refresh_token } = await response.json();

// Use access token in API calls
const posts = await fetch('<?php echo esc_url(rest_url('wp/v2/posts')); ?>', {
  headers: { 'Authorization': `Bearer ${access_token}` }
}).then(r => r.json());

// Refresh token when access token expires
const refreshResponse = await fetch('<?php echo esc_url(rest_url('wp-rest-shield/v1/refresh')); ?>', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ refresh_token: refresh_token })
});
const { access_token: newAccessToken } = await refreshResponse.json();</pre>
                                </div>
                                
                                <div class="wrs-usage-example">
                                    <h5><?php _e('PHP / cURL', 'wp-rest-shield'); ?></h5>
                                    <pre class="wrs-code-example">// Get tokens
$ch = curl_init('<?php echo esc_url(rest_url('wp-rest-shield/v1/token')); ?>');
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode([
    'username' => 'user',
    'password' => 'pass'
]));
curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
$response = json_decode(curl_exec($ch), true);
$access_token = $response['access_token'];
$refresh_token = $response['refresh_token'];

// Use access token
$ch = curl_init('<?php echo esc_url(rest_url('wp/v2/posts')); ?>');
curl_setopt($ch, CURLOPT_HTTPHEADER, [
    'Authorization: Bearer ' . $access_token
]);
$posts = json_decode(curl_exec($ch), true);

// Refresh token when needed
$ch = curl_init('<?php echo esc_url(rest_url('wp-rest-shield/v1/refresh')); ?>');
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode([
    'refresh_token' => $refresh_token
]));
$refreshResponse = json_decode(curl_exec($ch), true);
$new_access_token = $refreshResponse['access_token'];</pre>
                                </div>
                                
                                <div class="wrs-usage-example">
                                    <h5><?php _e('Python / Requests', 'wp-rest-shield'); ?></h5>
                                    <pre class="wrs-code-example">import requests

# Get token
r = requests.post('<?php echo esc_url(rest_url('wp-rest-shield/v1/token')); ?>',
    json={'username': 'user', 'password': 'pass'})
token = r.json()['token']

# Use token
r = requests.get('<?php echo esc_url(rest_url('wp/v2/posts')); ?>',
    headers={'Authorization': f'Bearer {token}'})
posts = r.json()</pre>
                                </div>
                            </div>
                            
                            <div class="wrs-doc-section">
                                <h4><?php _e('🔧 Server-to-Server Authentication', 'wp-rest-shield'); ?></h4>
                                <p><?php _e('For backend proxies (Laravel, Node.js, etc.), use server secrets:', 'wp-rest-shield'); ?></p>
                                <pre class="wrs-code-example">curl <?php echo esc_url(rest_url('wp/v2/posts')); ?> \
  -H "X-Server-Secret: your-server-secret-here"</pre>
                            </div>
                            
                            <div class="wrs-doc-section">
                                <h4><?php _e('📋 HTTP Status Codes', 'wp-rest-shield'); ?></h4>
                                <table class="wp-list-table widefat striped">
                                    <thead>
                                        <tr>
                                            <th><?php _e('Code', 'wp-rest-shield'); ?></th>
                                            <th><?php _e('Meaning', 'wp-rest-shield'); ?></th>
                                            <th><?php _e('Description', 'wp-rest-shield'); ?></th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <tr>
                                            <td><code>200</code></td>
                                            <td>OK</td>
                                            <td><?php _e('Request successful', 'wp-rest-shield'); ?></td>
                                        </tr>
                                        <tr>
                                            <td><code>401</code></td>
                                            <td>Unauthorized</td>
                                            <td><?php _e('Access denied by WP REST Shield', 'wp-rest-shield'); ?></td>
                                        </tr>
                                        <tr>
                                            <td><code>429</code></td>
                                            <td>Too Many Requests</td>
                                            <td><?php _e('Rate limit exceeded', 'wp-rest-shield'); ?></td>
                                        </tr>
                                        <tr>
                                            <td><code>403</code></td>
                                            <td>Forbidden</td>
                                            <td><?php _e('IP blacklisted or blocked', 'wp-rest-shield'); ?></td>
                                        </tr>
                                    </tbody>
                                </table>
                            </div>
                            
                            <div class="wrs-doc-section">
                                <h4><?php _e('💡 Quick Tips', 'wp-rest-shield'); ?></h4>
                                <ul class="wrs-tips-list">
                                    <li>✅ Always use HTTPS in production</li>
                                    <li>✅ Store JWT secret in wp-config.php for security</li>
                                    <li>✅ Set appropriate token lifetime based on your use case</li>
                                    <li>✅ Create specific rules for each endpoint you need</li>
                                    <li>✅ Test in Monitor mode before switching to Enforce</li>
                                    <li>✅ Enable logging to track API usage</li>
                                    <li>✅ Set rate limits to prevent abuse</li>
                                </ul>
                            </div>
                        </div>
                    </div>
                </div>
                
                <?php submit_button(); ?>
            </form>
        </div>
        <?php
    }
    
    // AJAX Handlers
    public function ajax_get_stats() {
        check_ajax_referer('wp_rest_shield_nonce', 'nonce');
        
        if (!current_user_can('manage_options')) {
            wp_send_json_error('Unauthorized');
        }
        
        $period = $_POST['period'] ?? '24h';
        $stats = Logger::get_stats($period);
        
        wp_send_json_success($stats);
    }
    
    public function ajax_get_logs() {
        check_ajax_referer('wp_rest_shield_nonce', 'nonce');
        
        if (!current_user_can('manage_options')) {
            wp_send_json_error('Unauthorized');
        }
        
        $args = [
            'limit' => $_POST['limit'] ?? 50,
            'offset' => $_POST['offset'] ?? 0,
            'blocked' => $_POST['blocked'] ?? null,
            'ip' => $_POST['ip'] ?? null,
            'endpoint' => $_POST['endpoint'] ?? null,
            'date_from' => $_POST['date_from'] ?? null,
            'date_to' => $_POST['date_to'] ?? null,
        ];
        
        $logs = Logger::get_logs($args);
        
        wp_send_json_success($logs);
    }
    
    public function ajax_save_rule() {
        check_ajax_referer('wp_rest_shield_nonce', 'nonce');
        
        if (!current_user_can('manage_options')) {
            wp_send_json_error('Unauthorized');
        }
        
        global $wpdb;
        $table = $wpdb->prefix . 'rest_shield_rules';
        
        $id = $_POST['id'] ?? null;
        $data = [
            'name' => sanitize_text_field($_POST['name']),
            'endpoint_pattern' => sanitize_text_field($_POST['endpoint_pattern']),
            'method' => sanitize_text_field($_POST['method']),
            'auth_type' => sanitize_text_field($_POST['auth_type'] ?? 'any'),
            'required_capability' => sanitize_text_field($_POST['required_capability'] ?? ''),
            'ip_whitelist' => sanitize_textarea_field($_POST['ip_whitelist'] ?? ''),
            'ip_blacklist' => sanitize_textarea_field($_POST['ip_blacklist'] ?? ''),
            'rate_limit' => intval($_POST['rate_limit'] ?? 0),
            'action' => sanitize_text_field($_POST['action']),
            'priority' => intval($_POST['priority']),
            'enabled' => 1,
        ];
        
        if ($id) {
            $wpdb->update($table, $data, ['id' => $id]);
        } else {
            $data['created_at'] = current_time('mysql');
            $wpdb->insert($table, $data);
        }
        
        wp_send_json_success(['message' => 'Rule saved successfully']);
    }
    
    public function ajax_delete_rule() {
        check_ajax_referer('wp_rest_shield_nonce', 'nonce');
        
        if (!current_user_can('manage_options')) {
            wp_send_json_error('Unauthorized');
        }
        
        global $wpdb;
        $table = $wpdb->prefix . 'rest_shield_rules';
        
        $id = intval($_POST['id']);
        $wpdb->delete($table, ['id' => $id]);
        
        wp_send_json_success(['message' => 'Rule deleted successfully']);
    }
    
    public function ajax_toggle_rule() {
        check_ajax_referer('wp_rest_shield_nonce', 'nonce');
        
        if (!current_user_can('manage_options')) {
            wp_send_json_error('Unauthorized');
        }
        
        global $wpdb;
        $table = $wpdb->prefix . 'rest_shield_rules';
        
        $id = intval($_POST['id']);
        $enabled = intval($_POST['enabled']);
        
        $wpdb->update($table, ['enabled' => $enabled], ['id' => $id]);
        
        wp_send_json_success(['message' => 'Rule updated successfully']);
    }
    
    public function ajax_export_logs() {
        check_ajax_referer('wp_rest_shield_nonce', 'nonce');
        
        if (!current_user_can('manage_options')) {
            wp_send_json_error('Unauthorized');
        }
        
        $args = [
            'limit' => 10000,
            'offset' => 0,
            'blocked' => $_POST['blocked'] ?? null,
            'ip' => $_POST['ip'] ?? null,
            'endpoint' => $_POST['endpoint'] ?? null,
            'date_from' => $_POST['date_from'] ?? null,
            'date_to' => $_POST['date_to'] ?? null,
        ];
        
        $logs = Logger::get_logs($args);
        
        // Generate CSV
        $filename = 'wp-rest-shield-logs-' . date('Y-m-d-His') . '.csv';
        
        header('Content-Type: text/csv');
        header('Content-Disposition: attachment; filename="' . $filename . '"');
        
        $output = fopen('php://output', 'w');
        
        fputcsv($output, ['Timestamp', 'IP Address', 'Endpoint', 'Method', 'Status Code', 'User ID', 'Blocked', 'Block Reason']);
        
        foreach ($logs as $log) {
            fputcsv($output, [
                $log['timestamp'],
                $log['ip_address'],
                $log['endpoint'],
                $log['method'],
                $log['status_code'],
                $log['user_id'],
                $log['blocked'] ? 'Yes' : 'No',
                $log['block_reason'],
            ]);
        }
        
        fclose($output);
        exit;
    }
    
    public function ajax_get_endpoints() {
        check_ajax_referer('wp_rest_shield_nonce', 'nonce');
        
        if (!current_user_can('manage_options')) {
            wp_send_json_error('Unauthorized');
        }
        
        $server = rest_get_server();
        $namespaces = $server->get_namespaces();
        
        $endpoints = [];
        
        foreach ($namespaces as $namespace) {
            $routes = $server->get_routes($namespace);
            
            foreach ($routes as $route => $route_data) {
                $endpoints[] = [
                    'namespace' => $namespace,
                    'route' => $route,
                    'methods' => array_keys($route_data),
                ];
            }
        }
        
        wp_send_json_success($endpoints);
    }
}