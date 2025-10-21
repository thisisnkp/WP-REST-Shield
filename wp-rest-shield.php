<?php
/**
 * Plugin Name: WP REST Shield
 * Plugin URI: Plugin URI: https://infotechzone.in/open-source-apps/wp-rest-shield
 * Description: Comprehensive WordPress REST API security, monitoring, and access control with JWT authentication, rate limiting, and detailed logging.
 * Version: 1.0.2
 * Author: Neeraj Krihna
 * Author URI: https://infotechzone.in
 * License: GPL v2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: wp-rest-shield
 * Domain Path: /languages
 * Requires at least: 5.8
 * Requires PHP: 7.4
 * GitHub Plugin URI: https://github.com/thisisnkp/WP-REST-Shield
 */

// Exit if accessed directly 
if (!defined('ABSPATH')) {
    exit;
}

// Define plugin constants
define('WP_REST_SHIELD_VERSION', '1.0.0');
define('WP_REST_SHIELD_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('WP_REST_SHIELD_PLUGIN_URL', plugin_dir_url(__FILE__));
define('WP_REST_SHIELD_PLUGIN_FILE', __FILE__);

// Autoloader
spl_autoload_register(function ($class) {
    $prefix = 'WPRestShield\\';
    $base_dir = WP_REST_SHIELD_PLUGIN_DIR . 'includes/';
    
    $len = strlen($prefix);
    if (strncmp($prefix, $class, $len) !== 0) {
        return;
    }
    
    $relative_class = substr($class, $len);
    $file = $base_dir . str_replace('\\', '/', $relative_class) . '.php';
    
    if (file_exists($file)) {
        require $file;
    }
});

// Main plugin class
final class WP_REST_Shield {
    
    private static $instance = null;
    
    public static function instance() {
        if (is_null(self::$instance)) {
            self::$instance = new self();
        }
        return self::$instance;
    }
    
    private function __construct() {
        $this->init_hooks();
    }
    
    private function init_hooks() {
        register_activation_hook(__FILE__, [$this, 'activate']);
        register_deactivation_hook(__FILE__, [$this, 'deactivate']);
        
        add_action('plugins_loaded', [$this, 'init']);
        add_action('init', [$this, 'load_textdomain']);
    }
    
    public function init() {
        // Initialize components
        new WPRestShield\Core\Plugin();
        new WPRestShield\Core\RestFilter();
        new WPRestShield\Admin\AdminPage();
        new WPRestShield\API\TokenEndpoint();
        new WPRestShield\Core\RateLimiter();
        new WPRestShield\Core\Logger();
    }
    
    public function activate() {
        global $wpdb;
        
        require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
        
        $charset_collate = $wpdb->get_charset_collate();
        
        // Create logs table
        $logs_table = $wpdb->prefix . 'rest_shield_logs';
        $sql_logs = "CREATE TABLE IF NOT EXISTS $logs_table (
            id bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,
            timestamp datetime NOT NULL,
            ip_address varchar(45) NOT NULL,
            endpoint varchar(255) NOT NULL,
            method varchar(10) NOT NULL,
            status_code int(11) NOT NULL,
            user_id bigint(20) DEFAULT NULL,
            token_id varchar(100) DEFAULT NULL,
            headers text,
            request_body text,
            response_body text,
            blocked tinyint(1) NOT NULL DEFAULT 0,
            block_reason varchar(255) DEFAULT NULL,
            rule_id bigint(20) DEFAULT NULL,
            PRIMARY KEY (id),
            KEY timestamp (timestamp),
            KEY ip_address (ip_address),
            KEY endpoint (endpoint),
            KEY blocked (blocked)
        ) $charset_collate;";
        
        dbDelta($sql_logs);
        
        // Create rules table
        $rules_table = $wpdb->prefix . 'rest_shield_rules';
        $sql_rules = "CREATE TABLE IF NOT EXISTS $rules_table (
            id bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,
            name varchar(255) NOT NULL,
            endpoint_pattern varchar(255) NOT NULL,
            method varchar(50) DEFAULT '*',
            auth_type varchar(50) DEFAULT 'any',
            required_capability varchar(100) DEFAULT NULL,
            ip_whitelist text,
            ip_blacklist text,
            rate_limit int(11) DEFAULT NULL,
            time_start time DEFAULT NULL,
            time_end time DEFAULT NULL,
            action varchar(20) NOT NULL DEFAULT 'allow',
            priority int(11) NOT NULL DEFAULT 10,
            enabled tinyint(1) NOT NULL DEFAULT 1,
            created_at datetime NOT NULL,
            PRIMARY KEY (id),
            KEY enabled (enabled),
            KEY priority (priority)
        ) $charset_collate;";
        
        dbDelta($sql_rules);
        
        // Create tokens table
        $tokens_table = $wpdb->prefix . 'rest_shield_tokens';
        $sql_tokens = "CREATE TABLE IF NOT EXISTS $tokens_table (
            id bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,
            token_id varchar(100) NOT NULL UNIQUE,
            user_id bigint(20) NOT NULL,
            issued_at datetime NOT NULL,
            expires_at datetime NOT NULL,
            last_used datetime DEFAULT NULL,
            ip_address varchar(45),
            revoked tinyint(1) NOT NULL DEFAULT 0,
            PRIMARY KEY (id),
            UNIQUE KEY token_id (token_id),
            KEY user_id (user_id),
            KEY expires_at (expires_at)
        ) $charset_collate;";
        
        dbDelta($sql_tokens);
        
        // Set default options
        $defaults = [
            'wp_rest_shield_enabled' => true,
            'wp_rest_shield_mode' => 'enforce',
            'wp_rest_shield_admin_bypass' => true,
            'wp_rest_shield_jwt_lifetime' => 3600,
            'wp_rest_shield_jwt_algorithm' => 'HS256',
            'wp_rest_shield_global_rate_limit' => 60,
            'wp_rest_shield_log_enabled' => true,
            'wp_rest_shield_log_retention_days' => 30,
            'wp_rest_shield_allowed_origins' => [],
            'wp_rest_shield_server_secrets' => [],
            'wp_rest_shield_ip_whitelist' => [],
            'wp_rest_shield_ip_blacklist' => [],
        ];
        
        foreach ($defaults as $key => $value) {
            if (get_option($key) === false) {
                add_option($key, $value);
            }
        }
        
        // Generate JWT secret if not exists
        if (!defined('WP_REST_SHIELD_JWT_SECRET') && !get_option('wp_rest_shield_jwt_secret')) {
            $secret = bin2hex(random_bytes(32));
            update_option('wp_rest_shield_jwt_secret', $secret);
        }
        
        // Add default block-all rule
        $wpdb->insert(
            $rules_table,
            [
                'name' => 'Default Block All',
                'endpoint_pattern' => '.*',
                'method' => '*',
                'action' => 'block',
                'priority' => 999,
                'enabled' => 1,
                'created_at' => current_time('mysql'),
            ]
        );
        
        // Add admin notice
        set_transient('wp_rest_shield_activated', true, 30);
        
        flush_rewrite_rules();
    }
    
    public function deactivate() {
        flush_rewrite_rules();
    }
    
    public function load_textdomain() {
        load_plugin_textdomain('wp-rest-shield', false, dirname(plugin_basename(__FILE__)) . '/languages');
    }
}

// Initialize plugin
function wp_rest_shield() {
    return WP_REST_Shield::instance();
}

wp_rest_shield();