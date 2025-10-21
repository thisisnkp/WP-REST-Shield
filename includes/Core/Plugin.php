<?php
/**
 * Core Plugin Class
 */

namespace WPRestShield\Core;

class Plugin {
    
    public function __construct() {
        add_action('rest_api_init', [$this, 'register_routes']);
        add_action('admin_notices', [$this, 'admin_notices']);
    }
    
    public function register_routes() {
        // Plugin will register its own routes for token management
    }
    
    public function admin_notices() {
        if (get_transient('wp_rest_shield_activated')) {
            delete_transient('wp_rest_shield_activated');
            ?>
            <div class="notice notice-success is-dismissible">
                <p><strong><?php _e('WP REST Shield activated!', 'wp-rest-shield'); ?></strong></p>
                <p><?php _e('All REST API endpoints are now protected. Please configure your settings and add allow rules for endpoints you want to expose.', 'wp-rest-shield'); ?></p>
                <p><a href="<?php echo admin_url('admin.php?page=wp-rest-shield'); ?>" class="button button-primary"><?php _e('Configure Settings', 'wp-rest-shield'); ?></a></p>
            </div>
            <?php
        }
    }
    
    public static function get_jwt_secret() {
        if (defined('WP_REST_SHIELD_JWT_SECRET')) {
            return WP_REST_SHIELD_JWT_SECRET;
        }
        
        $secret = get_option('wp_rest_shield_jwt_secret');
        if (!$secret) {
            $secret = bin2hex(random_bytes(32));
            update_option('wp_rest_shield_jwt_secret', $secret);
        }
        
        return $secret;
    }
    
    public static function is_enabled() {
        return (bool) get_option('wp_rest_shield_enabled', true);
    }
    
    public static function get_mode() {
        return get_option('wp_rest_shield_mode', 'enforce');
    }
    
    public static function admin_bypass_enabled() {
        return (bool) get_option('wp_rest_shield_admin_bypass', true);
    }
}