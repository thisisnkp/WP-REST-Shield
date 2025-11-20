<?php
/**
 * ===========================================
 * includes/Core/RestFilter.php
 * ===========================================
 */

namespace WPRestShield\Core;

use WP_REST_Request;
use WP_Error;

class RestFilter {
    
    public function __construct() {
        add_filter('rest_pre_dispatch', [$this, 'filter_rest_request'], 10, 3);
        add_filter('rest_authentication_errors', [$this, 'handle_authentication'], 99);
    }
    
    /**
     * Handle authentication for REST requests
     */
    public function handle_authentication($result) {
        if (!Plugin::is_enabled()) {
            return $result;
        }
        
        // Don't interfere with existing authentication
        if (is_wp_error($result) || !empty($result)) {
            return $result;
        }
        
        // Check for JWT token
        $token = $this->get_bearer_token();
        if ($token) {
            $validated = JWT::validate_token($token);
            if ($validated && !is_wp_error($validated)) {
                wp_set_current_user($validated['user_id']);
                return true;
            }
        }
        
        // Check for server-to-server secret
        $server_secret = $this->get_server_secret();
        if ($server_secret && $this->validate_server_secret($server_secret)) {
            return true;
        }
        
        return $result;
    }
    
    /**
     * Filter REST API requests
     */
    public function filter_rest_request($result, $server, $request) {
        if (!Plugin::is_enabled()) {
            return $result;
        }

        $route = $request->get_route();
        $method = $request->get_method();

        // Allow plugin's own endpoints (all versions)
        if (strpos($route, '/wp-rest-shield/') === 0) {
            return $result;
        }
        
        // Admin bypass
        if (Plugin::admin_bypass_enabled() && current_user_can('manage_options')) {
            return $result;
        }
        
        // Check if request should be allowed
        $allowed = $this->check_access($request);
        
        // Log the request
        Logger::log_request($request, !$allowed['allowed'], $allowed['reason'], $allowed['rule_id']);
        
        // Monitor mode - log but don't block
        if (Plugin::get_mode() === 'monitor') {
            return $result;
        }
        
        // Enforce mode - block if not allowed
        if (!$allowed['allowed']) {
            return new WP_Error(
                'rest_blocked',
                __('REST API access is restricted', 'wp-rest-shield'),
                ['status' => 401, 'reason' => $allowed['reason']]
            );
        }
        
        // Check rate limit
        $rate_limit = RateLimiter::check_limit($request);
        if (is_wp_error($rate_limit)) {
            Logger::log_request($request, true, 'Rate limit exceeded');
            return $rate_limit;
        }
        
        return $result;
    }
    
    /**
     * Check if request is allowed based on rules
     */
    private function check_access($request) {
        global $wpdb;
        
        $route = $request->get_route();
        $method = $request->get_method();
        $ip = $this->get_client_ip();
        
        // Check global IP blacklist
        $blacklist = get_option('wp_rest_shield_ip_blacklist', []);
        if ($this->ip_in_list($ip, $blacklist)) {
            return ['allowed' => false, 'reason' => 'IP blacklisted', 'rule_id' => null];
        }
        
        // Check global IP whitelist
        $whitelist = get_option('wp_rest_shield_ip_whitelist', []);
        if (!empty($whitelist) && $this->ip_in_list($ip, $whitelist)) {
            return ['allowed' => true, 'reason' => 'IP whitelisted', 'rule_id' => null];
        }
        
        // Get rules ordered by priority
        $table = $wpdb->prefix . 'rest_shield_rules';
        $rules = $wpdb->get_results(
            "SELECT * FROM $table WHERE enabled = 1 ORDER BY priority ASC",
            ARRAY_A
        );
        
        foreach ($rules as $rule) {
            if (!$this->rule_matches($rule, $route, $method, $request)) {
                continue;
            }
            
            // Rule matches - check additional conditions
            if (!$this->check_rule_conditions($rule, $request)) {
                continue;
            }
            
            // Rule applies
            $action = $rule['action'];
            $allowed = ($action === 'allow');
            
            return [
                'allowed' => $allowed,
                'reason' => $allowed ? 'Matched allow rule: ' . $rule['name'] : 'Matched block rule: ' . $rule['name'],
                'rule_id' => $rule['id']
            ];
        }
        
        // No rule matched - default deny
        return ['allowed' => false, 'reason' => 'No matching allow rule', 'rule_id' => null];
    }
    
    /**
     * Check if rule matches the request
     */
    private function rule_matches($rule, $route, $method, $request) {
        // Check endpoint pattern
        $pattern = $rule['endpoint_pattern'];
        if (!preg_match('#' . $pattern . '#', $route)) {
            return false;
        }
        
        // Check method
        if ($rule['method'] !== '*' && $rule['method'] !== $method) {
            $methods = array_map('trim', explode(',', $rule['method']));
            if (!in_array($method, $methods)) {
                return false;
            }
        }
        
        return true;
    }
    
    /**
     * Check additional rule conditions
     */
    private function check_rule_conditions($rule, $request) {
        $ip = $this->get_client_ip();
        
        // Check IP whitelist
        if (!empty($rule['ip_whitelist'])) {
            $whitelist = array_filter(array_map('trim', explode("\n", $rule['ip_whitelist'])));
            if (!$this->ip_in_list($ip, $whitelist)) {
                return false;
            }
        }
        
        // Check IP blacklist
        if (!empty($rule['ip_blacklist'])) {
            $blacklist = array_filter(array_map('trim', explode("\n", $rule['ip_blacklist'])));
            if ($this->ip_in_list($ip, $blacklist)) {
                return false;
            }
        }
        
        // Check time window
        if ($rule['time_start'] && $rule['time_end']) {
            $now = current_time('H:i:s');
            if ($now < $rule['time_start'] || $now > $rule['time_end']) {
                return false;
            }
        }
        
        // Check auth type
        if ($rule['auth_type'] !== 'any') {
            $auth_valid = $this->check_auth_type($rule['auth_type'], $request);
            if (!$auth_valid) {
                return false;
            }
        }
        
        // Check capability
        if (!empty($rule['required_capability'])) {
            if (!is_user_logged_in() || !current_user_can($rule['required_capability'])) {
                return false;
            }
        }
        
        return true;
    }
    
    /**
     * Check authentication type
     */
    private function check_auth_type($auth_type, $request) {
        switch ($auth_type) {
            case 'anonymous':
                return !is_user_logged_in();
            case 'logged_in':
                return is_user_logged_in();
            case 'jwt':
                $token = $this->get_bearer_token();
                return $token && !is_wp_error(JWT::validate_token($token));
            case 'server_token':
                $secret = $this->get_server_secret();
                return $secret && $this->validate_server_secret($secret);
            default:
                return false;
        }
    }
    
    /**
     * Get bearer token from request
     */
    private function get_bearer_token() {
        $header = isset($_SERVER['HTTP_AUTHORIZATION']) ? $_SERVER['HTTP_AUTHORIZATION'] : '';
        
        if (empty($header) && function_exists('apache_request_headers')) {
            $headers = apache_request_headers();
            $header = isset($headers['Authorization']) ? $headers['Authorization'] : '';
        }
        
        if (preg_match('/Bearer\s+(.*)$/i', $header, $matches)) {
            return $matches[1];
        }
        
        return null;
    }
    
    /**
     * Get server secret from request
     */
    private function get_server_secret() {
        return isset($_SERVER['HTTP_X_SERVER_SECRET']) ? $_SERVER['HTTP_X_SERVER_SECRET'] : null;
    }
    
    /**
     * Validate server secret
     */
    private function validate_server_secret($secret) {
        $valid_secrets = get_option('wp_rest_shield_server_secrets', []);
        return in_array($secret, $valid_secrets);
    }
    
    /**
     * Get client IP address
     */
    private function get_client_ip() {
        $ip_keys = ['HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'REMOTE_ADDR'];
        
        foreach ($ip_keys as $key) {
            if (!empty($_SERVER[$key])) {
                $ip = $_SERVER[$key];
                if (strpos($ip, ',') !== false) {
                    $ip = trim(explode(',', $ip)[0]);
                }
                return $ip;
            }
        }
        
        return '0.0.0.0';
    }
    
    /**
     * Check if IP is in list
     */
    private function ip_in_list($ip, $list) {
        // Ensure $list is an array
        if (!is_array($list)) {
            if (is_string($list) && !empty($list)) {
                // Convert string to array (handle comma or newline separated)
                $list = array_filter(array_map('trim', preg_split('/[\n,]+/', $list)));
            } else {
                return false;
            }
        }

        foreach ($list as $range) {
            if ($this->ip_in_range($ip, $range)) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * Check if IP is in range (supports CIDR)
     */
    private function ip_in_range($ip, $range) {
        if (strpos($range, '/') === false) {
            return $ip === $range;
        }
        
        list($subnet, $mask) = explode('/', $range);
        $ip_long = ip2long($ip);
        $subnet_long = ip2long($subnet);
        $mask_long = -1 << (32 - (int)$mask);
        
        return ($ip_long & $mask_long) === ($subnet_long & $mask_long);
    }
}