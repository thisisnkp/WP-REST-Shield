<?php
/**
 * Rate Limiter
 */

namespace WPRestShield\Core;

use WP_Error;

class RateLimiter {
    
    private static $cache_group = 'wp_rest_shield_rate_limit';
    
    public function __construct() {
        add_action('init', [$this, 'init_cache']);
    }
    
    public function init_cache() {
        wp_cache_add_global_groups(self::$cache_group);
    }
    
    public static function check_limit($request) {
        $route = $request->get_route();
        $method = $request->get_method();
        $ip = self::get_client_ip();
        
        // Check global rate limit
        $global_limit = get_option('wp_rest_shield_global_rate_limit', 60);
        if ($global_limit > 0) {
            $key = 'global_' . md5($ip);
            $exceeded = self::is_limit_exceeded($key, $global_limit, 60);
            
            if ($exceeded) {
                return new WP_Error(
                    'rate_limit_exceeded',
                    __('Too many requests. Please try again later.', 'wp-rest-shield'),
                    ['status' => 429, 'retry_after' => 60]
                );
            }
        }
        
        // Check route-specific rate limit
        $rule_limit = self::get_route_limit($route);
        if ($rule_limit > 0) {
            $key = 'route_' . md5($route . $ip);
            $exceeded = self::is_limit_exceeded($key, $rule_limit, 60);
            
            if ($exceeded) {
                return new WP_Error(
                    'rate_limit_exceeded',
                    __('Too many requests to this endpoint. Please try again later.', 'wp-rest-shield'),
                    ['status' => 429, 'retry_after' => 60]
                );
            }
        }
        
        return true;
    }
    
    private static function is_limit_exceeded($key, $limit, $window) {
        $current = self::get_counter($key);
        
        if ($current >= $limit) {
            return true;
        }
        
        self::increment_counter($key, $window);
        return false;
    }
    
    private static function get_counter($key) {
        // Try object cache first
        $value = wp_cache_get($key, self::$cache_group);
        
        if ($value === false) {
            // Try transient
            $value = get_transient('wrs_rl_' . $key);
            if ($value === false) {
                $value = 0;
            }
        }
        
        return (int) $value;
    }
    
    private static function increment_counter($key, $ttl) {
        $current = self::get_counter($key);
        $new_value = $current + 1;
        
        // Store in object cache
        wp_cache_set($key, $new_value, self::$cache_group, $ttl);
        
        // Also store in transient as backup
        set_transient('wrs_rl_' . $key, $new_value, $ttl);
        
        return $new_value;
    }
    
    private static function get_route_limit($route) {
        global $wpdb;
        $table = $wpdb->prefix . 'rest_shield_rules';
        
        $rule = $wpdb->get_row($wpdb->prepare(
            "SELECT rate_limit FROM $table 
            WHERE enabled = 1 
            AND endpoint_pattern REGEXP %s 
            AND rate_limit IS NOT NULL 
            ORDER BY priority ASC 
            LIMIT 1",
            $route
        ));
        
        return $rule ? (int) $rule->rate_limit : 0;
    }
    
    private static function get_client_ip() {
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
}