<?php
/**
 * ===========================================
 * includes/Core/Logger.php
 * ===========================================
 */

namespace WPRestShield\Core;

class Logger {
    
    public function __construct() {
        add_action('wp_rest_shield_cleanup_logs', [$this, 'cleanup_old_logs']);
        
        if (!wp_next_scheduled('wp_rest_shield_cleanup_logs')) {
            wp_schedule_event(time(), 'daily', 'wp_rest_shield_cleanup_logs');
        }
    }
    
    /**
     * Log a REST API request
     */
    public static function log_request($request, $blocked = false, $reason = '', $rule_id = null) {
        if (!get_option('wp_rest_shield_log_enabled', true)) {
            return;
        }
        
        global $wpdb;
        $table = $wpdb->prefix . 'rest_shield_logs';
        
        $route = $request->get_route();
        $method = $request->get_method();
        $ip = self::get_client_ip();
        
        $user_id = get_current_user_id();
        $token_id = self::extract_token_id($request);
        
        $headers = self::get_request_headers();
        $request_body = $request->get_body();
        
        // Sanitize sensitive data
        $headers = self::sanitize_headers($headers);
        
        $data = [
            'timestamp' => current_time('mysql'),
            'ip_address' => $ip,
            'endpoint' => $route,
            'method' => $method,
            'status_code' => $blocked ? 401 : 200,
            'user_id' => $user_id ?: null,
            'token_id' => $token_id,
            'headers' => json_encode($headers),
            'request_body' => mb_substr($request_body, 0, 5000),
            'blocked' => $blocked ? 1 : 0,
            'block_reason' => $reason,
            'rule_id' => $rule_id,
        ];
        
        $wpdb->insert($table, $data);
        
        // Check if we should send alerts
        self::check_alert_thresholds();
    }
    
    /**
     * Cleanup old logs based on retention period
     */
    public function cleanup_old_logs() {
        global $wpdb;
        $table = $wpdb->prefix . 'rest_shield_logs';
        
        $retention_days = get_option('wp_rest_shield_log_retention_days', 30);
        
        $wpdb->query($wpdb->prepare(
            "DELETE FROM $table WHERE timestamp < DATE_SUB(NOW(), INTERVAL %d DAY)",
            $retention_days
        ));
    }
    
    /**
     * Get logs with filters
     */
    public static function get_logs($args = []) {
        global $wpdb;
        $table = $wpdb->prefix . 'rest_shield_logs';
        
        $defaults = [
            'limit' => 100,
            'offset' => 0,
            'order_by' => 'timestamp',
            'order' => 'DESC',
            'blocked' => null,
            'ip' => null,
            'endpoint' => null,
            'date_from' => null,
            'date_to' => null,
        ];
        
        $args = wp_parse_args($args, $defaults);
        
        $where = ['1=1'];
        $where_values = [];
        
        if ($args['blocked'] !== null) {
            $where[] = 'blocked = %d';
            $where_values[] = $args['blocked'];
        }
        
        if ($args['ip']) {
            $where[] = 'ip_address = %s';
            $where_values[] = $args['ip'];
        }
        
        if ($args['endpoint']) {
            $where[] = 'endpoint LIKE %s';
            $where_values[] = '%' . $wpdb->esc_like($args['endpoint']) . '%';
        }
        
        if ($args['date_from']) {
            $where[] = 'timestamp >= %s';
            $where_values[] = $args['date_from'];
        }
        
        if ($args['date_to']) {
            $where[] = 'timestamp <= %s';
            $where_values[] = $args['date_to'];
        }
        
        $where_clause = implode(' AND ', $where);
        
        $query = "SELECT * FROM $table WHERE $where_clause ORDER BY {$args['order_by']} {$args['order']} LIMIT %d OFFSET %d";
        $where_values[] = $args['limit'];
        $where_values[] = $args['offset'];
        
        if (!empty($where_values)) {
            $query = $wpdb->prepare($query, $where_values);
        }
        
        return $wpdb->get_results($query, ARRAY_A);
    }
    
    /**
     * Get statistics for a time period
     */
    public static function get_stats($period = '24h') {
        global $wpdb;
        $table = $wpdb->prefix . 'rest_shield_logs';
        
        $interval = $period === '24h' ? '24 HOUR' : '7 DAY';
        
        $stats = [
            'total_requests' => 0,
            'blocked_requests' => 0,
            'top_endpoints' => [],
            'top_ips' => [],
        ];
        
        // Total requests
        $stats['total_requests'] = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM $table WHERE timestamp >= DATE_SUB(NOW(), INTERVAL %s)",
            $interval
        ));
        
        // Blocked requests
        $stats['blocked_requests'] = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM $table WHERE blocked = 1 AND timestamp >= DATE_SUB(NOW(), INTERVAL %s)",
            $interval
        ));
        
        // Top endpoints
        $stats['top_endpoints'] = $wpdb->get_results($wpdb->prepare(
            "SELECT endpoint, COUNT(*) as count FROM $table 
            WHERE timestamp >= DATE_SUB(NOW(), INTERVAL %s) 
            GROUP BY endpoint 
            ORDER BY count DESC 
            LIMIT 10",
            $interval
        ), ARRAY_A);
        
        // Top IPs
        $stats['top_ips'] = $wpdb->get_results($wpdb->prepare(
            "SELECT ip_address, COUNT(*) as count FROM $table 
            WHERE blocked = 1 AND timestamp >= DATE_SUB(NOW(), INTERVAL %s) 
            GROUP BY ip_address 
            ORDER BY count DESC 
            LIMIT 10",
            $interval
        ), ARRAY_A);
        
        return $stats;
    }
    
    /**
     * Check alert thresholds and send notifications
     */
    private static function check_alert_thresholds() {
        $webhook_url = get_option('wp_rest_shield_webhook_url', '');
        $threshold = get_option('wp_rest_shield_alert_threshold', 100);
        
        if (empty($webhook_url) || !$threshold) {
            return;
        }
        
        global $wpdb;
        $table = $wpdb->prefix . 'rest_shield_logs';
        
        $count = $wpdb->get_var(
            "SELECT COUNT(*) FROM $table 
            WHERE blocked = 1 
            AND timestamp >= DATE_SUB(NOW(), INTERVAL 1 HOUR)"
        );
        
        if ($count >= $threshold) {
            self::send_alert($webhook_url, $count);
        }
    }
    
    /**
     * Send alert to webhook
     */
    private static function send_alert($url, $count) {
        $payload = [
            'event' => 'threshold_exceeded',
            'count' => $count,
            'period' => '1 hour',
            'timestamp' => current_time('mysql'),
            'site_url' => get_bloginfo('url'),
        ];
        
        wp_remote_post($url, [
            'body' => json_encode($payload),
            'headers' => ['Content-Type' => 'application/json'],
            'timeout' => 5,
        ]);
    }
    
    /**
     * Extract token ID from request
     */
    private static function extract_token_id($request) {
        $header = isset($_SERVER['HTTP_AUTHORIZATION']) ? $_SERVER['HTTP_AUTHORIZATION'] : '';
        
        if (preg_match('/Bearer\s+(.*)$/i', $header, $matches)) {
            $token = $matches[1];
            $validated = JWT::validate_token($token);
            
            if (!is_wp_error($validated) && isset($validated['token_id'])) {
                return $validated['token_id'];
            }
        }
        
        return null;
    }
    
    /**
     * Get all request headers
     */
    private static function get_request_headers() {
        $headers = [];
        
        foreach ($_SERVER as $key => $value) {
            if (strpos($key, 'HTTP_') === 0) {
                $header_key = str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', substr($key, 5)))));
                $headers[$header_key] = $value;
            }
        }
        
        return $headers;
    }
    
    /**
     * Sanitize sensitive headers
     */
    private static function sanitize_headers($headers) {
        $sensitive = ['Authorization', 'X-Server-Secret', 'Cookie'];
        
        foreach ($sensitive as $key) {
            if (isset($headers[$key])) {
                $headers[$key] = '***REDACTED***';
            }
        }
        
        return $headers;
    }
    
    /**
     * Get client IP address
     */
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
