<?php
/**
 * Token Endpoint API
 */

namespace WPRestShield\API;

use WPRestShield\Core\JWT;
use WPRestShield\Core\Plugin;
use WP_REST_Request;
use WP_REST_Response;
use WP_Error;

class TokenEndpoint {
    
    public function __construct() {
        add_action('rest_api_init', [$this, 'register_routes']);
    }
    
    public function register_routes() {
        // Issue token endpoint
        register_rest_route('wp-rest-shield/v1', '/token', [
            'methods' => 'POST',
            'callback' => [$this, 'issue_token'],
            'permission_callback' => '__return_true',
        ]);
        
        // Validate token endpoint
        register_rest_route('wp-rest-shield/v1', '/validate', [
            'methods' => 'POST',
            'callback' => [$this, 'validate_token'],
            'permission_callback' => '__return_true',
        ]);
        
        // Revoke token endpoint
        register_rest_route('wp-rest-shield/v1', '/revoke', [
            'methods' => 'POST',
            'callback' => [$this, 'revoke_token'],
            'permission_callback' => [$this, 'check_revoke_permission'],
        ]);
        
        // Refresh token endpoint
        register_rest_route('wp-rest-shield/v1', '/refresh', [
            'methods' => 'POST',
            'callback' => [$this, 'refresh_token'],
            'permission_callback' => '__return_true',
        ]);
        
        // List active tokens
        register_rest_route('wp-rest-shield/v1', '/tokens', [
            'methods' => 'GET',
            'callback' => [$this, 'list_tokens'],
            'permission_callback' => [$this, 'check_admin_permission'],
        ]);
        
        // Health check endpoint
        register_rest_route('wp-rest-shield/v1', '/health', [
            'methods' => 'GET',
            'callback' => [$this, 'health_check'],
            'permission_callback' => '__return_true',
        ]);
    }
    
    public function issue_token($request) {
        $username = $request->get_param('username');
        $password = $request->get_param('password');
        $server_secret = $request->get_param('server_secret');
        
        // Authenticate via server secret
        if ($server_secret) {
            $valid_secrets = get_option('wp_rest_shield_server_secrets', []);
            
            if (!in_array($server_secret, $valid_secrets)) {
                return new WP_Error(
                    'invalid_server_secret',
                    __('Invalid server secret', 'wp-rest-shield'),
                    ['status' => 401]
                );
            }
            
            // Use a system user or the first admin
            $users = get_users(['role' => 'administrator', 'number' => 1]);
            $user = !empty($users) ? $users[0] : null;

            if (!$user) {
                return new WP_Error(
                    'no_admin_user',
                    __('No administrator user found', 'wp-rest-shield'),
                    ['status' => 500]
                );
            }

            $user_id = $user->ID;
        }
        // Authenticate via username/password
        elseif ($username && $password) {
            $user = wp_authenticate($username, $password);
            
            if (is_wp_error($user)) {
                return new WP_Error(
                    'authentication_failed',
                    __('Invalid username or password', 'wp-rest-shield'),
                    ['status' => 401]
                );
            }
            
            $user_id = $user->ID;
        }
        // Authenticate via Application Password
        else {
            $user = wp_get_current_user();
            
            if (!$user || !$user->ID) {
                return new WP_Error(
                    'authentication_required',
                    __('Authentication required', 'wp-rest-shield'),
                    ['status' => 401]
                );
            }
            
            $user_id = $user->ID;
        }
        
        // Generate token pair (access + refresh)
        $access_lifetime = $request->get_param('access_lifetime') ?: null;
        $refresh_lifetime = $request->get_param('refresh_lifetime') ?: null;
        $token_pair = JWT::generate_token_pair($user_id, $access_lifetime, $refresh_lifetime);
        
        return new WP_REST_Response([
            'access_token' => $token_pair['access_token'],
            'refresh_token' => $token_pair['refresh_token'],
            'token_type' => 'Bearer',
            'expires_in' => $token_pair['expires_in'],
            'refresh_expires_in' => $token_pair['refresh_expires_in'],
            'user_id' => $user_id,
        ], 200);
    }
    
    public function validate_token($request) {
        $token = $request->get_param('token');
        
        if (!$token) {
            // Try to get from Authorization header
            $header = $request->get_header('Authorization');
            if ($header && preg_match('/Bearer\s+(.*)$/i', $header, $matches)) {
                $token = $matches[1];
            }
        }
        
        if (!$token) {
            return new WP_Error(
                'missing_token',
                __('Token is required', 'wp-rest-shield'),
                ['status' => 400]
            );
        }
        
        $validated = JWT::validate_token($token);
        
        if (is_wp_error($validated)) {
            return $validated;
        }
        
        return new WP_REST_Response([
            'valid' => true,
            'user_id' => $validated['user_id'],
            'token_id' => $validated['token_id'],
            'issued_at' => date('Y-m-d H:i:s', $validated['issued_at']),
            'expires_at' => date('Y-m-d H:i:s', $validated['expires_at']),
        ], 200);
    }
    
    public function revoke_token($request) {
        $token_id = $request->get_param('token_id');
        
        if (!$token_id) {
            return new WP_Error(
                'missing_token_id',
                __('Token ID is required', 'wp-rest-shield'),
                ['status' => 400]
            );
        }
        
        $result = JWT::revoke_token($token_id);
        
        if ($result === false) {
            return new WP_Error(
                'revoke_failed',
                __('Failed to revoke token', 'wp-rest-shield'),
                ['status' => 500]
            );
        }
        
        return new WP_REST_Response([
            'success' => true,
            'message' => __('Token revoked successfully', 'wp-rest-shield'),
        ], 200);
    }
    
    public function list_tokens($request) {
        global $wpdb;
        $table = $wpdb->prefix . 'rest_shield_tokens';
        
        $user_id = $request->get_param('user_id');
        $active_only = $request->get_param('active_only') !== 'false';
        
        $where = ['1=1'];
        $values = [];
        
        if ($user_id) {
            $where[] = 'user_id = %d';
            $values[] = $user_id;
        }
        
        if ($active_only) {
            $where[] = 'revoked = 0';
            $where[] = 'expires_at > NOW()';
        }
        
        $where_clause = implode(' AND ', $where);
        
        $query = "SELECT * FROM $table WHERE $where_clause ORDER BY issued_at DESC LIMIT 100";
        
        if (!empty($values)) {
            $query = $wpdb->prepare($query, $values);
        }
        
        $tokens = $wpdb->get_results($query, ARRAY_A);
        
        return new WP_REST_Response([
            'tokens' => $tokens,
            'count' => count($tokens),
        ], 200);
    }
    
    public function refresh_token($request) {
        $refresh_token = $request->get_param('refresh_token');
        
        if (!$refresh_token) {
            // Try to get from Authorization header
            $header = $request->get_header('Authorization');
            if ($header && preg_match('/Bearer\s+(.*)$/i', $header, $matches)) {
                $refresh_token = $matches[1];
            }
        }
        
        if (!$refresh_token) {
            return new WP_Error(
                'missing_refresh_token',
                __('Refresh token is required', 'wp-rest-shield'),
                ['status' => 400]
            );
        }
        
        $result = JWT::refresh_token($refresh_token);
        
        if (is_wp_error($result)) {
            return $result;
        }
        
        return new WP_REST_Response($result, 200);
    }
    
    public function health_check($request) {
        $server_secret = $request->get_header('X-Server-Secret');
        
        if ($server_secret) {
            $valid_secrets = get_option('wp_rest_shield_server_secrets', []);
            
            if (!in_array($server_secret, $valid_secrets)) {
                return new WP_Error(
                    'unauthorized',
                    __('Unauthorized', 'wp-rest-shield'),
                    ['status' => 401]
                );
            }
        }
        
        return new WP_REST_Response([
            'status' => 'ok',
            'plugin_version' => WP_REST_SHIELD_VERSION,
            'enabled' => Plugin::is_enabled(),
            'mode' => Plugin::get_mode(),
            'timestamp' => current_time('mysql'),
        ], 200);
    }
    
    public function check_revoke_permission() {
        // Allow if authenticated user or valid server secret
        if (is_user_logged_in()) {
            return true;
        }
        
        $server_secret = $_SERVER['HTTP_X_SERVER_SECRET'] ?? null;
        if ($server_secret) {
            $valid_secrets = get_option('wp_rest_shield_server_secrets', []);
            return in_array($server_secret, $valid_secrets);
        }
        
        return false;
    }
    
    public function check_admin_permission() {
        return current_user_can('manage_options');
    }
}
