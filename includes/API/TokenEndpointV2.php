<?php
/**
 * Token Endpoint API V2
 * Enhanced version with improved security, validation, and features
 */

namespace WPRestShield\API;

use WPRestShield\Core\JWT;
use WPRestShield\Core\Plugin;
use WP_REST_Request;
use WP_REST_Response;
use WP_Error;

class TokenEndpointV2 {

    public function __construct() {
        add_action('rest_api_init', [$this, 'register_routes']);
    }

    public function register_routes() {
        // Issue token endpoint
        register_rest_route('wp-rest-shield/v2', '/token', [
            'methods' => 'POST',
            'callback' => [$this, 'issue_token'],
            'permission_callback' => '__return_true',
            'args' => $this->get_issue_token_args(),
        ]);

        // Validate token endpoint
        register_rest_route('wp-rest-shield/v2', '/validate', [
            'methods' => 'POST',
            'callback' => [$this, 'validate_token'],
            'permission_callback' => '__return_true',
            'args' => $this->get_validate_token_args(),
        ]);

        // Revoke token endpoint
        register_rest_route('wp-rest-shield/v2', '/revoke', [
            'methods' => 'POST',
            'callback' => [$this, 'revoke_token'],
            'permission_callback' => [$this, 'check_revoke_permission'],
            'args' => $this->get_revoke_token_args(),
        ]);

        // Refresh token endpoint
        register_rest_route('wp-rest-shield/v2', '/refresh', [
            'methods' => 'POST',
            'callback' => [$this, 'refresh_token'],
            'permission_callback' => '__return_true',
            'args' => $this->get_refresh_token_args(),
        ]);

        // List active tokens
        register_rest_route('wp-rest-shield/v2', '/tokens', [
            'methods' => 'GET',
            'callback' => [$this, 'list_tokens'],
            'permission_callback' => [$this, 'check_admin_permission'],
            'args' => $this->get_list_tokens_args(),
        ]);

        // Health check endpoint
        register_rest_route('wp-rest-shield/v2', '/health', [
            'methods' => 'GET',
            'callback' => [$this, 'health_check'],
            'permission_callback' => '__return_true',
        ]);

        // Token introspection (RFC 7662)
        register_rest_route('wp-rest-shield/v2', '/introspect', [
            'methods' => 'POST',
            'callback' => [$this, 'introspect_token'],
            'permission_callback' => [$this, 'check_admin_permission'],
            'args' => $this->get_introspect_args(),
        ]);

        // Revoke all user tokens
        register_rest_route('wp-rest-shield/v2', '/revoke-all', [
            'methods' => 'POST',
            'callback' => [$this, 'revoke_all_tokens'],
            'permission_callback' => [$this, 'check_revoke_permission'],
            'args' => $this->get_revoke_all_args(),
        ]);

        // Get current user info from token
        register_rest_route('wp-rest-shield/v2', '/me', [
            'methods' => 'GET',
            'callback' => [$this, 'get_current_user'],
            'permission_callback' => [$this, 'check_authenticated'],
        ]);

        // API documentation
        register_rest_route('wp-rest-shield/v2', '/docs', [
            'methods' => 'GET',
            'callback' => [$this, 'get_api_docs'],
            'permission_callback' => '__return_true',
        ]);
    }

    /**
     * Issue token with enhanced validation and security
     */
    public function issue_token($request) {
        $username = sanitize_text_field($request->get_param('username'));
        $password = $request->get_param('password');
        $server_secret = sanitize_text_field($request->get_param('server_secret'));
        $device_name = sanitize_text_field($request->get_param('device_name'));
        $device_id = sanitize_text_field($request->get_param('device_id'));

        // Authenticate via server secret
        if ($server_secret) {
            $valid_secrets = get_option('wp_rest_shield_server_secrets', []);

            if (!is_array($valid_secrets)) {
                $valid_secrets = [];
            }

            if (!in_array($server_secret, $valid_secrets, true)) {
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
        $access_lifetime = $request->get_param('access_lifetime');
        $refresh_lifetime = $request->get_param('refresh_lifetime');

        // Validate lifetimes
        if ($access_lifetime !== null) {
            $access_lifetime = absint($access_lifetime);
            if ($access_lifetime < 60 || $access_lifetime > 86400) {
                return new WP_Error(
                    'invalid_lifetime',
                    __('Access token lifetime must be between 60 and 86400 seconds', 'wp-rest-shield'),
                    ['status' => 400]
                );
            }
        }

        if ($refresh_lifetime !== null) {
            $refresh_lifetime = absint($refresh_lifetime);
            if ($refresh_lifetime < 3600 || $refresh_lifetime > 2592000) {
                return new WP_Error(
                    'invalid_lifetime',
                    __('Refresh token lifetime must be between 3600 and 2592000 seconds', 'wp-rest-shield'),
                    ['status' => 400]
                );
            }
        }

        $token_pair = JWT::generate_token_pair($user_id, $access_lifetime, $refresh_lifetime);

        // Store device info if provided
        if ($device_name || $device_id) {
            $this->store_device_info($token_pair['access_token'], $device_name, $device_id);
        }

        $user_data = get_userdata($user_id);

        return new WP_REST_Response([
            'success' => true,
            'access_token' => $token_pair['access_token'],
            'refresh_token' => $token_pair['refresh_token'],
            'token_type' => 'Bearer',
            'expires_in' => $token_pair['expires_in'],
            'refresh_expires_in' => $token_pair['refresh_expires_in'],
            'user' => [
                'id' => $user_id,
                'username' => $user_data->user_login,
                'email' => $user_data->user_email,
                'display_name' => $user_data->display_name,
                'roles' => $user_data->roles,
            ],
            'issued_at' => current_time('mysql'),
        ], 200);
    }

    /**
     * Validate token with detailed information
     */
    public function validate_token($request) {
        $token = sanitize_text_field($request->get_param('token'));

        if (!$token) {
            // Try to get from Authorization header
            $header = $request->get_header('Authorization');
            if ($header && preg_match('/Bearer\s+(.*)$/i', $header, $matches)) {
                $token = sanitize_text_field($matches[1]);
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
            return new WP_REST_Response([
                'valid' => false,
                'error' => $validated->get_error_code(),
                'error_description' => $validated->get_error_message(),
            ], 200);
        }

        $user_data = get_userdata($validated['user_id']);

        return new WP_REST_Response([
            'valid' => true,
            'active' => true,
            'user_id' => $validated['user_id'],
            'username' => $user_data ? $user_data->user_login : null,
            'token_id' => $validated['token_id'],
            'token_type' => $validated['token_type'],
            'issued_at' => date('Y-m-d H:i:s', $validated['issued_at']),
            'expires_at' => date('Y-m-d H:i:s', $validated['expires_at']),
            'expires_in' => max(0, $validated['expires_at'] - time()),
        ], 200);
    }

    /**
     * Revoke a specific token
     */
    public function revoke_token($request) {
        $token_id = sanitize_text_field($request->get_param('token_id'));
        $token = sanitize_text_field($request->get_param('token'));

        // If token is provided instead of token_id, extract token_id
        if (!$token_id && $token) {
            $validated = JWT::validate_token($token);
            if (!is_wp_error($validated)) {
                $token_id = $validated['token_id'];
            }
        }

        if (!$token_id) {
            return new WP_Error(
                'missing_token_id',
                __('Token ID or token is required', 'wp-rest-shield'),
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
            'token_id' => $token_id,
            'revoked_at' => current_time('mysql'),
        ], 200);
    }

    /**
     * List tokens with pagination
     */
    public function list_tokens($request) {
        global $wpdb;
        $table = $wpdb->prefix . 'rest_shield_tokens';

        $user_id = $request->get_param('user_id');
        $active_only = $request->get_param('active_only') !== 'false';
        $page = max(1, absint($request->get_param('page')));
        $per_page = max(1, min(100, absint($request->get_param('per_page') ?: 20)));
        $offset = ($page - 1) * $per_page;

        $where = ['1=1'];
        $values = [];

        if ($user_id) {
            $where[] = 'user_id = %d';
            $values[] = absint($user_id);
        }

        if ($active_only) {
            $where[] = 'revoked = 0';
            $where[] = 'expires_at > NOW()';
        }

        $where_clause = implode(' AND ', $where);

        // Get total count
        $count_query = "SELECT COUNT(*) FROM $table WHERE $where_clause";
        if (!empty($values)) {
            $count_query = $wpdb->prepare($count_query, $values);
        }
        $total = $wpdb->get_var($count_query);

        // Get tokens
        $query = "SELECT * FROM $table WHERE $where_clause ORDER BY issued_at DESC LIMIT %d OFFSET %d";
        $query_values = array_merge($values, [$per_page, $offset]);
        $query = $wpdb->prepare($query, $query_values);

        $tokens = $wpdb->get_results($query, ARRAY_A);

        return new WP_REST_Response([
            'success' => true,
            'tokens' => $tokens,
            'pagination' => [
                'total' => (int) $total,
                'count' => count($tokens),
                'per_page' => $per_page,
                'current_page' => $page,
                'total_pages' => ceil($total / $per_page),
            ],
        ], 200);
    }

    /**
     * Refresh token with enhanced security
     */
    public function refresh_token($request) {
        $refresh_token = sanitize_text_field($request->get_param('refresh_token'));

        if (!$refresh_token) {
            // Try to get from Authorization header
            $header = $request->get_header('Authorization');
            if ($header && preg_match('/Bearer\s+(.*)$/i', $header, $matches)) {
                $refresh_token = sanitize_text_field($matches[1]);
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

        return new WP_REST_Response([
            'success' => true,
            'access_token' => $result['access_token'],
            'refresh_token' => $result['refresh_token'],
            'token_type' => $result['token_type'],
            'expires_in' => $result['expires_in'],
            'refreshed_at' => current_time('mysql'),
        ], 200);
    }

    /**
     * Health check with detailed system info
     */
    public function health_check($request) {
        $server_secret = $request->get_header('X-Server-Secret');
        $detailed = false;

        if ($server_secret) {
            $valid_secrets = get_option('wp_rest_shield_server_secrets', []);

            if (!is_array($valid_secrets)) {
                $valid_secrets = [];
            }

            if (!in_array($server_secret, $valid_secrets, true)) {
                return new WP_Error(
                    'unauthorized',
                    __('Unauthorized', 'wp-rest-shield'),
                    ['status' => 401]
                );
            }

            $detailed = true;
        }

        global $wpdb;
        $response = [
            'status' => 'ok',
            'version' => '2.0',
            'plugin_version' => WP_REST_SHIELD_VERSION,
            'enabled' => Plugin::is_enabled(),
            'mode' => Plugin::get_mode(),
            'timestamp' => current_time('mysql'),
            'server_time' => time(),
        ];

        if ($detailed) {
            $tokens_table = $wpdb->prefix . 'rest_shield_tokens';
            $logs_table = $wpdb->prefix . 'rest_shield_logs';

            $response['statistics'] = [
                'active_tokens' => $wpdb->get_var("SELECT COUNT(*) FROM $tokens_table WHERE revoked = 0 AND expires_at > NOW()"),
                'total_tokens' => $wpdb->get_var("SELECT COUNT(*) FROM $tokens_table"),
                'requests_24h' => $wpdb->get_var("SELECT COUNT(*) FROM $logs_table WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)"),
                'blocked_24h' => $wpdb->get_var("SELECT COUNT(*) FROM $logs_table WHERE blocked = 1 AND timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)"),
            ];

            $response['configuration'] = [
                'jwt_algorithm' => get_option('wp_rest_shield_jwt_algorithm', 'HS256'),
                'jwt_lifetime' => get_option('wp_rest_shield_jwt_lifetime', 3600),
                'jwt_refresh_lifetime' => get_option('wp_rest_shield_jwt_refresh_lifetime', 604800),
                'global_rate_limit' => get_option('wp_rest_shield_global_rate_limit', 60),
                'log_enabled' => get_option('wp_rest_shield_log_enabled', true),
                'admin_bypass' => get_option('wp_rest_shield_admin_bypass', true),
            ];
        }

        return new WP_REST_Response($response, 200);
    }

    /**
     * Token introspection (RFC 7662)
     */
    public function introspect_token($request) {
        $token = sanitize_text_field($request->get_param('token'));

        if (!$token) {
            return new WP_Error(
                'missing_token',
                __('Token parameter is required', 'wp-rest-shield'),
                ['status' => 400]
            );
        }

        $validated = JWT::validate_token($token);

        if (is_wp_error($validated)) {
            return new WP_REST_Response([
                'active' => false,
            ], 200);
        }

        global $wpdb;
        $table = $wpdb->prefix . 'rest_shield_tokens';
        $token_record = $wpdb->get_row($wpdb->prepare(
            "SELECT * FROM $table WHERE token_id = %s",
            $validated['token_id']
        ), ARRAY_A);

        $user_data = get_userdata($validated['user_id']);

        return new WP_REST_Response([
            'active' => true,
            'scope' => 'api',
            'client_id' => $validated['user_id'],
            'username' => $user_data ? $user_data->user_login : null,
            'token_type' => $validated['token_type'],
            'exp' => $validated['expires_at'],
            'iat' => $validated['issued_at'],
            'sub' => $validated['user_id'],
            'jti' => $validated['token_id'],
            'ip_address' => $token_record['ip_address'] ?? null,
            'last_used' => $token_record['last_used'] ?? null,
        ], 200);
    }

    /**
     * Revoke all tokens for a user
     */
    public function revoke_all_tokens($request) {
        $user_id = absint($request->get_param('user_id'));
        $token_type = sanitize_text_field($request->get_param('token_type'));

        if (!$user_id) {
            $user_id = get_current_user_id();
        }

        if (!$user_id) {
            return new WP_Error(
                'missing_user_id',
                __('User ID is required', 'wp-rest-shield'),
                ['status' => 400]
            );
        }

        global $wpdb;
        $table = $wpdb->prefix . 'rest_shield_tokens';

        $where = ['user_id = %d', 'revoked = 0'];
        $values = [$user_id];

        if ($token_type && in_array($token_type, ['access', 'refresh'], true)) {
            $where[] = 'token_type = %s';
            $values[] = $token_type;
        }

        $where_clause = implode(' AND ', $where);

        $result = $wpdb->query($wpdb->prepare(
            "UPDATE $table SET revoked = 1 WHERE $where_clause",
            $values
        ));

        return new WP_REST_Response([
            'success' => true,
            'message' => __('All tokens revoked successfully', 'wp-rest-shield'),
            'revoked_count' => $result,
            'user_id' => $user_id,
            'revoked_at' => current_time('mysql'),
        ], 200);
    }

    /**
     * Get current user info from token
     */
    public function get_current_user($request) {
        $user_id = get_current_user_id();

        if (!$user_id) {
            return new WP_Error(
                'not_authenticated',
                __('You must be authenticated to access this endpoint', 'wp-rest-shield'),
                ['status' => 401]
            );
        }

        $user_data = get_userdata($user_id);

        if (!$user_data) {
            return new WP_Error(
                'user_not_found',
                __('User not found', 'wp-rest-shield'),
                ['status' => 404]
            );
        }

        // Get active tokens count
        global $wpdb;
        $table = $wpdb->prefix . 'rest_shield_tokens';
        $active_tokens = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM $table WHERE user_id = %d AND revoked = 0 AND expires_at > NOW()",
            $user_id
        ));

        return new WP_REST_Response([
            'success' => true,
            'user' => [
                'id' => $user_id,
                'username' => $user_data->user_login,
                'email' => $user_data->user_email,
                'display_name' => $user_data->display_name,
                'first_name' => $user_data->first_name,
                'last_name' => $user_data->last_name,
                'roles' => $user_data->roles,
                'capabilities' => array_keys(array_filter($user_data->allcaps)),
                'registered' => $user_data->user_registered,
            ],
            'active_tokens' => (int) $active_tokens,
        ], 200);
    }

    /**
     * Get API documentation
     */
    public function get_api_docs($request) {
        return new WP_REST_Response([
            'version' => '2.0',
            'endpoints' => [
                [
                    'path' => '/wp-rest-shield/v2/token',
                    'methods' => ['POST'],
                    'description' => 'Issue new access and refresh tokens',
                    'authentication' => 'username/password, server_secret, or application password',
                    'parameters' => [
                        'username' => 'User login name (optional)',
                        'password' => 'User password (optional)',
                        'server_secret' => 'Server-to-server secret (optional)',
                        'access_lifetime' => 'Custom access token lifetime in seconds (60-86400)',
                        'refresh_lifetime' => 'Custom refresh token lifetime in seconds (3600-2592000)',
                        'device_name' => 'Device name for tracking (optional)',
                        'device_id' => 'Device identifier (optional)',
                    ],
                ],
                [
                    'path' => '/wp-rest-shield/v2/validate',
                    'methods' => ['POST'],
                    'description' => 'Validate a JWT token',
                    'parameters' => [
                        'token' => 'JWT token to validate (or use Authorization header)',
                    ],
                ],
                [
                    'path' => '/wp-rest-shield/v2/refresh',
                    'methods' => ['POST'],
                    'description' => 'Refresh an access token using refresh token',
                    'parameters' => [
                        'refresh_token' => 'Refresh token (or use Authorization header)',
                    ],
                ],
                [
                    'path' => '/wp-rest-shield/v2/revoke',
                    'methods' => ['POST'],
                    'description' => 'Revoke a specific token',
                    'authentication' => 'required',
                    'parameters' => [
                        'token_id' => 'Token ID to revoke',
                        'token' => 'JWT token to revoke (alternative to token_id)',
                    ],
                ],
                [
                    'path' => '/wp-rest-shield/v2/revoke-all',
                    'methods' => ['POST'],
                    'description' => 'Revoke all tokens for a user',
                    'authentication' => 'required',
                    'parameters' => [
                        'user_id' => 'User ID (defaults to current user)',
                        'token_type' => 'Token type filter: access or refresh (optional)',
                    ],
                ],
                [
                    'path' => '/wp-rest-shield/v2/tokens',
                    'methods' => ['GET'],
                    'description' => 'List tokens with pagination',
                    'authentication' => 'admin required',
                    'parameters' => [
                        'user_id' => 'Filter by user ID (optional)',
                        'active_only' => 'Show only active tokens (default: true)',
                        'page' => 'Page number (default: 1)',
                        'per_page' => 'Items per page (default: 20, max: 100)',
                    ],
                ],
                [
                    'path' => '/wp-rest-shield/v2/introspect',
                    'methods' => ['POST'],
                    'description' => 'Token introspection (RFC 7662)',
                    'authentication' => 'admin required',
                    'parameters' => [
                        'token' => 'JWT token to introspect',
                    ],
                ],
                [
                    'path' => '/wp-rest-shield/v2/me',
                    'methods' => ['GET'],
                    'description' => 'Get current authenticated user information',
                    'authentication' => 'required',
                ],
                [
                    'path' => '/wp-rest-shield/v2/health',
                    'methods' => ['GET'],
                    'description' => 'Health check endpoint with optional detailed stats',
                    'authentication' => 'optional (X-Server-Secret header for detailed info)',
                ],
                [
                    'path' => '/wp-rest-shield/v2/docs',
                    'methods' => ['GET'],
                    'description' => 'API documentation',
                ],
            ],
            'authentication' => [
                'types' => [
                    'Bearer Token' => 'Include JWT token in Authorization header: "Bearer {token}"',
                    'Server Secret' => 'Include in X-Server-Secret header or as request parameter',
                    'WordPress Auth' => 'Standard WordPress authentication (cookies, application passwords)',
                ],
            ],
        ], 200);
    }

    // Permission callbacks

    public function check_revoke_permission() {
        // Allow if authenticated user or valid server secret
        if (is_user_logged_in()) {
            return true;
        }

        $server_secret = $_SERVER['HTTP_X_SERVER_SECRET'] ?? null;
        if ($server_secret) {
            $valid_secrets = get_option('wp_rest_shield_server_secrets', []);
            if (!is_array($valid_secrets)) {
                $valid_secrets = [];
            }
            return in_array($server_secret, $valid_secrets, true);
        }

        return false;
    }

    public function check_admin_permission() {
        return current_user_can('manage_options');
    }

    public function check_authenticated() {
        return is_user_logged_in();
    }

    // Argument schemas

    private function get_issue_token_args() {
        return [
            'username' => [
                'type' => 'string',
                'required' => false,
                'sanitize_callback' => 'sanitize_text_field',
            ],
            'password' => [
                'type' => 'string',
                'required' => false,
            ],
            'server_secret' => [
                'type' => 'string',
                'required' => false,
                'sanitize_callback' => 'sanitize_text_field',
            ],
            'access_lifetime' => [
                'type' => 'integer',
                'required' => false,
                'validate_callback' => function($value) {
                    return $value >= 60 && $value <= 86400;
                },
            ],
            'refresh_lifetime' => [
                'type' => 'integer',
                'required' => false,
                'validate_callback' => function($value) {
                    return $value >= 3600 && $value <= 2592000;
                },
            ],
            'device_name' => [
                'type' => 'string',
                'required' => false,
                'sanitize_callback' => 'sanitize_text_field',
            ],
            'device_id' => [
                'type' => 'string',
                'required' => false,
                'sanitize_callback' => 'sanitize_text_field',
            ],
        ];
    }

    private function get_validate_token_args() {
        return [
            'token' => [
                'type' => 'string',
                'required' => false,
                'sanitize_callback' => 'sanitize_text_field',
            ],
        ];
    }

    private function get_revoke_token_args() {
        return [
            'token_id' => [
                'type' => 'string',
                'required' => false,
                'sanitize_callback' => 'sanitize_text_field',
            ],
            'token' => [
                'type' => 'string',
                'required' => false,
                'sanitize_callback' => 'sanitize_text_field',
            ],
        ];
    }

    private function get_refresh_token_args() {
        return [
            'refresh_token' => [
                'type' => 'string',
                'required' => false,
                'sanitize_callback' => 'sanitize_text_field',
            ],
        ];
    }

    private function get_list_tokens_args() {
        return [
            'user_id' => [
                'type' => 'integer',
                'required' => false,
                'sanitize_callback' => 'absint',
            ],
            'active_only' => [
                'type' => 'string',
                'required' => false,
                'default' => 'true',
            ],
            'page' => [
                'type' => 'integer',
                'required' => false,
                'default' => 1,
                'sanitize_callback' => 'absint',
            ],
            'per_page' => [
                'type' => 'integer',
                'required' => false,
                'default' => 20,
                'sanitize_callback' => 'absint',
            ],
        ];
    }

    private function get_introspect_args() {
        return [
            'token' => [
                'type' => 'string',
                'required' => true,
                'sanitize_callback' => 'sanitize_text_field',
            ],
        ];
    }

    private function get_revoke_all_args() {
        return [
            'user_id' => [
                'type' => 'integer',
                'required' => false,
                'sanitize_callback' => 'absint',
            ],
            'token_type' => [
                'type' => 'string',
                'required' => false,
                'enum' => ['access', 'refresh'],
                'sanitize_callback' => 'sanitize_text_field',
            ],
        ];
    }

    // Helper methods

    private function store_device_info($token, $device_name, $device_id) {
        // Extract token_id from JWT
        $validated = JWT::validate_token($token);
        if (is_wp_error($validated)) {
            return;
        }

        global $wpdb;
        $table = $wpdb->prefix . 'rest_shield_tokens';

        $metadata = [];
        if ($device_name) {
            $metadata['device_name'] = $device_name;
        }
        if ($device_id) {
            $metadata['device_id'] = $device_id;
        }

        // Note: This requires adding a metadata column to the tokens table
        // For now, we'll skip this until the table structure is updated
    }
}
