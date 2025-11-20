<?php
/**
 * ===========================================
 * includes/Core/JWT.php
 * ===========================================
 */

namespace WPRestShield\Core;

class JWT {
    
    /**
     * Generate JWT token for user
     */
    public static function generate_token($user_id, $lifetime = null) {
        if (!$lifetime) {
            $lifetime = get_option('wp_rest_shield_jwt_lifetime', 3600);
        }
        
        $issued_at = time();
        $expires_at = $issued_at + $lifetime;
        $token_id = bin2hex(random_bytes(16));
        
        $payload = [
            'iss' => get_bloginfo('url'),
            'iat' => $issued_at,
            'exp' => $expires_at,
            'sub' => $user_id,
            'jti' => $token_id,
            'type' => 'access'
        ];
        
        $algorithm = get_option('wp_rest_shield_jwt_algorithm', 'HS256');
        $secret = Plugin::get_jwt_secret();
        
        $token = self::encode($payload, $secret, $algorithm);
        
        // Store token in database
        global $wpdb;
        $table = $wpdb->prefix . 'rest_shield_tokens';
        $wpdb->insert(
            $table,
            [
                'token_id' => $token_id,
                'user_id' => $user_id,
                'token_type' => 'access',
                'issued_at' => date('Y-m-d H:i:s', $issued_at),
                'expires_at' => date('Y-m-d H:i:s', $expires_at),
                'ip_address' => self::get_client_ip(),
            ]
        );
        
        return $token;
    }
    
    /**
     * Generate refresh token for user
     */
    public static function generate_refresh_token($user_id, $lifetime = null) {
        if (!$lifetime) {
            $lifetime = get_option('wp_rest_shield_jwt_refresh_lifetime', 86400 * 7); // 7 days default
        }
        
        $issued_at = time();
        $expires_at = $issued_at + $lifetime;
        $token_id = bin2hex(random_bytes(16));
        
        $payload = [
            'iss' => get_bloginfo('url'),
            'iat' => $issued_at,
            'exp' => $expires_at,
            'sub' => $user_id,
            'jti' => $token_id,
            'type' => 'refresh'
        ];
        
        $algorithm = get_option('wp_rest_shield_jwt_algorithm', 'HS256');
        $secret = Plugin::get_jwt_secret();
        
        $token = self::encode($payload, $secret, $algorithm);
        
        // Store refresh token in database
        global $wpdb;
        $table = $wpdb->prefix . 'rest_shield_tokens';
        $wpdb->insert(
            $table,
            [
                'token_id' => $token_id,
                'user_id' => $user_id,
                'token_type' => 'refresh',
                'issued_at' => date('Y-m-d H:i:s', $issued_at),
                'expires_at' => date('Y-m-d H:i:s', $expires_at),
                'ip_address' => self::get_client_ip(),
            ]
        );
        
        return $token;
    }
    
    /**
     * Generate token pair (access + refresh)
     */
    public static function generate_token_pair($user_id, $access_lifetime = null, $refresh_lifetime = null) {
        $access_token = self::generate_token($user_id, $access_lifetime);
        $refresh_token = self::generate_refresh_token($user_id, $refresh_lifetime);
        
        return [
            'access_token' => $access_token,
            'refresh_token' => $refresh_token,
            'token_type' => 'Bearer',
            'expires_in' => $access_lifetime ?: get_option('wp_rest_shield_jwt_lifetime', 3600),
            'refresh_expires_in' => $refresh_lifetime ?: get_option('wp_rest_shield_jwt_refresh_lifetime', 86400 * 7)
        ];
    }
    
    /**
     * Validate JWT token
     */
    public static function validate_token($token, $expected_type = 'access') {
        try {
            $algorithm = get_option('wp_rest_shield_jwt_algorithm', 'HS256');
            $secret = Plugin::get_jwt_secret();
            
            $payload = self::decode($token, $secret, $algorithm);
            
            if (!$payload) {
                return new \WP_Error('invalid_token', __('Invalid token', 'wp-rest-shield'));
            }
            
            // Check token type
            $token_type = $payload['type'] ?? 'access';
            if ($token_type !== $expected_type) {
                return new \WP_Error('invalid_token_type', __('Invalid token type', 'wp-rest-shield'));
            }
            
            // Check expiration
            if (isset($payload['exp']) && $payload['exp'] < time()) {
                return new \WP_Error('token_expired', __('Token has expired', 'wp-rest-shield'));
            }
            
            // Check if token is revoked
            global $wpdb;
            $table = $wpdb->prefix . 'rest_shield_tokens';
            $token_record = $wpdb->get_row($wpdb->prepare(
                "SELECT * FROM $table WHERE token_id = %s",
                $payload['jti']
            ));
            
            if ($token_record && $token_record->revoked) {
                return new \WP_Error('token_revoked', __('Token has been revoked', 'wp-rest-shield'));
            }
            
            // Update last used timestamp for access tokens
            if ($token_record && $expected_type === 'access') {
                $wpdb->update(
                    $table,
                    ['last_used' => current_time('mysql')],
                    ['token_id' => $payload['jti']]
                );
            }
            
            return [
                'user_id' => $payload['sub'] ?? 0,
                'token_id' => $payload['jti'] ?? '',
                'token_type' => $token_type,
                'issued_at' => $payload['iat'] ?? time(),
                'expires_at' => $payload['exp'] ?? time(),
            ];
            
        } catch (\Exception $e) {
            return new \WP_Error('token_error', $e->getMessage());
        }
    }
    
    /**
     * Refresh access token using refresh token
     */
    public static function refresh_token($refresh_token) {
        $validated = self::validate_token($refresh_token, 'refresh');
        
        if (is_wp_error($validated)) {
            return $validated;
        }
        
        $user_id = $validated['user_id'];
        
        // Generate new access token
        $new_access_token = self::generate_token($user_id);
        
        // Optionally generate new refresh token (rotating refresh tokens)
        $rotate_refresh = get_option('wp_rest_shield_rotate_refresh_tokens', false);
        $new_refresh_token = $refresh_token;
        
        if ($rotate_refresh) {
            // Revoke old refresh token
            self::revoke_token($validated['token_id']);
            // Generate new refresh token
            $new_refresh_token = self::generate_refresh_token($user_id);
        }
        
        return [
            'access_token' => $new_access_token,
            'refresh_token' => $new_refresh_token,
            'token_type' => 'Bearer',
            'expires_in' => get_option('wp_rest_shield_jwt_lifetime', 3600),
        ];
    }
    
    /**
     * Revoke a token
     */
    public static function revoke_token($token_id) {
        global $wpdb;
        $table = $wpdb->prefix . 'rest_shield_tokens';
        
        return $wpdb->update(
            $table,
            ['revoked' => 1],
            ['token_id' => $token_id]
        );
    }
    
    /**
     * Encode JWT token
     */
    private static function encode($payload, $secret, $algorithm = 'HS256') {
        $header = [
            'typ' => 'JWT',
            'alg' => $algorithm,
        ];
        
        $segments = [];
        $segments[] = self::base64url_encode(json_encode($header));
        $segments[] = self::base64url_encode(json_encode($payload));
        
        $signing_input = implode('.', $segments);
        $signature = self::sign($signing_input, $secret, $algorithm);
        $segments[] = self::base64url_encode($signature);
        
        return implode('.', $segments);
    }
    
    /**
     * Decode JWT token
     */
    private static function decode($token, $secret, $algorithm = 'HS256') {
        $segments = explode('.', $token);
        
        if (count($segments) !== 3) {
            throw new \Exception('Invalid token format');
        }
        
        list($header_b64, $payload_b64, $signature_b64) = $segments;
        
        $header = json_decode(self::base64url_decode($header_b64), true);
        $payload = json_decode(self::base64url_decode($payload_b64), true);
        $signature = self::base64url_decode($signature_b64);
        
        if (!$header || !$payload) {
            throw new \Exception('Invalid token encoding');
        }
        
        // Verify signature
        $signing_input = $header_b64 . '.' . $payload_b64;
        $expected_signature = self::sign($signing_input, $secret, $algorithm);
        
        if (!hash_equals($expected_signature, $signature)) {
            throw new \Exception('Signature verification failed');
        }
        
        return $payload;
    }
    
    /**
     * Sign data with secret
     */
    private static function sign($input, $secret, $algorithm) {
        switch ($algorithm) {
            case 'HS256':
                return hash_hmac('sha256', $input, $secret, true);
            case 'HS384':
                return hash_hmac('sha384', $input, $secret, true);
            case 'HS512':
                return hash_hmac('sha512', $input, $secret, true);
            default:
                throw new \Exception('Unsupported algorithm');
        }
    }
    
    /**
     * Base64 URL encode
     */
    private static function base64url_encode($data) {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }
    
    /**
     * Base64 URL decode
     */
    private static function base64url_decode($data) {
        return base64_decode(strtr($data, '-_', '+/'));
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