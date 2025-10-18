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
                'issued_at' => date('Y-m-d H:i:s', $issued_at),
                'expires_at' => date('Y-m-d H:i:s', $expires_at),
                'ip_address' => self::get_client_ip(),
            ]
        );
        
        return $token;
    }
    
    /**
     * Validate JWT token
     */
    public static function validate_token($token) {
        try {
            $algorithm = get_option('wp_rest_shield_jwt_algorithm', 'HS256');
            $secret = Plugin::get_jwt_secret();
            
            $payload = self::decode($token, $secret, $algorithm);
            
            if (!$payload) {
                return new \WP_Error('invalid_token', __('Invalid token', 'wp-rest-shield'));
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
            
            // Update last used timestamp
            if ($token_record) {
                $wpdb->update(
                    $table,
                    ['last_used' => current_time('mysql')],
                    ['token_id' => $payload['jti']]
                );
            }
            
            return [
                'user_id' => $payload['sub'],
                'token_id' => $payload['jti'],
                'issued_at' => $payload['iat'],
                'expires_at' => $payload['exp'],
            ];
            
        } catch (\Exception $e) {
            return new \WP_Error('token_error', $e->getMessage());
        }
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