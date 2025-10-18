<?php
/**
 * WP REST Shield Test Suite
 * File: tests/test-wp-rest-shield.php
 * 
 * Run with: phpunit tests/test-wp-rest-shield.php
 */

use WPRestShield\Core\JWT;
use WPRestShield\Core\Plugin;
use WPRestShield\Core\RestFilter;
use WPRestShield\Core\RateLimiter;
use WPRestShield\Core\Logger;

class WPRestShieldTest extends WP_UnitTestCase {
    
    protected $user_id;
    protected $admin_id;
    
    public function setUp() {
        parent::setUp();
        
        // Create test users
        $this->user_id = $this->factory->user->create([
            'role' => 'subscriber'
        ]);
        
        $this->admin_id = $this->factory->user->create([
            'role' => 'administrator'
        ]);
        
        // Enable plugin
        update_option('wp_rest_shield_enabled', true);
        update_option('wp_rest_shield_mode', 'enforce');
    }
    
    public function tearDown() {
        parent::tearDown();
        
        // Clean up
        wp_delete_user($this->user_id);
        wp_delete_user($this->admin_id);
    }
    
    /**
     * Test JWT Token Generation
     */
    public function test_jwt_token_generation() {
        $token = JWT::generate_token($this->user_id, 3600);
        
        $this->assertNotEmpty($token);
        $this->assertIsString($token);
        
        // Token should have 3 parts separated by dots
        $parts = explode('.', $token);
        $this->assertCount(3, $parts);
    }
    
    /**
     * Test JWT Token Validation
     */
    public function test_jwt_token_validation() {
        $token = JWT::generate_token($this->user_id, 3600);
        $validated = JWT::validate_token($token);
        
        $this->assertFalse(is_wp_error($validated));
        $this->assertEquals($this->user_id, $validated['user_id']);
        $this->assertArrayHasKey('token_id', $validated);
        $this->assertArrayHasKey('expires_at', $validated);
    }
    
    /**
     * Test Expired Token Rejection
     */
    public function test_expired_token_rejection() {
        // Generate token with 1 second lifetime
        $token = JWT::generate_token($this->user_id, 1);
        
        // Wait for token to expire
        sleep(2);
        
        $validated = JWT::validate_token($token);
        
        $this->assertWPError($validated);
        $this->assertEquals('token_expired', $validated->get_error_code());
    }
    
    /**
     * Test Invalid Token Format
     */
    public function test_invalid_token_format() {
        $validated = JWT::validate_token('invalid.token.format');
        
        $this->assertWPError($validated);
    }
    
    /**
     * Test Token Revocation
     */
    public function test_token_revocation() {
        $token = JWT::generate_token($this->user_id, 3600);
        $validated = JWT::validate_token($token);
        
        $this->assertFalse(is_wp_error($validated));
        
        $token_id = $validated['token_id'];
        
        // Revoke token
        JWT::revoke_token($token_id);
        
        // Try to validate revoked token
        $validated_after = JWT::validate_token($token);
        
        $this->assertWPError($validated_after);
        $this->assertEquals('token_revoked', $validated_after->get_error_code());
    }
    
    /**
     * Test Rule Matching
     */
    public function test_rule_matching() {
        global $wpdb;
        $table = $wpdb->prefix . 'rest_shield_rules';
        
        // Create allow rule for /wp/v2/posts GET
        $wpdb->insert($table, [
            'name' => 'Test Allow Posts',
            'endpoint_pattern' => '/wp/v2/posts',
            'method' => 'GET',
            'action' => 'allow',
            'priority' => 10,
            'enabled' => 1,
            'created_at' => current_time('mysql')
        ]);
        
        // Create test request
        $request = new WP_REST_Request('GET', '/wp/v2/posts');
        
        // Request should be allowed
        $filter = new RestFilter();
        $result = $filter->filter_rest_request(null, null, $request);
        
        $this->assertNull($result); // Null means allowed
        
        // Clean up
        $wpdb->delete($table, ['name' => 'Test Allow Posts']);
    }
    
    /**
     * Test Anonymous Request Blocking
     */
    public function test_anonymous_request_blocking() {
        // Make sure no allow rules exist
        global $wpdb;
        $table = $wpdb->prefix . 'rest_shield_rules';
        $wpdb->query("DELETE FROM $table WHERE action = 'allow'");
        
        $request = new WP_REST_Request('GET', '/wp/v2/posts');
        
        $filter = new RestFilter();
        $result = $filter->filter_rest_request(null, null, $request);
        
        $this->assertWPError($result);
        $this->assertEquals('rest_blocked', $result->get_error_code());
    }
    
    /**
     * Test Admin Bypass
     */
    public function test_admin_bypass() {
        update_option('wp_rest_shield_admin_bypass', true);
        
        // Set current user as admin
        wp_set_current_user($this->admin_id);
        
        $request = new WP_REST_Request('GET', '/wp/v2/posts');
        
        $filter = new RestFilter();
        $result = $filter->filter_rest_request(null, null, $request);
        
        // Should be allowed because admin
        $this->assertNull($result);
        
        // Reset
        wp_set_current_user(0);
    }
    
    /**
     * Test Monitor Mode
     */
    public function test_monitor_mode() {
        update_option('wp_rest_shield_mode', 'monitor');
        
        $request = new WP_REST_Request('GET', '/wp/v2/posts');
        
        $filter = new RestFilter();
        $result = $filter->filter_rest_request(null, null, $request);
        
        // In monitor mode, requests should not be blocked
        $this->assertNull($result);
    }
    
    /**
     * Test Rate Limiting
     */
    public function test_rate_limiting() {
        update_option('wp_rest_shield_global_rate_limit', 5);
        
        $request = new WP_REST_Request('GET', '/wp/v2/posts');
        
        // Make 5 requests (should succeed)
        for ($i = 0; $i < 5; $i++) {
            $result = RateLimiter::check_limit($request);
            $this->assertTrue($result);
        }
        
        // 6th request should fail
        $result = RateLimiter::check_limit($request);
        $this->assertWPError($result);
        $this->assertEquals('rate_limit_exceeded', $result->get_error_code());
    }
    
    /**
     * Test IP Whitelist
     */
    public function test_ip_whitelist() {
        $_SERVER['REMOTE_ADDR'] = '192.168.1.100';
        
        update_option('wp_rest_shield_ip_whitelist', ['192.168.1.100']);
        
        $request = new WP_REST_Request('GET', '/wp/v2/posts');
        
        $filter = new RestFilter();
        $result = $filter->filter_rest_request(null, null, $request);
        
        // Whitelisted IP should be allowed
        $this->assertNull($result);
    }
    
    /**
     * Test IP Blacklist
     */
    public function test_ip_blacklist() {
        $_SERVER['REMOTE_ADDR'] = '10.0.0.1';
        
        update_option('wp_rest_shield_ip_blacklist', ['10.0.0.1']);
        
        $request = new WP_REST_Request('GET', '/wp/v2/posts');
        
        $filter = new RestFilter();
        $result = $filter->filter_rest_request(null, null, $request);
        
        // Blacklisted IP should be blocked
        $this->assertWPError($result);
    }
    
    /**
     * Test CIDR Range Matching
     */
    public function test_cidr_range_matching() {
        $_SERVER['REMOTE_ADDR'] = '192.168.1.50';
        
        update_option('wp_rest_shield_ip_whitelist', ['192.168.1.0/24']);
        
        $request = new WP_REST_Request('GET', '/wp/v2/posts');
        
        $filter = new RestFilter();
        $result = $filter->filter_rest_request(null, null, $request);
        
        // IP in CIDR range should be allowed
        $this->assertNull($result);
    }
    
    /**
     * Test Server Secret Authentication
     */
    public function test_server_secret_authentication() {
        $secret = 'test-server-secret-' . bin2hex(random_bytes(16));
        
        update_option('wp_rest_shield_server_secrets', [$secret]);
        $_SERVER['HTTP_X_SERVER_SECRET'] = $secret;
        
        $filter = new RestFilter();
        $auth = $filter->handle_authentication(null);
        
        $this->assertTrue($auth);
        
        // Clean up
        unset($_SERVER['HTTP_X_SERVER_SECRET']);
    }
    
    /**
     * Test Invalid Server Secret
     */
    public function test_invalid_server_secret() {
        update_option('wp_rest_shield_server_secrets', ['valid-secret']);
        $_SERVER['HTTP_X_SERVER_SECRET'] = 'invalid-secret';
        
        $filter = new RestFilter();
        $auth = $filter->handle_authentication(null);
        
        // Should not authenticate
        $this->assertNotTrue($auth);
        
        unset($_SERVER['HTTP_X_SERVER_SECRET']);
    }
    
    /**
     * Test Logging Functionality
     */
    public function test_logging() {
        update_option('wp_rest_shield_log_enabled', true);
        
        $request = new WP_REST_Request('GET', '/wp/v2/posts');
        
        // Log a request
        Logger::log_request($request, true, 'Test block reason');
        
        // Retrieve logs
        $logs = Logger::get_logs(['limit' => 1]);
        
        $this->assertNotEmpty($logs);
        $this->assertEquals('/wp/v2/posts', $logs[0]['endpoint']);
        $this->assertEquals('GET', $logs[0]['method']);
        $this->assertEquals(1, $logs[0]['blocked']);
        $this->assertEquals('Test block reason', $logs[0]['block_reason']);
    }
    
    /**
     * Test Log Filtering
     */
    public function test_log_filtering() {
        update_option('wp_rest_shield_log_enabled', true);
        
        // Log multiple requests
        $request1 = new WP_REST_Request('GET', '/wp/v2/posts');
        $request2 = new WP_REST_Request('POST', '/wp/v2/comments');
        
        Logger::log_request($request1, true, 'Blocked');
        Logger::log_request($request2, false, '');
        
        // Filter blocked only
        $blocked_logs = Logger::get_logs(['blocked' => 1]);
        
        $this->assertNotEmpty($blocked_logs);
        
        foreach ($blocked_logs as $log) {
            $this->assertEquals(1, $log['blocked']);
        }
    }
    
    /**
     * Test Statistics Generation
     */
    public function test_statistics_generation() {
        update_option('wp_rest_shield_log_enabled', true);
        
        // Create some test logs
        $request = new WP_REST_Request('GET', '/wp/v2/posts');
        
        for ($i = 0; $i < 10; $i++) {
            Logger::log_request($request, $i % 2 === 0, $i % 2 === 0 ? 'Blocked' : '');
        }
        
        $stats = Logger::get_stats('24h');
        
        $this->assertArrayHasKey('total_requests', $stats);
        $this->assertArrayHasKey('blocked_requests', $stats);
        $this->assertGreaterThan(0, $stats['total_requests']);
    }
    
    /**
     * Test Endpoint Pattern Regex
     */
    public function test_endpoint_pattern_regex() {
        global $wpdb;
        $table = $wpdb->prefix . 'rest_shield_rules';
        
        // Create rule with regex pattern
        $wpdb->insert($table, [
            'name' => 'Test Regex Pattern',
            'endpoint_pattern' => '/wp/v2/posts.*',
            'method' => '*',
            'action' => 'allow',
            'priority' => 10,
            'enabled' => 1,
            'created_at' => current_time('mysql')
        ]);
        
        // Should match /wp/v2/posts
        $request1 = new WP_REST_Request('GET', '/wp/v2/posts');
        $filter = new RestFilter();
        $result1 = $filter->filter_rest_request(null, null, $request1);
        $this->assertNull($result1);
        
        // Should match /wp/v2/posts/123
        $request2 = new WP_REST_Request('GET', '/wp/v2/posts/123');
        $result2 = $filter->filter_rest_request(null, null, $request2);
        $this->assertNull($result2);
        
        // Clean up
        $wpdb->delete($table, ['name' => 'Test Regex Pattern']);
    }
    
    /**
     * Test Rule Priority
     */
    public function test_rule_priority() {
        global $wpdb;
        $table = $wpdb->prefix . 'rest_shield_rules';
        
        // Create high priority block rule
        $wpdb->insert($table, [
            'name' => 'High Priority Block',
            'endpoint_pattern' => '/wp/v2/posts',
            'method' => 'GET',
            'action' => 'block',
            'priority' => 1,
            'enabled' => 1,
            'created_at' => current_time('mysql')
        ]);
        
        // Create low priority allow rule
        $wpdb->insert($table, [
            'name' => 'Low Priority Allow',
            'endpoint_pattern' => '/wp/v2/posts',
            'method' => 'GET',
            'action' => 'allow',
            'priority' => 10,
            'enabled' => 1,
            'created_at' => current_time('mysql')
        ]);
        
        $request = new WP_REST_Request('GET', '/wp/v2/posts');
        $filter = new RestFilter();
        $result = $filter->filter_rest_request(null, null, $request);
        
        // High priority block rule should take precedence
        $this->assertWPError($result);
        
        // Clean up
        $wpdb->delete($table, ['name' => 'High Priority Block']);
        $wpdb->delete($table, ['name' => 'Low Priority Allow']);
    }
    
    /**
     * Test Plugin Enable/Disable
     */
    public function test_plugin_enable_disable() {
        // Disable plugin
        update_option('wp_rest_shield_enabled', false);
        
        $request = new WP_REST_Request('GET', '/wp/v2/posts');
        $filter = new RestFilter();
        $result = $filter->filter_rest_request(null, null, $request);
        
        // Should not block when disabled
        $this->assertNull($result);
        
        // Re-enable
        update_option('wp_rest_shield_enabled', true);
    }
    
    /**
     * Test Token Endpoint
     */
    public function test_token_endpoint() {
        $username = 'testuser';
        $password = 'testpass123';
        
        // Create test user
        $user_id = wp_create_user($username, $password, 'test@example.com');
        
        $request = new WP_REST_Request('POST', '/wp-rest-shield/v1/token');
        $request->set_param('username', $username);
        $request->set_param('password', $password);
        
        $endpoint = new \WPRestShield\API\TokenEndpoint();
        $response = $endpoint->issue_token($request);
        
        $this->assertInstanceOf('WP_REST_Response', $response);
        $this->assertEquals(200, $response->get_status());
        
        $data = $response->get_data();
        $this->assertArrayHasKey('token', $data);
        $this->assertArrayHasKey('expires_in', $data);
        
        // Clean up
        wp_delete_user($user_id);
    }
    
    /**
     * Test Health Check Endpoint
     */
    public function test_health_check_endpoint() {
        $request = new WP_REST_Request('GET', '/wp-rest-shield/v1/health');
        
        $endpoint = new \WPRestShield\API\TokenEndpoint();
        $response = $endpoint->health_check($request);
        
        $this->assertInstanceOf('WP_REST_Response', $response);
        $this->assertEquals(200, $response->get_status());
        
        $data = $response->get_data();
        $this->assertArrayHasKey('status', $data);
        $this->assertEquals('ok', $data['status']);
    }
    
    /**
     * Test Database Table Creation
     */
    public function test_database_tables_exist() {
        global $wpdb;
        
        $tables = [
            $wpdb->prefix . 'rest_shield_logs',
            $wpdb->prefix . 'rest_shield_rules',
            $wpdb->prefix . 'rest_shield_tokens'
        ];
        
        foreach ($tables as $table) {
            $exists = $wpdb->get_var("SHOW TABLES LIKE '$table'");
            $this->assertEquals($table, $exists, "Table $table should exist");
        }
    }
}

/**
 * Integration Tests
 */
class WPRestShieldIntegrationTest extends WP_UnitTestCase {
    
    /**
     * Test Complete Authentication Flow
     */
    public function test_complete_authentication_flow() {
        // 1. Create user
        $user_id = $this->factory->user->create([
            'user_login' => 'integrationtest',
            'user_pass' => 'testpass123'
        ]);
        
        // 2. Get token
        $token = JWT::generate_token($user_id, 3600);
        $this->assertNotEmpty($token);
        
        // 3. Validate token
        $validated = JWT::validate_token($token);
        $this->assertFalse(is_wp_error($validated));
        
        // 4. Create allow rule
        global $wpdb;
        $table = $wpdb->prefix . 'rest_shield_rules';
        $wpdb->insert($table, [
            'name' => 'Integration Test Allow',
            'endpoint_pattern' => '/wp/v2/posts',
            'method' => 'GET',
            'action' => 'allow',
            'auth_type' => 'jwt',
            'priority' => 10,
            'enabled' => 1,
            'created_at' => current_time('mysql')
        ]);
        
        // 5. Simulate authenticated request
        $_SERVER['HTTP_AUTHORIZATION'] = 'Bearer ' . $token;
        $request = new WP_REST_Request('GET', '/wp/v2/posts');
        
        $filter = new RestFilter();
        $auth_result = $filter->handle_authentication(null);
        $this->assertTrue($auth_result);
        
        // 6. Request should be allowed
        $filter_result = $filter->filter_rest_request(null, null, $request);
        $this->assertNull($filter_result);
        
        // Clean up
        unset($_SERVER['HTTP_AUTHORIZATION']);
        wp_delete_user($user_id);
        $wpdb->delete($table, ['name' => 'Integration Test Allow']);
    }
    
    /**
     * Test Rate Limiting with Multiple Requests
     */
    public function test_rate_limiting_integration() {
        update_option('wp_rest_shield_global_rate_limit', 3);
        
        $_SERVER['REMOTE_ADDR'] = '203.0.113.100';
        
        $request = new WP_REST_Request('GET', '/wp/v2/posts');
        
        $allowed_count = 0;
        $blocked_count = 0;
        
        // Make 10 requests
        for ($i = 0; $i < 10; $i++) {
            $result = RateLimiter::check_limit($request);
            
            if (is_wp_error($result)) {
                $blocked_count++;
            } else {
                $allowed_count++;
            }
        }
        
        // First 3 should be allowed, rest blocked
        $this->assertEquals(3, $allowed_count);
        $this->assertEquals(7, $blocked_count);
    }
}