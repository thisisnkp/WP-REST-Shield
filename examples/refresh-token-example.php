<?php
/**
 * JWT Refresh Token Example
 * This file demonstrates how to use the refresh token functionality
 */

// Configuration
$base_url = 'http://your-wordpress-site.com'; // Update this
$username = 'your-username'; // Update this
$password = 'your-password'; // Update this

/**
 * Get initial token pair
 */
function get_initial_tokens($base_url, $username, $password) {
    $url = $base_url . '/wp-json/wp-rest-shield/v1/token';
    
    $data = json_encode([
        'username' => $username,
        'password' => $password
    ]);
    
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Content-Type: application/json',
        'Content-Length: ' . strlen($data)
    ]);
    
    $response = curl_exec($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    
    if ($http_code === 200) {
        return json_decode($response, true);
    } else {
        throw new Exception("Failed to get tokens: HTTP $http_code - $response");
    }
}

/**
 * Refresh access token using refresh token
 */
function refresh_access_token($base_url, $refresh_token) {
    $url = $base_url . '/wp-json/wp-rest-shield/v1/refresh';
    
    $data = json_encode([
        'refresh_token' => $refresh_token
    ]);
    
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Content-Type: application/json',
        'Content-Length: ' . strlen($data)
    ]);
    
    $response = curl_exec($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    
    if ($http_code === 200) {
        return json_decode($response, true);
    } else {
        throw new Exception("Failed to refresh token: HTTP $http_code - $response");
    }
}

/**
 * Make authenticated API request
 */
function make_authenticated_request($base_url, $access_token, $endpoint = '/wp/v2/posts') {
    $url = $base_url . '/wp-json' . $endpoint;
    
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Authorization: Bearer ' . $access_token
    ]);
    
    $response = curl_exec($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    
    return [
        'status' => $http_code,
        'data' => json_decode($response, true)
    ];
}

// Example usage
try {
    echo "=== JWT Refresh Token Example ===\n\n";
    
    // Step 1: Get initial tokens
    echo "1. Getting initial token pair...\n";
    $initial_tokens = get_initial_tokens($base_url, $username, $password);
    
    echo "✓ Access Token: " . substr($initial_tokens['access_token'], 0, 50) . "...\n";
    echo "✓ Refresh Token: " . substr($initial_tokens['refresh_token'], 0, 50) . "...\n";
    echo "✓ Access Token Expires In: " . $initial_tokens['expires_in'] . " seconds\n";
    echo "✓ Refresh Token Expires In: " . $initial_tokens['refresh_expires_in'] . " seconds\n\n";
    
    // Step 2: Use access token
    echo "2. Making authenticated request with access token...\n";
    $response = make_authenticated_request($base_url, $initial_tokens['access_token']);
    echo "✓ Request Status: " . $response['status'] . "\n\n";
    
    // Step 3: Refresh the access token
    echo "3. Refreshing access token...\n";
    $refreshed_tokens = refresh_access_token($base_url, $initial_tokens['refresh_token']);
    
    echo "✓ New Access Token: " . substr($refreshed_tokens['access_token'], 0, 50) . "...\n";
    echo "✓ Refresh Token: " . substr($refreshed_tokens['refresh_token'], 0, 50) . "...\n";
    echo "✓ New Access Token Expires In: " . $refreshed_tokens['expires_in'] . " seconds\n\n";
    
    // Step 4: Use new access token
    echo "4. Making authenticated request with new access token...\n";
    $response = make_authenticated_request($base_url, $refreshed_tokens['access_token']);
    echo "✓ Request Status: " . $response['status'] . "\n\n";
    
    echo "=== All tests passed! ===\n";
    
} catch (Exception $e) {
    echo "❌ Error: " . $e->getMessage() . "\n";
}