# WP REST Shield - Installation & Setup Guide

## Table of Contents
1. [Installation](#installation)
2. [Initial Configuration](#initial-configuration)
3. [Common Use Cases](#common-use-cases)
4. [Troubleshooting](#troubleshooting)
5. [Advanced Configuration](#advanced-configuration)

---

## Installation

### Method 1: WordPress Admin (Recommended)

1. Download the `wp-rest-shield.zip` file
2. Log in to WordPress Admin
3. Navigate to **Plugins → Add New → Upload Plugin**
4. Choose the zip file and click **Install Now**
5. Click **Activate Plugin**

### Method 2: Manual Installation

1. Extract the zip file
2. Upload the `wp-rest-shield` folder to `/wp-content/plugins/`
3. Activate via **Plugins** menu in WordPress Admin

### Method 3: WP-CLI

```bash
wp plugin install wp-rest-shield.zip --activate
```

---

## Initial Configuration

### Step 1: Access Plugin Settings

After activation, you'll see a notice. Click **Configure Settings** or navigate to:
- **Dashboard → REST Shield** (main menu)
- **Settings → WP REST Shield**

### Step 2: Generate JWT Secret

1. Go to **REST Shield → Settings**
2. Scroll to **JWT Settings**
3. Click **Generate New** to create a secure secret
4. **Important**: Copy the generated secret

For production, add to `wp-config.php`:

```php
define('WP_REST_SHIELD_JWT_SECRET', 'your-generated-secret-here');
```

### Step 3: Set Operating Mode

Choose your mode:

- **Enforce Mode** (Recommended for production): Blocks unauthorized requests
- **Monitor Mode** (Recommended for testing): Logs requests but doesn't block

Start with **Monitor Mode** to test your configuration.

### Step 4: Create Your First Allow Rule

By default, **all endpoints are blocked**. You need to create allow rules.

#### Example: Allow Public Access to Posts

1. Go to **REST Shield → Rules**
2. Click **Add New Rule**
3. Configure:
   - **Name**: `Allow Public Posts`
   - **Endpoint Pattern**: `/wp/v2/posts`
   - **Method**: `GET`
   - **Action**: `Allow`
   - **Auth Type**: `any`
   - **Priority**: `10`
4. Click **Save Rule**

### Step 5: Test Your Configuration

Test with curl:

```bash
curl https://yoursite.com/wp-json/wp/v2/posts
```

Should return posts (not 401 error).

---

## Common Use Cases

### Use Case 1: Headless WordPress with React Frontend

**Scenario**: React app on `https://myapp.com` needs to access WordPress API at `https://wp.mysite.com`

**Configuration**:

1. **Add Frontend Domain to CORS**
   - Settings → Allowed Origins
   - Add: `https://myapp.com`

2. **Create Allow Rules for Public Endpoints**
   ```
   Rule 1: Allow Posts (GET)
   - Endpoint: /wp/v2/posts.*
   - Method: GET
   - Action: Allow
   
   Rule 2: Allow Categories (GET)
   - Endpoint: /wp/v2/categories.*
   - Method: GET
   - Action: Allow
   
   Rule 3: Allow Media (GET)
   - Endpoint: /wp/v2/media.*
   - Method: GET
   - Action: Allow
   ```

3. **Create JWT Rules for Authenticated Actions**
   ```
   Rule 4: Allow Post Creation (JWT)
   - Endpoint: /wp/v2/posts
   - Method: POST
   - Action: Allow
   - Auth Type: jwt
   - Required Capability: publish_posts
   ```

**Frontend Code**:

```javascript
// Get token
const token = await fetch('https://wp.mysite.com/wp-json/wp-rest-shield/v1/token', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ username: 'user', password: 'pass' })
}).then(r => r.json());

// Fetch posts
const posts = await fetch('https://wp.mysite.com/wp-json/wp/v2/posts', {
  headers: { 'Authorization': `Bearer ${token.token}` }
}).then(r => r.json());
```

---

### Use Case 2: Laravel Backend Proxy

**Scenario**: Laravel app proxies requests to WordPress

**WordPress Configuration**:

1. **Generate Server Secret**
   - Settings → Server-to-Server Authentication
   - Add new secret: `laravel-secret-abc123xyz`

2. **Create Allow Rule for Laravel**
   ```
   Rule: Laravel Proxy Access
   - Endpoint: .*
   - Method: *
   - Action: Allow
   - Auth Type: server_token
   ```

**Laravel Configuration**:

```php
// .env
WP_API_URL=https://yoursite.com/wp-json
WP_SERVER_SECRET=laravel-secret-abc123xyz

// Controller
use Illuminate\Support\Facades\Http;

$response = Http::withHeaders([
    'X-Server-Secret' => env('WP_SERVER_SECRET')
])->get(env('WP_API_URL') . '/wp/v2/posts');

return $response->json();
```

---

### Use Case 3: Mobile App with JWT

**Scenario**: iOS/Android app needs secure API access

**Configuration**:

1. **Create Allow Rules for Mobile**
   ```
   Rule 1: Mobile Login
   - Endpoint: /wp-rest-shield/v1/token
   - Method: POST
   - Action: Allow
   - Auth Type: any
   
   Rule 2: Mobile Content Access
   - Endpoint: /wp/v2/.*
   - Method: GET
   - Action: Allow
   - Auth Type: jwt
   ```

2. **Set Token Lifetime**
   - Settings → JWT Settings
   - Token Lifetime: `86400` (24 hours for mobile)

**Mobile App Code** (Swift):

```swift
// Login
func login(username: String, password: String) async throws -> String {
    let url = URL(string: "https://yoursite.com/wp-json/wp-rest-shield/v1/token")!
    var request = URLRequest(url: url)
    request.httpMethod = "POST"
    request.setValue("application/json", forHTTPHeaderField: "Content-Type")
    
    let body = ["username": username, "password": password]
    request.httpBody = try JSONEncoder().encode(body)
    
    let (data, _) = try await URLSession.shared.data(for: request)
    let response = try JSONDecoder().decode(TokenResponse.self, from: data)
    return response.token
}

// API Request
func fetchPosts(token: String) async throws -> [Post] {
    let url = URL(string: "https://yoursite.com/wp-json/wp/v2/posts")!
    var request = URLRequest(url: url)
    request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
    
    let (data, _) = try await URLSession.shared.data(for: request)
    return try JSONDecoder().decode([Post].self, from: data)
}
```

---

### Use Case 4: Protect WooCommerce API

**Scenario**: Secure WooCommerce REST API endpoints

**Configuration**:

1. **Block WooCommerce by Default**
   ```
   Rule 1: Block WooCommerce
   - Endpoint: /wc/v3/.*
   - Method: *
   - Action: Block
   - Priority: 999
   ```

2. **Allow Specific Endpoints with JWT**
   ```
   Rule 2: Allow Products (Read)
   - Endpoint: /wc/v3/products.*
   - Method: GET
   - Action: Allow
   - Auth Type: jwt
   - Priority: 10
   
   Rule 3: Allow Orders (Create)
   - Endpoint: /wc/v3/orders
   - Method: POST
   - Action: Allow
   - Auth Type: jwt
   - Required Capability: edit_shop_orders
   - Priority: 10
   ```

3. **Rate Limit Checkout**
   ```
   Rule 4: Rate Limit Orders
   - Endpoint: /wc/v3/orders
   - Method: POST
   - Action: Allow
   - Rate Limit: 10
   ```

---

## Troubleshooting

### Problem: "All requests return 401"

**Solution**:
1. Check if plugin is in **Enforce** mode
2. Verify allow rules exist and are **enabled**
3. Check rule priority (lower number = higher priority)
4. Test in **Monitor** mode first

### Problem: "JWT token not working"

**Solution**:
1. Verify token hasn't expired
2. Check JWT secret matches between generation and validation
3. Ensure `Authorization: Bearer token` header is correct
4. Check token wasn't revoked

### Problem: "Frontend CORS errors"

**Solution**:
1. Add frontend domain to **Allowed Origins**
2. Ensure domain matches exactly (include https://)
3. Check browser console for specific error
4. Verify allow rules exist for OPTIONS requests

### Problem: "Rate limit always triggered"

**Solution**:
1. Check if Redis/Memcached is available
2. Clear object cache
3. Increase rate limit value
4. Check if IP is correctly detected (check logs)

### Problem: "Admin can't access anything"

**Solution**:
1. Enable **Admin Bypass** in Settings → General
2. Verify user has `manage_options` capability
3. Check if logged in properly

---

## Advanced Configuration

### 1. IP Whitelisting for Known Servers

**Settings → Global IP Lists**

Add your server IPs (supports CIDR):
```
203.0.113.0/24
198.51.100.50
```

### 2. Time-Based Access Control

Create rule with time restrictions:
```
Rule: Business Hours Only
- Endpoint: /wp/v2/posts
- Method: POST
- Time Start: 09:00:00
- Time End: 18:00:00
```

### 3. Custom Rate Limits per Endpoint

```
Rule: Comment Rate Limit
- Endpoint: /wp/v2/comments
- Method: POST
- Rate Limit: 5 (requests/minute)
```

### 4. Multiple Authentication Methods

```
Rule: Flexible Auth
- Endpoint: /wp/v2/posts
- Method: GET
- Auth Type: any