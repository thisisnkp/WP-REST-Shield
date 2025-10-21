# WP REST Shield

Complete WordPress REST API security and monitoring plugin with JWT authentication, rate limiting, access control rules, and comprehensive logging.

## Features

- **Default Block All**: All REST API endpoints are blocked by default after activation
- **JWT Authentication**: Built-in JWT token issuing and validation with HS256/384/512 algorithms
- **Granular Access Rules**: Define precise rules by endpoint pattern, HTTP method, auth type, IP, and more
- **Rate Limiting**: Per-route and global rate limits with burst protection
- **Comprehensive Logging**: Detailed request logs with filtering and CSV export
- **Real-time Dashboard**: Monitor traffic, blocked requests, and top endpoints
- **Server-to-Server Auth**: Backend proxy support with shared secrets
- **CORS Support**: Whitelist allowed origins for frontend applications
- **IP Management**: Global IP whitelist/blacklist with CIDR support
- **Modern Admin UI**: Responsive React-based interface with charts and real-time stats

## Installation

1. Upload the `wp-rest-shield` folder to `/wp-content/plugins/`
2. Activate the plugin through the 'Plugins' menu in WordPress
3. Go to **REST Shield → Settings** to configure

## Quick Start

### 1. Initial Setup

After activation, all REST API endpoints are blocked by default. You'll see an admin notice with a link to settings.

**Important**: Configure at least one allow rule or your frontend/API consumers won't be able to access the API.

### 2. Generate JWT Secret

Go to **Settings → JWT Settings** and click "Generate New" to create a secure JWT secret. 

For production, add this to `wp-config.php`:
```php
define('WP_REST_SHIELD_JWT_SECRET', 'your-generated-secret-here');
```

### 3. Create Access Rules

Go to **REST Shield → Rules** and create your first allow rule:

**Example: Allow public access to posts**
- Name: "Allow Public Posts"
- Endpoint Pattern: `/wp/v2/posts`
- Method: GET
- Action: Allow
- Priority: 10

### 4. Issue a JWT Token

**Using username/password:**
```bash
curl -X POST https://yoursite.com/wp-json/wp-rest-shield/v1/token \
  -H "Content-Type: application/json" \
  -d '{
    "username": "your-username",
    "password": "your-password"
  }'
```

**Response:**
```json
{
  "token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "user_id": 1
}
```

### 5. Use the Token

Include the token in the Authorization header:

```bash
curl https://yoursite.com/wp-json/wp/v2/posts \
  -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGc..."
```

## Authentication Methods

### 1. JWT Token

Issue tokens via `/wp-json/wp-rest-shield/v1/token` and include in requests:

```javascript
// JavaScript example
fetch('https://yoursite.com/wp-json/wp/v2/posts', {
  headers: {
    'Authorization': 'Bearer ' + token
  }
})
```

### 2. Server-to-Server Secret

For backend proxies (e.g., Laravel, Node.js):

1. Add server secret in **Settings → Server-to-Server Authentication**
2. Send in `X-Server-Secret` header:

```bash
curl https://yoursite.com/wp-json/wp/v2/posts \
  -H "X-Server-Secret: your-server-secret"
```

### 3. Application Passwords

WordPress built-in Application Passwords work with WP REST Shield. Use Basic Auth:

```bash
curl https://yoursite.com/wp-json/wp/v2/posts \
  -u "username:application-password"
```

## Access Rules

Rules are evaluated in priority order (lowest number = highest priority). First matching rule determines the action.

### Rule Configuration

- **Endpoint Pattern**: Regex pattern (e.g., `/wp/v2/.*` for all wp/v2 endpoints)
- **HTTP Method**: Specific method or `*` for all
- **Action**: Allow or Block
- **Auth Type**: 
  - `any` - Any authentication state
  - `anonymous` - Only unauthenticated requests
  - `logged_in` - Logged-in WordPress users
  - `jwt` - Valid JWT token required
  - `server_token` - Server secret required
- **Required Capability**: WordPress capability (e.g., `edit_posts`)
- **Rate Limit**: Requests per minute (0 = no limit)
- **IP Whitelist/Blacklist**: One IP or CIDR per line
- **Time Window**: Restrict to specific hours

### Example Rules

**Allow public read access to posts:**
```
Endpoint: /wp/v2/posts
Method: GET
Action: Allow
Auth Type: any
```

**Require JWT for creating posts:**
```
Endpoint: /wp/v2/posts
Method: POST
Action: Allow
Auth Type: jwt
Required Capability: publish_posts
```

**Block a specific endpoint:**
```
Endpoint: /wp/v2/users
Method: *
Action: Block
```

**Rate limit an endpoint:**
```
Endpoint: /wp/v2/comments
Method: POST
Action: Allow
Rate Limit: 10
```

## Rate Limiting

Configure global and per-route rate limits:

- **Global Rate Limit**: Applies to all requests per IP
- **Rule Rate Limit**: Specific to matching rule
- **429 Response**: Returns `Retry-After` header when exceeded

Rate limits use WordPress transients/object cache (Redis compatible).

## Logging

All requests are logged with:
- Timestamp
- IP address
- Endpoint and method
- User ID (if authenticated)
- Token ID (if JWT)
- Status code
- Block reason (if blocked)
- Request/response headers and body

### View Logs

Go to **REST Shield → Logs** to:
- Filter by date, IP, endpoint, status
- Export to CSV
- View detailed request information

### Log Retention

Set retention period in **Settings → Logging**. Old logs are automatically cleaned up daily.

## Dashboard

The dashboard shows:
- Total requests (24h and 7d)
- Blocked requests and block rate
- Top blocked IPs
- Top accessed endpoints
- Activity chart

## Headless WordPress Setup

For headless WordPress with a separate frontend (React, Vue, Next.js, etc.):

### 1. Configure CORS

Add your frontend domain to **Settings → Allowed Origins**:
```
https://yourdomain.com
```

### 2. Create Allow Rules for Frontend

Allow your frontend to access needed endpoints:

```
Name: Frontend Posts Access
Endpoint: /wp/v2/posts.*
Method: GET
Action: Allow
Auth Type: any
```

### 3. Frontend Authentication

**Option A: Public Endpoints**
Allow anonymous access for public content

**Option B: JWT Authentication**
Frontend requests token, stores it, includes in requests:

```javascript
// Get token
const response = await fetch('https://wp.site/wp-json/wp-rest-shield/v1/token', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ username, password })
});
const { token } = await response.json();

// Use token
fetch('https://wp.site/wp-json/wp/v2/posts', {
  headers: { 'Authorization': `Bearer ${token}` }
});
```

### 4. Laravel Proxy Setup

If using Laravel as backend proxy:

```php
// .env
WP_API_URL=https://yoursite.com/wp-json
WP_SERVER_SECRET=your-server-secret

// API call
$response = Http::withHeaders([
    'X-Server-Secret' => env('WP_SERVER_SECRET')
])->get(env('WP_API_URL') . '/wp/v2/posts');
```

## Security Best Practices

1. **Store JWT Secret in wp-config.php**
   ```php
   define('WP_REST_SHIELD_JWT_SECRET', 'your-secret');
   ```

2. **Use HTTPS**: Always use SSL for production

3. **Rotate Secrets**: Regularly rotate JWT and server secrets

4. **Monitor Logs**: Review blocked requests regularly

5. **IP Whitelist**: Whitelist known good IPs (e.g., your servers)

6. **Rate Limits**: Set appropriate rate limits to prevent abuse

7. **Minimal Exposure**: Only allow endpoints you actually need

## API Endpoints

### Issue Token
```
POST /wp-json/wp-rest-shield/v1/token
Body: { "username": "user", "password": "pass" }
```

### Validate Token
```
POST /wp-json/wp-rest-shield/v1/validate
Body: { "token": "your-token" }
or
Header: Authorization: Bearer your-token
```

### Revoke Token
```
POST /wp-json/wp-rest-shield/v1/revoke
Body: { "token_id": "token-id" }
Auth: Required (JWT or server secret)
```

### List Tokens
```
GET /wp-json/wp-rest-shield/v1/tokens
Auth: Admin only
```

### Health Check
```
GET /wp-json/wp-rest-shield/v1/health
Header: X-Server-Secret (optional)
```

## Hooks & Filters

### Filters

**Modify request allowed status:**
```php
add_filter('wp_rest_shield_is_request_allowed', function($allowed, $request) {
    // Custom logic
    return $allowed;
}, 10, 2);
```

**Modify log event before saving:**
```php
add_filter('wp_rest_shield_log_event', function($event_data) {
    // Modify event data
    return $event_data;
}, 10, 1);
```

### Actions

**After request is logged:**
```php
add_action('wp_rest_shield_request_logged', function($request, $blocked) {
    // Custom action
}, 10, 2);
```

## Troubleshooting

### Frontend Can't Access API

1. Check plugin is not in "Enforce" mode while testing
2. Verify allow rules exist for needed endpoints
3. Check browser console for CORS errors
4. Add frontend domain to allowed origins

### Token Validation Fails

1. Verify JWT secret matches between issue and validate
2. Check token hasn't expired
3. Ensure token isn't revoked
4. Verify server time is accurate

### All Requests Blocked

1. Check plugin is enabled
2. Verify mode is not "Enforce" without allow rules
3. Check if admin bypass is enabled (admins can always access)
4. Review rules in priority order

### Rate Limit Issues

1. Object cache recommended for high traffic
2. Transients fallback may be slower
3. Clear cache if limits seem stuck

## Performance

- Minimal overhead per request (~5ms)
- Uses WordPress object cache (Redis compatible)
- Asynchronous logging for high traffic sites
- Database indexes on log table

## Requirements

- WordPress 5.8+
- PHP 7.4+
- MySQL 5.6+ or MariaDB 10.0+

## Support

For issues, feature requests, or questions:
- GitHub Issues: https://github.com/thisisnkp/WP-REST-Shield
- Documentation: https://infotechzone.in/apps/wp-rest-sheild/docs

## License

GPL v2 or later

## Credits

Developed by Neeraj Krishna