# WP REST Shield - Quick Reference Card

## 🚀 Quick Start (3 Steps)

```bash
1. Activate plugin → All APIs blocked by default
2. Settings → JWT → Click "Generate New"
3. Rules → Add allow rule for your endpoints
```

---

## 📋 Common Commands

### Get JWT Token
```bash
curl -X POST https://site.com/wp-json/wp-rest-shield/v1/token \
  -H "Content-Type: application/json" \
  -d '{"username":"user","password":"pass"}'
```

### Use JWT Token
```bash
curl https://site.com/wp-json/wp/v2/posts \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### Server-to-Server Request
```bash
curl https://site.com/wp-json/wp/v2/posts \
  -H "X-Server-Secret: YOUR_SECRET"
```

### Validate Token
```bash
curl -X POST https://site.com/wp-json/wp-rest-shield/v1/validate \
  -H "Authorization: Bearer YOUR_TOKEN"
```

---

## 🔧 Plugin Endpoints

| Endpoint | Method | Purpose | Auth |
|----------|--------|---------|------|
| `/wp-rest-shield/v1/token` | POST | Issue JWT token | None |
| `/wp-rest-shield/v1/validate` | POST | Validate token | None |
| `/wp-rest-shield/v1/revoke` | POST | Revoke token | Required |
| `/wp-rest-shield/v1/tokens` | GET | List active tokens | Admin |
| `/wp-rest-shield/v1/health` | GET | Health check | Optional |

---

## 🎯 Rule Configuration

### Basic Allow Rule
```
Name: Allow Public Posts
Endpoint: /wp/v2/posts
Method: GET
Action: Allow
Priority: 10
```

### Authenticated Rule
```
Name: Create Posts (JWT)
Endpoint: /wp/v2/posts
Method: POST
Action: Allow
Auth Type: jwt
Capability: publish_posts
```

### Rate Limited Rule
```
Name: Comment Limit
Endpoint: /wp/v2/comments
Method: POST
Rate Limit: 10
```

### Regex Pattern Rule
```
Name: Allow All WP v2 (GET)
Endpoint: /wp/v2/.*
Method: GET
Action: Allow
```

---

## 🔐 Auth Types

| Type | Description | Use Case |
|------|-------------|----------|
| `any` | Any auth state | Public endpoints |
| `anonymous` | No authentication | Rate-limited public access |
| `logged_in` | WordPress user | Admin pages |
| `jwt` | Valid JWT token | API consumers |
| `server_token` | Server secret | Backend proxies |

---

## ⚙️ Settings Quick Reference

### General
- **Enable Plugin**: Master on/off switch
- **Mode**: `enforce` or `monitor`
- **Admin Bypass**: Let admins bypass rules

### JWT
- **Secret**: 64-char hex (store in wp-config.php)
- **Lifetime**: Seconds (default: 3600)
- **Algorithm**: HS256, HS384, or HS512

### Rate Limiting
- **Global Limit**: Requests/minute per IP
- **Per-Rule Limit**: Override global per endpoint

### Server Secrets
- One per line
- Sent in `X-Server-Secret` header

---

## 🔍 Endpoint Patterns (Regex)

| Pattern | Matches |
|---------|---------|
| `/wp/v2/posts` | Exact: /wp/v2/posts only |
| `/wp/v2/posts.*` | All: /wp/v2/posts, /wp/v2/posts/123 |
| `/wp/v2/.*` | All wp/v2 endpoints |
| `.*` | Everything (use carefully!) |
| `/wp/v2/(posts\|pages)` | Posts OR pages |

---

## 📊 HTTP Status Codes

| Code | Meaning | When |
|------|---------|------|
| 200 | OK | Request allowed |
| 401 | Unauthorized | Blocked by plugin |
| 429 | Too Many Requests | Rate limit exceeded |
| 403 | Forbidden | IP blacklisted |

---

## 🐛 Debugging Checklist

```
❌ Getting 401 errors?
   → Check plugin mode (Monitor vs Enforce)
   → Verify allow rule exists and enabled
   → Check rule priority order
   → Test with Admin Bypass enabled

❌ JWT not working?
   → Verify secret matches
   → Check token expiration
   → Ensure Bearer format: "Bearer TOKEN"
   → Check token not revoked

❌ CORS errors?
   → Add frontend domain to Allowed Origins
   → Include https:// in domain
   → Check browser console for details

❌ Rate limit issues?
   → Clear WordPress cache
   → Check rate limit values
   → Verify IP detection in logs
```

---

## 💻 Code Snippets

### JavaScript Fetch
```javascript
// Get token
const { token } = await fetch('/wp-json/wp-rest-shield/v1/token', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ username, password })
}).then(r => r.json());

// Use token
const posts = await fetch('/wp-json/wp/v2/posts', {
  headers: { 'Authorization': `Bearer ${token}` }
}).then(r => r.json());
```

### PHP cURL
```php
// Get token
$ch = curl_init('https://site.com/wp-json/wp-rest-shield/v1/token');
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode([
    'username' => 'user',
    'password' => 'pass'
]));
curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
$response = json_decode(curl_exec($ch), true);
$token = $response['token'];

// Use token
$ch = curl_init('https://site.com/wp-json/wp/v2/posts');
curl_setopt($ch, CURLOPT_HTTPHEADER, [
    'Authorization: Bearer ' . $token
]);
$posts = json_decode(curl_exec($ch), true);
```

### Python
```python
import requests

# Get token
r = requests.post('https://site.com/wp-json/wp-rest-shield/v1/token',
    json={'username': 'user', 'password': 'pass'})
token = r.json()['token']

# Use token
r = requests.get('https://site.com/wp-json/wp/v2/posts',
    headers={'Authorization': f'Bearer {token}'})
posts = r.json()
```

---

## 🔒 Security Best Practices

```
✅ Store JWT secret in wp-config.php
✅ Use HTTPS (SSL) in production
✅ Set appropriate token lifetime
✅ Enable logging and monitor regularly
✅ Rotate secrets quarterly
✅ Use rate limits on all POST endpoints
✅ Whitelist known server IPs
✅ Only allow needed endpoints
✅ Test in Monitor mode first
✅ Set up alert webhooks
```

---

## 📁 File Structure

```
wp-rest-shield/
├── wp-rest-shield.php          # Main plugin file
├── includes/
│   ├── Core/
│   │   ├── Plugin.php          # Core plugin class
│   │   ├── RestFilter.php      # Request filtering
│   │   ├── JWT.php             # JWT handling
│   │   ├── RateLimiter.php     # Rate limiting
│   │   └── Logger.php          # Logging
│   ├── Admin/
│   │   └── AdminPage.php       # Admin interface
│   └── API/
│       └── TokenEndpoint.php   # Token endpoints
├── assets/
│   ├── css/
│   │   └── admin.css           # Admin styles
│   └── js/
│       └── admin.js            # Admin scripts
├── tests/
│   └── test-wp-rest-shield.php # PHPUnit tests
├── examples/
│   └── client-examples.php     # Client code examples
└── README.md                   # Documentation
```

---

## 🎨 Admin Pages

| Page | Path | Purpose |
|------|------|---------|
| Dashboard | `admin.php?page=wp-rest-shield` | Stats & overview |
| Rules | `admin.php?page=wp-rest-shield-rules` | Manage access rules |
| Logs | `admin.php?page=wp-rest-shield-logs` | View request logs |
| Settings | `admin.php?page=wp-rest-shield-settings` | Plugin configuration |

---

## 📊 Database Tables

| Table | Purpose |
|-------|---------|
| `wp_rest_shield_logs` | Request logs |
| `wp_rest_shield_rules` | Access rules |
| `wp_rest_shield_tokens` | Issued JWT tokens |

---

## 🔌 Hooks & Filters

### Filters
```php
// Modify allowed status
add_filter('wp_rest_shield_is_request_allowed', function($allowed, $request) {
    return $allowed;
}, 10, 2);

// Modify log data
add_filter('wp_rest_shield_log_event', function($event_data) {
    return $event_data;
}, 10, 1);
```

### Actions
```php
// After request logged
add_action('wp_rest_shield_request_logged', function($request, $blocked) {
    // Custom action
}, 10, 2);
```

---

## 📞 Support

- **Docs**: https://yoursite.com/docs
- **Issues**: https://github.com/yourname/wp-rest-shield/issues
- **Email**: support@yoursite.com

---

## 📄 License

GPL v2 or later

---

**Version**: 1.0.0 | **Last Updated**: 2025-10-18