# WP REST Shield - 404 Error Troubleshooting Guide

## Step-by-Step Fix for "No route was found" Error

### Step 1: Upload Diagnostic Tool

1. Upload `diagnostic.php` to your WordPress root directory (same folder as `wp-config.php`)
2. Access it in your browser: `https://stage.learnelite.in/diagnostic.php`
3. This will show you exactly what's wrong

### Step 2: Most Common Causes & Fixes

#### Issue A: Plugin Files Not Uploaded Correctly

**Check**: Does diagnostic show "File NOT found" for any files?

**Fix**:
1. Delete the entire `wp-content/plugins/wp-rest-shield/` folder on server
2. Re-upload ALL plugin files, ensuring this structure:
```
wp-content/plugins/wp-rest-shield/
├── wp-rest-shield.php
├── includes/
│   ├── API/
│   │   ├── TokenEndpoint.php
│   │   └── TokenEndpointV2.php  ← IMPORTANT!
│   ├── Core/
│   │   ├── Plugin.php
│   │   ├── RestFilter.php
│   │   ├── JWT.php
│   │   ├── RateLimiter.php
│   │   └── Logger.php
│   └── Admin/
│       └── AdminPage.php
└── assets/
    ├── css/
    └── js/
```

#### Issue B: PHP Syntax Error Preventing Class Loading

**Check**: Does diagnostic show "Class NOT loaded"?

**Fix**:
1. Enable WordPress debug mode in `wp-config.php`:
```php
define('WP_DEBUG', true);
define('WP_DEBUG_LOG', true);
define('WP_DEBUG_DISPLAY', false);
```
2. Check `wp-content/debug.log` for PHP errors
3. Fix any syntax errors shown

#### Issue C: Routes Not Registered

**Check**: Does diagnostic show "No V1 routes found" or "No V2 routes found"?

**Fix (Try in order)**:

**Option 1 - Flush Permalinks**:
1. Go to: `https://stage.learnelite.in/wp-admin/options-permalink.php`
2. Click "Save Changes" (don't change anything)
3. Test again

**Option 2 - Deactivate/Reactivate**:
1. Go to: Plugins → Installed Plugins
2. Click "Deactivate" on WP REST Shield
3. Click "Activate"
4. Test again

**Option 3 - Manual Flush via Code**:
Add this to your `wp-config.php` temporarily:
```php
// Add BEFORE "That's all, stop editing!"
flush_rewrite_rules(true);
```
Then remove it after testing.

**Option 4 - Clear .htaccess**:
1. Rename `.htaccess` to `.htaccess.backup`
2. Go to Settings → Permalinks → Save Changes
3. WordPress will regenerate `.htaccess`

#### Issue D: .htaccess Rules Blocking REST API

**Check**: Can you access other REST endpoints like:
- `https://stage.learnelite.in/wp-json/`
- `https://stage.learnelite.in/wp-json/wp/v2/posts`

If these also return 404, your `.htaccess` is blocking REST API.

**Fix**: Check your `.htaccess` file for rules blocking `wp-json`. It should look like:
```apache
# BEGIN WordPress
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteBase /
RewriteRule ^index\.php$ - [L]
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule . /index.php [L]
</IfModule>
# END WordPress
```

### Step 3: Verify Fix

After applying fixes, test these URLs:

**Health Check (should return JSON)**:
```
GET https://stage.learnelite.in/wp-json/wp-rest-shield/v1/health
```

**API Documentation (should return JSON)**:
```
GET https://stage.learnelite.in/wp-json/wp-rest-shield/v2/docs
```

**Token Endpoint (should return error about missing credentials, NOT 404)**:
```
POST https://stage.learnelite.in/wp-json/wp-rest-shield/v1/token
```

### Step 4: Test Token Generation

Once routes work, test generating a token:

```bash
curl -X POST https://stage.learnelite.in/wp-json/wp-rest-shield/v1/token \
  -H "Content-Type: application/json" \
  -d '{
    "username": "your_admin_username",
    "password": "your_admin_password"
  }'
```

Expected response:
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_expires_in": 604800,
  "user_id": 1
}
```

## Quick Checklist

- [ ] All plugin files uploaded correctly
- [ ] Plugin is activated
- [ ] Permalinks flushed (Settings → Permalinks → Save)
- [ ] No PHP errors in debug.log
- [ ] `.htaccess` allows REST API
- [ ] Routes show up in diagnostic.php
- [ ] Can access `/wp-json/` endpoint
- [ ] Can access `/wp-json/wp-rest-shield/v1/health`

## Still Not Working?

Run the diagnostic and send me:
1. Screenshot of diagnostic.php output
2. Contents of `.htaccess` file
3. Any errors from `wp-content/debug.log`

## Security Note

**IMPORTANT**: Delete `diagnostic.php` after troubleshooting!
```bash
rm diagnostic.php
```

## Common Server-Specific Issues

### Nginx
If using Nginx, you need this in your server block:
```nginx
location / {
    try_files $uri $uri/ /index.php?$args;
}
```

### Cloudflare
If using Cloudflare, temporarily pause it to rule out caching issues.

### Caching Plugins
Disable all caching plugins temporarily:
- WP Super Cache
- W3 Total Cache
- WP Rocket
- etc.

## Advanced Debugging

Add this to `wp-config.php` to see route registration:
```php
define('WP_DEBUG', true);
define('WP_DEBUG_LOG', true);

// Add this temporarily
add_action('rest_api_init', function() {
    error_log('REST API initialized at: ' . current_time('mysql'));

    $server = rest_get_server();
    $routes = $server->get_routes();
    $shield_routes = array_filter(array_keys($routes), function($route) {
        return strpos($route, 'wp-rest-shield') !== false;
    });

    error_log('WP REST Shield routes: ' . print_r($shield_routes, true));
}, 999);
```

Check `wp-content/debug.log` for the output.
