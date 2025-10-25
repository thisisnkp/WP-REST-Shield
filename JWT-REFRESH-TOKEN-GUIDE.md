# JWT Refresh Token Implementation Guide

## Overview

This implementation adds complete JWT refresh token functionality to WP REST Shield, providing a more secure and flexible authentication system for WordPress REST API access.

## New Features Added

### 1. Refresh Token Generation
- **Access Tokens**: Short-lived tokens for API access (default: 1 hour)
- **Refresh Tokens**: Long-lived tokens for obtaining new access tokens (default: 7 days)
- **Token Rotation**: Optional automatic refresh token rotation for enhanced security

### 2. New Settings

#### Admin Dashboard Settings
- **Access Token Lifetime**: Configure how long access tokens remain valid
- **Refresh Token Lifetime**: Configure how long refresh tokens remain valid  
- **Rotate Refresh Tokens**: Enable/disable automatic refresh token rotation

### 3. New API Endpoints

#### `/wp-json/wp-rest-shield/v1/token` (Enhanced)
**Method**: POST

**Request Body**:
```json
{
  "username": "your-username",
  "password": "your-password",
  "access_lifetime": 3600,  // Optional: custom access token lifetime
  "refresh_lifetime": 604800 // Optional: custom refresh token lifetime
}
```

**Response**:
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

#### `/wp-json/wp-rest-shield/v1/refresh` (New)
**Method**: POST

**Request Body**:
```json
{
  "refresh_token": "your-refresh-token"
}
```

**Response**:
```json
{
  "access_token": "new-access-token",
  "refresh_token": "refresh-token-or-new-one",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

## Implementation Details

### Database Schema Updates

The `rest_shield_tokens` table now includes:
- `token_type` field to distinguish between 'access' and 'refresh' tokens
- Proper indexing for efficient token lookups

### Security Features

1. **Token Type Validation**: Ensures tokens are used for their intended purpose
2. **Automatic Expiration**: Both token types have configurable expiration times
3. **Token Rotation**: Optional refresh token rotation prevents long-term token reuse
4. **Revocation Support**: Tokens can be individually revoked

### Fixed Issues

1. **Eye Button Functionality**: Fixed JavaScript event binding issues in admin interface
2. **Token Validation**: Enhanced validation with proper error handling
3. **Admin UI**: Improved secret management with better user feedback

## Usage Examples

### PHP Example
```php
// Get initial tokens
$tokens = get_initial_tokens($base_url, $username, $password);

// Use access token for API calls
$response = make_api_request($base_url, $tokens['access_token'], '/wp/v2/posts');

// Refresh when access token expires
$new_tokens = refresh_access_token($base_url, $tokens['refresh_token']);
```

### JavaScript Example
```javascript
// Initialize token manager
const tokenManager = new JWTTokenManager('http://your-site.com');

// Login and get tokens
await tokenManager.login('username', 'password');

// Make authenticated requests (auto-refreshes tokens)
const posts = await tokenManager.apiRequest('/wp/v2/posts');
```

## Migration Notes

### For Existing Installations
1. Activate the plugin to run database migrations
2. New default settings will be applied automatically
3. Existing access tokens continue to work
4. New tokens will include refresh tokens

### Backward Compatibility
- Existing API clients continue to work without modification
- Old token validation remains functional
- New features are additive, not breaking

## Security Best Practices

### Recommended Settings
- **Access Token Lifetime**: 15-60 minutes for high-security applications
- **Refresh Token Lifetime**: 7-30 days depending on security requirements
- **Token Rotation**: Enable for maximum security

### Client Implementation
1. Store refresh tokens securely (never in localStorage for web apps)
2. Implement automatic token refresh logic
3. Handle token expiration gracefully
4. Clear tokens on logout

### Server Configuration
1. Use HTTPS in production
2. Store JWT secret in wp-config.php
3. Enable logging for token audit trails
4. Set appropriate CORS policies

## Error Handling

### Common Error Responses

#### Invalid Refresh Token
```json
{
  "code": "token_expired",
  "message": "Token has expired",
  "data": {"status": 401}
}
```

#### Invalid Token Type
```json
{
  "code": "invalid_token_type", 
  "message": "Invalid token type",
  "data": {"status": 401}
}
```

#### Missing Refresh Token
```json
{
  "code": "missing_refresh_token",
  "message": "Refresh token is required", 
  "data": {"status": 400}
}
```

## Testing

### Manual Testing
1. Generate token pair via `/token` endpoint
2. Verify access token works for authenticated requests
3. Test refresh functionality via `/refresh` endpoint
4. Verify token rotation (if enabled)
5. Test token expiration handling

### Automated Testing
- Use provided example files for testing scenarios
- Implement unit tests for critical functionality
- Test edge cases like expired tokens and invalid requests

## Performance Considerations

### Database Optimization
- Token table is indexed for efficient lookups
- Automatic cleanup of expired tokens (recommended)
- Consider token pruning for high-traffic sites

### Caching
- JWT validation is stateless for performance
- Database lookups only for revocation checking
- Consider Redis for token blacklisting in cluster environments

## Troubleshooting

### Common Issues

1. **Eye button not working**: Clear browser cache after update
2. **Tokens not refreshing**: Check refresh token expiration
3. **Database errors**: Verify table schema migration completed
4. **Invalid tokens**: Ensure JWT secret consistency

### Debug Mode
Enable WordPress debug mode and check logs for detailed error information:
```php
define('WP_DEBUG', true);
define('WP_DEBUG_LOG', true);
```

## Support

For issues or questions:
1. Check the error logs first
2. Verify all settings are configured correctly
3. Test with provided examples
4. Ensure database schema is up to date

## Changelog

### Version 1.0.3
- Added refresh token functionality
- Enhanced JWT system with token types
- Fixed admin interface eye button
- Added comprehensive examples and documentation
- Improved security with token rotation option
- Updated database schema for refresh tokens