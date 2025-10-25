/**
 * JWT Refresh Token Example - JavaScript
 * This demonstrates how to use refresh tokens in a JavaScript application
 */

class JWTTokenManager {
    constructor(baseUrl) {
        this.baseUrl = baseUrl;
        this.accessToken = null;
        this.refreshToken = null;
        this.accessTokenExpiry = null;
    }

    /**
     * Initial login to get token pair
     */
    async login(username, password) {
        const response = await fetch(`${this.baseUrl}/wp-json/wp-rest-shield/v1/token`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                username: username,
                password: password
            })
        });

        if (!response.ok) {
            throw new Error(`Login failed: ${response.status}`);
        }

        const data = await response.json();
        
        this.accessToken = data.access_token;
        this.refreshToken = data.refresh_token;
        this.accessTokenExpiry = Date.now() + (data.expires_in * 1000);

        console.log('✓ Login successful');
        console.log('✓ Access token expires in:', data.expires_in, 'seconds');
        console.log('✓ Refresh token expires in:', data.refresh_expires_in, 'seconds');

        return data;
    }

    /**
     * Refresh the access token
     */
    async refreshAccessToken() {
        if (!this.refreshToken) {
            throw new Error('No refresh token available');
        }

        const response = await fetch(`${this.baseUrl}/wp-json/wp-rest-shield/v1/refresh`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                refresh_token: this.refreshToken
            })
        });

        if (!response.ok) {
            throw new Error(`Token refresh failed: ${response.status}`);
        }

        const data = await response.json();
        
        this.accessToken = data.access_token;
        this.refreshToken = data.refresh_token; // May be the same or new depending on rotation setting
        this.accessTokenExpiry = Date.now() + (data.expires_in * 1000);

        console.log('✓ Access token refreshed');
        return data;
    }

    /**
     * Check if access token needs refreshing
     */
    needsRefresh() {
        if (!this.accessToken || !this.accessTokenExpiry) {
            return false;
        }
        
        // Refresh 5 minutes before expiry
        const bufferTime = 5 * 60 * 1000; // 5 minutes in milliseconds
        return Date.now() > (this.accessTokenExpiry - bufferTime);
    }

    /**
     * Get valid access token (refresh if needed)
     */
    async getValidAccessToken() {
        if (this.needsRefresh()) {
            console.log('Access token needs refresh...');
            await this.refreshAccessToken();
        }
        return this.accessToken;
    }

    /**
     * Make authenticated API request
     */
    async apiRequest(endpoint, options = {}) {
        const accessToken = await this.getValidAccessToken();
        
        const response = await fetch(`${this.baseUrl}/wp-json${endpoint}`, {
            ...options,
            headers: {
                'Authorization': `Bearer ${accessToken}`,
                'Content-Type': 'application/json',
                ...options.headers
            }
        });

        if (!response.ok) {
            throw new Error(`API request failed: ${response.status}`);
        }

        return response.json();
    }
}

// Example usage
async function example() {
    const tokenManager = new JWTTokenManager('http://your-wordpress-site.com');

    try {
        console.log('=== JWT Refresh Token Example ===\n');

        // Login
        await tokenManager.login('your-username', 'your-password');

        // Make API requests
        console.log('\n1. Making authenticated request...');
        const posts = await tokenManager.apiRequest('/wp/v2/posts?per_page=5');
        console.log('✓ Fetched', posts.length, 'posts');

        // Simulate time passing (you can manually test refresh by waiting)
        console.log('\n2. Checking if token needs refresh...');
        if (tokenManager.needsRefresh()) {
            console.log('Token needs refresh');
        } else {
            console.log('Token is still valid');
        }

        // Force refresh for demo
        console.log('\n3. Manually refreshing token...');
        await tokenManager.refreshAccessToken();

        // Make another request with refreshed token
        console.log('\n4. Making request with refreshed token...');
        const users = await tokenManager.apiRequest('/wp/v2/users?per_page=5');
        console.log('✓ Fetched', users.length, 'users');

        console.log('\n=== All tests passed! ===');

    } catch (error) {
        console.error('❌ Error:', error.message);
    }
}

// Advanced example with automatic token management
class AutoRefreshFetch {
    constructor(baseUrl, username, password) {
        this.tokenManager = new JWTTokenManager(baseUrl);
        this.initPromise = this.tokenManager.login(username, password);
    }

    async fetch(endpoint, options = {}) {
        await this.initPromise;
        return this.tokenManager.apiRequest(endpoint, options);
    }
}

// Usage:
// const api = new AutoRefreshFetch('http://your-site.com', 'user', 'pass');
// const posts = await api.fetch('/wp/v2/posts');

// Run example (uncomment to test)
// example();