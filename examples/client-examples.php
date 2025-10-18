<?php
/**
 * WP REST Shield - Client Examples
 * File: examples/client-examples.php
 * 
 * This file contains example code for various clients to interact
 * with a WordPress REST API protected by WP REST Shield
 */

// ============================================
// PHP cURL Examples
// ============================================

/**
 * Example 1: Get JWT Token using username/password
 */
function get_jwt_token($wp_url, $username, $password) {
    $url = $wp_url . '/wp-json/wp-rest-shield/v1/token';
    
    $data = json_encode([
        'username' => $username,
        'password' => $password
    ]);
    
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Content-Type: application/json'
    ]);
    
    $response = curl_exec($ch);
    curl_close($ch);
    
    $result = json_decode($response, true);
    
    return $result['token'] ?? null;
}

/**
 * Example 2: Make authenticated request with JWT token
 */
function get_posts_with_jwt($wp_url, $token) {
    $url = $wp_url . '/wp-json/wp/v2/posts';
    
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Authorization: Bearer ' . $token
    ]);
    
    $response = curl_exec($ch);
    curl_close($ch);
    
    return json_decode($response, true);
}

/**
 * Example 3: Server-to-server request with shared secret
 */
function get_posts_with_server_secret($wp_url, $server_secret) {
    $url = $wp_url . '/wp-json/wp/v2/posts';
    
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'X-Server-Secret: ' . $server_secret
    ]);
    
    $response = curl_exec($ch);
    curl_close($ch);
    
    return json_decode($response, true);
}

/**
 * Example 4: Complete workflow - Get token and fetch posts
 */
function example_complete_workflow() {
    $wp_url = 'https://yoursite.com';
    $username = 'your-username';
    $password = 'your-password';
    
    // Get token
    $token = get_jwt_token($wp_url, $username, $password);
    
    if (!$token) {
        echo "Failed to get token\n";
        return;
    }
    
    echo "Token received: " . substr($token, 0, 20) . "...\n";
    
    // Fetch posts
    $posts = get_posts_with_jwt($wp_url, $token);
    
    if (isset($posts['code'])) {
        echo "Error: " . $posts['message'] . "\n";
        return;
    }
    
    echo "Posts fetched: " . count($posts) . "\n";
    
    foreach ($posts as $post) {
        echo "- " . $post['title']['rendered'] . "\n";
    }
}

?>

<!-- ============================================ -->
<!-- JavaScript / Node.js Examples -->
<!-- ============================================ -->

<script>
/**
 * Example 5: JavaScript Fetch API - Get Token
 */
async function getJWTToken(wpUrl, username, password) {
    const response = await fetch(`${wpUrl}/wp-json/wp-rest-shield/v1/token`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ username, password })
    });
    
    const data = await response.json();
    return data.token;
}

/**
 * Example 6: Fetch posts with JWT token
 */
async function fetchPostsWithJWT(wpUrl, token) {
    const response = await fetch(`${wpUrl}/wp-json/wp/v2/posts`, {
        headers: {
            'Authorization': `Bearer ${token}`
        }
    });
    
    if (!response.ok) {
        const error = await response.json();
        throw new Error(error.message);
    }
    
    return await response.json();
}

/**
 * Example 7: React Component with JWT Authentication
 */
class WordPressAPIClient extends React.Component {
    constructor(props) {
        super(props);
        this.state = {
            token: localStorage.getItem('wp_token'),
            posts: [],
            loading: false,
            error: null
        };
    }
    
    async login(username, password) {
        try {
            const response = await fetch(`${this.props.apiUrl}/wp-json/wp-rest-shield/v1/token`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            });
            
            const data = await response.json();
            
            if (data.token) {
                this.setState({ token: data.token });
                localStorage.setItem('wp_token', data.token);
                return true;
            }
            
            return false;
        } catch (error) {
            console.error('Login failed:', error);
            return false;
        }
    }
    
    async fetchPosts() {
        if (!this.state.token) {
            this.setState({ error: 'Not authenticated' });
            return;
        }
        
        this.setState({ loading: true, error: null });
        
        try {
            const response = await fetch(`${this.props.apiUrl}/wp-json/wp/v2/posts`, {
                headers: {
                    'Authorization': `Bearer ${this.state.token}`
                }
            });
            
            if (!response.ok) {
                throw new Error('Failed to fetch posts');
            }
            
            const posts = await response.json();
            this.setState({ posts, loading: false });
        } catch (error) {
            this.setState({ error: error.message, loading: false });
        }
    }
    
    render() {
        return (
            <div>
                {this.state.error && <p>Error: {this.state.error}</p>}
                {this.state.loading && <p>Loading...</p>}
                {this.state.posts.map(post => (
                    <div key={post.id}>
                        <h2>{post.title.rendered}</h2>
                        <div dangerouslySetInnerHTML={{ __html: post.excerpt.rendered }} />
                    </div>
                ))}
            </div>
        );
    }
}

/**
 * Example 8: Axios with Token Refresh
 */
const axios = require('axios');

class WPAPIClient {
    constructor(baseURL) {
        this.baseURL = baseURL;
        this.token = null;
        this.tokenExpiry = null;
        
        this.client = axios.create({
            baseURL: `${baseURL}/wp-json`
        });
        
        // Add token to all requests
        this.client.interceptors.request.use(async (config) => {
            await this.ensureValidToken();
            if (this.token) {
                config.headers.Authorization = `Bearer ${this.token}`;
            }
            return config;
        });
    }
    
    async login(username, password) {
        const response = await this.client.post('/wp-rest-shield/v1/token', {
            username,
            password
        });
        
        this.token = response.data.token;
        this.tokenExpiry = Date.now() + (response.data.expires_in * 1000);
        
        return this.token;
    }
    
    async ensureValidToken() {
        if (!this.token || Date.now() >= this.tokenExpiry - 60000) {
            // Token expired or will expire in 1 minute
            // Re-login logic here
        }
    }
    
    async getPosts(params = {}) {
        const response = await this.client.get('/wp/v2/posts', { params });
        return response.data;
    }
    
    async createPost(data) {
        const response = await this.client.post('/wp/v2/posts', data);
        return response.data;
    }
}

// Usage
const client = new WPAPIClient('https://yoursite.com');
await client.login('username', 'password');
const posts = await client.getPosts({ per_page: 10 });

</script>

<?php
// ============================================
// Laravel Example (Backend Proxy)
// ============================================
?>

<script type="text/plain">
// Laravel Controller
<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Cache;

class WordPressProxyController extends Controller
{
    protected $wpUrl;
    protected $serverSecret;
    
    public function __construct()
    {
        $this->wpUrl = config('services.wordpress.url');
        $this->serverSecret = config('services.wordpress.server_secret');
    }
    
    /**
     * Proxy request to WordPress API
     */
    public function proxy(Request $request, $endpoint)
    {
        $method = $request->method();
        $url = "{$this->wpUrl}/wp-json/{$endpoint}";
        
        $response = Http::withHeaders([
            'X-Server-Secret' => $this->serverSecret,
            'Content-Type' => 'application/json',
        ])->send($method, $url, [
            'query' => $request->query(),
            'json' => $request->all()
        ]);
        
        return response($response->body(), $response->status())
            ->header('Content-Type', 'application/json');
    }
    
    /**
     * Get posts with caching
     */
    public function getPosts(Request $request)
    {
        $cacheKey = 'wp_posts_' . md5(json_encode($request->all()));
        
        return Cache::remember($cacheKey, 300, function () use ($request) {
            return Http::withHeaders([
                'X-Server-Secret' => $this->serverSecret
            ])->get("{$this->wpUrl}/wp-json/wp/v2/posts", $request->all());
        });
    }
    
    /**
     * Health check
     */
    public function health()
    {
        try {
            $response = Http::withHeaders([
                'X-Server-Secret' => $this->serverSecret
            ])->get("{$this->wpUrl}/wp-json/wp-rest-shield/v1/health");
            
            if ($response->successful()) {
                return response()->json(['status' => 'ok']);
            }
            
            return response()->json(['status' => 'error'], 503);
        } catch (\Exception $e) {
            return response()->json(['status' => 'error', 'message' => $e->getMessage()], 503);
        }
    }
}

// routes/api.php
Route::middleware('api')->group(function () {
    Route::any('wp/{endpoint}', [WordPressProxyController::class, 'proxy'])
        ->where('endpoint', '.*');
    
    Route::get('posts', [WordPressProxyController::class, 'getPosts']);
    Route::get('health', [WordPressProxyController::class, 'health']);
});

// config/services.php
return [
    'wordpress' => [
        'url' => env('WP_URL', 'https://yoursite.com'),
        'server_secret' => env('WP_SERVER_SECRET'),
    ],
];
</script>

<?php
// ============================================
// Python Example
// ============================================
?>

<script type="text/plain">
# Python with requests library

import requests
from datetime import datetime, timedelta

class WPAPIClient:
    def __init__(self, base_url):
        self.base_url = base_url
        self.token = None
        self.token_expiry = None
    
    def login(self, username, password):
        """Get JWT token"""
        response = requests.post(
            f"{self.base_url}/wp-json/wp-rest-shield/v1/token",
            json={"username": username, "password": password}
        )
        
        if response.status_code == 200:
            data = response.json()
            self.token = data['token']
            self.token_expiry = datetime.now() + timedelta(seconds=data['expires_in'])
            return True
        
        return False
    
    def _get_headers(self):
        """Get headers with token"""
        if not self.token:
            raise Exception("Not authenticated")
        
        return {
            "Authorization": f"Bearer {self.token}"
        }
    
    def get_posts(self, params=None):
        """Get posts"""
        response = requests.get(
            f"{self.base_url}/wp-json/wp/v2/posts",
            headers=self._get_headers(),
            params=params
        )
        
        response.raise_for_status()
        return response.json()
    
    def create_post(self, data):
        """Create a post"""
        response = requests.post(
            f"{self.base_url}/wp-json/wp/v2/posts",
            headers=self._get_headers(),
            json=data
        )
        
        response.raise_for_status()
        return response.json()

# Usage
client = WPAPIClient("https://yoursite.com")
client.login("username", "password")
posts = client.get_posts({"per_page": 10})

for post in posts:
    print(f"{post['title']['rendered']}")
</script>

<?php
// ============================================
// cURL Command Line Examples
// ============================================
?>

<script type="text/plain">
# Example 1: Get JWT Token
curl -X POST https://yoursite.com/wp-json/wp-rest-shield/v1/token \
  -H "Content-Type: application/json" \
  -d '{"username":"your-username","password":"your-password"}'

# Example 2: Use JWT Token
TOKEN="your-jwt-token-here"
curl https://yoursite.com/wp-json/wp/v2/posts \
  -H "Authorization: Bearer $TOKEN"

# Example 3: Create Post with JWT
curl -X POST https://yoursite.com/wp-json/wp/v2/posts \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "My New Post",
    "content": "Post content here",
    "status": "publish"
  }'

# Example 4: Server-to-Server Request
curl https://yoursite.com/wp-json/wp/v2/posts \
  -H "X-Server-Secret: your-server-secret"

# Example 5: Validate Token
curl -X POST https://yoursite.com/wp-json/wp-rest-shield/v1/validate \
  -H "Authorization: Bearer $TOKEN"

# Example 6: Health Check
curl https://yoursite.com/wp-json/wp-rest-shield/v1/health \
  -H "X-Server-Secret: your-server-secret"
</script>